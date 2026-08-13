// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! What a ROW actually holds after a write, as opposed to what the trait's return value said.
//!
//! Two things the other suites cannot see, both found by the 0.9.1 audit.
//!
//! # The index columns are a projection, and a write that skips them breaks two readers
//!
//! `migrations/0001_core.sql` says of `client_id`, `subject` and `expires_at_ns` that they are "a
//! projection of the payload, never a second source of truth". Every write path keeps that true by
//! writing all of them; `compare_and_swap_authorization_code` did not, and rewrote only `payload`.
//! Nothing in `AuthorizationServer` noticed, because the only field it ever swaps is `state`, but
//! implementing `Storage` directly is a supported use and the entire premise of this crate, and two
//! readers key on the columns rather than on the payload: `revoke_consent`'s cascade
//! (`WHERE client_id = $1 AND subject = $2`) and `sweep_expired` (`WHERE expires_at_ns <= $1`). A
//! stale column therefore means a code that survives a withdrawal of the subject it now names, and
//! a code reclaimed on a deadline it no longer has.
//!
//! Both halves are checked below: the column directly, and the user-visible consequence.
//!
//! # The feature-gated fields were never in a payload that round-tripped
//!
//! `IssuedToken::act`, `IssuedToken::x5t_s256` and `IssuedToken::authorization_details` are gated
//! on `token-exchange`, `mtls` and `rar`. Through 0.9.1 the `pg-integration` feature enabled only
//! the four features that gate trait METHODS, so those three fields were not in the test build at
//! all and no assertion here could even name them. They are serde, so nothing in `store.rs` had to
//! change for them to work. But "it is serde, so it must work" is the kind of claim this
//! repository does not accept without a run against a real server.

#![cfg(feature = "pg-integration")]

use std::time::{Duration, SystemTime};

use oauth_as::authorization::{AuthorizationCodeRecord, AuthorizationCodeState};
use oauth_as::client::ClientId;
use oauth_as::consent::ConsentRecord;
use oauth_as::scope::ScopeSet;
use oauth_as::store::{RevocationWindow, Storage};
use oauth_as::token::IssuedToken;
use oauth_as_postgres::{to_nanos, PostgresStorage};
use sqlx::Row;

mod support;

const CLIENT: &str = "client-persisted-shape";

fn scopes() -> ScopeSet {
    ScopeSet::parse("read").expect("a valid RFC 6749 s3.3 scope")
}

/// An unredeemed code for `subject`, expiring an hour out.
fn code_for(code: &str, subject: &str, expires_at: SystemTime) -> AuthorizationCodeRecord {
    AuthorizationCodeRecord::new(
        code,
        ClientId::new(CLIENT),
        "https://client.example/cb",
        scopes(),
        subject,
        "challenge-persisted-shape",
        expires_at,
    )
}

/// Plant a code, then swap in a record that differs from it in every projected column.
///
/// The swap compares on `state`, which is what the server does, so this is a swap the store must
/// accept: the point is not that the state changed, it is that the rest of the record did.
async fn swap_to(store: &PostgresStorage, code: &str, to_subject: &str, to_expires_at: SystemTime) {
    let mut updated = code_for(code, to_subject, to_expires_at);
    updated.state = AuthorizationCodeState::Consumed {
        access_token: None,
        refresh_token: None,
    };
    let applied = store
        .compare_and_swap_authorization_code(&AuthorizationCodeState::Issued, updated)
        .await
        .expect("compare_and_swap_authorization_code");
    assert!(
        applied,
        "the swap did not apply, so the rest proves nothing"
    );
}

/// THE COLUMN, read directly. The trait says "replace the record stored under `updated.code` with
/// `updated`", and a row whose payload says one subject and whose column says another has not been
/// replaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_swap_rewrites_the_index_columns_and_not_only_the_payload() {
    const SCHEMA: &str = "oauth_as_shape_columns";
    support::fresh_schema(SCHEMA).await;
    let store = support::store(SCHEMA, 2).await;
    let probe = support::pool(SCHEMA, 1).await;

    let planted_deadline = SystemTime::now() + Duration::from_secs(3600);
    let swapped_deadline = SystemTime::now() + Duration::from_secs(7200);
    store
        .put_authorization_code(code_for("code-columns", "subject-before", planted_deadline))
        .await
        .expect("plant the code");
    swap_to(&store, "code-columns", "subject-after", swapped_deadline).await;

    let row = sqlx::query(
        "SELECT subject, expires_at_ns, payload -> 'subject' AS payload_subject \
         FROM oauth_as_authorization_codes WHERE code = $1",
    )
    .bind("code-columns")
    .fetch_one(&probe)
    .await
    .expect("the swapped row is still there");
    let subject: String = row.try_get("subject").expect("the subject column");
    let expires_at_ns: i64 = row.try_get("expires_at_ns").expect("the expiry column");
    let payload_subject: serde_json::Value = row
        .try_get("payload_subject")
        .expect("the subject inside the payload");

    assert_eq!(
        payload_subject,
        serde_json::json!("subject-after"),
        "the payload itself was not replaced, so this test is checking the wrong thing"
    );
    assert_eq!(
        subject, "subject-after",
        "the subject COLUMN still names the record the swap replaced, so it is a second source of \
         truth rather than a projection of the payload; revoke_consent's cascade keys on it"
    );
    assert_eq!(
        expires_at_ns,
        to_nanos(swapped_deadline),
        "the expiry COLUMN still holds the replaced record's deadline, so sweep_expired reclaims \
         this code on an instant its payload no longer names"
    );
}

/// THE USER-VISIBLE CONSEQUENCE, with no raw SQL in it: a code whose subject the swap changed must
/// be cascaded away when THAT subject withdraws their consent. With the columns stale the cascade
/// keys on the subject the code no longer names, and an in-flight grant survives a withdrawal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_withdrawal_cascades_a_code_the_swap_moved_to_that_subject() {
    const SCHEMA: &str = "oauth_as_shape_cascade";
    support::fresh_schema(SCHEMA).await;
    let store = support::store(SCHEMA, 2).await;

    let deadline = SystemTime::now() + Duration::from_secs(3600);
    store
        .put_authorization_code(code_for("code-cascade", "subject-before", deadline))
        .await
        .expect("plant the code");
    swap_to(&store, "code-cascade", "subject-after", deadline).await;

    store
        .put_consent(ConsentRecord {
            consent_id: "consent-cascade".into(),
            client_id: ClientId::new(CLIENT),
            subject: "subject-after".into(),
            scope: scopes(),
            resource: Vec::new(),
            granted_at: SystemTime::now(),
            authentication: None,
        })
        .await
        .expect("put_consent");
    let now = SystemTime::now();
    store
        .revoke_consent(
            "consent-cascade",
            RevocationWindow {
                recorded_at: now,
                until: now + Duration::from_secs(3600),
            },
        )
        .await
        .expect("revoke_consent");

    assert!(
        store
            .take_authorization_code("code-cascade")
            .await
            .expect("take_authorization_code")
            .is_none(),
        "the withdrawal of subject-after left a live authorization code whose payload names \
         subject-after, because the cascade keys on the index column and the swap left it stale: \
         the client can still mint a token seconds after the user withdrew"
    );
}

/// The three fields that only exist under `mtls`, `rar` and `token-exchange`, through a real
/// server and back. Nothing in `store.rs` names any of them, which is exactly why this is worth
/// running: the claim being checked is that the payload is the core's own type and the store does
/// not have an opinion about its shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_round_tripped_token_keeps_its_feature_gated_fields() {
    const SCHEMA: &str = "oauth_as_shape_gated_fields";
    support::fresh_schema(SCHEMA).await;
    let store = support::store(SCHEMA, 2).await;

    let now = SystemTime::now();
    let mut token = IssuedToken::new(
        "at-gated-fields",
        ClientId::new(CLIENT),
        Some("subject-gated".to_string()),
        scopes(),
        now,
        now + Duration::from_secs(3600),
    );
    token.grant_established_at = now;
    // RFC 8693 s4.1: the delegation this token carries. Nested one level, because the chain is
    // what a flat `sub` cannot express and is the part a naive mapping layer would drop.
    token.act = Some(Box::new(oauth_as::token_exchange::ActClaim {
        sub: "actor-gated".to_string(),
        client_id: Some("actor-client".to_string()),
        act: Some(Box::new(oauth_as::token_exchange::ActClaim {
            sub: "prior-actor-gated".to_string(),
            client_id: None,
            act: None,
        })),
    }));
    // RFC 8705 s3.1: dropping this turns a certificate-bound token back into a bearer token, which
    // is the failure `0001_core.sql` gives as its reason for storing the record as one document.
    token.x5t_s256 = Some(Box::new(oauth_as::mtls::CertificateThumbprint::from_der(
        b"a certificate, for the hash only",
    )));
    // RFC 9396 s2.
    token.authorization_details = oauth_as::rar::AuthorizationDetails::parse(
        r#"[{"type":"payment","instructedAmount":{"currency":"EUR","amount":"12.34"}}]"#,
    )
    .expect("a valid RFC 9396 authorization_details");

    let expected = token.clone();
    assert!(
        store
            .put_token(token)
            .await
            .expect("put_token")
            .is_applied(),
        "no barrier stands, so the plant must have been applied"
    );
    let read = store
        .get_token("at-gated-fields")
        .await
        .expect("get_token")
        .expect("the token that was just written");

    assert_eq!(
        read.act, expected.act,
        "the RFC 8693 act claim did not survive the round trip, so introspection cannot tell \
         \"A acting for B\" from \"B\""
    );
    assert!(
        read.act.is_some(),
        "act came back None, which is the shape a store that silently drops the field also has"
    );
    assert_eq!(
        read.x5t_s256, expected.x5t_s256,
        "the RFC 8705 certificate thumbprint did not survive the round trip, so a bound token \
         came back as a bearer token"
    );
    assert_eq!(
        read.authorization_details, expected.authorization_details,
        "the RFC 9396 authorization details did not survive the round trip, so the token grants \
         something other than what the user approved"
    );
}
