// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 7662 token introspection.
//!
//! Section 2.2 gives the endpoint exactly one legal answer for a token the caller has not proven
//! it holds: `{"active": false}`, nothing else. Section 4 explains why that matters: any extra
//! member (a scope, a subject, an expiry) turns the endpoint into an oracle a caller can use to
//! probe tokens it does not possess. That constraint, not the happy path, is most of what is worth
//! pinning here.

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use oauth_as::{
    AuthorizationServer, ClientAuthFailure, ClientId, ErrorCode, Event, EventSink,
    IntrospectionResponse, MemoryStorage, ServerConfig, TokenType, TokenTypeHint,
};
use support::{
    confidential_client, device_only_client, mint_code_token, other_confidential_client,
    public_client, server_with, ManualClock, CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET,
    OTHER_CONFIDENTIAL_SECRET,
};

/// RFC 7662 s2.2: a token the caller owns reports the full set of members the RFC defines for an
/// active token.
#[tokio::test]
async fn active_token_owned_by_caller_reports_full_details() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![confidential_client()]).await;
    let issued = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read write",
        "user-1",
    )
    .await;

    let resp = srv
        .introspection_response(
            &ClientId::new("confidential-app"),
            Some(CONFIDENTIAL_SECRET),
            &issued.access_token,
        )
        .await
        .expect("an authenticated owning client must get an answer");

    assert!(resp.active, "the token is live and just minted");
    assert_eq!(resp.scope.as_deref(), Some("read write"));
    assert_eq!(resp.client_id.as_deref(), Some("confidential-app"));
    assert_eq!(resp.sub.as_deref(), Some("user-1"));
    assert_eq!(resp.token_type, Some(TokenType::Bearer));
    assert!(resp.exp.is_some(), "RFC 7662 s2.2: exp for an active token");
    assert!(resp.iat.is_some(), "RFC 7662 s2.2: iat for an active token");
    assert_eq!(resp.iss.as_deref(), Some("https://as.example"));
}

/// RFC 7662 s2.2 / s4: an unknown token reports `active: false` and NOTHING else. This is checked
/// against the serialized JSON, not just the struct, because a struct-level check would pass even
/// if a leaking field were added and merely left at `None` by coincidence in this particular case.
#[tokio::test]
async fn unknown_token_is_exactly_active_false_on_the_wire() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![confidential_client()]).await;

    let resp = srv
        .introspection_response(
            &ClientId::new("confidential-app"),
            Some(CONFIDENTIAL_SECRET),
            "this-token-was-never-issued",
        )
        .await
        .expect("an unknown token is answered, not refused");

    assert_eq!(resp, IntrospectionResponse::inactive());
    let value = serde_json::to_value(&resp).unwrap();
    assert_eq!(
        value,
        serde_json::json!({"active": false}),
        "RFC 7662 s2.2: an inactive answer must carry no other member, got {value}"
    );
}

/// RFC 7662 s2.2: expiry is judged live, not merely recorded at issuance.
#[tokio::test]
async fn expired_token_reads_inactive() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![confidential_client()]).await;
    let issued = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;

    // The default access token lifetime is 3600 seconds.
    clock.advance(Duration::from_secs(3601));

    let resp = srv
        .introspection_response(
            &ClientId::new("confidential-app"),
            Some(CONFIDENTIAL_SECRET),
            &issued.access_token,
        )
        .await
        .unwrap();
    assert_eq!(
        resp,
        IntrospectionResponse::inactive(),
        "an expired token must not still read active"
    );
}

/// RFC 7662 s2.2 and s4: a token belonging to a DIFFERENT client must not describe somebody
/// else's grant. This is verified against the raw JSON too, because leaking even one member
/// (e.g. `client_id` while omitting `sub`) is still the oracle the RFC forbids.
#[tokio::test]
async fn another_clients_token_reads_inactive_and_leaks_nothing() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(
        clock,
        vec![confidential_client(), other_confidential_client()],
    )
    .await;
    let issued = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read write",
        "user-1",
    )
    .await;

    let resp = srv
        .introspection_response(
            &ClientId::new("other-app"),
            Some(OTHER_CONFIDENTIAL_SECRET),
            &issued.access_token,
        )
        .await
        .expect("a well-authenticated caller still gets an answer, just an inactive one");

    let value = serde_json::to_value(&resp).unwrap();
    assert_eq!(
        value,
        serde_json::json!({"active": false}),
        "another client's token must not describe the grant, got {value}"
    );
}

/// RFC 7662 s2.1: introspection is a protected endpoint. An unauthenticated caller, or one that
/// authenticates as the wrong client, does not get an answer about the token at all: it gets
/// `invalid_client`, the same refusal client authentication uses everywhere else in this crate.
#[tokio::test]
async fn introspection_requires_client_authentication() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![confidential_client(), device_only_client()]).await;
    let issued = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;

    // No credential at all.
    let err = srv
        .introspection_response(
            &ClientId::new("confidential-app"),
            None,
            &issued.access_token,
        )
        .await
        .expect_err("a confidential client presenting no secret must not be authenticated");
    assert_eq!(err.error, ErrorCode::InvalidClient);

    // Wrong secret.
    let err = srv
        .introspection_response(
            &ClientId::new("confidential-app"),
            Some("not-the-real-secret"),
            &issued.access_token,
        )
        .await
        .expect_err("the wrong secret must not authenticate");
    assert_eq!(err.error, ErrorCode::InvalidClient);

    // Unknown client entirely.
    let err = srv
        .introspection_response(
            &ClientId::new("no-such-client"),
            Some("anything"),
            &issued.access_token,
        )
        .await
        .expect_err("an unregistered client_id must not be authenticated");
    assert_eq!(err.error, ErrorCode::InvalidClient);
}

/// RFC 7662 s4, applied to the ERROR channel rather than to the response body.
///
/// A caller who reaches this endpoint with a client id and nothing else learns whether that id is
/// registered, if the three refusals differ. They must not: the crate collapses "no such client"
/// and "wrong secret" into one bare `invalid_client` on purpose, and a description saying "this
/// one is public" would sort registered ids from unregistered ones just as well. Compared BYTE FOR
/// BYTE (the whole `ErrorResponse`), not merely on `error`, because the description is exactly
/// where the previous distinction lived.
#[tokio::test]
async fn a_public_client_is_refused_indistinguishably_from_an_unknown_one() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![confidential_client(), public_client()]).await;

    let public = srv
        .introspection_response(&ClientId::new("public-app"), None, "some-token")
        .await
        .expect_err("a public client may not introspect");
    let unknown = srv
        .introspection_response(&ClientId::new("no-such-client"), None, "some-token")
        .await
        .expect_err("an unknown client may not introspect");
    let wrong_secret = srv
        .introspection_response(
            &ClientId::new("confidential-app"),
            Some("not-the-real-secret"),
            "some-token",
        )
        .await
        .expect_err("a wrong secret may not introspect");

    assert_eq!(public.error, ErrorCode::InvalidClient);
    assert_eq!(
        public.error_description, None,
        "a description here says the id is registered AND public; the other two carry none"
    );
    assert_eq!(
        public, unknown,
        "a registered public client and an unregistered id must be one answer"
    );
    assert_eq!(public, wrong_secret);
    assert_eq!(
        serde_json::to_value(&public).unwrap(),
        serde_json::json!({"error": "invalid_client"}),
        "and the difference must not survive serialization either"
    );
}

/// `Box<dyn EventSink>` takes ownership and this test also has to read what was recorded, so what
/// is installed is a handle over a shared vector. Same shape as `tests/events.rs`'s recorder.
#[derive(Default)]
struct Failures(Mutex<Vec<(String, ClientAuthFailure)>>);

struct FailuresHandle(Arc<Failures>);

impl EventSink for FailuresHandle {
    fn on_event(&self, event: Event<'_>) {
        if let Event::ClientAuthenticationFailed { client_id, failure } = event {
            self.0
                 .0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((client_id.to_string(), failure));
        }
    }
}

/// The reason did not vanish, it MOVED: the host's audit channel is told which of the two it was,
/// because the operator is not the attacker and the usual cause here is a resource server
/// registered with the wrong `token_endpoint_auth_method` rather than an attack. Without this, the
/// fix above would have traded an oracle for a refusal nobody can diagnose.
#[tokio::test]
async fn the_public_client_refusal_reaches_the_audit_channel() {
    let recorded = Arc::new(Failures::default());
    let srv = AuthorizationServer::with_clock(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        MemoryStorage::new(),
        ManualClock::at_epoch(),
    )
    .with_event_sink(Box::new(FailuresHandle(recorded.clone())));
    srv.register_client(public_client()).await.unwrap();

    srv.introspection_response(&ClientId::new("public-app"), None, "some-token")
        .await
        .expect_err("a public client may not introspect");

    let seen = recorded.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(
        seen,
        vec![("public-app".to_string(), ClientAuthFailure::NotConfidential)],
        "the operator must be told exactly what the wire deliberately does not say"
    );
}

/// A token that has been revoked (RFC 7009) is exactly as inactive as one that was never issued.
#[tokio::test]
async fn revoked_token_reads_inactive() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![confidential_client()]).await;
    let issued = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;

    srv.revoke(
        &ClientId::new("confidential-app"),
        Some(CONFIDENTIAL_SECRET),
        &issued.access_token,
        Some(TokenTypeHint::AccessToken),
    )
    .await
    .expect("revoking a live token must succeed");

    let resp = srv
        .introspection_response(
            &ClientId::new("confidential-app"),
            Some(CONFIDENTIAL_SECRET),
            &issued.access_token,
        )
        .await
        .unwrap();
    assert_eq!(resp, IntrospectionResponse::inactive());
}
