// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 8693 bounds and the one opt-in the exchange has.
//!
//! Two unrelated things share a file because they share a fixture: the section 2.1.1 `audience`
//! array (repeatable, deduplicated with an O(n) scan per element, and uncapped) and
//! `ServerConfig::allow_sender_constrained_exchange`, the migration switch behind the refusal of a
//! bound subject token.

#![cfg(feature = "token-exchange")]

mod support;

use std::time::{Duration, UNIX_EPOCH};

use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientId, ErrorCode, GrantType, IssuedToken,
    MemoryStorage, ScopeSet, ServerConfig, Storage, TokenExchange, TokenExchangeRequest,
    TokenRequest, TokenTypeIdentifier,
};
use support::ManualClock;

const SECRET: &str = "exchanger-secret-for-tests";

fn exchanger() -> Client {
    Client {
        client_id: ClientId::new("exchanger"),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.into(),
        },
        grant_types: vec![GrantType::TokenExchange, GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

async fn server(allow_bound: bool) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.allow_sender_constrained_exchange = allow_bound;
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    srv.register_client(exchanger()).await.unwrap();
    srv
}

/// A subject token held by the exchanging client itself, which is all this file needs: what is on
/// trial is the `audience` array and the binding check, neither of which cares who the subject is.
async fn subject_token<S: Storage>(srv: &AuthorizationServer<S, ManualClock>) -> String {
    srv.token(TokenRequest::ClientCredentials {
        client_id: ClientId::new("exchanger"),
        client_secret: Some(SECRET.to_string()),
        scope: None,
    })
    .await
    .expect("fixture subject token")
    .access_token
}

fn audiences(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("urn:svc:{i}")).collect()
}

/// THE FINDING. Section 2.1.1 makes `audience` repeatable, this crate dedups it against `targets`
/// with an O(n) scan per element, and nothing bounded how many a request could carry.
#[tokio::test]
async fn the_exchange_refuses_more_audience_values_than_the_cap() {
    let srv = server(false).await;
    let subject = subject_token(&srv).await;
    let client_id = ClientId::new("exchanger");

    let over = audiences(oauth_as::token_exchange::MAX_AUDIENCE_VALUES + 1);
    let mut request =
        TokenExchangeRequest::new(&client_id, &subject, TokenTypeIdentifier::AccessToken);
    request.client_secret = Some(SECRET);
    request.audience = &over;

    let refused = srv
        .exchange_token(&request)
        .await
        .expect_err("one past the cap is refused");
    assert_eq!(
        refused.error,
        ErrorCode::InvalidTarget,
        "RFC 8693 s2.1.1 audiences go to the same ceiling as RFC 8707 resources"
    );
    // The CODE alone does not discriminate: an over-cap request would also be refused
    // `invalid_target` a few lines later by the audience ceiling, for a different reason. The
    // description is what says the SIZE check is the thing that fired, which is the point: the
    // work must be refused before it is done, not after.
    assert!(
        refused
            .error_description
            .unwrap_or_default()
            .contains("too many audience values"),
        "the size check has to be what refused, and it has to refuse BEFORE the dedup scan runs"
    );
}

/// The cap is not so tight that a legal request trips it. At the cap the request still reaches the
/// audience CEILING, which refuses for a different reason (a subject token carrying no resource has
/// nothing to narrow to), and that is the answer this suite expects: the size check passed.
#[tokio::test]
async fn exactly_the_cap_is_not_a_size_refusal() {
    let srv = server(false).await;
    let subject = subject_token(&srv).await;
    let client_id = ClientId::new("exchanger");

    let at = audiences(oauth_as::token_exchange::MAX_AUDIENCE_VALUES);
    let mut request =
        TokenExchangeRequest::new(&client_id, &subject, TokenTypeIdentifier::AccessToken);
    request.client_secret = Some(SECRET);
    request.audience = &at;

    let outcome = srv.exchange_token(&request).await;
    let description = outcome
        .expect_err("the subject token names no resource, so the ceiling refuses it")
        .error_description
        .unwrap_or_default();
    assert!(
        !description.contains("too many"),
        "at the cap the size check must not be what refused: {description}"
    );
}

/// GROUP E, the half `ServerConfig` owns. A sender-constrained subject token is refused by DEFAULT,
/// because the token this server would hand back belongs to the exchanging client, which cannot
/// prove possession of the binding key, so it can only be a plain bearer token. The switch exists
/// only as a migration path off the silent downgrade 0.9.0 and earlier performed.
#[cfg(feature = "dpop")]
#[tokio::test]
async fn a_bound_subject_token_is_refused_by_default_and_allowed_only_by_opt_in() {
    // Written into the store directly rather than minted through a DPoP proof: what is on trial is
    // the CONFIG guard, and a real proof exchange would be testing RFC 9449's verifier instead.
    async fn bound_token<S: Storage>(srv: &AuthorizationServer<S, ManualClock>) -> String {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let token = IssuedToken {
            access_token: "bound-subject-token".to_string(),
            client_id: ClientId::new("exchanger"),
            subject: Some("user-1".to_string()),
            scope: ScopeSet::parse("read").unwrap(),
            resource: Vec::new(),
            #[cfg(feature = "rar")]
            authorization_details: Default::default(),
            issued_at: now,
            expires_at: now + Duration::from_secs(3600),
            jkt: Some("a-thumbprint-standing-in-for-a-real-one".into()),
            #[cfg(feature = "mtls")]
            x5t_s256: None,
            family_id: None,
            #[cfg(feature = "consent")]
            authentication: None,
        };
        srv.store().put_token(token).await.unwrap();
        "bound-subject-token".to_string()
    }

    let client_id = ClientId::new("exchanger");

    let refusing = server(false).await;
    let subject = bound_token(&refusing).await;
    let mut request =
        TokenExchangeRequest::new(&client_id, &subject, TokenTypeIdentifier::AccessToken);
    request.client_secret = Some(SECRET);
    let refused = refusing
        .exchange_token(&request)
        .await
        .expect_err("the default must refuse to strip a binding");
    assert_eq!(refused.error, ErrorCode::InvalidRequest);
    assert!(
        refused
            .error_description
            .unwrap_or_default()
            .contains("sender constrained"),
        "the client needs to be told WHY: it just presented the token carrying the binding"
    );

    let permissive = server(true).await;
    let subject = bound_token(&permissive).await;
    let mut request =
        TokenExchangeRequest::new(&client_id, &subject, TokenTypeIdentifier::AccessToken);
    request.client_secret = Some(SECRET);
    permissive
        .exchange_token(&request)
        .await
        .expect("the opt-in is what a deployment mid-migration off the silent downgrade needs");
}
