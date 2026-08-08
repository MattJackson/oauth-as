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

use std::time::Duration;

use oauth_as::{ClientId, ErrorCode, IntrospectionResponse, TokenType, TokenTypeHint};
use support::{
    confidential_client, device_only_client, mint_code_token, other_confidential_client,
    server_with, ManualClock, CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET,
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
