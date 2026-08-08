// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 7009 token revocation.
//!
//! Most of what is worth pinning here is what the RFC insists does NOT change the wire answer:
//! revoking a token nobody has ever seen still gets a 200 (section 2.2), a wrong `token_type_hint`
//! still finds and kills the right token (section 2.1), and revoking twice is still success. The
//! sharpest case is ownership: a client must never be able to revoke another client's token, and
//! the other client's token must still work afterwards, because "any registered client can end any
//! other client's session" is a denial of service, not a feature.

mod support;

use oauth_as::{ClientId, ErrorCode, IntrospectionResponse, TokenRequest, TokenTypeHint};
use support::{
    confidential_client, mint_code_token, other_confidential_client, server_with, ManualClock,
    CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET, OTHER_CONFIDENTIAL_SECRET,
};

/// RFC 7009 s2.1: revoking an access token must make it dead, verified through the RFC 7662
/// introspection surface rather than the host-only `introspect` shortcut, since the wire-visible
/// answer is what actually matters.
#[tokio::test]
async fn revoking_an_access_token_makes_it_inactive_to_introspection() {
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
    .expect("revoking a live access token must succeed");

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

/// RFC 7009 s2.1: "If the particular token is a refresh token and the authorization server
/// supports the revocation of access tokens, then the authorization server SHOULD also invalidate
/// all access tokens based on the same authorization grant."
///
/// This is the half of revocation a client cannot do for itself. A client that revokes its refresh
/// token has said "this session is over"; leaving the access token minted from the same grant live
/// means the session is over for the party that asked and not for whoever holds the token, which is
/// exactly inverted when the reason for revoking is that something leaked.
#[tokio::test]
async fn revoking_a_refresh_token_also_kills_the_access_tokens_of_the_same_grant() {
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
    let refresh_token = issued.refresh_token.clone().expect("a refresh token");

    srv.revoke(
        &ClientId::new("confidential-app"),
        Some(CONFIDENTIAL_SECRET),
        &refresh_token,
        Some(TokenTypeHint::RefreshToken),
    )
    .await
    .expect("revoking a live refresh token must succeed");

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
        "the access token issued with the revoked refresh token is still live"
    );
}

/// RFC 7009 s2.1: revoking a refresh token must break the chain it belonged to, so the next
/// attempt to use it is `invalid_grant` rather than a fresh token.
#[tokio::test]
async fn revoking_a_refresh_token_makes_the_next_refresh_invalid_grant() {
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
    let refresh_token = issued.refresh_token.expect("a refresh token was issued");

    srv.revoke(
        &ClientId::new("confidential-app"),
        Some(CONFIDENTIAL_SECRET),
        &refresh_token,
        Some(TokenTypeHint::RefreshToken),
    )
    .await
    .expect("revoking a live refresh token must succeed");

    let err = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            refresh_token,
            scope: None,
        })
        .await
        .expect_err("a revoked refresh token must not redeem");
    assert_eq!(err.error, ErrorCode::InvalidGrant);
}

/// RFC 7009 s2.2: the server MUST respond with a 200 even when the presented token was never
/// issued, because refusing it would let a caller distinguish "revoked" from "never existed" and
/// so test whether an arbitrary string is a real token.
#[tokio::test]
async fn revoking_an_unknown_token_still_returns_ok() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![confidential_client()]).await;

    srv.revoke(
        &ClientId::new("confidential-app"),
        Some(CONFIDENTIAL_SECRET),
        "this-token-was-never-issued",
        None,
    )
    .await
    .expect("RFC 7009 s2.2: an unknown token must not produce an error response");
}

/// Revocation is idempotent: nothing about a second revocation of the same token is a failure.
#[tokio::test]
async fn revocation_is_idempotent() {
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

    for attempt in 0..2 {
        srv.revoke(
            &ClientId::new("confidential-app"),
            Some(CONFIDENTIAL_SECRET),
            &issued.access_token,
            Some(TokenTypeHint::AccessToken),
        )
        .await
        .unwrap_or_else(|e| panic!("revocation attempt {attempt} must succeed, got {e:?}"));
    }
}

/// RFC 7009 s2.1 requires the server to verify the token belongs to the authenticated client. A
/// client cannot revoke another client's token, and critically the target token must survive the
/// attempt intact: silently destroying another client's refresh chain from an unrelated,
/// legitimately registered client would be a denial of service available to anyone who can
/// register a client. Both the access token and the refresh token halves are checked.
#[tokio::test]
async fn a_client_cannot_revoke_another_clients_token_and_it_still_works() {
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
    let refresh_token = issued
        .refresh_token
        .clone()
        .expect("a refresh token was issued");

    // The attempt itself must still answer 200 (an attacker must not be able to distinguish "not
    // yours" from "unknown" either), but it must not touch the token.
    srv.revoke(
        &ClientId::new("other-app"),
        Some(OTHER_CONFIDENTIAL_SECRET),
        &issued.access_token,
        Some(TokenTypeHint::AccessToken),
    )
    .await
    .expect("the wire answer for someone else's token is still success");

    let after_access_attempt = srv
        .introspection_response(
            &ClientId::new("confidential-app"),
            Some(CONFIDENTIAL_SECRET),
            &issued.access_token,
        )
        .await
        .unwrap();
    assert!(
        after_access_attempt.active,
        "another client's revoke attempt must not touch the access token"
    );

    srv.revoke(
        &ClientId::new("other-app"),
        Some(OTHER_CONFIDENTIAL_SECRET),
        &refresh_token,
        Some(TokenTypeHint::RefreshToken),
    )
    .await
    .expect("the wire answer for someone else's refresh token is still success");

    // The refresh chain must still be redeemable by its real owner.
    srv.token(TokenRequest::RefreshToken {
        client_id: ClientId::new("confidential-app"),
        client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
        refresh_token,
        scope: None,
    })
    .await
    .expect("another client's failed revoke attempt must not have destroyed the refresh chain");
}

/// RFC 7009 s2.1: `token_type_hint` is an optimisation only. The server MUST keep looking when the
/// hint does not match, so every hint/kind combination, including the two mismatched ones, must
/// still revoke the right token.
#[tokio::test]
async fn wrong_type_hint_still_revokes_the_right_token() {
    for hint_for_access in [
        None,
        Some(TokenTypeHint::AccessToken),
        Some(TokenTypeHint::RefreshToken),
    ] {
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
            hint_for_access,
        )
        .await
        .unwrap();

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
            "hint {hint_for_access:?} must not stop the access token from being revoked"
        );
    }

    for hint_for_refresh in [
        None,
        Some(TokenTypeHint::AccessToken),
        Some(TokenTypeHint::RefreshToken),
    ] {
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
        let refresh_token = issued.refresh_token.expect("a refresh token was issued");

        srv.revoke(
            &ClientId::new("confidential-app"),
            Some(CONFIDENTIAL_SECRET),
            &refresh_token,
            hint_for_refresh,
        )
        .await
        .unwrap();

        let err = srv
            .token(TokenRequest::RefreshToken {
                client_id: ClientId::new("confidential-app"),
                client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
                refresh_token,
                scope: None,
            })
            .await
            .expect_err(&format!(
                "hint {hint_for_refresh:?} must not stop the refresh token from being revoked"
            ));
        assert_eq!(err.error, ErrorCode::InvalidGrant);
    }
}

/// Revocation is a protected endpoint exactly like introspection: no credential, or the wrong
/// one, gets `invalid_client` rather than an answer about the token.
#[tokio::test]
async fn revocation_requires_client_authentication() {
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

    let err = srv
        .revoke(
            &ClientId::new("confidential-app"),
            None,
            &issued.access_token,
            None,
        )
        .await
        .expect_err("a confidential client presenting no secret must not be authenticated");
    assert_eq!(err.error, ErrorCode::InvalidClient);

    let err = srv
        .revoke(
            &ClientId::new("confidential-app"),
            Some("not-the-real-secret"),
            &issued.access_token,
            None,
        )
        .await
        .expect_err("the wrong secret must not authenticate");
    assert_eq!(err.error, ErrorCode::InvalidClient);

    let err = srv
        .revoke(
            &ClientId::new("no-such-client"),
            Some("anything"),
            &issued.access_token,
            None,
        )
        .await
        .expect_err("an unregistered client_id must not be authenticated");
    assert_eq!(err.error, ErrorCode::InvalidClient);

    // The token must have survived every one of those failed attempts.
    let resp = srv
        .introspection_response(
            &ClientId::new("confidential-app"),
            Some(CONFIDENTIAL_SECRET),
            &issued.access_token,
        )
        .await
        .unwrap();
    assert!(
        resp.active,
        "an unauthenticated revoke attempt must not have revoked anything"
    );
}
