// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! EVERY ENDPOINT FAILS CLOSED WHEN THE STORE FAILS UNDER IT.
//!
//! `containment_truth.rs` proves the AUDIT SIGNAL is honest when a containment write fails. This
//! file is the broader, duller sibling: it walks each endpoint's own `store` calls and asserts that
//! a failure of that call surfaces as a `server_error` (RFC 6749 section 5.2 / a 5xx) rather than as
//! a success, an authorization, or a silently swallowed error. "The store could not say" must never
//! read as "the store said yes": these are exactly the `.map_err(storage_error)?` sites in
//! `server.rs`, one fault switch per storage operation, driven through the public endpoint that
//! reaches it.
//!
//! Each test mints whatever it needs with a HEALTHY store first, then flips one fault switch and
//! drives the one endpoint, so the only thing that can produce the error under test is the injected
//! failure and not the setup.

mod support;

use std::sync::atomic::Ordering;

use oauth_as::server::UserApproval;
use oauth_as::{AuthorizationRequest, ClientId, ErrorCode, TokenRequest, TokenTypeHint};

use support::{
    confidential_client, device_only_client, fault_server_with, mint_code_token, ManualClock,
    CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET, RFC7636_VERIFIER,
};

const DEVICE_SECRET: &str = "s3cret-value-for-tests";

// --------------------------------------------------------------------------- client resolution

/// Every client-authenticated endpoint resolves the client first. A `get_client` failure must fail
/// closed, never fall through to an unauthenticated or unknown-client answer.
#[tokio::test]
async fn a_get_client_failure_fails_closed() {
    let srv = fault_server_with(ManualClock::at_epoch(), vec![device_only_client()]).await;
    srv.store().fail_get_client.store(true, Ordering::SeqCst);
    let err = srv
        .device_authorization(&ClientId::new("device-only"), Some(DEVICE_SECRET), None)
        .await
        .expect_err("a store that cannot resolve the client must fail closed");
    assert_eq!(err.error, ErrorCode::ServerError);
}

// --------------------------------------------------------------------------- device authorization

/// The device-authorization endpoint writes a fresh grant; a `put_device_grant` failure is a 5xx,
/// not a device-authorization response naming a code that was never stored.
#[tokio::test]
async fn a_device_grant_write_failure_fails_closed() {
    let srv = fault_server_with(ManualClock::at_epoch(), vec![device_only_client()]).await;
    srv.store()
        .fail_put_device_grant
        .store(true, Ordering::SeqCst);
    let err = srv
        .device_authorization(&ClientId::new("device-only"), Some(DEVICE_SECRET), None)
        .await
        .expect_err("a failed grant write must fail closed");
    assert_eq!(err.error, ErrorCode::ServerError);
}

/// Minting a user code checks the store for a collision. If that lookup ERRORS (as opposed to
/// reporting a collision), the generator cannot know the code is free, so the request fails closed
/// rather than issuing a possibly-colliding code.
#[tokio::test]
async fn a_user_code_lookup_failure_fails_closed() {
    let srv = fault_server_with(ManualClock::at_epoch(), vec![device_only_client()]).await;
    srv.store()
        .error_find_device_grant
        .store(true, Ordering::SeqCst);
    let err = srv
        .device_authorization(&ClientId::new("device-only"), Some(DEVICE_SECRET), None)
        .await
        .expect_err("a failed user-code collision check must fail closed");
    assert_eq!(err.error, ErrorCode::ServerError);
}

// --------------------------------------------------------------------------- authorization code

/// Redeeming a code consumes it through the atomic take. A `take_authorization_code` failure is a
/// 5xx, not a redemption that proceeds without having burned the code.
#[tokio::test]
async fn a_code_take_failure_fails_closed() {
    let srv = fault_server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;

    // Issue a code with a healthy store, leaving it unredeemed.
    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let req = AuthorizationRequest::from_pairs([
        ("response_type", "code"),
        ("client_id", "confidential-app"),
        ("redirect_uri", CONFIDENTIAL_REDIRECT),
        ("scope", "read"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]);
    let validated = srv.validate_authorization_request(&req).await.unwrap();
    let issued = srv
        .issue_authorization_code(UserApproval::granted(&validated, "alice"))
        .await
        .unwrap();

    srv.store()
        .fail_take_authorization_code
        .store(true, Ordering::SeqCst);
    let err = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            code: issued.code,
            redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await
        .expect_err("a code redemption whose take fails must fail closed");
    assert_eq!(err.error, ErrorCode::ServerError);
}

/// Issuance writes the refresh token. A `put_refresh_token` failure during the issue that a code
/// redemption drives is a 5xx, not a token response missing its refresh half.
#[tokio::test]
async fn a_refresh_write_failure_during_issuance_fails_closed() {
    let srv = fault_server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;

    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let req = AuthorizationRequest::from_pairs([
        ("response_type", "code"),
        ("client_id", "confidential-app"),
        ("redirect_uri", CONFIDENTIAL_REDIRECT),
        ("scope", "read"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]);
    let validated = srv.validate_authorization_request(&req).await.unwrap();
    let issued = srv
        .issue_authorization_code(UserApproval::granted(&validated, "alice"))
        .await
        .unwrap();

    srv.store().fail_put_refresh.store(true, Ordering::SeqCst);
    let err = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            code: issued.code,
            redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await
        .expect_err("an issuance whose refresh write fails must fail closed");
    assert_eq!(err.error, ErrorCode::ServerError);
}

// --------------------------------------------------------------------------- refresh grant

/// The refresh grant consumes the presented refresh token through the atomic take. A
/// `take_refresh_token` failure is a 5xx, not a refresh that proceeds without consuming the old
/// token.
#[tokio::test]
async fn a_refresh_take_failure_fails_closed() {
    let srv = fault_server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let issued = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "alice",
    )
    .await;
    let refresh = issued
        .refresh_token
        .expect("the code flow mints a refresh token");

    srv.store()
        .fail_take_refresh_token
        .store(true, Ordering::SeqCst);
    let err = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            refresh_token: refresh,
            scope: None,
        })
        .await
        .expect_err("a refresh whose take fails must fail closed");
    assert_eq!(err.error, ErrorCode::ServerError);
}

// --------------------------------------------------------------------------- introspection

/// Introspection reads the token by name. A `get_token` failure is a 5xx, not an `active: false`
/// answer that would tell a resource server the token is not valid when the store simply could not
/// say.
#[tokio::test]
async fn an_introspection_token_read_failure_fails_closed() {
    let srv = fault_server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let issued = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "alice",
    )
    .await;

    srv.store().fail_get_token.store(true, Ordering::SeqCst);
    let err = srv
        .introspection_response(
            &ClientId::new("confidential-app"),
            Some(CONFIDENTIAL_SECRET),
            &issued.access_token,
        )
        .await
        .expect_err("introspection whose token read fails must fail closed");
    assert_eq!(err.error, ErrorCode::ServerError);
}

// --------------------------------------------------------------------------- revocation

/// Revoking a refresh token consumes it through the atomic take. A `take_refresh_token` failure is a
/// 5xx: the client must not be told a revocation completed that the store could not carry out.
#[tokio::test]
async fn a_revocation_refresh_take_failure_fails_closed() {
    let srv = fault_server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let issued = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "alice",
    )
    .await;
    let refresh = issued
        .refresh_token
        .expect("the code flow mints a refresh token");

    srv.store()
        .fail_take_refresh_token
        .store(true, Ordering::SeqCst);
    let err = srv
        .revoke(
            &ClientId::new("confidential-app"),
            Some(CONFIDENTIAL_SECRET),
            &refresh,
            Some(TokenTypeHint::RefreshToken),
        )
        .await
        .expect_err("a revocation whose take fails must fail closed");
    assert_eq!(err.error, ErrorCode::ServerError);
}

/// Revoking an access token deletes it by name. A `delete_token` failure is a 5xx: the same rule,
/// on the other token type.
#[tokio::test]
async fn a_revocation_access_delete_failure_fails_closed() {
    let srv = fault_server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let issued = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "alice",
    )
    .await;

    srv.store().fail_delete_token.store(true, Ordering::SeqCst);
    let err = srv
        .revoke(
            &ClientId::new("confidential-app"),
            Some(CONFIDENTIAL_SECRET),
            &issued.access_token,
            Some(TokenTypeHint::AccessToken),
        )
        .await
        .expect_err("a revocation whose delete fails must fail closed");
    assert_eq!(err.error, ErrorCode::ServerError);
}

// --------------------------------------------------------------------------- device token poll

/// Polling a device grant reads it first. A `get_device_grant` failure is a 5xx, not an
/// `authorization_pending` answer the store could not actually support.
#[tokio::test]
async fn a_device_poll_read_failure_fails_closed() {
    let srv = fault_server_with(ManualClock::at_epoch(), vec![device_only_client()]).await;
    let auth = srv
        .device_authorization(&ClientId::new("device-only"), Some(DEVICE_SECRET), None)
        .await
        .unwrap();

    srv.store()
        .fail_get_device_grant
        .store(true, Ordering::SeqCst);
    let err = srv
        .token(TokenRequest::DeviceCode {
            client_id: ClientId::new("device-only"),
            client_secret: Some(DEVICE_SECRET.to_string()),
            device_code: auth.device_code,
        })
        .await
        .expect_err("a device poll whose read fails must fail closed");
    assert_eq!(err.error, ErrorCode::ServerError);
}

/// The first poll of a pending grant records the poll via a compare-and-swap. A failure of THAT swap
/// (as opposed to merely losing the race, which is tolerated) is a 5xx.
#[tokio::test]
async fn a_device_pending_swap_failure_fails_closed() {
    let srv = fault_server_with(ManualClock::at_epoch(), vec![device_only_client()]).await;
    let auth = srv
        .device_authorization(&ClientId::new("device-only"), Some(DEVICE_SECRET), None)
        .await
        .unwrap();

    srv.store()
        .fail_compare_and_swap_device_grant
        .store(true, Ordering::SeqCst);
    let err = srv
        .token(TokenRequest::DeviceCode {
            client_id: ClientId::new("device-only"),
            client_secret: Some(DEVICE_SECRET.to_string()),
            device_code: auth.device_code,
        })
        .await
        .expect_err("a pending poll whose swap fails must fail closed");
    assert_eq!(err.error, ErrorCode::ServerError);
}

/// A too-fast second poll takes the slow-down path, which also records the (grown) interval via a
/// compare-and-swap. A failure of that swap is a 5xx. The first poll runs with a healthy store to
/// set `last_poll_at`, so only the second poll's swap can be the failure under test.
#[tokio::test]
async fn a_device_slow_down_swap_failure_fails_closed() {
    let srv = fault_server_with(ManualClock::at_epoch(), vec![device_only_client()]).await;
    let auth = srv
        .device_authorization(&ClientId::new("device-only"), Some(DEVICE_SECRET), None)
        .await
        .unwrap();

    // First poll (healthy) records last_poll_at; the clock does not advance, so the next poll is
    // inside the interval and takes the slow-down path.
    let pending = srv
        .token(TokenRequest::DeviceCode {
            client_id: ClientId::new("device-only"),
            client_secret: Some(DEVICE_SECRET.to_string()),
            device_code: auth.device_code.clone(),
        })
        .await
        .expect_err("the first poll of a pending grant is authorization_pending");
    assert_eq!(pending.error, ErrorCode::AuthorizationPending);

    srv.store()
        .fail_compare_and_swap_device_grant
        .store(true, Ordering::SeqCst);
    let err = srv
        .token(TokenRequest::DeviceCode {
            client_id: ClientId::new("device-only"),
            client_secret: Some(DEVICE_SECRET.to_string()),
            device_code: auth.device_code,
        })
        .await
        .expect_err("a slow-down poll whose swap fails must fail closed");
    assert_eq!(err.error, ErrorCode::ServerError);
}

/// Redeeming an APPROVED device grant consumes it through the atomic take. A `take_device_grant`
/// failure is a 5xx, not a redemption that mints a token without consuming the grant.
#[tokio::test]
async fn a_device_approved_take_failure_fails_closed() {
    let srv = fault_server_with(ManualClock::at_epoch(), vec![device_only_client()]).await;
    let auth = srv
        .device_authorization(&ClientId::new("device-only"), Some(DEVICE_SECRET), None)
        .await
        .unwrap();
    srv.approve_device(&auth.user_code, "user-1").await.unwrap();

    srv.store()
        .fail_take_device_grant
        .store(true, Ordering::SeqCst);
    let err = srv
        .token(TokenRequest::DeviceCode {
            client_id: ClientId::new("device-only"),
            client_secret: Some(DEVICE_SECRET.to_string()),
            device_code: auth.device_code,
        })
        .await
        .expect_err("an approved-grant redemption whose take fails must fail closed");
    assert_eq!(err.error, ErrorCode::ServerError);
}

// --------------------------------------------------------------------------- token exchange

/// RFC 8693 token exchange introspects the subject token to learn what it may exchange. That
/// introspection reads the token from the store; a `get_token` failure is a 5xx, not an exchange
/// that proceeds on a token the store could not vouch for. (The actor-token read on the delegation
/// path is the same `.map_err(storage_error)?` shape, but it cannot be isolated here: `fail_get_token`
/// fails the subject read first, so the actor read is never reached; a fail-Nth-call fault would be
/// needed and is not worth a switch for one line.)
#[cfg(feature = "token-exchange")]
#[tokio::test]
async fn a_token_exchange_subject_read_failure_fails_closed() {
    use oauth_as::{
        Client, ClientAuth, GrantType, ScopeSet, TokenExchange, TokenExchangeRequest,
        TokenTypeIdentifier,
    };

    const EXCHANGER_SECRET: &str = "exchanger-secret-for-tests";
    let exchanger = Client {
        client_id: ClientId::new("exchanger"),
        auth: ClientAuth::ConfidentialSecret {
            secret: EXCHANGER_SECRET.into(),
        },
        grant_types: vec![
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::TokenExchange,
        ],
        redirect_uris: vec![CONFIDENTIAL_REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    };
    let srv = fault_server_with(ManualClock::at_epoch(), vec![exchanger]).await;

    // A live subject token, minted with a healthy store.
    let subject = mint_code_token(
        &srv,
        "exchanger",
        Some(EXCHANGER_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "alice",
    )
    .await;

    // Subject-token introspection fails.
    srv.store().fail_get_token.store(true, Ordering::SeqCst);
    let client_id = ClientId::new("exchanger");
    let mut req = TokenExchangeRequest::new(
        &client_id,
        &subject.access_token,
        TokenTypeIdentifier::AccessToken,
    );
    req.client_secret = Some(EXCHANGER_SECRET);
    let err = srv
        .exchange_token(&req)
        .await
        .expect_err("an exchange whose subject read fails must fail closed");
    assert_eq!(err.error, ErrorCode::ServerError);
}
