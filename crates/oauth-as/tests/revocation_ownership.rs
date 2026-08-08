// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Who is allowed to ask the two token-plane administration endpoints anything at all.
//!
//! RFC 7662 section 2.1 requires introspection to be a PROTECTED endpoint, and section 4 is blunt
//! about why: "the endpoint MUST NOT be publicly available", because it otherwise answers
//! questions about tokens the caller merely holds a copy of. RFC 7009 section 2.1 says the same
//! of revocation, and adds that the server MUST verify that the token was issued to the client
//! making the request.
//!
//! Naming a public client is not authentication. A public client has no secret by definition, so
//! "authenticated as a public client" is a description of every caller on the internet. An
//! ownership check performed against an identity anyone may claim is not an access control.
//!
//! The second thing pinned here is that an ownership check must not be built out of a
//! read-modify-write on somebody else's live credential. Taking a record out in order to look at
//! it, and putting it back if it turns out not to belong to the caller, means a failure of the
//! second write destroys a chain the caller was never entitled to touch.

mod support;

use std::sync::atomic::Ordering;

use oauth_as::{ClientId, ErrorCode, TokenRequest, TokenTypeHint};
use support::{
    confidential_client, fault_server_with, mint_code_token, mint_code_token_keeping_code,
    other_confidential_client, public_client, server_with, ManualClock, CONFIDENTIAL_REDIRECT,
    CONFIDENTIAL_SECRET, OTHER_CONFIDENTIAL_SECRET, PUBLIC_REDIRECT,
};

/// THE ATTACK (RFC 7662 sections 2.1 and 4): a public client's access token turns up in a proxy
/// log. Anyone holding it POSTs it to the introspection endpoint naming that public client, with
/// no credential, because a public client has none to present. If naming the client is accepted as
/// authentication, the endpoint hands back `sub`, `scope`, `exp` and `iat`: it has become the
/// public token-description oracle section 4 forbids.
#[tokio::test]
async fn introspection_refuses_a_public_client_caller() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;
    let issued = mint_code_token(&srv, "public-app", None, PUBLIC_REDIRECT, "read", "user-1").await;

    let err = srv
        .introspection_response(&ClientId::new("public-app"), None, &issued.access_token)
        .await
        .expect_err("introspection must not answer an unauthenticated caller");
    assert_eq!(
        err.error,
        ErrorCode::InvalidClient,
        "RFC 7662 s2.1: the endpoint requires authorization, and a public client id is not it"
    );
}

/// THE ATTACK (RFC 7009 section 2.1): the same leaked token, aimed at the revocation endpoint.
/// With no credential required, anyone who has seen a public client's token can end that user's
/// session at will, which is an unauthenticated denial of service against every user of every
/// public client.
#[tokio::test]
async fn revocation_refuses_a_public_client_caller() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;
    let issued = mint_code_token(&srv, "public-app", None, PUBLIC_REDIRECT, "read", "user-1").await;
    let refresh_token = issued.refresh_token.expect("the code grant issues a chain");

    let err = srv
        .revoke(
            &ClientId::new("public-app"),
            None,
            &issued.access_token,
            None,
        )
        .await
        .expect_err("revocation must not act for an unauthenticated caller");
    assert_eq!(err.error, ErrorCode::InvalidClient);

    let err = srv
        .revoke(
            &ClientId::new("public-app"),
            None,
            &refresh_token,
            Some(TokenTypeHint::RefreshToken),
        )
        .await
        .expect_err("revocation must not act for an unauthenticated caller");
    assert_eq!(err.error, ErrorCode::InvalidClient);

    // And nothing may have been destroyed on the way to that refusal.
    assert!(
        srv.introspect(&issued.access_token)
            .await
            .unwrap()
            .is_some(),
        "a refused revocation must not have revoked anything"
    );
    srv.token(TokenRequest::RefreshToken {
        client_id: ClientId::new("public-app"),
        client_secret: None,
        refresh_token,
        scope: None,
    })
    .await
    .expect("a refused revocation must not have destroyed the refresh chain");
}

/// THE ATTACK (RFC 7009 section 2.1): client B calls revoke with a refresh token belonging to
/// client A. The ownership check is supposed to leave A's token untouched. If it is implemented as
/// take-then-put-back, the token is briefly GONE, and if the restoring write fails, it is gone for
/// good. Here the restoring write fails, which a real store does under transient pressure; the
/// endpoint even returns 200 while the victim's chain is destroyed. A read-only ownership check
/// never removes the record at all, so there is nothing to restore and nothing to lose.
#[tokio::test]
async fn a_failed_restore_cannot_destroy_another_clients_refresh_chain() {
    let clock = ManualClock::at_epoch();
    let srv = fault_server_with(
        clock,
        vec![confidential_client(), other_confidential_client()],
    )
    .await;
    let (issued, _code) = mint_code_token_keeping_code(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    let refresh_token = issued.refresh_token.expect("the code grant issues a chain");

    // Every write of a refresh record now fails, as it would under a transient store fault.
    srv.store().fail_put_refresh.store(true, Ordering::SeqCst);

    srv.revoke(
        &ClientId::new("other-app"),
        Some(OTHER_CONFIDENTIAL_SECRET),
        &refresh_token,
        Some(TokenTypeHint::RefreshToken),
    )
    .await
    .expect("RFC 7009 s2.2: revoking a token that is not the caller's still answers 200");

    srv.store().fail_put_refresh.store(false, Ordering::SeqCst);

    srv.token(TokenRequest::RefreshToken {
        client_id: ClientId::new("confidential-app"),
        client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
        refresh_token,
        scope: None,
    })
    .await
    .expect("the victim's chain must still be redeemable");
}
