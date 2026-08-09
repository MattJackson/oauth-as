// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Who is allowed to ask the two token-plane administration endpoints anything at all.
//!
//! THE TWO ENDPOINTS ANSWER A PUBLIC CLIENT DIFFERENTLY, ON PURPOSE, and that asymmetry is the
//! first thing this file records. Both RFCs were read as one rule until 0.9.0 and only one of them
//! says it.
//!
//! RFC 7662 section 2.1 requires introspection to be a PROTECTED endpoint, and section 4 is blunt
//! about why: "the endpoint MUST NOT be publicly available", because it otherwise answers
//! questions about tokens the caller merely holds a copy of. Naming a public client is not
//! authentication: a public client has no secret by definition, so "authenticated as a public
//! client" is a description of every caller on the internet, and an ownership check performed
//! against an identity anyone may claim is not an access control. So introspection refuses.
//!
//! RFC 7009 says something different about revocation. Section 2.1 scopes the credential check in
//! a parenthesis, "(in case of a confidential client)", and makes the OWNERSHIP check the
//! unconditional half; section 5 names "a valid `client_id`, in the case of a public client" as
//! what such a request carries, and settles the obvious objection in terms: a caller holding
//! somebody's token "could do much worse damage by using the token elsewhere than by revoking it".
//! So revocation admits a public client, and the ownership check against the stored RECORD is what
//! keeps it safe.
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
    other_confidential_client, public_client, server_with, two_redirect_client, ManualClock,
    CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET, OTHER_CONFIDENTIAL_SECRET, PUBLIC_REDIRECT,
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

/// THE RULE, and it is deliberately NOT the same rule introspection follows above: a public
/// client may revoke its OWN token, access or refresh, presenting no credential, and may revoke
/// NOTHING ELSE.
///
/// # Why this is not the hole the introspection test above describes
///
/// This test pinned the opposite behaviour until 0.9.0, and its reasoning was that "with no
/// credential required, anyone who has seen a public client's token can end that user's session
/// at will". The threat is real. RFC 7009 considered it and decided against refusing, and the
/// decision is in the text rather than left to inference, which is why the refusal was removed
/// and must not be re-introduced by anybody re-deriving the argument:
///
/// - Section 2.1: the server "first validates the client credentials (in case of a confidential
///   client) and then verifies whether the token was issued to the client making the revocation
///   request". The parenthesis SCOPES the credential check; the ownership check is unconditional.
/// - Section 5, on exactly this attacker: a caller holding somebody's token "could do much worse
///   damage by using the token elsewhere than by revoking it", and names "a valid `client_id`, in
///   the case of a public client" as what such a request carries.
///
/// So the capability an attacker gains here is strictly SMALLER than the one they already have by
/// holding the string: spending a token is worse than ending it. Against that sits what refusing
/// costs an honest deployment: this server issues tokens to public clients through code + PKCE and
/// through the device grant, so a refusal leaves every native and browser app with no standard way
/// to make a logout mean anything, and the refresh chain outlives the user's decision entirely.
///
/// Introspection stays refused (RFC 7662 section 4, above) because it is a request to DESCRIBE a
/// token rather than to destroy one, and a description is a capability the holder of the string
/// does NOT already have.
#[tokio::test]
async fn a_public_client_may_revoke_its_own_token_and_only_its_own() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(
        clock,
        vec![
            public_client(),
            confidential_client(),
            two_redirect_client(),
        ],
    )
    .await;
    let issued = mint_code_token(&srv, "public-app", None, PUBLIC_REDIRECT, "read", "user-1").await;
    let refresh_token = issued.refresh_token.expect("the code grant issues a chain");

    // ---------------------------------------------------------- its own access token: revocable
    srv.revoke(
        &ClientId::new("public-app"),
        None,
        &issued.access_token,
        Some(TokenTypeHint::AccessToken),
    )
    .await
    .expect("RFC 7009 s2.1: a public client presents a client_id and no credential");
    assert!(
        srv.introspect(&issued.access_token)
            .await
            .unwrap()
            .is_none(),
        "the access token the client asked to revoke must actually be gone"
    );

    // --------------------------------------------------------- its own refresh token: revocable
    srv.revoke(
        &ClientId::new("public-app"),
        None,
        &refresh_token,
        Some(TokenTypeHint::RefreshToken),
    )
    .await
    .expect("the refresh half of the same grant is the half a logout has to reach");
    srv.token(TokenRequest::RefreshToken {
        client_id: ClientId::new("public-app"),
        client_secret: None,
        refresh_token,
        scope: None,
    })
    .await
    .expect_err("a revoked refresh token must no longer mint anything");
}

/// THE ATTACK, and the half that carries the whole security property now that the credential
/// check no longer does: a caller names a PUBLIC client id, which anyone may do, and presents
/// somebody else's token.
///
/// RFC 7009 section 2.1's ownership check is what refuses this, and it is checked against the
/// stored RECORD rather than against the asserted identity, which is why naming an identity anyone
/// may claim buys nothing. The assertion is that the victim's token is STILL LIVE afterwards, not
/// merely that the call returned something: section 2.2 makes the answer a 200 either way (so a
/// caller cannot use this endpoint to test whether a token string is real), so a test that read
/// only the return value would pass against a server that revoked strangers' tokens on request.
#[tokio::test]
async fn a_public_client_cannot_revoke_another_clients_token() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(
        clock,
        vec![
            public_client(),
            confidential_client(),
            two_redirect_client(),
        ],
    )
    .await;
    let victim = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    let victim_refresh = victim.refresh_token.expect("the code grant issues a chain");

    // Two different public callers, which rules out any accidental "every public client is one
    // identity" collapse: the check has to be against THIS client's id, not against "is public".
    for caller in ["public-app", "multi-redirect"] {
        srv.revoke(
            &ClientId::new(caller),
            None,
            &victim.access_token,
            Some(TokenTypeHint::AccessToken),
        )
        .await
        .expect("RFC 7009 s2.2: a token that is not the caller's still answers 200");
        srv.revoke(
            &ClientId::new(caller),
            None,
            &victim_refresh,
            Some(TokenTypeHint::RefreshToken),
        )
        .await
        .expect("RFC 7009 s2.2: same answer, and the same nothing done");
    }

    assert!(
        srv.introspect(&victim.access_token)
            .await
            .unwrap()
            .is_some(),
        "another client's access token must survive: the ownership check is the access control"
    );
    srv.token(TokenRequest::RefreshToken {
        client_id: ClientId::new("confidential-app"),
        client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
        refresh_token: victim_refresh,
        scope: None,
    })
    .await
    .expect("and so must its refresh chain");
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
