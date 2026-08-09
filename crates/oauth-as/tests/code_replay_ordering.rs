// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The ORDER of the checks in the authorization code path, which is a security property in its own
//! right (RFC 6749 section 4.1.3, RFC 9700 section 4.1.1).
//!
//! Replaying a code revokes the tokens that code already minted. That is correct, and it is also a
//! destructive action, so it must be reachable only by the client the code was issued to. If the
//! revocation branch is evaluated before the ownership check, the destructive half of replay
//! handling becomes available to any caller who can name a registered `client_id` and holds a
//! leaked code, without presenting a redirect URI, a PKCE verifier, or (for a public client) any
//! credential at all.
//!
//! The second property pinned here is retention: a consumed code is kept until its own expiry, so
//! that replay detection works more than once. `src/authorization.rs` and `src/store.rs` both
//! promise this in prose, and a promise with no test is a promise nobody has to keep.

mod support;

use oauth_as::{ClientId, ErrorCode, Storage, TokenRequest};
use support::{
    confidential_client, mint_code_token_keeping_code, public_client, server_with, ManualClock,
    CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET,
};

/// THE ATTACK (RFC 6749 section 4.1.3 client binding; RFC 9700 section 4.1.1 replay handling): an
/// attacker reads a leaked authorization code out of a log or a `Referer` header, then POSTs it to
/// the token endpoint naming an UNRELATED registered public client. A public client has no
/// credential to present, so this costs the attacker nothing. If the replay-revocation branch runs
/// before the code's client is checked, that request deletes the victim's live access token and
/// refresh chain: a remote kill switch reached with no authentication and no PKCE verifier.
#[tokio::test]
async fn a_stranger_replaying_a_leaked_code_cannot_revoke_the_victims_tokens() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![confidential_client(), public_client()]).await;

    // The victim completes an ordinary flow. `mint_code_token` redeems the code, so the record is
    // now retained in the consumed state, which is the state the attack needs.
    let (issued, leaked_code) = mint_code_token_keeping_code(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    let refresh_token = issued.refresh_token.expect("the code grant issues a chain");

    // The attacker: someone else's code, their own (public, unauthenticated) client id, no
    // redirect_uri, no code_verifier.
    let err = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("public-app"),
            client_secret: None,
            code: leaked_code,
            redirect_uri: None,
            code_verifier: None,
        })
        .await
        .expect_err("a code presented by a client it was not issued to is invalid_grant");
    assert_eq!(err.error, ErrorCode::InvalidGrant);

    // Nothing of the victim's may have been touched.
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
        "a stranger's replay must not revoke the victim's access token"
    );
    srv.token(TokenRequest::RefreshToken {
        client_id: ClientId::new("confidential-app"),
        client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
        refresh_token,
        scope: None,
    })
    .await
    .expect("a stranger's replay must not revoke the victim's refresh chain");
}

/// RFC 9700 section 4.1.1 and the retention contract stated in `src/authorization.rs`: a consumed
/// code is kept until expiry. Taking the record out of the store on the FIRST replay makes replay
/// detection one-shot, so a later genuine replay reads as an unknown code and revokes nothing.
#[tokio::test]
async fn replay_detection_is_not_one_shot() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![confidential_client()]).await;
    let (_issued, code) = mint_code_token_keeping_code(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;

    for attempt in 0..2 {
        let err = srv
            .token(TokenRequest::AuthorizationCode {
                client_id: ClientId::new("confidential-app"),
                client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
                code: code.clone(),
                redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
                code_verifier: Some(support::RFC7636_VERIFIER.to_string()),
            })
            .await
            .unwrap_err();
        assert_eq!(
            err.error,
            ErrorCode::InvalidGrant,
            "replay {attempt} must be refused"
        );
    }

    // The record must still be there: that is what makes the SECOND replay a recognised replay
    // rather than an unknown code.
    let retained = srv
        .store()
        .take_authorization_code(&code)
        .await
        .unwrap()
        .expect("the consumed code must be retained until its own expiry");
    assert!(
        matches!(
            retained.state,
            oauth_as::AuthorizationCodeState::Consumed { .. }
        ),
        "the retained record must still say what the code minted"
    );
}

/// A code presented by the wrong client must not be BURNED either: the real client has to be able
/// to finish its flow. The record goes back untouched, in the `Issued` state, and redeems
/// normally afterwards (RFC 6749 section 4.1.3).
#[tokio::test]
async fn a_wrong_client_presentation_leaves_an_unredeemed_code_usable() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![confidential_client(), public_client()]).await;

    let challenge = oauth_as::pkce::code_challenge_s256(support::RFC7636_VERIFIER);
    let req = oauth_as::AuthorizationRequest {
        resource: Vec::new(),
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        response_type: Some("code".to_string().into()),
        client_id: Some("confidential-app".to_string().into()),
        redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string().into()),
        scope: Some("read".to_string().into()),
        state: None,
        code_challenge: Some(challenge.into()),
        code_challenge_method: Some("S256".to_string().into()),
        #[cfg(feature = "consent")]
        acr_values: None,
        #[cfg(feature = "consent")]
        max_age: None,
    };
    let validated = srv.validate_authorization_request(&req).await.unwrap();
    let response = srv
        .issue_authorization_code(&validated, "user-1")
        .await
        .unwrap();

    let err = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("public-app"),
            client_secret: None,
            code: response.code.clone(),
            redirect_uri: None,
            code_verifier: None,
        })
        .await
        .expect_err("another client may not redeem this code");
    assert_eq!(err.error, ErrorCode::InvalidGrant);

    srv.token(TokenRequest::AuthorizationCode {
        client_id: ClientId::new("confidential-app"),
        client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
        code: response.code,
        redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
        code_verifier: Some(support::RFC7636_VERIFIER.to_string()),
    })
    .await
    .expect("the code's real owner must still be able to redeem it");
}
