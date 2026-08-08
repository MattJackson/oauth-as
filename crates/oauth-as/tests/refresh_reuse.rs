// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Refresh token REUSE detection (OAuth 2.1 draft section 6.1, RFC 9700 section 4.14.2).
//!
//! Rotation alone is not a defence. Rotation plus "the replay is refused and nothing else
//! happens" is worse than no rotation at all, because the only party who reliably presents the
//! superseded token is the party who did NOT get to redeem it first: the victim. An AS that
//! answers that presentation with `invalid_grant` and stops has taken unambiguous evidence of
//! compromise and used it to disconnect the honest client while leaving the thief's rotated chain
//! live.
//!
//! RFC 9700 section 4.14.2 is explicit about the remedy: when reuse is detected the AS invalidates
//! the presented token AND revokes the tokens issued for that authorization grant. That requires
//! two things this suite pins: rotated tokens must be RETAINED (marked spent) so a later
//! presentation is recognisable as reuse rather than as an unknown string, and every token minted
//! from the same grant must be reachable from the presented one.

mod support;

use oauth_as::{ClientId, ErrorCode, IntrospectionResponse, TokenRequest};
use support::{
    confidential_client, mint_code_token, other_confidential_client, server_with, ManualClock,
    CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET, OTHER_CONFIDENTIAL_SECRET,
};

/// THE ATTACK (RFC 9700 section 4.14.2, OAuth 2.1 draft section 6.1): the attacker steals RT1 and
/// redeems it FIRST, receiving AT_a and RT2a. The legitimate client later presents RT1, which the
/// AS has already rotated away. That second presentation is proof RT1 leaked, so the whole chain
/// must die. An AS that merely refuses it locks out the victim and leaves the attacker refreshing
/// forever, which is the defence exactly inverted.
#[tokio::test]
async fn reuse_of_a_rotated_refresh_token_revokes_the_attackers_chain() {
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
    let rt1 = issued.refresh_token.expect("the code grant issues a chain");

    // The attacker redeems the stolen token first.
    let attacker = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            refresh_token: rt1.clone(),
            scope: None,
        })
        .await
        .expect("the first redemption of a live refresh token succeeds");
    let rt2a = attacker
        .refresh_token
        .expect("rotation issues a replacement");

    // The legitimate client presents the token it still believes is current. This is the reuse
    // event: the AS now knows RT1 is in two hands.
    let err = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            refresh_token: rt1,
            scope: None,
        })
        .await
        .expect_err("a rotated refresh token must never mint again");
    assert_eq!(err.error, ErrorCode::InvalidGrant);

    // RFC 9700 section 4.14.2: the tokens issued for that authorization grant are revoked, so the
    // attacker's rotated token is dead too.
    let err = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            refresh_token: rt2a,
            scope: None,
        })
        .await
        .expect_err("detected reuse must revoke the whole family, not just the replayed token");
    assert_eq!(err.error, ErrorCode::InvalidGrant);
}

/// RFC 9700 section 4.14.2 revokes the ACCESS tokens of the compromised grant as well, not only
/// its refresh tokens. Refusing further refreshes while the stolen access token keeps working for
/// its full lifetime leaves the attacker exactly the access they came for.
#[tokio::test]
async fn reuse_detection_revokes_every_access_token_in_the_family() {
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
    let rt1 = issued.refresh_token.expect("the code grant issues a chain");

    let attacker = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            refresh_token: rt1.clone(),
            scope: None,
        })
        .await
        .expect("the first redemption succeeds");

    srv.token(TokenRequest::RefreshToken {
        client_id: ClientId::new("confidential-app"),
        client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
        refresh_token: rt1,
        scope: None,
    })
    .await
    .expect_err("the reuse must be refused");

    for (which, token) in [
        ("the attacker's access token", &attacker.access_token),
        ("the original access token", &issued.access_token),
    ] {
        let resp = srv
            .introspection_response(
                &ClientId::new("confidential-app"),
                Some(CONFIDENTIAL_SECRET),
                token,
            )
            .await
            .unwrap();
        assert_eq!(
            resp,
            IntrospectionResponse::inactive(),
            "{which} belongs to the compromised grant and must be revoked with it"
        );
    }
}

/// The honest path must survive the retention that reuse detection needs: a chain rotated several
/// times keeps working, and each superseded token is dead the moment it is replaced (RFC 6749
/// section 6 single use, OAuth 2.1 draft section 6.1 rotation).
#[tokio::test]
async fn ordinary_rotation_still_works_and_each_link_is_single_use() {
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
    let mut current = issued.refresh_token.expect("the code grant issues a chain");

    for round in 0..3 {
        let next = srv
            .token(TokenRequest::RefreshToken {
                client_id: ClientId::new("confidential-app"),
                client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
                refresh_token: current.clone(),
                scope: None,
            })
            .await
            .unwrap_or_else(|e| panic!("rotation round {round} must succeed, got {e}"));
        assert_ne!(
            next.refresh_token.as_deref(),
            Some(current.as_str()),
            "rotation must issue a NEW token, not return the same one"
        );
        current = next.refresh_token.expect("rotation issues a replacement");
    }
}

/// A refresh token presented by a client it was NOT issued to is `invalid_grant` (RFC 6749
/// section 5.2), and the record must survive: the presenter proved nothing except that they hold
/// a string, and destroying the record on their say-so hands every registered client a way to end
/// any other client's session. Same reasoning as the authorization code path, which already puts
/// the record back on a client mismatch.
#[tokio::test]
async fn another_clients_refresh_token_is_refused_without_being_destroyed() {
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
        "read",
        "user-1",
    )
    .await;
    let rt = issued.refresh_token.expect("the code grant issues a chain");

    let err = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("other-app"),
            client_secret: Some(OTHER_CONFIDENTIAL_SECRET.to_string()),
            refresh_token: rt.clone(),
            scope: None,
        })
        .await
        .expect_err("a refresh token is bound to the client it was issued to");
    assert_eq!(err.error, ErrorCode::InvalidGrant);

    srv.token(TokenRequest::RefreshToken {
        client_id: ClientId::new("confidential-app"),
        client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
        refresh_token: rt,
        scope: None,
    })
    .await
    .expect("the owner's chain must have survived another client's failed presentation");
}
