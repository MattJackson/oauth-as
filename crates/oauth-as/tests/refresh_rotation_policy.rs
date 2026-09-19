// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The refresh-token rotation policy switch (`ServerConfig::refresh_rotation`).
//!
//! This crate rotates refresh tokens by default (OAuth 2.1 draft section 6.1, RFC 9700 section
//! 4.14.2): single use, with a re-presentation of a spent token detected as reuse and revoking the
//! whole family. FAPI 2.0's Security Profile forbids that (section 5.3.2.1-9, "the AS shall not use
//! refresh token rotation"), so the AS must be configurable to NOT rotate for a conformance run.
//!
//! `RefreshRotation::Reuse` is that mode, and it is a DELIBERATE downgrade of the reuse protection
//! above: it is off by default and a non-FAPI host must never select it. These tests pin both ends
//! of the switch — that `Reuse` genuinely stops rotating and revoking, and that the default
//! `Rotate` is completely unaffected by the switch existing.

mod support;

use oauth_as::{
    AuthorizationServer, Client, ClientId, ErrorCode, MemoryStorage, RefreshRotation, ServerConfig,
    TokenRequest,
};
use support::{
    confidential_client, mint_code_token, ManualClock, CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET,
};

/// Build a server whose only non-default setting is the rotation policy under test.
async fn server_with_policy(
    clock: ManualClock,
    policy: RefreshRotation,
    clients: Vec<Client>,
) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device")
        .with_refresh_rotation(policy);
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), clock);
    for c in clients {
        srv.register_client(c).await.unwrap();
    }
    srv
}

fn refresh(token: &str) -> TokenRequest {
    TokenRequest::RefreshToken {
        client_id: ClientId::new("confidential-app"),
        client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
        refresh_token: token.to_string(),
        scope: None,
    }
}

/// FAPI 2.0 mode: the SAME refresh token is presented twice and BOTH succeed, the value handed
/// back is the same one (no rotation), and the family is NOT revoked — the access tokens from both
/// redemptions stay live and a third redemption still works.
///
/// RED-BEFORE-GREEN: with the switch ignored (default rotation), the first redemption rotates the
/// token away and marks it spent, so the second presentation of the same value is detected as reuse
/// and returns `invalid_grant`; the `expect` on the second redemption then panics. Confirmed by
/// temporarily forcing `refresh_rotation` back to `Rotate` in `server_with_policy` (or deleting the
/// `if reuse { .. }` branch in `AuthorizationServer::refresh_token`): the test fails there and
/// passes only with `Reuse` honoured.
#[tokio::test]
async fn reuse_mode_returns_the_same_token_twice_without_revoking_the_family() {
    let clock = ManualClock::at_epoch();
    let srv = server_with_policy(clock, RefreshRotation::Reuse, vec![confidential_client()]).await;
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

    // First redemption: fresh access token, and the refresh token comes back UNCHANGED.
    let first = srv
        .token(refresh(&rt))
        .await
        .expect("a live refresh token mints under Reuse");
    assert_eq!(
        first.refresh_token.as_deref(),
        Some(rt.as_str()),
        "Reuse must return the SAME refresh token, not a rotated successor"
    );
    assert_ne!(
        first.access_token, issued.access_token,
        "each redemption still mints a fresh access token"
    );

    // Second redemption of the SAME token: under rotation this is reuse and would be refused.
    let second = srv
        .token(refresh(&rt))
        .await
        .expect("re-presenting the same refresh token must succeed under Reuse, not be reuse");
    assert_eq!(
        second.refresh_token.as_deref(),
        Some(rt.as_str()),
        "the token is still the same value after a second use"
    );
    assert_ne!(
        second.access_token, first.access_token,
        "the second redemption mints its own fresh access token"
    );

    // The family was NOT revoked: every access token minted so far is still active, and the chain
    // still mints a third time.
    for (which, token) in [
        ("the original", &issued.access_token),
        ("the first redemption's", &first.access_token),
        ("the second redemption's", &second.access_token),
    ] {
        let resp = srv
            .introspection_response(
                &ClientId::new("confidential-app"),
                Some(CONFIDENTIAL_SECRET),
                token,
            )
            .await
            .unwrap();
        assert!(
            resp.active,
            "{which} access token must stay live: Reuse revokes no family"
        );
    }
    srv.token(refresh(&rt))
        .await
        .expect("the same refresh token still mints a third time");
}

/// The default `Rotate` is unchanged by the switch existing: single use, and a re-presentation of a
/// rotated token is detected as reuse and revokes the whole family (RFC 9700 section 4.14.2). This
/// is the regression guard for the audited path.
///
/// RED-BEFORE-GREEN: if `Reuse` semantics leaked into the default (the token not being spent), the
/// second presentation would SUCCEED and the two `expect_err` calls would panic. Confirmed by
/// temporarily making `server_with_policy` pass `Reuse`: this test fails, proving the assertions
/// actually bind the rotating behaviour.
#[tokio::test]
async fn rotate_mode_is_still_single_use_and_revokes_on_reuse() {
    let clock = ManualClock::at_epoch();
    let srv = server_with_policy(clock, RefreshRotation::Rotate, vec![confidential_client()]).await;
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

    let rotated = srv
        .token(refresh(&rt1))
        .await
        .expect("the first redemption of a live token succeeds");
    let rt2 = rotated
        .refresh_token
        .expect("rotation issues a replacement");
    assert_ne!(
        rt2, rt1,
        "Rotate must mint a NEW refresh token, never return the presented one"
    );

    // Re-presenting the rotated-away token is reuse: refused, and the family is revoked.
    let err = srv
        .token(refresh(&rt1))
        .await
        .expect_err("a rotated refresh token is single use");
    assert_eq!(err.error, ErrorCode::InvalidGrant);

    let err = srv
        .token(refresh(&rt2))
        .await
        .expect_err("detected reuse revokes the whole family, including the live successor");
    assert_eq!(err.error, ErrorCode::InvalidGrant);
}
