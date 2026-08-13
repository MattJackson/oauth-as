// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! CONTAINMENT MUST NOT DEPEND ON WHAT HAD ALREADY BEEN WRITTEN WHEN THE ALARM FIRED.
//!
//! Two changes that are each right on their own opened a window between them:
//!
//! 1. the spent-refresh tombstone and the consumed-code record are written BEFORE issuance, so
//!    that a store failure halfway through a redemption cannot take RFC 9700 s4.14.2 replay
//!    detection offline (see `AuthorizationServer::refresh_token`), and
//! 2. signing an RFC 9068 access token is the host's [`oauth_as::jwt::Es256Signer`], which may be
//!    a network round trip to a KMS and is therefore unbounded.
//!
//! Between the two, a redemption is DETECTABLE as spent while the tokens it is minting do not
//! exist yet. A second party presenting the same credential in that window detects the reuse
//! correctly, revokes what it can find, and finds nothing, because the first party has not written
//! anything. The first party then resumes and persists exactly the tokens the alarm fired about.
//! Reuse detection reports containment and the tokens survive it, which is the worst possible
//! outcome: an operator reads a revocation event and does not investigate.
//!
//! The gate below is the window, made deterministic rather than raced for: the signer parks inside
//! issuance until the test lets it go, which is what a slow KMS does on its own.
//!
//! What is asserted is the PROPERTY, not the mechanism: after both parties have finished, no token
//! from the compromised grant is live. A fix that refuses the second party, or that undoes the
//! first, or that does something else entirely, passes; a fix that leaves a usable token does not.

#![cfg(feature = "jwt")]

mod support;

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use oauth_as::jwt::{AccessTokenFormat, Es256Signer, Jwk, JwtConfig, SignerError};
use oauth_as::{
    AuthorizationServer, ClientId, ErrorCode, MemoryStorage, ServerConfig, TokenRequest,
};
use support::{
    confidential_client, mint_code_token, mint_code_token_keeping_code, ManualClock,
    CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET, RFC7636_VERIFIER,
};

/// A signer that parks in the middle of issuance until it is released, and reports that it got
/// there. Exactly what a KMS that is answering in ten seconds looks like from in here.
///
/// The spin plus `yield_now` is deliberate: the dev `tokio` has `rt`, `macros` and `time` and no
/// `sync`, and on a current-thread runtime yielding is what hands the executor to the other task.
/// Nothing here sleeps, so the ordering is decided by the test rather than by a timer.
struct GatedSigner {
    armed: AtomicBool,
    entered: AtomicBool,
    released: AtomicBool,
}

impl GatedSigner {
    fn new() -> Arc<Self> {
        Arc::new(GatedSigner {
            armed: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            released: AtomicBool::new(false),
        })
    }

    /// Fixture issuance runs through this signer too, so the gate is armed only once the setup is
    /// done and the race is about to be run.
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    async fn wait_until_signing(&self) {
        while !self.entered.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
    }
}

impl Es256Signer for GatedSigner {
    #[allow(clippy::manual_async_fn)]
    fn sign(
        &self,
        _signing_input: &[u8],
    ) -> impl Future<Output = Result<[u8; 64], SignerError>> + Send {
        async move {
            if self.armed.load(Ordering::SeqCst) {
                self.entered.store(true, Ordering::SeqCst);
                while !self.released.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
            }
            // Not a real signature, and nothing on this path checks one: what is under test is
            // the ORDER of the writes around it. `tests/signer_seam.rs` states the same reasoning.
            Ok([0x5A; 64])
        }
    }

    fn public_jwk(&self) -> Jwk {
        Jwk {
            kty: "EC",
            crv: "P-256",
            x: URL_SAFE_NO_PAD.encode([0x11u8; 32]),
            y: URL_SAFE_NO_PAD.encode([0x22u8; 32]),
            kid: "gated".to_string(),
            use_: "sig",
            alg: "ES256",
        }
    }
}

async fn server(signer: Arc<GatedSigner>) -> Arc<AuthorizationServer<MemoryStorage, ManualClock>> {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.access_token_format = AccessTokenFormat::Jwt(Box::new(JwtConfig::new(
        signer,
        "https://rs.example".to_string(),
    )));
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    srv.register_client(confidential_client())
        .await
        .expect("the fixture client registers");
    Arc::new(srv)
}

fn refresh(rt: &str) -> TokenRequest {
    TokenRequest::RefreshToken {
        client_id: ClientId::new("confidential-app"),
        client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
        refresh_token: rt.to_string(),
        scope: None,
    }
}

/// RFC 9700 s4.14.2, raced. Task A rotates a refresh token and parks in the signer; task B
/// presents the same token, which is reuse, and the revocation that follows must not be defeated
/// by A's tokens not existing yet.
#[tokio::test]
// WAS IGNORED BECAUSE IT WAS RED. It is green as of the 0.9.1 `Storage` break, and the ignore
// attribute is gone rather than the test.
//
// This reproduces the defect that shipped in 0.9.0 and is named in README, SECURITY and the
// CHANGELOG: a revocation and an issuance already in flight across the `await` inside ES256
// signing, where the issuance completed behind the revocation and left a live token. It was kept
// rather than deleted, and ignored rather than committed red, because a red gate that everyone
// learns to walk past protects nothing.
//
// What made it pass is the `RevocationBarrier` in `oauth_as::store`: `revoke_token_family` records
// what it removed, and A's `put_token` and `put_refresh_token` are refused when they wake. VERIFIED
// RED FIRST, at commit a58c5ee, where it failed on exactly the assertion below with "the access
// token minted during a detected-reuse window is live, so the revocation contained nothing".
async fn a_reuse_revocation_during_the_signing_window_still_contains_the_grant() {
    let signer = GatedSigner::new();
    let srv = server(signer.clone()).await;
    let issued = mint_code_token(
        srv.as_ref(),
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    let rt1 = issued.refresh_token.expect("the code grant issues a chain");

    signer.arm();
    let a = tokio::spawn({
        let srv = srv.clone();
        let rt1 = rt1.clone();
        async move { srv.token(refresh(&rt1)).await }
    });
    signer.wait_until_signing().await;

    // B presents the SAME token while A is still signing. This is unambiguous reuse and it is
    // refused; what matters is what it revokes.
    let refused = srv
        .token(refresh(&rt1))
        .await
        .expect_err("a token already rotated away must never mint again");
    assert_eq!(refused.error, ErrorCode::InvalidGrant);

    signer.release();
    let resumed = a.await.expect("task A does not panic");

    // THE PROPERTY. Whatever A was told, nothing A minted may still be usable: the grant was
    // proven compromised while A was in flight.
    if let Ok(tokens) = &resumed {
        assert!(
            srv.introspect(&tokens.access_token)
                .await
                .expect("the store answers")
                .is_none(),
            "the access token minted during a detected-reuse window is live, so the revocation \
             contained nothing"
        );
        if let Some(rt2) = &tokens.refresh_token {
            let err = srv
                .token(refresh(rt2))
                .await
                .expect_err("the rotated chain of a revoked family must be dead too");
            assert_eq!(err.error, ErrorCode::InvalidGrant);
        }
    }
}

/// The same window on the authorization code path (RFC 6749 s4.1.2, RFC 9700 s4.1.1). A redeems a
/// code and parks in the signer; B replays the code. B reads `Consumed { access_token: None }`,
/// which means "the issuance did not complete" and is being read as "there is nothing to revoke",
/// when here it means "not written YET".
#[tokio::test]
// The SECOND half of the same defect, and it needed a second mechanism, which is the useful thing
// this pair records. The barrier that fixed the test above does NOT reach here: B is racing an
// issuance that has not chosen a `family_id` yet, so there is no family to record a barrier for.
// What closes it is the durable `AuthorizationCodeState::Replayed` trace plus
// `compare_and_swap_authorization_code`, so that A's second write fails and A undoes its own
// issuance.
//
// Both had to go green together, because a fix that closed one window and not the other would
// have been a narrow patch rather than the rule. VERIFIED RED FIRST at commit a58c5ee, and STILL
// RED at the barrier commit 8b33e99, which is what proved the second mechanism was needed.
async fn a_code_replay_during_the_signing_window_still_contains_the_grant() {
    let signer = GatedSigner::new();
    let srv = server(signer.clone()).await;

    // A live code, minted the same way `mint_code_token_keeping_code` mints its own, so that the
    // redemption below is the FIRST one and the replay is the second.
    let (_, _spent) = mint_code_token_keeping_code(
        srv.as_ref(),
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    let code = fresh_code(srv.as_ref()).await;

    signer.arm();
    let a = tokio::spawn({
        let srv = srv.clone();
        let code = code.clone();
        async move { srv.token(redeem(&code)).await }
    });
    signer.wait_until_signing().await;

    let refused = srv
        .token(redeem(&code))
        .await
        .expect_err("a code presented twice must never mint twice");
    assert_eq!(refused.error, ErrorCode::InvalidGrant);

    signer.release();
    let resumed = a.await.expect("task A does not panic");

    if let Ok(tokens) = &resumed {
        assert!(
            srv.introspect(&tokens.access_token)
                .await
                .expect("the store answers")
                .is_none(),
            "the access token minted during a detected code replay is live, so the replay \
             revoked nothing"
        );
        if let Some(rt) = &tokens.refresh_token {
            let err = srv
                .token(refresh(rt))
                .await
                .expect_err("the chain minted by a replayed code must be dead too");
            assert_eq!(err.error, ErrorCode::InvalidGrant);
        }
    }
}

fn redeem(code: &str) -> TokenRequest {
    TokenRequest::AuthorizationCode {
        client_id: ClientId::new("confidential-app"),
        client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
        code: code.to_string(),
        redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
        code_verifier: Some(RFC7636_VERIFIER.to_string()),
    }
}

/// One freshly issued, unredeemed authorization code.
async fn fresh_code(srv: &AuthorizationServer<MemoryStorage, ManualClock>) -> String {
    use oauth_as::server::UserApproval;
    use oauth_as::AuthorizationRequest;

    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let req = AuthorizationRequest::from_pairs([
        ("response_type", "code"),
        ("client_id", "confidential-app"),
        ("redirect_uri", CONFIDENTIAL_REDIRECT),
        ("scope", "read"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]);
    let validated = srv
        .validate_authorization_request(&req)
        .await
        .expect("the fixture request validates");
    srv.issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .expect("the fixture code issues")
        .code
}
