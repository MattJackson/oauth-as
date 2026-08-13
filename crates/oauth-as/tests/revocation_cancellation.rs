// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A DROPPED REVOCATION MUST NOT LEAVE THE GRANT HALF ALIVE, AND MUST NOT MAKE THE RETRY LIE.
//!
//! `revoke_with_credential` performs a two-write sequence for a refresh token: the presented string
//! is removed, and the RFC 7009 s2.1 cascade revokes every token of the same authorization grant.
//! A Rust future stops at an `await` when it is dropped, and the host's HTTP layer drops this one
//! whenever the client's connection goes away, so the sequence can stop between those two writes.
//! Which write runs FIRST is therefore the whole safety property, and it used to be the wrong one.
//!
//! Taking first is fail-OPEN. The presented string is gone and the family is untouched, and the
//! damage is not that one attempt failed: it is that the client's RETRY is answered 200 with no
//! cascade at all. The retry's `get_refresh_token` finds nothing, so it falls to the "unknown, or
//! somebody else's" arm and reports success, and every access token minted from a grant the user
//! logged out of stays live for its whole TTL with nothing anywhere recording it. Note the
//! asymmetry that hid this: the store-ERROR path was already handled honestly, setting
//! `cascade_failed` on the emitted event; the DROP path emitted nothing.
//!
//! Cascading first is fail-CLOSED. A drop leaves the family revoked, with a barrier recorded, and a
//! live-looking refresh string that names a family nothing will honour, and the retry re-runs a
//! cascade that `Storage::revoke_token_family` makes idempotent by contract.
//!
//! This does not make a dropped future finish, and nothing in this crate can: see the cancellation
//! section on `AuthorizationServer::revoke`. It makes the point it stops at a safe one.

mod support;

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use oauth_as::{
    AuthorizationServer, ClientId, MemoryStorage, ServerConfig, Storage, TokenTypeHint,
};

use support::{
    confidential_client, mint_code_token, ManualClock, CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET,
};

/// A store whose FIRST `revoke_token_family` never completes, and whose later ones behave.
///
/// Pending forever is the honest model of the interruption: a future dropped mid-`await` is a
/// future whose next poll never came, and the store call it was suspended in never happened. The
/// first call is the one the dropped attempt makes; the second is the one the retry makes, and it
/// has to be allowed to work, because the property under test is what the RETRY achieves.
struct StallFirstCascade {
    inner: MemoryStorage,
    calls: AtomicUsize,
}

impl Storage for StallFirstCascade {
    async fn revoke_token_family(
        &self,
        family_id: &str,
        window: oauth_as::store::RevocationWindow,
    ) -> Result<u64, oauth_as::StorageError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            std::future::pending::<()>().await;
        }
        self.inner.revoke_token_family(family_id, window).await
    }

    oauth_as::delegate_storage! {
        to inner;
        get_client, put_client, compare_and_swap_client, delete_client,
        put_device_grant, get_device_grant, find_device_grant_by_user_code,
        take_device_grant, compare_and_swap_device_grant,
        put_authorization_code, compare_and_swap_authorization_code, take_authorization_code,
        put_pushed_authorization_request, take_pushed_authorization_request,
        put_token, get_token, delete_token,
        put_refresh_token, get_refresh_token, take_refresh_token,
        put_consent, compare_and_swap_consent, get_consent, find_consent,
        consents_for_subject, revoke_consent,
        claim_replay_id,
        sweep_expired,
    }
}

struct NoopWake;
impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

/// Drive `fut` until it would suspend, then drop it. This is a client disconnecting mid-request,
/// made deterministic: no timing, no second task, and no runtime that might poll it again.
fn poll_once_then_drop<F: Future>(fut: F) {
    let waker = Waker::from(Arc::new(NoopWake));
    let mut cx = Context::from_waker(&waker);
    let mut fut = Box::pin(fut);
    assert!(
        matches!(Pin::new(&mut fut).poll(&mut cx), Poll::Pending),
        "the fixture store must suspend this revocation rather than complete it"
    );
    drop(fut);
}

/// ATTACK, and the user is the victim rather than a client: a person presses log out, their client
/// calls RFC 7009 revocation, the connection dies mid-request, the client retries, and the server
/// answers 200. The question this asks is whether that 200 is true.
///
/// The assertion is made on a SIBLING access token of the same family, not on the refresh token,
/// because the sibling is what the cascade exists for (s2.1's SHOULD: "invalidate all access tokens
/// based on the same authorization grant"). A refresh token that is merely gone is not a revocation
/// if the access token it was rotated alongside still opens every door for another TTL.
#[tokio::test]
async fn a_revocation_dropped_mid_flight_still_cascades_when_the_client_retries() {
    let srv = AuthorizationServer::with_clock(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        StallFirstCascade {
            inner: MemoryStorage::new(),
            calls: AtomicUsize::new(0),
        },
        ManualClock::at_epoch(),
    );
    srv.register_client(confidential_client()).await.unwrap();
    let issued = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    let refresh = issued
        .refresh_token
        .expect("the code grant opens a refresh chain");
    // The sibling: minted by the same redemption, so it carries the same `family_id`.
    let sibling = issued.access_token;
    let client_id = ClientId::new("confidential-app");

    // ATTEMPT ONE: dropped at the first await that suspends.
    poll_once_then_drop(srv.revoke(
        &client_id,
        Some(CONFIDENTIAL_SECRET),
        &refresh,
        Some(TokenTypeHint::RefreshToken),
    ));

    // ATTEMPT TWO: the client's retry, which is what a real one does and what the property is
    // about. It must be able to reach the cascade, which means the dropped attempt must not have
    // consumed the only record that leads to it.
    srv.revoke(
        &client_id,
        Some(CONFIDENTIAL_SECRET),
        &refresh,
        Some(TokenTypeHint::RefreshToken),
    )
    .await
    .expect("RFC 7009 s2.2 answers 200");

    let still_live = srv
        .introspect(&sibling)
        .await
        .expect("the store is healthy on the retry");
    assert!(
        still_live.is_none(),
        "a revocation interrupted mid-flight and retried left an access token of the revoked \
         grant live: the user pressed log out and this token opens every door for another full \
         access token lifetime"
    );
}
