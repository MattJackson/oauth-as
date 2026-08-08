// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Pins the `Storage` trait contract documented in `src/store.rs` against `MemoryStorage`, the
//! reference implementation. That doc comment asserts, in prose:
//!
//! - `take_*` operations are ATOMIC remove-and-return: under concurrent redemption exactly one
//!   caller receives the value. This is the property that makes single-use artifacts (device
//!   codes, rotating refresh tokens, authorization codes) actually single use.
//! - `put_device_grant` upserts by `device_code` and must keep the user-code index consistent.
//! - User-code lookups are by NORMALIZED code, and the store indexes what it is given: it does
//!   not normalize on the caller's behalf.
//!
//! These tests exist because a prose contract with no test is a contract nobody has to keep.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use oauth_as::{
    AuthorizationCodeRecord, AuthorizationCodeState, ClientId, CodeChallengeMethod, DeviceGrant,
    DeviceGrantState, MemoryStorage, RefreshTokenRecord, RefreshTokenState, ScopeSet, Storage,
};

fn scope() -> ScopeSet {
    ScopeSet::parse("read").unwrap()
}

fn sample_device_grant(device_code: &str, user_code: &str) -> DeviceGrant {
    let now = SystemTime::now();
    DeviceGrant {
        device_code: device_code.to_string(),
        user_code: user_code.to_string(),
        client_id: ClientId::new("some-client"),
        scope: scope(),
        state: DeviceGrantState::Approved {
            subject: "user-1".into(),
        },
        created_at: now,
        expires_at: now + Duration::from_secs(600),
        interval: Duration::from_secs(5),
        last_poll_at: None,
    }
}

fn sample_refresh_token(token: &str) -> RefreshTokenRecord {
    RefreshTokenRecord {
        resource: Vec::new(),
        refresh_token: token.to_string(),
        client_id: ClientId::new("some-client"),
        subject: Some("user-1".into()),
        scope: scope(),
        expires_at: None,
        family_id: "family-1".into(),
        state: RefreshTokenState::Active,
    }
}

fn sample_authorization_code(code: &str) -> AuthorizationCodeRecord {
    AuthorizationCodeRecord {
        resource: Vec::new(),
        code: code.to_string(),
        client_id: ClientId::new("some-client"),
        redirect_uri: "https://app.example/cb".into(),
        scope: scope(),
        subject: "user-1".into(),
        code_challenge: "a".repeat(43),
        code_challenge_method: CodeChallengeMethod::S256,
        expires_at: SystemTime::now() + Duration::from_secs(60),
        state: AuthorizationCodeState::Issued,
    }
}

/// How many of `n` concurrent tokio tasks, all racing `take_device_grant` on the same key,
/// receive `Some`. A read-then-delete (non-atomic) implementation would let more than one task
/// observe the value before either removes it.
async fn concurrent_takes_of_one_device_grant(
    storage: Arc<MemoryStorage>,
    key: &str,
    n: usize,
) -> usize {
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let s = storage.clone();
        let key = key.to_string();
        handles.push(tokio::spawn(async move {
            s.take_device_grant(&key).await.unwrap()
        }));
    }
    let mut winners = 0;
    for h in handles {
        if h.await.unwrap().is_some() {
            winners += 1;
        }
    }
    winners
}

/// RFC 8628's single-use device code redemption is only true if `take_device_grant` is atomic.
/// Eight tasks race to take the same grant; exactly one may receive it, per the `src/store.rs`
/// contract note on `take_*`.
#[tokio::test]
async fn take_device_grant_delivers_the_value_exactly_once_under_concurrency() {
    let storage = Arc::new(MemoryStorage::new());
    storage
        .put_device_grant(sample_device_grant("dc-1", "WDJB-MJHT"))
        .await
        .unwrap();

    let winners = concurrent_takes_of_one_device_grant(storage.clone(), "dc-1", 8).await;
    assert_eq!(
        winners, 1,
        "exactly one concurrent take_device_grant must succeed"
    );

    // And it is genuinely gone afterward, for every path (not just the losing tasks).
    assert!(storage.get_device_grant("dc-1").await.unwrap().is_none());
    assert!(storage.take_device_grant("dc-1").await.unwrap().is_none());
}

/// OAuth 2.1 single-use refresh rotation depends on the same atomicity: `take_refresh_token` must
/// hand the record to exactly one of several concurrent redeemers.
#[tokio::test]
async fn take_refresh_token_delivers_the_value_exactly_once_under_concurrency() {
    let storage = Arc::new(MemoryStorage::new());
    storage
        .put_refresh_token(sample_refresh_token("rt-1"))
        .await
        .unwrap();

    let mut handles = Vec::with_capacity(8);
    for _ in 0..8 {
        let s = storage.clone();
        handles.push(tokio::spawn(async move {
            s.take_refresh_token("rt-1").await.unwrap()
        }));
    }
    let mut winners = 0;
    for h in handles {
        if h.await.unwrap().is_some() {
            winners += 1;
        }
    }
    assert_eq!(
        winners, 1,
        "exactly one concurrent take_refresh_token must succeed"
    );
    assert!(storage.take_refresh_token("rt-1").await.unwrap().is_none());
}

/// A replayed authorization code is a leak signal (RFC 6749 s4.1.2, RFC 9700 s4.1.1), which the
/// server can only act on correctly if `take_authorization_code` hands the record to exactly one
/// concurrent redeemer; anything else would let a race mint two access tokens from one code.
#[tokio::test]
async fn take_authorization_code_delivers_the_value_exactly_once_under_concurrency() {
    let storage = Arc::new(MemoryStorage::new());
    storage
        .put_authorization_code(sample_authorization_code("code-1"))
        .await
        .unwrap();

    let mut handles = Vec::with_capacity(8);
    for _ in 0..8 {
        let s = storage.clone();
        handles.push(tokio::spawn(async move {
            s.take_authorization_code("code-1").await.unwrap()
        }));
    }
    let mut winners = 0;
    for h in handles {
        if h.await.unwrap().is_some() {
            winners += 1;
        }
    }
    assert_eq!(
        winners, 1,
        "exactly one concurrent take_authorization_code must succeed"
    );
    assert!(storage
        .take_authorization_code("code-1")
        .await
        .unwrap()
        .is_none());
}

// ---------------------------------------------------- put_device_grant / user-code index

/// The ordinary path: putting a grant makes it findable by its (normalized) user code, and taking
/// it removes it from both the primary map and the user-code index in one step.
#[tokio::test]
async fn put_then_take_leaves_no_trace_in_the_user_code_index() {
    let storage = MemoryStorage::new();
    storage
        .put_device_grant(sample_device_grant("dc-1", "WDJB-MJHT"))
        .await
        .unwrap();

    assert!(storage
        .find_device_grant_by_user_code("WDJBMJHT")
        .await
        .unwrap()
        .is_some());

    storage.take_device_grant("dc-1").await.unwrap();

    assert!(
        storage
            .find_device_grant_by_user_code("WDJBMJHT")
            .await
            .unwrap()
            .is_none(),
        "a taken grant must no longer be reachable by user code"
    );
}

/// `src/store.rs` documents that `put_device_grant` "must keep any user-code index consistent".
/// This is the case a naive "insert the new mapping" implementation gets wrong: re-putting the
/// SAME `device_code` with a DIFFERENT `user_code` must retire the old user-code mapping, not
/// just add the new one.
///
/// `MemoryStorage::put_device_grant` currently only inserts `normalize(new_user_code) ->
/// device_code`; it never removes the entry for the OLD user code, so the old code goes on
/// resolving to the grant (now showing the new user_code) until the grant is taken. That is a
/// real deviation from the documented contract, even though no current server.rs code path ever
/// changes a grant's `user_code` after creation (state transitions only ever touch `state`), so
/// the bug is latent rather than reachable through `AuthorizationServer` today.
///
/// Fixed in `src/store.rs`: `put_device_grant` now retires the previous normalized entry when a
/// put changes a grant's user code, so this test is no longer ignored.
#[tokio::test]
async fn put_device_grant_retires_the_old_user_code_when_it_changes() {
    let storage = MemoryStorage::new();
    storage
        .put_device_grant(sample_device_grant("dc-1", "AAAA-AAAA"))
        .await
        .unwrap();

    // Re-put the SAME device_code with a DIFFERENT user_code (as if the grant were reissued a
    // fresh display code without changing its device_code).
    storage
        .put_device_grant(sample_device_grant("dc-1", "BBBB-BBBB"))
        .await
        .unwrap();

    assert!(
        storage
            .find_device_grant_by_user_code("BBBBBBBB")
            .await
            .unwrap()
            .is_some(),
        "the new user code must resolve"
    );
    assert!(
        storage
            .find_device_grant_by_user_code("AAAAAAAA")
            .await
            .unwrap()
            .is_none(),
        "the OLD user code must no longer resolve, once the grant it named has moved on"
    );
}

/// The affirmative half of the bug above: even though a stale `user_code_index` entry can be left
/// behind by `put_device_grant`, `take_device_grant` still answers correctly for it, because the
/// stale entry points at a `device_code` that `take` has already removed from `device_by_code`,
/// and `find_device_grant_by_user_code` joins through that map. So the inconsistency the doc
/// comment warns about cannot resurrect an already-taken grant, even though it can (per the
/// ignored test above) let a stale user code answer for a still-pending one.
#[tokio::test]
async fn a_stale_user_code_index_entry_cannot_resurrect_a_taken_grant() {
    let storage = MemoryStorage::new();
    storage
        .put_device_grant(sample_device_grant("dc-1", "AAAA-AAAA"))
        .await
        .unwrap();
    storage
        .put_device_grant(sample_device_grant("dc-1", "BBBB-BBBB"))
        .await
        .unwrap();

    storage.take_device_grant("dc-1").await.unwrap();

    assert!(storage
        .find_device_grant_by_user_code("AAAAAAAA")
        .await
        .unwrap()
        .is_none());
    assert!(storage
        .find_device_grant_by_user_code("BBBBBBBB")
        .await
        .unwrap()
        .is_none());
}

// ---------------------------------------------------- normalization is the caller's job

/// `src/store.rs`: "User-code lookups are by NORMALIZED code ... the store indexes what it is
/// given and does not normalize." So a query using the display form (with its hyphen, or wrong
/// case) is a DIFFERENT string to the store and must miss, even though
/// `crate::device::normalize_user_code` would treat it as the same code. This is the boundary
/// that `AuthorizationServer` is responsible for crossing before it ever calls into `Storage`.
#[tokio::test]
async fn the_store_does_not_normalize_user_code_queries_on_the_callers_behalf() {
    let storage = MemoryStorage::new();
    storage
        .put_device_grant(sample_device_grant("dc-1", "WDJB-MJHT"))
        .await
        .unwrap();

    // The exact normalized form (uppercase, no hyphen) is what the index is keyed by.
    assert!(storage
        .find_device_grant_by_user_code("WDJBMJHT")
        .await
        .unwrap()
        .is_some());

    // The display form, with its hyphen, is a different string and must miss: the store does
    // not strip hyphens for the caller.
    assert!(
        storage
            .find_device_grant_by_user_code("WDJB-MJHT")
            .await
            .unwrap()
            .is_none(),
        "the store must not normalize hyphenation on the caller's behalf"
    );

    // Lowercase input is likewise a different string: the store does not case-fold for the
    // caller either.
    assert!(
        storage
            .find_device_grant_by_user_code("wdjbmjht")
            .await
            .unwrap()
            .is_none(),
        "the store must not case-fold on the caller's behalf"
    );
}
