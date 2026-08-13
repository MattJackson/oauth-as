// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The `delegate_storage!` doctest, compiled as an ORDINARY DOWNSTREAM CRATE.
//!
//! There is no `#[test]` here and there should not be. The assertion this crate makes is that it
//! COMPILES, because the defect it gates is a missing trait method: if
//! [`oauth_as::delegate_storage`] fails to generate a forwarder, this crate fails with E0046
//! ("not all trait items implemented") naming exactly what was dropped, and the build is red before
//! anything runs.
//!
//! Keep the body below IDENTICAL to the doctest in `crates/oauth-as/src/delegate.rs`. The two are
//! deliberately the same text compiled two ways, and the difference between the two ways is the
//! whole finding: rustdoc compiles a doctest with the DECLARING crate's cfg flags, so the doctest
//! cannot distinguish "the macro generated the forwarder" from "the macro emitted a `#[cfg]` that
//! happened to be true here". This crate can, because its own feature set is empty and always will
//! be. See its Cargo.toml for why it asks `oauth-as` for no features either.

use oauth_as::store::{MemoryStorage, Storage, StorageError, WriteOutcome};
use oauth_as::IssuedToken;

/// Counts issuance, and is otherwise an ordinary in-memory store.
pub struct CountingStore {
    inner: MemoryStorage,
    issued: std::sync::atomic::AtomicU64,
}

impl Storage for CountingStore {
    // The one method this store is actually for.
    async fn put_token(&self, token: IssuedToken) -> Result<WriteOutcome, StorageError> {
        let outcome = self.inner.put_token(token).await?;
        if outcome.is_applied() {
            self.issued
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(outcome)
    }

    // Everything else, including the feature-gated methods: each gated one is generated only
    // when `oauth-as` itself has the feature, so naming one you have not enabled produces
    // nothing rather than an error. Your OWN crate's features are not consulted and do not
    // need to exist.
    oauth_as::delegate_storage! {
        to inner;
        get_client, put_client, compare_and_swap_client, delete_client,
        put_device_grant, get_device_grant, find_device_grant_by_user_code,
        take_device_grant, compare_and_swap_device_grant,
        put_authorization_code, compare_and_swap_authorization_code,
        take_authorization_code,
        put_pushed_authorization_request, take_pushed_authorization_request,
        get_token, delete_token,
        put_refresh_token, get_refresh_token, take_refresh_token, revoke_token_family,
        put_consent, compare_and_swap_consent, get_consent, find_consent,
        consents_for_subject, revoke_consent,
        claim_replay_id,
        sweep_expired,
    }
}
