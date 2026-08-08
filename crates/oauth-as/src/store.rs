// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The storage seam. This crate never assumes what the host's persistence looks like: the host
//! implements [`Storage`], and the server only ever talks through it. [`MemoryStorage`] is the
//! reference implementation, used by this crate's tests and suitable for single-process embedding.
//!
//! CONTRACT NOTES the server relies on:
//!
//! - `take_*` operations are ATOMIC remove-and-return. They are how single-use artifacts (device
//!   codes at redemption, rotating refresh tokens) stay single use under concurrency. A shared
//!   multi-node store must implement them with a genuinely atomic primitive (compare-and-set,
//!   `DELETE ... RETURNING`, or equivalent); a plain read-then-delete reintroduces the double-spend.
//! - `put_device_grant` upserts by `device_code` and must keep any user-code index consistent.
//!   "Consistent" has two halves, and both are load bearing: a put that CHANGES a grant's user
//!   code must retire the old index entry, and a put whose user code is already indexed for a
//!   DIFFERENT `device_code` must be REFUSED rather than repointing the index. See
//!   [`Storage::put_device_grant`].
//! - User-code lookups are by NORMALIZED code (see [`crate::device::normalize_user_code`]); the
//!   store indexes what it is given and does not normalize.
//! - Nothing in this crate evicts anything on a timer: there is no background task, by design.
//!   Expired records are reclaimed only when the HOST calls [`Storage::sweep_expired`]. A host
//!   that never calls it has a store that only grows.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::Mutex;

use crate::authorization::AuthorizationCodeRecord;
use crate::client::{Client, ClientId};
use crate::device::DeviceGrant;
use crate::token::{IssuedToken, RefreshTokenRecord};

/// An opaque host-side storage failure. The server maps these to `server_error` on wire paths;
/// the text is for the host's logs, never for the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageError(pub String);

impl StorageError {
    /// Wrap a failure description.
    pub fn new(msg: impl Into<String>) -> Self {
        StorageError(msg.into())
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "storage error: {}", self.0)
    }
}

impl std::error::Error for StorageError {}

/// What the authorization server needs from the host's persistence. All futures are `Send` so the
/// server can be driven from any multi-threaded async runtime.
pub trait Storage: Send + Sync {
    /// Look up a registered client.
    fn get_client(
        &self,
        client_id: &ClientId,
    ) -> impl Future<Output = Result<Option<Client>, StorageError>> + Send;

    /// Insert or replace a client registration.
    fn put_client(&self, client: Client) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Insert or replace a device grant, keyed by `device_code`, maintaining the user-code index.
    ///
    /// Two REQUIRED behaviours beyond a plain upsert, both of which a naive "insert the new
    /// mapping" implementation gets wrong:
    ///
    /// 1. If the grant's normalized user code is already indexed for a DIFFERENT `device_code`,
    ///    this MUST fail with a [`StorageError`] and write nothing. RFC 8628 section 6.1 makes the
    ///    user code the credential a human types, so two live grants answering to one code is two
    ///    devices sharing an identity. Silently repointing the index also orphans both grants: the
    ///    older one can no longer be approved, and taking it removes an index entry that now names
    ///    the newer one.
    /// 2. If a put CHANGES the user code of an existing `device_code`, the OLD index entry MUST be
    ///    retired. Leaving it behind means the superseded code goes on resolving to the grant.
    ///
    /// The server relies on (1) to make its user-code generation retry loop meaningful: it asks
    /// the store whether a code is taken, but only the store can answer that without a race.
    fn put_device_grant(
        &self,
        grant: DeviceGrant,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Look up a device grant by device code.
    fn get_device_grant(
        &self,
        device_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceGrant>, StorageError>> + Send;

    /// Look up a device grant by NORMALIZED user code.
    fn find_device_grant_by_user_code(
        &self,
        normalized_user_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceGrant>, StorageError>> + Send;

    /// Atomically remove and return a device grant. This is the single-use redemption primitive:
    /// under concurrent redemption exactly one caller receives the grant.
    fn take_device_grant(
        &self,
        device_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceGrant>, StorageError>> + Send;

    /// Insert or replace an authorization code record, keyed by its code string.
    fn put_authorization_code(
        &self,
        record: AuthorizationCodeRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Atomically remove and return an authorization code record. This is the single-use
    /// redemption primitive for the authorization code grant: under concurrent redemption exactly
    /// one caller receives the record and every other caller sees `None`.
    ///
    /// The server puts a CONSUMED record back after a successful redemption (see
    /// [`crate::authorization::AuthorizationCodeState`]), so that a replay can be recognised as a
    /// replay and revoke what the code already minted, rather than looking like a typo.
    fn take_authorization_code(
        &self,
        code: &str,
    ) -> impl Future<Output = Result<Option<AuthorizationCodeRecord>, StorageError>> + Send;

    /// Persist an issued access token.
    fn put_token(
        &self,
        token: IssuedToken,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Look up an access token (introspection).
    fn get_token(
        &self,
        access_token: &str,
    ) -> impl Future<Output = Result<Option<IssuedToken>, StorageError>> + Send;

    /// Remove an access token. Idempotent: removing a token that is already gone is success, as
    /// RFC 7009 section 2.2 requires of revocation.
    fn delete_token(
        &self,
        access_token: &str,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Persist a refresh token record.
    fn put_refresh_token(
        &self,
        record: RefreshTokenRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Look up a refresh token record WITHOUT removing it.
    ///
    /// This exists so that a check ABOUT a refresh token never has to be built out of a
    /// read-modify-write ON it. RFC 7009 section 2.1 requires revocation to verify that the token
    /// was issued to the requesting client; doing that by taking the record and putting it back on
    /// a mismatch is a destructive operation on a credential the caller was never entitled to
    /// touch, and if the restoring write fails, the victim's chain is gone for good while the
    /// endpoint still answers 200.
    fn get_refresh_token(
        &self,
        refresh_token: &str,
    ) -> impl Future<Output = Result<Option<RefreshTokenRecord>, StorageError>> + Send;

    /// Atomically remove and return a refresh token record. This is what makes rotation single
    /// use: under concurrent refresh exactly one caller wins and every other presentation of the
    /// same token is `invalid_grant`.
    ///
    /// The server puts a SPENT record back after a successful rotation (see
    /// [`crate::token::RefreshTokenState`]), so that a later presentation is recognisable as reuse
    /// rather than as an unknown string.
    fn take_refresh_token(
        &self,
        refresh_token: &str,
    ) -> impl Future<Output = Result<Option<RefreshTokenRecord>, StorageError>> + Send;

    /// Revoke EVERY token, access and refresh, carrying `family_id`, and return how many records
    /// were removed.
    ///
    /// This is the RFC 9700 section 4.14.2 remedy for detected refresh token reuse: the AS
    /// invalidates the presented token and revokes the tokens issued for that authorization grant.
    /// Removing only the replayed token would leave the thief's rotated chain, and every access
    /// token minted along it, entirely live.
    ///
    /// Implementations SHOULD make this reachable without a full scan (index `family_id` on both
    /// the access token and the refresh token tables). It runs only on a detected compromise, so
    /// it is not a hot path, but it must actually complete.
    ///
    /// Removing records that are already gone is success: this runs on evidence of compromise and
    /// must not be turned into an error by a concurrent revocation.
    fn revoke_token_family(
        &self,
        family_id: &str,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;

    /// Remove every record that is dead at `now`, and return how many were removed.
    ///
    /// The HOST must call this, on whatever schedule it likes; this crate has no background task
    /// and will never grow one (see the crate docs on zero cost until enabled). Nothing else
    /// reclaims storage: consumed authorization codes are retained deliberately until their
    /// expiry, spent refresh records are retained deliberately until theirs, and expired access
    /// tokens and abandoned device grants are simply never looked at again. RFC 8628 section 3.1
    /// lets any client entitled to the device grant allocate a grant per request, so without a
    /// sweep the growth is attacker-paced.
    ///
    /// "Dead at `now`" means, for each kind:
    ///
    /// - device grants with `expires_at <= now`
    /// - authorization codes with `expires_at <= now` (in either state)
    /// - access tokens with `expires_at <= now`
    /// - refresh records with `Some(expires_at) <= now`. A record with `expires_at: None` is a
    ///   chain with no absolute lifetime and is NOT dead; the server gives a spent record a
    ///   retention deadline precisely so this method can reclaim it.
    ///
    /// It must be safe to call concurrently with request handling, and safe to call when there is
    /// nothing to do (answering 0).
    fn sweep_expired(
        &self,
        now: std::time::SystemTime,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;
}

#[derive(Default)]
struct MemoryInner {
    clients: HashMap<String, Client>,
    device_by_code: HashMap<String, DeviceGrant>,
    /// normalized user code -> device_code
    user_code_index: HashMap<String, String>,
    codes: HashMap<String, AuthorizationCodeRecord>,
    tokens: HashMap<String, IssuedToken>,
    refresh: HashMap<String, RefreshTokenRecord>,
}

/// The in-memory [`Storage`]: a mutexed set of maps. Reference implementation for the trait's
/// contract (its `take_*` are atomic by construction) and the store this crate's own tests run on.
/// Allocates nothing beyond its empty maps until used.
#[derive(Default)]
pub struct MemoryStorage {
    inner: Mutex<MemoryInner>,
}

impl MemoryStorage {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemoryInner> {
        // A poisoned mutex means a panic mid-update; the maps hold owned values that are written
        // whole, so continuing with the recovered guard is sound.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Storage for MemoryStorage {
    async fn get_client(&self, client_id: &ClientId) -> Result<Option<Client>, StorageError> {
        Ok(self.lock().clients.get(client_id.as_str()).cloned())
    }

    async fn put_client(&self, client: Client) -> Result<(), StorageError> {
        self.lock()
            .clients
            .insert(client.client_id.as_str().to_string(), client);
        Ok(())
    }

    async fn put_device_grant(&self, grant: DeviceGrant) -> Result<(), StorageError> {
        let mut g = self.lock();
        let normalized = crate::device::normalize_user_code(&grant.user_code);

        // (1) The code must not already belong to a different device. Checked BEFORE any write, so
        // a refusal leaves the store exactly as it was.
        if let Some(owner) = g.user_code_index.get(&normalized) {
            if owner != &grant.device_code {
                return Err(StorageError::new(
                    "user code is already indexed for a different device_code",
                ));
            }
        }

        // (2) A put that changes this grant's user code retires the old entry, or the superseded
        // code goes on resolving here.
        if let Some(previous) = g.device_by_code.get(&grant.device_code) {
            let previous_normalized = crate::device::normalize_user_code(&previous.user_code);
            if previous_normalized != normalized {
                g.user_code_index.remove(&previous_normalized);
            }
        }

        g.user_code_index
            .insert(normalized, grant.device_code.clone());
        g.device_by_code.insert(grant.device_code.clone(), grant);
        Ok(())
    }

    async fn get_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        Ok(self.lock().device_by_code.get(device_code).cloned())
    }

    async fn find_device_grant_by_user_code(
        &self,
        normalized_user_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        let g = self.lock();
        Ok(g.user_code_index
            .get(normalized_user_code)
            .and_then(|dc| g.device_by_code.get(dc))
            .cloned())
    }

    async fn take_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        let mut g = self.lock();
        let grant = g.device_by_code.remove(device_code);
        if let Some(grant) = &grant {
            let normalized = crate::device::normalize_user_code(&grant.user_code);
            g.user_code_index.remove(&normalized);
        }
        Ok(grant)
    }

    async fn put_authorization_code(
        &self,
        record: AuthorizationCodeRecord,
    ) -> Result<(), StorageError> {
        self.lock().codes.insert(record.code.clone(), record);
        Ok(())
    }

    async fn take_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCodeRecord>, StorageError> {
        Ok(self.lock().codes.remove(code))
    }

    async fn put_token(&self, token: IssuedToken) -> Result<(), StorageError> {
        self.lock().tokens.insert(token.access_token.clone(), token);
        Ok(())
    }

    async fn get_token(&self, access_token: &str) -> Result<Option<IssuedToken>, StorageError> {
        Ok(self.lock().tokens.get(access_token).cloned())
    }

    async fn delete_token(&self, access_token: &str) -> Result<(), StorageError> {
        self.lock().tokens.remove(access_token);
        Ok(())
    }

    async fn put_refresh_token(&self, record: RefreshTokenRecord) -> Result<(), StorageError> {
        self.lock()
            .refresh
            .insert(record.refresh_token.clone(), record);
        Ok(())
    }

    async fn get_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshTokenRecord>, StorageError> {
        Ok(self.lock().refresh.get(refresh_token).cloned())
    }

    async fn take_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshTokenRecord>, StorageError> {
        Ok(self.lock().refresh.remove(refresh_token))
    }

    async fn revoke_token_family(&self, family_id: &str) -> Result<u64, StorageError> {
        // A scan is honest for a map with no secondary index, and this runs once per detected
        // compromise rather than per request. A host with a real database indexes `family_id`.
        let mut g = self.lock();
        let before = g.tokens.len() + g.refresh.len();
        g.tokens
            .retain(|_, t| t.family_id.as_deref() != Some(family_id));
        g.refresh.retain(|_, r| r.family_id != family_id);
        Ok((before - (g.tokens.len() + g.refresh.len())) as u64)
    }

    async fn sweep_expired(&self, now: std::time::SystemTime) -> Result<u64, StorageError> {
        let mut g = self.lock();
        let mut removed = 0u64;

        // Device grants first, so the index pass below sees the survivors.
        let before = g.device_by_code.len();
        g.device_by_code.retain(|_, grant| now < grant.expires_at);
        removed += (before - g.device_by_code.len()) as u64;
        // The index is not counted separately: it is not a record, it is a pointer to one, and a
        // dangling pointer here would make a reaped user code resolve to nothing.
        let live = &g.device_by_code;
        let stale: Vec<String> = g
            .user_code_index
            .iter()
            .filter(|(_, dc)| !live.contains_key(*dc))
            .map(|(uc, _)| uc.clone())
            .collect();
        for uc in stale {
            g.user_code_index.remove(&uc);
        }

        let before = g.codes.len();
        g.codes.retain(|_, c| now < c.expires_at);
        removed += (before - g.codes.len()) as u64;

        let before = g.tokens.len();
        g.tokens.retain(|_, t| now < t.expires_at);
        removed += (before - g.tokens.len()) as u64;

        // `None` means the chain has no absolute lifetime, so it is not dead. A SPENT record from
        // such a chain was stamped with a retention deadline at rotation, which is what lets this
        // reclaim it (see `RefreshTokenRecord::expires_at`).
        let before = g.refresh.len();
        g.refresh.retain(|_, r| match r.expires_at {
            Some(exp) => now < exp,
            None => true,
        });
        removed += (before - g.refresh.len()) as u64;

        Ok(removed)
    }
}
