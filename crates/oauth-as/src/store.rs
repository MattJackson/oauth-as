// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The storage seam. This crate never assumes what the host's persistence looks like: the host
//! implements [`Storage`], and the server only ever talks through it. [`MemoryStorage`] is the
//! reference implementation, used by this crate's tests and suitable for single-process embedding.
//!
//! CONTRACT NOTES the server relies on:
//!
//! - `take_*` operations are ATOMIC remove-and-return. They are how single-use artifacts (device
//!   codes at redemption, rotating refresh tokens, RFC 9126 pushed authorization request handles)
//!   stay single use under concurrency. A shared
//!   multi-node store must implement them with a genuinely atomic primitive (compare-and-set,
//!   `DELETE ... RETURNING`, or equivalent); a plain read-then-delete reintroduces the double-spend.
//! - PURE READS hand back `Arc<T>`, and `take_*` hand back owned `T`. The split is deliberate and
//!   it is NOT a weakening of the atomicity contract above. A read is a question about a record
//!   that STAYS in the store, so the answer can be a second pointer to it; a `take_*` REMOVES the
//!   record, so there is nothing left for a shared pointer to be shared with, and handing back an
//!   owned value is what makes "exactly one caller got it" expressible in the type. A host must not
//!   read that asymmetry as "reads are cheap so they may be stale": an `Arc` this crate holds is a
//!   snapshot of the record as of the read, exactly as the previous owned clone was.
//!   MEASURED, with the counting allocator in `tests/allocation.rs`: `get_client` returning an
//!   owned `Client` cost 8 allocations per authenticated call against `MemoryStorage` (auth,
//!   grant types, redirect URIs, scope sets, name), and every token-plane request pays it. A store
//!   that already holds `Arc<Client>` now pays one atomic increment instead. A SQL-backed store
//!   that builds the `Client` per query pays ONE extra allocation for the `Arc` itself, on a path
//!   that has already done I/O.
//! - `put_device_grant` upserts by `device_code` and must keep any user-code index consistent.
//!   "Consistent" has two halves, and both are load bearing: a put that CHANGES a grant's user
//!   code must retire the old index entry, and a put whose user code is already indexed for a
//!   DIFFERENT `device_code` must be REFUSED rather than repointing the index. See
//!   [`Storage::put_device_grant`].
//! - User-code lookups are by NORMALIZED code (see [`crate::device::normalize_user_code`]); the
//!   store indexes what it is given and does not normalize.
//! - `claim_replay_id` is an ATOMIC claim-if-absent, and it is what makes RFC 7523 client
//!   assertions and RFC 9449 DPoP proofs single use. A store that implements it as "look, then
//!   insert" has reintroduced exactly the replay the two RFCs require to be prevented, and unlike
//!   the `take_*` operations the damage is silent: nothing else in the system notices.
//! - SWEEPING IS THE HOST'S JOB AND IT IS NOT OPTIONAL. Nothing in this crate evicts anything on
//!   a timer: there is no background task, by design. Expired records are reclaimed only when the
//!   HOST calls [`Storage::sweep_expired`] on a schedule of its own. A host that never calls it
//!   has not merely an untidy store: the RFC 8628 section 3.1 device authorization endpoint takes
//!   no credential from a public client, so an unswept deployment hands anyone who can open a
//!   socket an unbounded allocation loop. See [`Storage::sweep_expired`] for the obligation in
//!   full, and `examples/production_server.rs` for it wired up.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex};

use crate::authorization::AuthorizationCodeRecord;
use crate::client::{Client, ClientId};
use crate::device::DeviceGrant;
#[cfg(feature = "consent")]
use crate::device::DeviceGrantState;
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
    ///
    /// `Arc` rather than an owned `Client` because this is the single most called read in the
    /// crate: every authenticated request on the token plane starts here, and the record is only
    /// ever READ. A store that keeps its clients as `Arc<Client>` answers with a pointer clone; a
    /// store that materialises one per query wraps what it built. See the module docs for the
    /// measurement and for why this does not touch the `take_*` atomicity contract.
    fn get_client(
        &self,
        client_id: &ClientId,
    ) -> impl Future<Output = Result<Option<Arc<Client>>, StorageError>> + Send;

    /// Insert or replace a client registration.
    fn put_client(&self, client: Client) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Remove a client registration AND everything it was issued, returning whether a
    /// registration was actually removed.
    ///
    /// The second half is a REQUIREMENT, not a convenience, and it is why this is one operation
    /// rather than two. RFC 7592 section 2.3 deletes a registration and invalidates what that
    /// registration holds; a store that removed only the row would leave every access token,
    /// refresh chain and outstanding authorization code of a deleted client live until its own
    /// expiry, which is a client that no longer exists still calling resource servers. Doing it
    /// here rather than in the server is what lets a real database do it in ONE transaction: a
    /// delete that half succeeded, in either order, is either an orphaned credential set or a
    /// registration nobody can reach.
    ///
    /// "Everything it was issued" means, for `client_id`: access tokens, refresh records, device
    /// grants (with their user-code index entries) and authorization codes whose `client_id` is
    /// this one.
    ///
    /// Removing a client that is already gone is `Ok(false)`, not an error.
    fn delete_client(
        &self,
        client_id: &ClientId,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;

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

    /// Insert or replace a pushed authorization request (RFC 9126 section 2.2), keyed by its
    /// `request_uri`.
    #[cfg(feature = "par")]
    fn put_pushed_authorization_request(
        &self,
        record: crate::par::PushedAuthorizationRequest,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Atomically remove and return a pushed authorization request. This is what makes a
    /// `request_uri` single use: RFC 9126 section 4 says a client MUST use one once and section
    /// 7.3 asks the server to enforce it rather than trust that, so under concurrent authorization
    /// requests exactly one caller receives the record and every other caller sees `None`. A plain
    /// read-then-delete reintroduces the replay this is here to prevent.
    ///
    /// Unlike [`Storage::take_authorization_code`], nothing is put back after a SUCCESSFUL
    /// resolution: a spent handle minted no credential of its own, so there is nothing a later
    /// presentation of it could need to be recognised for, and retaining it would only keep a live
    /// capability string in the store. The server DOES put it back when the handle was presented by
    /// the wrong client, so that a stranger cannot destroy a legitimate client's request.
    #[cfg(feature = "par")]
    fn take_pushed_authorization_request(
        &self,
        request_uri: &str,
    ) -> impl Future<Output = Result<Option<crate::par::PushedAuthorizationRequest>, StorageError>> + Send;

    /// Persist an issued access token.
    fn put_token(
        &self,
        token: IssuedToken,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Look up an access token (introspection).
    ///
    /// `Arc` for the same reason [`Storage::get_client`] is: the record is only READ here, and
    /// with opaque tokens this is the read a resource server makes on every protected request,
    /// which makes it the hottest read in the crate after `get_client`. MEASURED against
    /// [`MemoryStorage`]: 7 allocations per call when it handed back an owned [`IssuedToken`],
    /// none now.
    fn get_token(
        &self,
        access_token: &str,
    ) -> impl Future<Output = Result<Option<Arc<IssuedToken>>, StorageError>> + Send;

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
    ///
    /// `Arc`, and note the contrast with [`Storage::take_refresh_token`] directly below: this one
    /// asks a question about a record that stays put, so a shared pointer answers it, while the
    /// take REMOVES the record and must hand back an owned value because "exactly one caller got
    /// it" is the whole of what rotation rests on. MEASURED: 7 allocations per call before.
    fn get_refresh_token(
        &self,
        refresh_token: &str,
    ) -> impl Future<Output = Result<Option<Arc<RefreshTokenRecord>>, StorageError>> + Send;

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

    /// Insert or replace a consent record, keyed by its `consent_id`.
    ///
    /// The server keeps at most ONE live consent per (`client_id`, `subject`) pair and widens it
    /// in place, so a store that indexes that pair (see [`Storage::find_consent`]) must keep the
    /// index consistent with this write.
    #[cfg(feature = "consent")]
    fn put_consent(
        &self,
        record: crate::consent::ConsentRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Look up a consent record by its identifier.
    #[cfg(feature = "consent")]
    fn get_consent(
        &self,
        consent_id: &str,
    ) -> impl Future<Output = Result<Option<Arc<crate::consent::ConsentRecord>>, StorageError>> + Send;

    /// The live consent for one (client, subject) pair, if there is one.
    ///
    /// This is what remembered consent is read from, and unlike the rest of the consent operations
    /// it runs on the AUTHORIZATION ENDPOINT'S path, so a store SHOULD index the pair rather than
    /// scanning.
    #[cfg(feature = "consent")]
    fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> impl Future<Output = Result<Option<Arc<crate::consent::ConsentRecord>>, StorageError>> + Send;

    /// Every consent one resource owner has granted, so a host can show a user what they have
    /// approved. Order is not specified; a host that wants one sorts what it gets back.
    #[cfg(feature = "consent")]
    fn consents_for_subject(
        &self,
        subject: &str,
    ) -> impl Future<Output = Result<Vec<Arc<crate::consent::ConsentRecord>>, StorageError>> + Send;

    /// WITHDRAW a consent: remove the record AND everything issued under it, returning how many
    /// records were removed (the consent record itself is not counted).
    ///
    /// This is [`Storage::revoke_token_family`] at a BROADER granularity, and it is deliberately
    /// the same primitive rather than a parallel mechanism. A family is one refresh chain and the
    /// tokens minted along it; a consent is every grant one client ever obtained for one user, and
    /// one consent spans many families over time because every fresh trip through the
    /// authorization endpoint mints another one. Withdrawing a consent and revoking only the newest
    /// family would leave every earlier chain live, which is this feature failing silently, and
    /// silently is the worst way for it to fail: the user has been told they stopped something they
    /// did not.
    ///
    /// "Everything issued under it" means, for the consent's (`client_id`, `subject`) pair:
    ///
    /// - access tokens for that subject;
    /// - refresh records for that subject, whatever family they belong to;
    /// - authorization codes issued to that subject, which are grants in flight and would otherwise
    ///   mint a token seconds after the user said stop;
    /// - device grants that subject has APPROVED but the device has not yet polled, for the same
    ///   reason. A PENDING device grant is left alone: nobody has consented to it yet, so there is
    ///   nothing there to withdraw.
    ///
    /// It is ONE operation rather than five so a real database can do it in one transaction. A
    /// withdrawal that half succeeded leaves a user believing they revoked something they did not,
    /// which is the failure this whole feature exists to prevent.
    ///
    /// Withdrawing a consent that is already gone is `Ok(0)`, not an error, for the same reason
    /// [`Storage::revoke_token_family`] tolerates a concurrent revocation: a user who clicks twice
    /// has not made a mistake.
    ///
    /// This runs when a person clicks something, never on a token-plane request, so it is not a hot
    /// path. It must simply complete.
    #[cfg(feature = "consent")]
    fn revoke_consent(
        &self,
        consent_id: &str,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;

    /// Atomically CLAIM a single-use identifier, returning `true` when this caller is the first
    /// to claim it and `false` when it has already been claimed.
    ///
    /// This is the replay-prevention primitive behind two REQUIREMENTS, not two optimisations:
    /// RFC 7523 section 3 makes a client assertion's `jti` single use within the assertion's
    /// validity, and RFC 9449 section 4.3 makes a DPoP proof's `jti` single use within the proof's
    /// acceptance window. An implementation that verifies the signature and skips this has built a
    /// credential that anybody who observed one request can send again, which is the whole of what
    /// those two mechanisms exist to prevent.
    ///
    /// `expires_at` is when the claim may be reclaimed by [`Storage::sweep_expired`], and it is the
    /// caller's job to pass the instant past which the artifact would be refused on time alone
    /// (the assertion's `exp`, the proof's `iat` plus the acceptance window). Reclaiming EARLIER
    /// than that reopens the replay window; the two callers in this crate both derive it from the
    /// artifact rather than from a policy of their own.
    ///
    /// ATOMICITY IS THE CONTRACT, exactly as for the `take_*` operations above. A shared multi-node
    /// store must implement this with a genuinely atomic primitive (`INSERT ... ON CONFLICT DO
    /// NOTHING` and check the row count, `SET NX`, a compare-and-set); a read-then-write lets two
    /// concurrent presentations of the SAME assertion both be told they were first, which is the
    /// replay this method exists to refuse. Failing CLOSED on a storage error is the caller's job
    /// and this crate does it: a claim that could not be recorded is treated as a claim that
    /// failed.
    ///
    /// Claiming an id that is already present but EXPIRED is at the store's discretion: this crate
    /// never presents such an id, because the artifact carrying it would have been refused on time
    /// first. [`MemoryStorage`] treats a live entry as claimed regardless of its deadline and lets
    /// `sweep_expired` do the reclaiming, which is the conservative reading.
    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
    fn claim_replay_id(
        &self,
        id: &str,
        expires_at: std::time::SystemTime,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;

    /// Remove every record that is dead at `now`, and return how many were removed.
    ///
    /// # THE HOST MUST CALL THIS, ON A TIMER, FOREVER
    ///
    /// It is an OBLIGATION of running this crate, not a tuning knob. This crate has no background
    /// task and will never grow one (see the crate docs on zero cost until enabled), so this
    /// method runs when the host runs it and at no other time. Nothing else reclaims storage:
    /// consumed authorization codes are retained deliberately until their expiry, spent refresh
    /// records are retained deliberately until theirs, and expired access tokens and abandoned
    /// device grants are simply never looked at again.
    ///
    /// What a host that never calls it has built is a MEMORY EXHAUSTION PATH, not an untidy
    /// store. The RFC 8628 section 3.1 device authorization endpoint takes no client credential
    /// from a public client (it sends only its `client_id`, which RFC 6749 section 2.2 says is
    /// not a secret), so anyone who can open a socket can allocate a device grant plus a
    /// user-code index entry per request, in a loop, and none of it is ever reclaimed. The growth
    /// is attacker-paced and it ends with the process dying.
    ///
    /// Expiry ITSELF is enforced on read, so an unswept store is not INSECURE, it is UNBOUNDED.
    /// That is why the interval matters much less than the existence of the task: sweeping every
    /// few minutes and sweeping every few seconds are both fine, and never sweeping is not.
    ///
    /// One task per PROCESS. It must be safe to call concurrently with request handling (see
    /// below), so every node sweeping is harmless; a host that would rather not have N nodes
    /// deleting the same rows runs it from one of them, or from a scheduled job that calls the
    /// same method. A sweep failure must be logged and retried on the next tick, never allowed
    /// to end the task: a silently stopped sweeper shows up hours later as memory growth.
    ///
    /// `crates/oauth-as/examples/production_server.rs` wires this, with the interval reasoning.
    ///
    /// ```ignore
    /// // Once per process, at startup.
    /// tokio::spawn(async move {
    ///     let mut ticker = tokio::time::interval(Duration::from_secs(60));
    ///     loop {
    ///         ticker.tick().await;
    ///         if let Err(e) = server.store().sweep_expired(SystemTime::now()).await {
    ///             // Log and continue. Do not return: returning stops the sweep forever.
    ///             eprintln!("sweep failed, retrying next tick: {e}");
    ///         }
    ///     }
    /// });
    /// ```
    ///
    /// "Dead at `now`" means, for each kind:
    ///
    /// - device grants with `expires_at <= now`
    /// - authorization codes with `expires_at <= now` (in either state)
    /// - access tokens with `expires_at <= now`
    /// - claimed replay identifiers (see [`Storage::claim_replay_id`]) with `expires_at <= now`
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
    /// `Arc` so that [`Storage::get_client`] answers with a pointer clone rather than a deep copy
    /// of the registration on every authenticated request. MEASURED: 8 allocations per call before,
    /// one atomic increment after.
    clients: HashMap<String, Arc<Client>>,
    device_by_code: HashMap<String, DeviceGrant>,
    /// normalized user code -> device_code
    user_code_index: HashMap<String, String>,
    codes: HashMap<String, AuthorizationCodeRecord>,
    #[cfg(feature = "par")]
    pushed: HashMap<String, crate::par::PushedAuthorizationRequest>,
    /// `Arc` so that `get_token` (introspection, once per protected resource request when tokens
    /// are opaque) is a pointer clone. MEASURED: 7 allocations per read before, one on the write.
    tokens: HashMap<String, Arc<IssuedToken>>,
    /// `Arc` for the same reason as `tokens`; `take_refresh_token` unwraps it back to an owned
    /// record, which costs nothing when the store is the only holder, and clones when a reader is
    /// still looking at the snapshot it was handed.
    refresh: HashMap<String, Arc<RefreshTokenRecord>>,
    /// Consent records by `consent_id`. Present only under the `consent` feature, so a
    /// default build's store is byte for byte the store it was before.
    #[cfg(feature = "consent")]
    consents: HashMap<String, Arc<crate::consent::ConsentRecord>>,
    /// Claimed RFC 7523 / RFC 9449 single-use identifiers, mapped to when they may be reclaimed.
    /// Present only under the features that produce them, so a default build's store is byte for
    /// byte the store it was before.
    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
    replay_ids: HashMap<String, std::time::SystemTime>,
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
    async fn get_client(&self, client_id: &ClientId) -> Result<Option<Arc<Client>>, StorageError> {
        // `Arc::clone` through `Option::cloned`: one atomic increment, no deep copy of the
        // registration. This is the hot read the module docs' measurement is about.
        Ok(self.lock().clients.get(client_id.as_str()).cloned())
    }

    async fn put_client(&self, client: Client) -> Result<(), StorageError> {
        // The one allocation the `Arc` costs is paid HERE, on registration, which happens once per
        // client, rather than on `get_client`, which happens once per authenticated request.
        self.lock()
            .clients
            .insert(client.client_id.as_str().to_string(), Arc::new(client));
        Ok(())
    }

    async fn delete_client(&self, client_id: &ClientId) -> Result<bool, StorageError> {
        let mut g = self.lock();
        let existed = g.clients.remove(client_id.as_str()).is_some();
        // Every credential the registration holds goes with it (see the trait doc). Under the one
        // mutex, so no request can observe a half-deleted client.
        g.tokens.retain(|_, t| &t.client_id != client_id);
        g.refresh.retain(|_, r| &r.client_id != client_id);
        g.codes.retain(|_, c| &c.client_id != client_id);
        // RFC 9126 s2.2 binds a request_uri to the client that pushed it, so a deleted client's
        // outstanding handles are handles nobody may ever redeem.
        #[cfg(feature = "par")]
        g.pushed.retain(|_, p| &p.client_id != client_id);
        g.device_by_code.retain(|_, d| &d.client_id != client_id);
        // A consent names a client that no longer exists; leaving it would show a user an
        // application they cannot revoke, on a registration nothing can reach. The same
        // "everything the registration holds goes with it" rule as the four lines above.
        #[cfg(feature = "consent")]
        g.consents.retain(|_, c| &c.client_id != client_id);
        // The index is a pointer to a grant, not a record of its own; a dangling entry would make
        // a reaped user code resolve to nothing. Same pass `sweep_expired` makes.
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
        Ok(existed)
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

    #[cfg(feature = "par")]
    async fn put_pushed_authorization_request(
        &self,
        record: crate::par::PushedAuthorizationRequest,
    ) -> Result<(), StorageError> {
        self.lock()
            .pushed
            .insert(record.request_uri.clone(), record);
        Ok(())
    }

    #[cfg(feature = "par")]
    async fn take_pushed_authorization_request(
        &self,
        request_uri: &str,
    ) -> Result<Option<crate::par::PushedAuthorizationRequest>, StorageError> {
        // Atomic by construction, like every other `take_*` here: one mutex, one `remove`.
        Ok(self.lock().pushed.remove(request_uri))
    }

    async fn put_token(&self, token: IssuedToken) -> Result<(), StorageError> {
        // The `Arc` costs ONE allocation here, on issuance, and saves seven on every introspection
        // of the token afterwards. A token is issued once and introspected once per protected
        // request it is presented with, so the trade is measured in the direction that pays.
        self.lock()
            .tokens
            .insert(token.access_token.clone(), Arc::new(token));
        Ok(())
    }

    async fn get_token(
        &self,
        access_token: &str,
    ) -> Result<Option<Arc<IssuedToken>>, StorageError> {
        Ok(self.lock().tokens.get(access_token).cloned())
    }

    async fn delete_token(&self, access_token: &str) -> Result<(), StorageError> {
        self.lock().tokens.remove(access_token);
        Ok(())
    }

    async fn put_refresh_token(&self, record: RefreshTokenRecord) -> Result<(), StorageError> {
        self.lock()
            .refresh
            .insert(record.refresh_token.clone(), Arc::new(record));
        Ok(())
    }

    async fn get_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<Arc<RefreshTokenRecord>>, StorageError> {
        Ok(self.lock().refresh.get(refresh_token).cloned())
    }

    async fn take_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshTokenRecord>, StorageError> {
        // Owned, because this is the rotation primitive: the record is GONE from the store and
        // "exactly one caller got it" has to be what the type says. `try_unwrap` reclaims the
        // record in place when nothing else is holding the snapshot, which is the ordinary case,
        // and falls back to a clone when a concurrent reader is still looking at it.
        Ok(self
            .lock()
            .refresh
            .remove(refresh_token)
            .map(|a| Arc::try_unwrap(a).unwrap_or_else(|a| (*a).clone())))
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

    #[cfg(feature = "consent")]
    async fn put_consent(&self, record: crate::consent::ConsentRecord) -> Result<(), StorageError> {
        self.lock()
            .consents
            .insert(record.consent_id.to_string(), Arc::new(record));
        Ok(())
    }

    #[cfg(feature = "consent")]
    async fn get_consent(
        &self,
        consent_id: &str,
    ) -> Result<Option<Arc<crate::consent::ConsentRecord>>, StorageError> {
        Ok(self.lock().consents.get(consent_id).cloned())
    }

    #[cfg(feature = "consent")]
    async fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> Result<Option<Arc<crate::consent::ConsentRecord>>, StorageError> {
        // A scan, honestly, for a map with no secondary index; a host with a real database indexes
        // the pair, and the trait doc says so because this one IS on the authorization path.
        Ok(self
            .lock()
            .consents
            .values()
            .find(|c| &c.client_id == client_id && c.subject.as_ref() == subject)
            .cloned())
    }

    #[cfg(feature = "consent")]
    async fn consents_for_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<Arc<crate::consent::ConsentRecord>>, StorageError> {
        Ok(self
            .lock()
            .consents
            .values()
            .filter(|c| c.subject.as_ref() == subject)
            .cloned()
            .collect())
    }

    #[cfg(feature = "consent")]
    async fn revoke_consent(&self, consent_id: &str) -> Result<u64, StorageError> {
        // The whole cascade under the ONE mutex, which is this store's version of the single
        // transaction the trait doc asks a real database for: no request can observe a
        // half-withdrawn consent, and nothing can be issued between the lookup and the sweep.
        let mut g = self.lock();
        let consent = match g.consents.remove(consent_id) {
            Some(c) => c,
            // Already withdrawn, or never existed. Both are success; see the trait doc.
            None => return Ok(0),
        };
        let client_id = &consent.client_id;
        let subject: &str = consent.subject.as_ref();
        let before = g.tokens.len() + g.refresh.len() + g.codes.len() + g.device_by_code.len();
        g.tokens
            .retain(|_, t| !(&t.client_id == client_id && t.subject.as_deref() == Some(subject)));
        g.refresh
            .retain(|_, r| !(&r.client_id == client_id && r.subject.as_deref() == Some(subject)));
        // An unredeemed code is a grant in flight. Leaving it would let the client mint a token
        // seconds after the user withdrew, which is the withdrawal failing in the way nobody
        // notices until it matters.
        g.codes
            .retain(|_, c| !(&c.client_id == client_id && c.subject == subject));
        // Same for a device grant this user has already approved but the device has not polled for
        // yet. A PENDING one is left alone: nobody has consented to it, and killing it would end a
        // login the user may be in the middle of.
        g.device_by_code.retain(|_, d| {
            !(&d.client_id == client_id
                && matches!(&d.state, DeviceGrantState::Approved { subject: s } if s == subject))
        });
        // The user-code index points at grants rather than being a record of its own, so a dangling
        // entry would make a reaped code resolve to nothing. The same pass `sweep_expired` makes.
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
        let after = g.tokens.len() + g.refresh.len() + g.codes.len() + g.device_by_code.len();
        Ok((before - after) as u64)
    }

    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
    async fn claim_replay_id(
        &self,
        id: &str,
        expires_at: std::time::SystemTime,
    ) -> Result<bool, StorageError> {
        // Atomic by construction: the whole claim happens under the one mutex, so two concurrent
        // presentations of the same identifier cannot both observe it absent. The `id` is only
        // allocated when the claim is actually taken, which keeps a replayed request from costing
        // an allocation as well as a lookup.
        let mut g = self.lock();
        if g.replay_ids.contains_key(id) {
            return Ok(false);
        }
        g.replay_ids.insert(id.to_string(), expires_at);
        Ok(true)
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

        // RFC 9126 s4: an expired request_uri MUST be rejected, and once it is expired there is
        // nothing left to recognise it for, so it is swept like anything else. A swept handle and
        // a used one are the same answer at the authorization endpoint, deliberately.
        #[cfg(feature = "par")]
        {
            let before = g.pushed.len();
            g.pushed.retain(|_, p| now < p.expires_at);
            removed += (before - g.pushed.len()) as u64;
        }

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

        // The replay set is the one collection here that an unauthenticated caller can grow: every
        // refused-but-well-formed assertion or proof adds an entry. It is bounded by the artifact
        // lifetime caps in `client_assertion.rs` and `dpop.rs`, but only a sweep actually reclaims
        // it, exactly as for everything else in this store.
        #[cfg(any(feature = "client_assertion", feature = "dpop"))]
        {
            let before = g.replay_ids.len();
            g.replay_ids.retain(|_, exp| now < *exp);
            removed += (before - g.replay_ids.len()) as u64;
        }

        Ok(removed)
    }
}
