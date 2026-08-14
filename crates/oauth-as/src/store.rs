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
//! - User-code lookups are by NORMALIZED code (see [`crate::device::normalize_user_code`]), and
//!   the split of responsibility is exact rather than approximate, because an earlier version of
//!   this sentence got it wrong in a way that contradicted both bundled stores AND the conformance
//!   harness. A store NORMALIZES THE CODE IT IS GIVEN ON THE WAY IN, so that the index is keyed by
//!   the normalized form however the grant spells its `user_code`; it does NOT normalize the
//!   QUERY, so [`Storage::find_device_grant_by_user_code`] is a lookup of the exact key it is
//!   handed. The server normalizes before it ever calls in (RFC 8628 section 6.1), so a store that
//!   also normalized the query would make the display form "WDJB-MJHT" and the key "WDJBMJHT" two
//!   spellings of one entry, and the display form is precisely the input an attacker controls.
//!   [`crate::storage_conformance`]'s `user_code_index/store_does_not_normalize` check holds a
//!   store to BOTH halves: it plants a grant whose `user_code` is "WDJB-MJHT" and requires
//!   `find_device_grant_by_user_code("WDJBMJHT")` to resolve it and the two unnormalized spellings
//!   to miss.
//! - `claim_replay_id` is an ATOMIC claim-if-absent, and it is what makes RFC 7523 client
//!   assertions and RFC 9449 DPoP proofs single use. A store that implements it as "look, then
//!   insert" has reintroduced exactly the replay the two RFCs require to be prevented, and unlike
//!   the `take_*` operations the damage is silent: nothing else in the system notices.
//! - A WRITE MUST NOT RESURRECT STATE THAT A REVOCATION REMOVED. This is the rule the whole
//!   [`RevocationBarrier`] machinery below exists to enforce, and it is stated here rather than on
//!   one method because it is a property of the STORE, not of any single call. Every revocation in
//!   this trait removes records that some concurrent request may already be holding, mid
//!   read-modify-write, and every one of those requests ends in a write. Without a rule, the last
//!   writer wins, and the last writer is the one that was told to stop.
//!
//!   There are exactly TWO shapes of evidence a write can be judged against, and the trait uses
//!   both because neither covers the other:
//!
//!   1. Where the revocation leaves DURABLE ABSENCE, absence is the evidence, and the write states
//!      what it believed the store held: [`Storage::compare_and_swap_client`],
//!      [`Storage::compare_and_swap_consent`], [`Storage::compare_and_swap_device_grant`]. A
//!      deleted record fails the comparison and the write does not happen.
//!   2. Where the writer ITSELF removed the record, absence is the normal case and proves nothing:
//!      a rotation that took a refresh token cannot tell "I took this" from "a revocation took
//!      this". There the evidence is a [`RevocationBarrier`], recorded BY the revocation and
//!      consulted BY the write. [`Storage::put_token`] and [`Storage::put_refresh_token`] answer
//!      [`WriteOutcome::RefusedRevoked`] rather than writing.
//!
//!   A host implementing this trait owes both. [`crate::storage_conformance`] checks both.
//!
//!   FOUR WRITES ARE EXEMPT, and they are named here rather than left to be discovered:
//!
//!   1. [`Storage::put_authorization_code`], because refusing it would disarm replay detection at
//!      the moment a grant is being revoked. Its own doc gives the argument and states exactly
//!      what the exemption leaves behind, which is a row rather than a capability.
//!   2. [`Storage::put_device_grant`], because the record it writes CANNOT be one a revocation
//!      removed. Both cascades reach device grants, so the method belongs on this list rather than
//!      being passed over in silence — but the only caller in this crate is the RFC 8628 section
//!      3.1 device authorization endpoint, which MINTS a grant under a freshly drawn random
//!      `device_code` and never puts back a record it took. A grant that did not exist when the
//!      cascade ran is a grant established after the revocation, which is exactly what the
//!      `Client` and `Consent` scopes are documented to ADMIT (see [`RevocationWindow`]), so a
//!      barrier consulted here could only ever answer "write it", and the `TokenFamily` scope
//!      cannot reach a record that carries no `family_id`. The exemption is therefore about what
//!      the record IS, not about what refusing would cost. A host whose own code puts a device
//!      grant back after taking one has left that argument behind and owes the check itself.
//!   3. [`Storage::put_client`], because it is PROVISIONING and not a put-back.
//!      [`Storage::delete_client`] removes the client row, so this method's record kind is one a
//!      cascade reaches and it belongs on this list rather than being passed over. The argument is
//!      the one [`RevocationWindow`] already makes: a `Client` barrier covers a write only when the
//!      grant behind it was established at or before `recorded_at`, exactly so that a host may
//!      re-provision a `client_id` it deleted, and a provisioning write establishes the
//!      registration NOW. A barrier consulted here could only ever answer "write it". The crate's
//!      two callers are both provisioning: RFC 7591 section 3.2 dynamic registration, which mints a
//!      `client_id` this store has never seen, and
//!      [`crate::server::AuthorizationServer::register_client`], which is a host stating its own
//!      configuration.
//!
//!      THE DANGER IS REAL BUT IT IS NOT THIS METHOD, and the distinction is the whole exemption: an
//!      RFC 7592 section 2.2 read-modify-write that ENDS in `put_client` undoes a `delete_client`
//!      that landed in between, restoring the registration with its old credential. That is the
//!      resurrection, and the answer to it is [`Storage::compare_and_swap_client`], which this crate
//!      uses and which `put_client`'s own doc directs a host to in capitals. A host that reaches for
//!      `put_client` at the end of a read-modify-write has left this argument behind.
//!   4. [`Storage::put_consent`], for the same reason in the same shape, and it is the one on this
//!      list with NO caller in this crate at all: consent records are written by the HOST, from its
//!      own approval UI. Both cascades reach consents ([`Storage::delete_client`] at the client
//!      scope, [`Storage::revoke_consent`] at the consent scope), so it belongs here. The record it
//!      writes is a decision the resource owner has JUST made, and `Consent` barriers are
//!      established-at-or-before comparisons for precisely that case: [`RevocationWindow`] documents
//!      that a user who withdraws an application and approves it again has made a new decision, and
//!      admitting it is the intent rather than a gap. So a barrier here could only answer "write
//!      it". Updating an EXISTING consent is the read-modify-write, and it has the same answer:
//!      [`Storage::compare_and_swap_consent`], whose `expected: Option<&ConsentRecord>` exists to
//!      carry it.
//!
//!   THAT LIST WAS WRONG WHEN 0.9.1 FIRST CLAIMED IT, and the correction is worth more than the
//!   defect was. `put_pushed_authorization_request` was a SEVENTH site: it is written back by the
//!   cross-client refusal in `validate_pushed_authorization_request`, which must TAKE the record
//!   before it can read the `client_id` bound into it, so a `delete_client` landing in that window
//!   cascades nothing and the put-back restored a handle belonging to a deleted client. It was
//!   neither protected nor exempted, because the enumeration was asserted rather than derived. It
//!   consults the barrier now, and [`crate::storage_conformance`] holds a host to that with
//!   `revocation_barrier/refuses_put_pushed_authorization_request`.
//!
//!   The count was ALSO wrong in the other direction, and the second error is the instructive one:
//!   the doc claimed the exemption count was "one, by construction" while `put_device_grant`,
//!   which no cascade spares, was named nowhere. Nothing was broken by that — the argument above
//!   holds — but an enumeration that omits a site because the site is harmless is an enumeration
//!   nobody can check, which is the same defect as the consent and PAR kinds missing from
//!   `delete_client`'s cascade list.
//!
//!   AND IT WAS STILL SHORT AFTER THAT CORRECTION, by two: entries 3 and 4 above, `put_client` and
//!   `put_consent`, were absent from the list while a cascade in this trait removed the kind each
//!   one writes. Both were in fact safe, for the arguments now written beside them, which is exactly
//!   what made the omission the same mistake as `put_device_grant`'s: the list was derived by
//!   noticing harm rather than by reading the cascades. That is the THIRD time this enumeration has
//!   been found short by reading, and it is why it is no longer only prose:
//!   `tests/storage_cascade_definitions.rs`'s
//!   `every_storage_write_either_consults_the_barrier_or_is_an_argued_exemption` scans this file and
//!   requires every `fn put_*` on the trait to EITHER return [`WriteOutcome`], which is how a method
//!   says it consults the predicate, OR be named in the block above. It cannot judge an argument; it
//!   can insist one is written where a host reads, and that is the half that kept failing. A fifth
//!   write added without either fails the build.
//!
//!   THE RULE FOR ANYONE ADDING A METHOD: a write on a record that any revocation cascade removes
//!   must consult this predicate or be listed above with its argument. Deriving that list means
//!   reading every cascade in this trait and asking what it removes, not counting the call sites
//!   that already do the right thing.
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
use crate::device::{DeviceGrant, DeviceGrantState};
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

/// What a revocation removed, in the terms a later write can be judged against.
///
/// A barrier is not a record and it is not a tombstone for one key. It names a SET of records, so
/// that a write which was already in flight when the revocation ran can be refused without the
/// store having to have seen that particular record at the time. That is the whole difficulty: the
/// record a rotation is about to write back does not exist yet when the revocation runs, so there
/// is nothing to delete and nothing to compare against.
///
/// The three variants are the three granularities at which this crate revokes, and they are not
/// interchangeable. A family is one refresh chain; a consent is every family one client ever
/// obtained for one user; a client is everything a registration ever held. A write is refused if
/// ANY recorded barrier covers it.
///
/// # Covering a write is not the same as naming its identity
///
/// A barrier names an identity, and two of these three identities can legitimately be established
/// AGAIN: a user who withdraws an application and approves it again has made a new decision, and a
/// host may re-provision a `client_id` it deleted. So `Client` and `Consent` cover a write only
/// when the GRANT behind it was established at or before [`RevocationWindow::recorded_at`].
///
/// `TokenFamily` covers UNCONDITIONALLY, and the asymmetry is deliberate. Rotation legitimately
/// mints fresh records inside an EXISTING family, so comparing there would admit precisely the
/// write RFC 9700 section 4.14.2 containment exists to refuse — the rotation that completes after
/// the cascade. Nothing legitimate is lost by refusing always, because a new grant gets a new
/// `family_id`.
///
/// The instant compared against is the GRANT's, never the write's. A rotation and a code
/// redemption both write at `now`, so `now` cannot tell a grant that predates a revocation from
/// one made after it: comparing the write's own instant would make every barrier either useless
/// (family) or permanent (consent). See [`crate::token::IssuedToken::grant_established_at`].
///
/// This was got WRONG in 0.9.1 before the audit: barriers refused on identity alone, so a user who
/// re-approved an application held a live consent record and could not obtain a token from it for
/// as long as a refresh token lives. The refusal tests all passed, because refusing MORE is not
/// something a test asking "did it refuse?" can see.
///
/// # Every scope is a NON-EMPTY identifier, and that is a requirement on the store
///
/// The empty string is not an identity. A store that keys barriers by value has to distinguish
/// "no family" from "a family whose id happens to be empty", and every scheme for doing that
/// either collides or needs a nullable column with the awkward equality semantics that follow. So
/// [`Storage::delete_client`], [`Storage::revoke_token_family`] and [`Storage::revoke_consent`]
/// REFUSE an empty scope with a [`StorageError`], and refuse it BEFORE removing anything, rather
/// than one store accepting it and another rejecting it. That divergence is worse than either
/// behaviour on its own, and it is not hypothetical: it is what the two bundled stores did, and it
/// was found only by running the same call through both.
///
/// # Every barrier has a deadline, and it is not optional
///
/// A barrier only has to outlive the writes that could resurrect what it removed, and those are
/// bounded: a request holding a record is holding it across at most one issuance. Keeping barriers
/// forever would turn every revocation into permanent storage, on a path an ordinary user drives
/// by clicking "log out", so [`Storage::sweep_expired`] reclaims them like anything else. Callers
/// in this crate derive the deadline from the longest-lived thing the revocation removed, never
/// from a policy of their own: see [`crate::server::AuthorizationServer`]'s revocation paths.
/// # Deliberately NOT `#[non_exhaustive]`
///
/// This crate marks its feature-varying public types (see `tests/host_api_shape.rs`, which gates
/// the rule), and this one is not feature varying: all three variants exist in every build, and
/// only the writing of a `Consent` barrier is gated. The rule therefore does not reach it, and the
/// SAFETY argument runs the other way.
///
/// A host implements the refusal predicate by MATCHING this enum. `#[non_exhaustive]` would force
/// a wildcard arm into every one of those matches, and the only sensible thing a wildcard can
/// return is `false`, which is "not revoked". A variant added later would then be silently ignored
/// by every existing host store: a new revocation scope that refuses nothing, failing OPEN, with
/// no diagnostic anywhere. Leaving the enum exhaustive makes that same change a COMPILE ERROR at
/// the exact place that has to be updated, which is what this crate wants from a security
/// predicate and is the same argument [`Storage`] makes for having no default method bodies.
/// `Hash` is derived even though [`MemoryStorage`] does not key a map by this value (it keys by
/// the identifier the barrier NAMES, so that the lookup can be probed with a `&str` the caller
/// already holds rather than with a key it would have to build): a host whose own store wants a
/// `HashMap<RevocationBarrier, _>` should be able to have one, and a derive costs this library
/// nothing until something instantiates it.

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RevocationBarrier {
    /// Everything a client registration was ever issued (RFC 7592 section 2.3 deletion).
    Client(ClientId),
    /// One refresh chain and every token minted along it (RFC 9700 section 4.14.2 reuse
    /// detection, and RFC 7009 section 2.1's cascade from a revoked refresh token).
    TokenFamily(Box<str>),
    /// Everything one client ever obtained for one resource owner (consent withdrawal).
    Consent {
        /// The client the withdrawn consent named.
        client_id: ClientId,
        /// The resource owner who withdrew it.
        subject: Box<str>,
    },
}

/// A [`RevocationBarrier`] scope must be a NON-EMPTY identifier, and this is where that is
/// enforced rather than assumed.
///
/// A barrier names an identity. The empty string is not one: a store that keys barriers by value
/// has to distinguish "no family" from "a family whose id happens to be empty", and every scheme
/// for doing that either collides or needs a nullable column with the awkward equality semantics
/// that follow. `PostgresStorage` resolves it with a `''` sentinel plus CHECK constraints, which
/// makes an empty identifier a hard error at the database.
///
/// So the contract is that an empty identifier is REFUSED, by every store, rather than accepted by
/// one and rejected by another. That divergence is worse than either behaviour on its own: it was
/// found by comparing the two backends, where `delete_client("")` cascaded everything in memory
/// and — because the barrier insert runs first — deleted NOTHING through Postgres while returning
/// an error.
pub(crate) fn reject_empty_scope(what: &str, value: &str) -> Result<(), StorageError> {
    if value.is_empty() {
        return Err(StorageError::new(format!(
            "a revocation needs a non-empty {what}; the empty string does not name an identity a \
             barrier can be recorded for"
        )));
    }
    Ok(())
}

/// WHEN a revocation happened, and how long its barrier stands.
///
/// The two instants answer different questions and a store needs both, which is why they travel
/// together in one value rather than as two `SystemTime` parameters: both have the same type, so a
/// positional pair could be passed the wrong way round and still compile, and the failure would be
/// a barrier that refuses nothing (`recorded_at` far in the future is compared against by every
/// write) or one that never expires. Naming them makes that mistake impossible to write.
///
/// - `recorded_at` is the instant the revocation was made. A write is refused only when the GRANT
///   behind it was established at or before this instant, for the two scopes where an identity can
///   legitimately be established again. See [`RevocationBarrier`].
/// - `until` is the instant the barrier may be reaped, and is read only by
///   [`Storage::sweep_expired`]. It must be at least as far out as the longest-lived record the
///   revocation was entitled to kill.
///
/// Both are supplied by the caller rather than taken from the store's own clock, because only the
/// caller knows the configured lifetimes, and because a store that read the wall clock could not be
/// driven deterministically by a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationWindow {
    /// The instant the revocation was made.
    pub recorded_at: std::time::SystemTime,
    /// The instant the barrier may be reaped.
    pub until: std::time::SystemTime,
}

/// Whether a write happened, or was refused because a revocation covers it.
///
/// `#[must_use]`: a caller that ignores this has written exactly the bug this type exists to make
/// impossible, and it is the kind of bug that is invisible until somebody's revocation quietly
/// stops working. The server treats [`WriteOutcome::RefusedRevoked`] as a signal to UNDO the
/// issuance it was in the middle of, not as an error to report.
/// Exhaustive, for the same reason [`RevocationBarrier`] is: it does not vary with a feature, and
/// a host matching it wants a third variant to be a compile error rather than a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a refused write means the record was NOT stored; the caller must undo what it was issuing"]
pub enum WriteOutcome {
    /// The record is in the store.
    Applied,
    /// A [`RevocationBarrier`] covers this record, so it was NOT written. Whatever the caller was
    /// in the middle of issuing has been revoked underneath it.
    RefusedRevoked,
}

impl WriteOutcome {
    /// True when the record was actually stored.
    pub fn is_applied(self) -> bool {
        matches!(self, WriteOutcome::Applied)
    }

    /// True when a revocation refused the write.
    pub fn is_refused(self) -> bool {
        matches!(self, WriteOutcome::RefusedRevoked)
    }
}

/// What the authorization server needs from the host's persistence. All futures are `Send` so the
/// server can be driven from any multi-threaded async runtime.
///
/// # Why every method is required, and none has a default
///
/// It is 29 methods at `--all-features` and not one of them has a default body. That is a decision,
/// not an omission, and the first thing to say about it is the honest arithmetic: 9 of the 29 are
/// feature gated (6 behind `consent`, 2 behind `par`, and `claim_replay_id` behind
/// `client-assertion` or `dpop`), all features are off by default, so a default-features host
/// implements 20.
///
/// 20 IS NOT A NUMBER THE HOST CHOOSES, and this has to be said here because the arithmetic above
/// reads as though it were. Cargo unifies features across a dependency GRAPH, not per dependent: if
/// anything anywhere in the host's tree enables `consent`, the host's own build of `oauth-as` has
/// `consent`, this trait grows six methods, and the host's `impl Storage` stops compiling. They did
/// not ask for it and they cannot prevent it. `tests/host_api_shape.rs` states the same hazard for
/// public types, where the answer is `#[non_exhaustive]`; there is no such attribute for a trait,
/// and there is no defaulting the six without reintroducing precisely the "accepts a write and keeps
/// nothing" failure the paragraph below is about.
///
/// So a compile error is the RIGHT outcome and not a defect: the six methods appeared because the
/// build now has a consent-aware authorization server in it, and a store that silently did nothing
/// with consent records would be worse than one that will not build. What a host owes itself is
/// planning for it: [`crate::delegate_storage`] forwards whichever of the 29 the build actually has,
/// tracking the feature set rather than a fixed list, and it is the intended answer to this exact
/// event. (It could not be, until 0.9.1: the macro gated its nine on the HOST crate's features
/// instead of this one's, so it generated 20 forwarders no matter what. See the macro's docs.)
///
/// The rest is one argument. THERE IS NO METHOD HERE WHOSE OBVIOUS DEFAULT IS SAFE. A defaulted
/// `put_refresh_token` that does nothing is a server issuing refresh tokens nobody can redeem. A
/// defaulted [`Storage::revoke_token_family`] answering `Ok(0)` is a revocation that reports
/// success and revokes nothing, on the RFC 9700 section 4.14.2 path that runs only on evidence of
/// compromise. A defaulted `take_*` answering `Ok(None)` turns every redemption into a silent
/// `invalid_grant`. A defaulted [`Storage::sweep_expired`] answering `Ok(0)` is precisely the
/// memory exhaustion path that method's own docs are about. Every one of those compiles, passes a
/// smoke test, and fails in production in the direction that loses credentials.
///
/// That matters more here than it would in a general-purpose trait. This crate has already found
/// SIX separate places where a write silently undid a revocation, and each one took a test written
/// specifically to catch it. A default that accepts a write and keeps nothing is that same defect
/// shipped in the trait itself, with this crate's name on it, in the one place no host would think
/// to test. So the compile error is the FEATURE: it is this crate saying "you have not implemented
/// revocation yet" at build time, rather than at three in the morning.
///
/// What the trait owes an adopter instead of defaults is a way not to start from nothing:
///
/// - [`MemoryStorage`] is `pub`, not test-gated, exactly so it can be the on-ramp. It is a complete
///   implementation of all 29, it is the store this crate's own tests run on, and for a
///   single-process deployment it is an answer rather than a placeholder.
/// - The mix-and-match case (clients in Postgres, codes in memory) is answered by DELEGATION rather
///   than by defaults: a wrapper that forwards the methods it does not specialise. Forwarding is
///   mechanical, so [`crate::delegate_storage`] writes it.
/// - [`crate::storage_conformance`] (feature `test-util`) is how a host finds out its
///   implementation is wrong before its users do. Write the 20, run the harness, read what it says.
///
/// # MUST NOT PANIC. Return a [`StorageError`] instead
///
/// Every method here MUST return `Err(StorageError)` for every failure it can have, including the
/// ones a host would ordinarily assert on: a connection that is gone, a row that does not
/// deserialize, a slice index that is out of range, a `Mutex` poisoned by an earlier panic. This
/// crate catches no unwind anywhere on a request path, so a panic in a store is not caught, logged
/// and turned into `server_error`. It unwinds through whatever the server was in the middle of.
///
/// NAMING THE CONSEQUENCE, because a rule with no consequence attached is one a host talks itself
/// out of. Redemption is a TAKE followed by a WRITE, and the two are separate calls into this
/// trait by construction: the atomicity the `take_*` methods promise is per call, not across the
/// pair. A panic between them leaves byte for byte what a dropped future leaves.
///
/// - [`Storage::take_refresh_token`] has removed the record, and the spent marker that
///   [`Storage::put_refresh_token`] was about to write is never written. RFC 9700 section 4.14.2
///   reuse detection for that chain is now disarmed: the chain is gone, so a later presentation of
///   the old token is an ordinary unknown token rather than the evidence of compromise it is.
/// - [`Storage::take_authorization_code`] has removed the code, and the consumed record
///   [`Storage::put_authorization_code`] was about to write back is never written. RFC 6749
///   section 4.1.2 replay detection for that code is off permanently, because the alarm is the
///   record.
///
/// Neither of those is a crash a host sees. Both are a quiet loss of a detection this server is
/// relied on for, on the paths that only matter when something has already gone wrong. So: no
/// `unwrap`, no `expect`, no indexing, no `panic!`, in any of the 29. [`MemoryStorage`] holds
/// itself to this even where it would be entitled not to, which is why it recovers from a poisoned
/// mutex rather than propagating the panic (see `MemoryStorage::lock`).
///
/// The same clause is on [`crate::client::SecretVerifier`] and [`crate::events::RateLimiter`], for
/// the same reason and with the same absence of a net.
///
/// # Transient contention is the store's to resolve, not the caller's
///
/// This applies to the `take_*` operations and to the `compare_and_swap_*` operations, which are
/// the only methods here that two requests can legitimately reach for the same record at the same
/// instant.
///
/// A [`StorageError`] is NOT how a store says "somebody else got there first". Those methods
/// already have a word for that and it is not an error: `take_*` answers `Ok(None)` and
/// `compare_and_swap_*` answers `Ok(false)`, and the server knows what to do with both. A
/// `StorageError` means something the caller cannot act on, and it is mapped to `server_error` on
/// every wire path, so surfacing an ordinary overlap as one fails a legitimate redemption for a
/// reason the client cannot fix and cannot understand.
///
/// THIS IS A REQUIREMENT ON THE STORE BECAUSE ONLY THE STORE CAN MEET IT. A backend using
/// optimistic concurrency will see conflicts under exactly the concurrency these operations are
/// FOR: PostgreSQL at `SERIALIZABLE` raises `40001`, CockroachDB the same, etcd answers a
/// compare-and-swap mismatch, and a compare-and-swap loop over any of them observes a version that
/// moved. Every one of those is transient by definition, and the caller has no way to tell it apart
/// from a dead connection. So the store retries internally, and answers with the outcome the retry
/// settled on.
///
/// What is NOT required is retrying forever. A bounded retry that gives up is a store saying the
/// contention did not clear, and a [`StorageError`] is the right answer to that: the distinction
/// this rule draws is between a conflict that has been RESOLVED (answer `Ok`) and one that has
/// not, never between an error and a slow path.
///
/// [`crate::storage_conformance`] holds a store to this: its race checks fail a store whose
/// concurrent `take_*` or `compare_and_swap_*` calls return [`StorageError`], and they cite this
/// rule by name when they do, because a harness that fails a store on a rule the trait never
/// stated is a harness the store cannot argue with.
pub trait Storage: Send + Sync {
    /// Look up a registered client.
    ///
    /// `Arc` rather than an owned `Client` because this is the single most called read in the
    /// crate: every authenticated request on the token plane starts here, and the record is only
    /// ever READ. A store that keeps its clients as `Arc<Client>` answers with a pointer clone; a
    /// store that materialises one per query wraps what it built. See the module docs for the
    /// measurement and for why this does not touch the `take_*` atomicity contract.
    ///
    /// # `client_id` IS ATTACKER-CHOSEN, AND THIS CRATE VALIDATES NOTHING ABOUT IT
    ///
    /// [`ClientId::new`] wraps a `String` and checks nothing, deliberately: RFC 6749 section 2.2
    /// leaves the identifier's syntax to the server, and a host provisioning its own clients names
    /// them whatever its own scheme names them. What that means HERE is that the value arriving in
    /// this method is a string an unauthenticated stranger picked, on several routes at once:
    ///
    /// - `GET /authorize?client_id=...`, straight out of the query, filtered only for empty.
    /// - `POST /token`, out of the form body or an RFC 7617 `Authorization` header.
    /// - `GET`, `PUT` and `DELETE {registration_endpoint}/{client_id}` (RFC 7592), out of ONE
    ///   percent-decoded path segment. The router matches the prefix on the RAW path and refuses a
    ///   raw `/`, so no request can reach an endpoint mounted underneath the registration one — but
    ///   the segment is decoded AFTER that decision, so `%2F` becomes a real `/` here, `%2E%2E`
    ///   becomes `..`, `%00` becomes a NUL, and bytes that are not UTF-8 become U+FFFD (the decode
    ///   is lossy: see `crate::http`).
    ///
    /// So the identifier reaching this method may contain a path separator, a dot-dot segment, a
    /// NUL, a control character, a newline or a replacement character, and it may be up to the
    /// length of a URL or a request body. That is not a defect being described: `get_client` is a
    /// LOOKUP, and refusing to look a value up is not this crate's decision to make when the host's
    /// own naming scheme is the only thing that says what an identifier may look like — a host
    /// whose ids are RFC 9728-style HTTPS URLs has `/` in every one of them.
    ///
    /// WHAT THE STORE MUST DO: treat this as an opaque key and nothing else. A `HashMap`, a
    /// parameterised SQL query and a key-value `GET` are all safe as written; `MemoryStorage` and
    /// `oauth-as-postgres` are both in that class. A store that interpolates this into a PATH (one
    /// file per client), into an object key, into an LDAP filter or into SQL text is the case this
    /// paragraph exists for, and it must encode or reject the identifier ITSELF. Rejecting is
    /// always safe: answer `Ok(None)` for an id your scheme could not have minted, which is the
    /// truth — this crate treats that as an unknown client and refuses on the same terms it refuses
    /// any other.
    ///
    /// The same rule applies to every other method on this trait that takes a host-visible
    /// identifier; it is stated here because this is the one an unauthenticated request reaches
    /// first and from the most routes.
    fn get_client(
        &self,
        client_id: &ClientId,
    ) -> impl Future<Output = Result<Option<Arc<Client>>, StorageError>> + Send;

    /// Insert or replace a client registration.
    ///
    /// This is PROVISIONING: it creates a registration or replaces one outright, and it is what
    /// [`crate::server::AuthorizationServer::register_client`] and a host provisioning its own
    /// clients call. It is an upsert, deliberately, because re-provisioning a `client_id` the host
    /// chose is a legitimate thing for a host to do after deleting it.
    ///
    /// IT IS THE WRONG METHOD FOR A READ-MODIFY-WRITE, and that is not a style note. RFC 7592
    /// section 2.2 updates read the registration, apply a metadata document to it, and write it
    /// back; a blind upsert at the end of that sequence UNDOES a
    /// [`Storage::delete_client`] that landed in between, restoring the client with its old
    /// credential and its old `registration_access_token_hash`. Deleting a compromised
    /// registration would then be defeatable by whoever holds the stolen token. Use
    /// [`Storage::compare_and_swap_client`] for that, and see the resurrection rule in the module
    /// docs for why this distinction exists at all.
    fn put_client(&self, client: Client) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Replace the registration stored under `updated.client_id` with `updated`, but ONLY if the
    /// stored record is still exactly `expected`. Answers whether the write happened.
    ///
    /// This is [`Storage::put_device_grant`]'s compare-and-swap sibling, for the same reason and
    /// with the same contract: the comparison and the write MUST happen as ONE atomic step. A
    /// store that reads, compares, and then writes separately has reintroduced precisely the
    /// window this closes, and it will do so silently.
    ///
    /// `Ok(false)` for a `client_id` that is not present, and the write MUST NOT insert. Absence
    /// is the case that matters: it is what [`Storage::delete_client`] leaves behind, and an
    /// upsert here would put a deleted registration back. `UPDATE ... WHERE` is the shape to reach
    /// for; `INSERT ... ON CONFLICT` is the shape that reintroduces the defect.
    ///
    /// Comparing the WHOLE record rather than a version column is deliberate: it costs one
    /// equality test on a path that runs once per management request, and it closes the lost
    /// update between two concurrent RFC 7592 updates as well as the resurrection, without asking
    /// every host to carry a revision field it would otherwise have no use for.
    ///
    /// Two concurrent management requests are what this method is FOR, so a store that resolves
    /// its own concurrency optimistically will see conflicts here as a matter of course. See the
    /// trait's rule that contention is the store's to resolve, not the caller's: `Ok(false)` is
    /// how a loser is told it lost, and a [`StorageError`] is not.
    fn compare_and_swap_client(
        &self,
        expected: &Client,
        updated: Client,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;

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
    /// "Everything it was issued" is DEFINED by the list below, and the list is what a host
    /// implements against: nothing in the type system can check a cascade, so a kind this
    /// enumeration omits is a kind that survives every deletion in a store that was written to the
    /// letter of it. It means, for `client_id`, every record of every one of these kinds:
    ///
    /// - access tokens whose `client_id` is this one
    /// - refresh records whose `client_id` is this one
    /// - authorization codes whose `client_id` is this one, in either state
    /// - device grants whose `client_id` is this one, WITH their user-code index entries. An index
    ///   entry left pointing at a reaped grant makes that user code resolve to nothing.
    /// - pushed authorization requests (present only under the `par` feature) whose `client_id` is
    ///   this one. RFC 9126 section 2.2 binds a `request_uri` to the client that pushed it, so a
    ///   deleted client's outstanding handles are handles nobody may ever redeem.
    /// - consent records (present only under the `consent` feature) whose `client_id` is this one.
    ///   This one is the least obvious and it is NOT optional. A consent left behind names an
    ///   application that no longer exists: `consents_for_subject` lists it to the user,
    ///   who cannot meaningfully withdraw it, and because `client_id` is chosen by the HOST
    ///   ([`crate::server::AuthorizationServer::register_client`] takes whatever it is given), a
    ///   later client provisioned under the same id inherits the old user's standing approval,
    ///   with its scope and its resource set, without that user ever being asked.
    ///
    /// Both bundled stores delete all six. The last two were MISSING from this enumeration while
    /// both stores removed them, which is the worst way for a contract to be wrong: it is invisible
    /// to the `storage_conformance` harness, which can only check what this text requires, so a host
    /// store that certified clean was leaking exactly the two kinds nothing else ever reclaims.
    ///
    /// Removing a client that is already gone is `Ok(false)`, not an error. THE BARRIER BELOW IS
    /// STILL RECORDED IN THAT CASE, and it is stated here rather than left as an implementation
    /// detail because the natural shape a host reaches for gets it wrong: `if rows_deleted > 0 {
    /// insert_barrier(..) }` satisfies every other word of this method and silently drops the
    /// protection in exactly the interleaving that needs it. A client deleted twice, or deleted
    /// while a first deletion is still committing, is a client whose in-flight issuances still
    /// have to be refused, and absence of the registration row proves nothing about them: the
    /// issuance is holding a `Client` it read before either deletion ran.
    ///
    /// An EMPTY `client_id` is REFUSED with a [`StorageError`], before anything is removed: the
    /// empty string does not name an identity a barrier can be recorded for, and a store that
    /// accepted it here would cascade against a scope no later write can be compared to. Refusing
    /// BEFORE the first deletion is part of the requirement, so that a refusal leaves the store
    /// untouched rather than half cascaded — this crate found the divergence by comparing its two
    /// backends, where `delete_client("")` cascaded everything in memory and, because the barrier
    /// insert ran first, deleted NOTHING through Postgres while returning an error.
    /// [`RevocationBarrier`] says the same thing about the other two scopes.
    ///
    /// # It MUST also record a barrier, in the same step
    ///
    /// [`RevocationBarrier::Client`] for this `client_id`, over `window`, recorded
    /// ATOMICALLY with the deletions above. Without it the cascade is only as good as the moment
    /// it ran: a token issuance already in flight for this client completes afterwards and writes
    /// an access token and a refresh chain for a registration that no longer exists, and nothing
    /// ever reclaims them because the client they belong to is gone. See the resurrection rule in
    /// the module docs.
    ///
    /// `window` is supplied by the caller because only the caller knows both instants. Its
    /// `until` is how long an in-flight issuance could still be holding, and this crate passes the
    /// longest access token or refresh chain lifetime it is configured to mint. Its `recorded_at`
    /// is when the deletion happened, and a write is refused only when the GRANT behind it was
    /// established at or before that instant — so a `client_id` a host RE-PROVISIONS after the
    /// deletion is served rather than locked out for the barrier's whole life. See
    /// [`RevocationWindow`].
    fn delete_client(
        &self,
        client_id: &ClientId,
        window: RevocationWindow,
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
    ///
    /// This write does NOT consult a [`RevocationBarrier`], and it is one of the two exemptions
    /// the module docs enumerate rather than an omission. The reason is about the record and not
    /// about the cost of refusing: both cascades remove device grants, but the only caller in this
    /// crate mints a grant under a freshly drawn `device_code`, so there is no record for a
    /// cascade to have removed and nothing for a barrier to compare against that would not answer
    /// "write it". A host that puts a grant BACK after taking one has left that argument behind.
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
    ///
    /// IT ALSO RETIRES THE GRANT'S USER-CODE INDEX ENTRY, in the same step. That was documented
    /// nowhere while both bundled stores did it and [`crate::storage_conformance`] enforced it
    /// (`user_code_index/cleared_by_take`), which is the shape of contract error this trait is
    /// least able to survive: a host implementing the method to the letter of the words above
    /// fails a check whose requirement appears in no sentence it was given. A store that keeps the
    /// index as a pointer into the primary table gets this for free, because the entry resolves to
    /// nothing once the row is gone. A store whose index is its OWN row carrying its own copy of
    /// the grant — the ordinary Redis or DynamoDB shape — does not, and there the code a human
    /// typed goes on resolving to a grant that has already been exchanged for a token.
    fn take_device_grant(
        &self,
        device_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceGrant>, StorageError>> + Send;

    /// Replace the grant stored under `updated.device_code` with `updated`, but ONLY if the stored
    /// record's [`DeviceGrantState`] is still `expected`. Answers whether the write happened.
    ///
    /// # Why this exists, which is the whole of it
    ///
    /// Three unrelated actors write one device grant: the DEVICE polling the token endpoint (which
    /// restamps the RFC 8628 section 3.5 pacing fields), and the USER approving or denying at the
    /// host's verification UI. Every one of those is a read-modify-write, and with only
    /// [`Storage::put_device_grant`] to write through, the last writer wins by accident. The
    /// interleaving that matters is a poll whose read saw `Pending` landing its write after the
    /// user has already said no: the blind put reverts the record to `Pending`, the verification UI
    /// has already told the user their refusal was recorded, and nothing anywhere reports an error.
    /// A DECISION A USER ACTUALLY MADE IS SILENTLY THROWN AWAY.
    ///
    /// A poll TIMESTAMP is losable (the cost is one extra `slow_down`); a decision is not. This is
    /// the primitive that expresses the difference, and it is a compare-and-swap rather than a
    /// narrower "write only the pacing fields" call because the verification UI needs the same
    /// guarantee against ITSELF: two host UI actions on one user code must not clobber each other
    /// either, and there the field being written IS the state.
    ///
    /// # The contract
    ///
    /// The comparison and the write MUST happen as ONE atomic step. A store that implements this as
    /// a read, a comparison, and a separate write has reintroduced precisely the window it is meant
    /// to close, and it will do so silently, exactly as the `take_*` note at the top of this module
    /// describes. `SELECT ... FOR UPDATE`, `UPDATE ... WHERE state = $expected`, a Redis
    /// `WATCH`/`MULTI`, or a compare-and-set on a document revision all express it directly.
    ///
    /// `Ok(false)` for a `device_code` that is not present. A grant that has been redeemed or swept
    /// is gone, and a swap must never bring it back: reinstating a consumed grant would make a
    /// single-use device code redeemable twice. In particular the write MUST NOT be an
    /// insert-or-update: `UPDATE ... WHERE` cannot create a row and is the shape to reach for,
    /// whereas an upsert does not fail and does not no-op against a row that has just been
    /// redeemed, it puts the grant back.
    ///
    /// BOTH HALVES OF THE USER-CODE INDEX CONTRACT ON [`Storage::put_device_grant`] APPLY HERE
    /// TOO, and they are restated rather than referred to in passing because this trait has
    /// already watched them drift. A swap that CHANGES the grant's user code must retire the old
    /// entry, and a swap whose user code is already indexed for a DIFFERENT `device_code` must
    /// fail with a [`StorageError`] and write nothing — a refusal rather than `Ok(false)`, because
    /// `Ok(false)` means "the state moved on", which a caller answers by giving up quietly, and
    /// this is a store-level conflict the caller has to hear about. The requirement was stated on
    /// the put alone, and the reference implementation's own doc claimed the swap DELEGATED to it;
    /// it did not, it duplicated it, and the duplicate was missing the refusal, so a swap could
    /// hand one user code to two grants where a put would have refused.
    ///
    /// # THERE IS NO DEFAULT IMPLEMENTATION, deliberately
    ///
    /// One was provided at first, doing the read, the comparison and the write as three separate
    /// calls, on the reasoning that it NARROWED the window even though it could not close it. That
    /// reasoning was wrong twice over, and the shim is gone.
    ///
    /// It was wrong about the window, because narrowing it was not the only thing the shim did. Its
    /// write went through [`Storage::put_device_grant`], which is an INSERT-OR-UPDATE: a grant
    /// redeemed by [`Storage::take_device_grant`] between the shim's read and the shim's write was
    /// put BACK, so the shim did not merely fail to prevent a lost update, it manufactured a
    /// single-use device code that could be redeemed twice. That is a worse defect than the one it
    /// was written to mitigate.
    ///
    /// And it was wrong about the signal. A default implementation that is silently incorrect is
    /// worse than no default at all, because the host who never reads this paragraph gets NOTHING:
    /// their store compiles, their tests pass, and RFC 8628 section 3.3's first-decision-wins
    /// guarantee is void in production. Requiring the method makes that a compile error naming the
    /// method, which is the loudest and cheapest signal available, and it costs a host who has
    /// already written the other four device-grant methods one more.
    ///
    /// [`crate::storage_conformance`] checks all four properties (a swap that must apply, a swap
    /// that must be refused, a swap that must not resurrect a redeemed grant, and — since the
    /// atomicity above is the whole point and was for a long time the one thing nothing raced —
    /// N callers swapping the same `expected` concurrently, of which exactly one may win). Run it.
    ///
    /// The polling device and the verification UI are different requests on different nodes, so
    /// the race in that fourth check is the ordinary case rather than a manufactured one. See the
    /// trait's rule that contention is the store's to resolve, not the caller's: the loser of that
    /// race is told `Ok(false)`, never a [`StorageError`].
    fn compare_and_swap_device_grant(
        &self,
        expected: &DeviceGrantState,
        updated: DeviceGrant,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;

    /// Insert or replace an authorization code record, keyed by its code string.
    ///
    /// # THE ONE WRITE ON A REVOCABLE RECORD THAT DOES NOT CONSULT A BARRIER
    ///
    /// The module docs state the resurrection rule without exceptions, so this one is stated here
    /// rather than left for a host to discover by reading the implementation.
    ///
    /// It is exempt because refusing here would be WORSE than the resurrection it would prevent. A
    /// redemption writes the consumed record BEFORE issuing, precisely so that a store failure
    /// halfway through cannot take RFC 6749 section 4.1.2 replay detection offline with it. A
    /// barrier that refused that write would disarm the alarm at exactly the moment a grant was
    /// being revoked, which is when replay detection is most likely to matter.
    ///
    /// WHAT THE EXEMPTION ACTUALLY COSTS, measured against the rule rather than waved at: a
    /// redemption that took a code before [`Storage::delete_client`] or [`Storage::revoke_consent`]
    /// cascaded it away will write its record back, so the ROW comes back. That row mints nothing.
    /// The issuance behind it calls [`Storage::put_token`], which the barrier refuses, so no
    /// credential outlives the revocation. What is left is a consumed code belonging to no live
    /// grant, which [`Storage::sweep_expired`] reclaims at its own expiry. A row, not a
    /// capability.
    ///
    /// [`Storage::compare_and_swap_authorization_code`] is the conditional form, and it is what
    /// the redemption's SECOND write uses, where refusing is exactly right.
    fn put_authorization_code(
        &self,
        record: AuthorizationCodeRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Replace the record stored under `updated.code` with `updated`, but ONLY if the stored
    /// record's [`crate::authorization::AuthorizationCodeState`] is still `expected`. Answers whether the write happened.
    ///
    /// Same contract as [`Storage::compare_and_swap_device_grant`], and it is here for the same
    /// class of reason: two actors write one authorization code record, and one of them is
    /// suspended across an unbounded await while the other is deciding what to do.
    ///
    /// The interleaving, in full, because it is the reason this method exists. A redemption writes
    /// `Consumed { access_token: None, .. }` BEFORE issuing, so that a store failure mid-issuance
    /// cannot disarm replay detection, then suspends on the host's signer. A replay arriving in
    /// that window sees `access_token: None`, correctly finds nothing to revoke, and marks the
    /// record [`crate::authorization::AuthorizationCodeState::Replayed`]. When the redemption wakes and records what it
    /// minted, THIS comparison fails, and the redemption undoes its own issuance instead of
    /// handing out tokens that a detected replay was supposed to have contained.
    ///
    /// `Ok(false)` for a `code` that is not present, and the write MUST NOT insert: a code that
    /// has been swept or cascaded away by [`Storage::delete_client`] or
    /// [`Storage::revoke_consent`] must stay gone, for the reason the module docs give.
    fn compare_and_swap_authorization_code(
        &self,
        expected: &crate::authorization::AuthorizationCodeState,
        updated: AuthorizationCodeRecord,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;

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
    ///
    /// UNLESS A REVOCATION COVERS IT, exactly as [`Storage::put_token`] and
    /// [`Storage::put_refresh_token`] are, and for the same reason. A pushed request is a
    /// revocable record: [`Storage::delete_client`]'s cascade removes the handles of the client
    /// being deleted, because RFC 9126 section 2.2 binds a `request_uri` to the client that
    /// pushed it.
    ///
    /// It needs the barrier rather than absence, because the caller may be the one who created
    /// the absence. `validate_pushed_authorization_request` TAKES the record before it can check
    /// which client the handle belongs to, and puts it back when the presenter was a stranger, so
    /// a `delete_client` landing in that window finds nothing to cascade and the put-back would
    /// otherwise restore a handle belonging to a client that no longer exists. If the host then
    /// re-provisions the same `client_id`, which the trait explicitly permits, the restored
    /// handle resolves against the NEW registration and carries authorization parameters its
    /// owner never pushed.
    #[cfg(feature = "par")]
    fn put_pushed_authorization_request(
        &self,
        record: crate::par::PushedAuthorizationRequest,
    ) -> impl Future<Output = Result<WriteOutcome, StorageError>> + Send;

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

    /// Persist an issued access token, UNLESS a revocation covers it.
    ///
    /// The store derives the barriers to consult from the record itself: its `client_id`, its
    /// `family_id` when it has one, and its `subject` paired with its `client_id`. A caller
    /// therefore cannot forget to pass the right scope, because there is no scope to pass. If any
    /// matching [`RevocationBarrier`] is recorded, this writes NOTHING and answers
    /// [`WriteOutcome::RefusedRevoked`].
    ///
    /// The check and the write MUST be ONE atomic step, exactly as for the `take_*` operations: a
    /// look-then-insert leaves the window this method exists to close.
    ///
    /// This is the write that makes revocation mean something under concurrency. A token minted
    /// from a grant that was revoked while the signature was being computed is a token the user
    /// was told did not exist, and with a host `Es256Signer` fronting a KMS that window is a
    /// network round trip wide.
    fn put_token(
        &self,
        token: IssuedToken,
    ) -> impl Future<Output = Result<WriteOutcome, StorageError>> + Send;

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

    /// Persist a refresh token record, UNLESS a revocation covers it.
    ///
    /// Same contract as [`Storage::put_token`], and it carries more weight here, because this is
    /// the method every refusal path of a rotation calls. [`Storage::take_refresh_token`] has
    /// already REMOVED the record by then, so a cascade that ran in that window found nothing to
    /// cascade to; writing the record back unconditionally restores a live, rotatable refresh
    /// token that the user has been told was revoked. Absence cannot be the evidence on this path,
    /// because the caller is the one who created it. A barrier can.
    fn put_refresh_token(
        &self,
        record: RefreshTokenRecord,
    ) -> impl Future<Output = Result<WriteOutcome, StorageError>> + Send;

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
    /// NOT CHECKED, and it cannot be: [`crate::storage_conformance`] sees answers, not plans, so a
    /// store that satisfies this by scanning is indistinguishable from one that satisfies it by
    /// index at the sizes a harness can plant. It is a SHOULD for that reason rather than as a
    /// softening. Said here so that a host reading "write the 20, run the harness, read what it
    /// says" does not take a green as covering it.
    ///
    /// Removing records that are already gone is success: this runs on evidence of compromise and
    /// must not be turned into an error by a concurrent revocation.
    ///
    /// An EMPTY `family_id` is the one input that is NOT success. It is REFUSED with a
    /// [`StorageError`], before anything is removed, because the empty string does not name a
    /// family a barrier can be recorded for; see [`RevocationBarrier`]. Every access token this
    /// crate mints for a client credentials grant carries `family_id: None`, so a store that
    /// treated `""` as a family would be one careless call away from matching them all.
    ///
    /// # It MUST also record a barrier, in the same step
    ///
    /// [`RevocationBarrier::TokenFamily`] for this `family_id`, over `window`,
    /// recorded ATOMICALLY with the removals. This is the variant with the sharpest failure mode
    /// in the crate. The rotation that this revocation is racing has already TAKEN its refresh
    /// record, so the scan above cannot see it; when the rotation then writes its spent record and
    /// its freshly minted tokens, the family is whole again, and the AS has answered a detected
    /// compromise by revoking nothing. RFC 9700 section 4.14.2 is the reason this path exists, and
    /// a revocation that a concurrent redemption can undo does not satisfy it.
    ///
    /// `window.until` must be at least the family's longest-lived token: a chain with an absolute
    /// lifetime uses that, and a chain without one uses the access token lifetime, which is the
    /// longest anything issued from it can outlive the revocation.
    ///
    /// A family barrier refuses UNCONDITIONALLY, so it is the one scope that does NOT compare
    /// against `window.recorded_at`. Rotation legitimately mints fresh records inside an existing
    /// family, so a comparison here would admit exactly the write this exists to refuse: the
    /// rotation that completes after the cascade. Nothing legitimate is lost, because a new grant
    /// gets a new `family_id`.
    fn revoke_token_family(
        &self,
        family_id: &str,
        window: RevocationWindow,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;

    /// Insert or replace a consent record, keyed by its `consent_id`.
    ///
    /// The server keeps at most ONE live consent per (`client_id`, `subject`) pair and widens it
    /// in place, so a store that indexes that pair (see [`Storage::find_consent`]) must keep the
    /// index consistent with this write.
    ///
    /// Like [`Storage::put_client`], this is the unconditional form and it is NOT what the widen
    /// path uses: see [`Storage::compare_and_swap_consent`].
    #[cfg(feature = "consent")]
    fn put_consent(
        &self,
        record: crate::consent::ConsentRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Write `updated` only if the live consent for its (`client_id`, `subject`) pair is still
    /// exactly `expected`. Answers whether the write happened.
    ///
    /// `expected` is an `Option` because both transitions matter and they fail differently:
    ///
    /// - `Some(record)`: the caller read a consent and is WIDENING it. `Ok(false)` if the stored
    ///   record has changed or is gone. Gone is the case that matters, because that is what
    ///   [`Storage::revoke_consent`] leaves: without the comparison, a widen that was in flight
    ///   when the user clicked withdraw puts the consent back, and every future authorization
    ///   request is answered from a record the user believes they destroyed.
    /// - `None`: the caller found NO consent for the pair and is CREATING one. `Ok(false)` if the
    ///   pair now has one. This is the half that closes the duplicate-record race the server's
    ///   `record_consent` doc used to concede: two overlapping first-time approvals can no longer
    ///   each create a record, so the pair really does hold at most one.
    ///
    /// Comparison and write MUST be ONE atomic step, and the comparison is against whatever
    /// [`Storage::find_consent`] would answer for the pair, NOT against the `consent_id`: a
    /// withdrawal removes the record the caller read, and a fresh one created after it has a
    /// different id, so comparing ids would miss exactly the interleaving this exists to catch.
    #[cfg(feature = "consent")]
    fn compare_and_swap_consent(
        &self,
        expected: Option<&crate::consent::ConsentRecord>,
        updated: crate::consent::ConsentRecord,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;

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
    /// scanning. NOT CHECKED, for the reason [`Storage::revoke_token_family`] gives about its own
    /// indexing clause: the harness observes answers, and both shapes answer the same.
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
    ///   nothing there to withdraw;
    /// - the USER-CODE INDEX ENTRIES of any device grant removed above. Not a record and not
    ///   counted in the return, but a store that keeps such an index MUST retire the entry with the
    ///   grant. Both bundled stores do. An entry left pointing at a removed grant is worse than
    ///   untidy: [`Storage::put_device_grant`] must refuse a user code that is already indexed for
    ///   a different `device_code`, so a stale entry takes that code out of circulation for good,
    ///   and the server's generation loop cannot see the collision coming because the lookup it
    ///   makes resolves to nothing.
    ///
    /// That list is the DEFINITION a host implements against: nothing in the type system can check
    /// a cascade, so a kind it omits is a kind that survives every withdrawal in a store written to
    /// the letter of it.
    ///
    /// # What the PAIR cannot reach, and why that is written here rather than left to be found
    ///
    /// Every clause above, and the barrier below, keys on the WITHDRAWN consent's `client_id`. RFC
    /// 8693 token exchange (the `token-exchange` feature) issues a token to the EXCHANGING client
    /// while carrying the subject token's resource owner and the instant its grant was established:
    /// the instant is inherited, the identity is not. So a token some other client exchanged out of
    /// this consent's tokens matches neither the retain predicates above nor
    /// [`RevocationBarrier::Consent`], and a host implementing this list exactly is not the reason
    /// — no store can see a descendant this crate never records a link to.
    ///
    /// It is BOUNDED and it is not indefinite: an exchanged token's expiry is clamped to the
    /// subject token's (see `crate::token_exchange`), and that clamp holds along a chain of
    /// exchanges, so the descendant dies when the token it came from would have. What it costs is
    /// the difference between "immediately" and "within one access token lifetime", on the one
    /// operation whose whole promise is the first of those. Closing it needs the origin grant's
    /// identity recorded ON the issued token and compared here, which is a persisted-record change
    /// and therefore a clause of this contract and a [`crate::storage_conformance`] case, not
    /// something a store can be left to infer.
    ///
    /// It is ONE operation rather than five so a real database can do it in one transaction. A
    /// withdrawal that half succeeded leaves a user believing they revoked something they did not,
    /// which is the failure this whole feature exists to prevent.
    ///
    /// Withdrawing a consent that is already gone is `Ok(0)`, not an error, for the same reason
    /// [`Storage::revoke_token_family`] tolerates a concurrent revocation: a user who clicks twice
    /// has not made a mistake.
    ///
    /// A consent whose `client_id` or `subject` is EMPTY is REFUSED with a [`StorageError`],
    /// before anything is removed and before the consent row itself is, because the pair is what
    /// the barrier is recorded for and the empty string does not name one; see
    /// [`RevocationBarrier`]. The scope is read from the STORED record rather than passed in, so
    /// unlike the other two revocations the refusal is reachable only through a record some
    /// earlier `put_consent` accepted — which is the argument for refusing here rather than
    /// trusting that nobody ever wrote one. A refusal must leave the consent standing: a
    /// withdrawal that removed the record and then declined to record the barrier the withdrawal
    /// depends on is the worst of both answers.
    ///
    /// This runs when a person clicks something, never on a token-plane request, so it is not a hot
    /// path. It must simply complete.
    ///
    /// # It MUST also record a barrier, in the same step
    ///
    /// [`RevocationBarrier::Consent`] for the withdrawn record's (`client_id`, `subject`) pair,
    /// over `window`, recorded ATOMICALLY with the cascade. The cascade above can
    /// only reach records that are IN the store when it runs, and this is the feature whose whole
    /// promise is that it reaches everything: a refresh rotation or an authorization code
    /// redemption in flight for this pair completes afterwards and writes a live token for a
    /// relationship the user just ended. A user who is told "you have revoked this application"
    /// and still has a working token is the exact failure this feature exists to prevent, so the
    /// barrier is part of the withdrawal rather than an optimisation of it.
    ///
    /// Withdrawing a consent that is already gone records NO barrier and answers `Ok(0)`: there is
    /// no pair to name.
    #[cfg(feature = "consent")]
    fn revoke_consent(
        &self,
        consent_id: &str,
        window: RevocationWindow,
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
    #[cfg(any(feature = "client-assertion", feature = "dpop"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "client-assertion", feature = "dpop"))))]
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
    /// "Dead at `now`" is DEFINED by the list below, kind by kind, and the list is what a host
    /// implements against. A kind it omits is a table nothing ever reclaims, which is the memory
    /// exhaustion path three paragraphs up, reached by a host that did everything this doc asked.
    ///
    /// "Dead at `now`" means, for each kind:
    ///
    /// - device grants with `expires_at <= now`, AND the user-code index entries of the grants
    ///   removed. The index is a pointer rather than a record, so it is not counted in the return,
    ///   but a store that keeps one must retire the entry with the grant: see
    ///   the `revoke_consent` list below for what a stale entry costs, which is that user code
    ///   permanently unusable rather than merely a leaked row. Both bundled stores make this pass.
    /// - authorization codes with `expires_at <= now` (in either state)
    /// - pushed authorization requests (present only under the `par` feature) with
    ///   `expires_at <= now`. RFC 9126 section 4 refuses an expired `request_uri`, and a spent one
    ///   is removed by [`Storage::take_pushed_authorization_request`], so nothing else in this
    ///   crate ever reclaims a handle that was pushed and then abandoned. This kind was MISSING
    ///   from this list while both bundled stores swept it, which is the worst way for a contract
    ///   to be wrong: a host implementing the trait to the letter of the enumeration got a store
    ///   that certified clean and never reclaimed its pushed-request table. The push endpoint is
    ///   client authenticated (RFC 9126 section 2.1), so this is not an anonymous flood like the
    ///   device endpoint above, but one chatty or compromised client grows the table without bound.
    /// - access tokens with `expires_at <= now`
    /// - claimed replay identifiers (`claim_replay_id`, present only under the `client-assertion`
    ///   or `dpop` features) with `expires_at <= now`
    /// - refresh records with `Some(expires_at) <= now`. A record with `expires_at: None` is a
    ///   chain with no absolute lifetime and is NOT dead; the server gives a spent record a
    ///   retention deadline precisely so this method can reclaim it.
    /// - [`RevocationBarrier`]s whose `until` is at or before `now`. A barrier is not a record
    ///   either, but
    ///   unlike the user-code index it IS counted here, because it is a row an unswept store
    ///   accumulates one of per revocation and nothing else ever removes. Reaping one EARLY
    ///   reopens the resurrection window it was recorded to close, which is why the deadline comes
    ///   from the caller rather than from a fixed retention: sweep on the deadline, never before.
    ///
    /// Nothing else is time limited, and the omissions are deliberate: a client registration and a
    /// consent record last until something removes them ([`Storage::delete_client`],
    /// [`Storage::revoke_consent`]), so a sweep that reaped either would delete a live grant a user
    /// still relies on. [`crate::storage_conformance`] plants a DEAD record of every kind in this
    /// list and checks the count this method returns, with LIVE records beside them, so a store
    /// that reaps too little and a store that reaps too much are each told which.
    ///
    /// It must be safe to call concurrently with request handling, and safe to call when there is
    /// nothing to do (answering 0). BOTH HALVES ARE CHECKED, and the first was not until 0.9.1:
    /// [`crate::storage_conformance`] runs `sweep_expired/empty_is_zero` for the second and
    /// `sweep_expired/safe_under_concurrent_writes` for the first, the latter by sweeping at an
    /// instant when nothing is dead while `put_token` calls land beside it and then requiring every
    /// write the store reported as applied to still be readable. The store that fails only that
    /// check is the one that reads the table, decides what to keep and writes the kept set back:
    /// correct in every measurement taken while nothing else is running, and losing an issued
    /// access token per overlap in production.
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
    #[cfg(any(feature = "client-assertion", feature = "dpop"))]
    replay_ids: HashMap<String, std::time::SystemTime>,
    /// Recorded revocations, KEYED BY THE IDENTIFIER THEY NAME. Consulted by `put_token`,
    /// `put_refresh_token` AND `put_pushed_authorization_request`, each under the SAME guard that
    /// the revocation recorded them under, which is what makes the check-and-write one atomic step
    /// here.
    ///
    /// # Why this is a map, and why ONE map
    ///
    /// This was a `Vec` scanned linearly until the 0.9.1 audit, on the argument that a token is
    /// checked against three scopes at once so there is no single key to look up. The argument was
    /// wrong about the cost of being right: the scan runs on the ISSUANCE path, and the number of
    /// standing barriers is the number of revocations within one barrier lifetime, which at the
    /// shipped defaults is `refresh_reuse_window` and thirty days of them. So every token minted
    /// was priced by every revocation the deployment had recorded and not yet swept, and recording
    /// one was itself a scan, which makes filling the collection quadratic.
    ///
    /// That is the same operation this crate already refused to ship against PostgreSQL.
    /// `oauth-as-postgres/migrations/0005_revocation_barriers.sql` indexes the equivalent table
    /// because "without them every token issued costs a sequential scan of every revocation the
    /// deployment has ever recorded and not yet swept", with a measurement beside it. That is a
    /// statement about the operation rather than about a database, and this store is `pub` and is
    /// what a host reads first. `tests/storage_contract.rs`'s
    /// `a_standing_barrier_does_not_price_every_later_issuance` holds the bound.
    ///
    /// ONE map keyed by the identifier STRING, rather than one per scope or one keyed by
    /// [`RevocationBarrier`] itself, and both halves of that are deliberate:
    ///
    /// - Keying by `RevocationBarrier` is what this was before the `Vec`, and it cost a whole
    ///   hashbrown instantiation for a compound enum key (MEASURED with `scripts/size-report.sh`:
    ///   2,204 bytes on the DEFAULT feature set, which every consumer pays). It also cannot be
    ///   PROBED without building the key, so `is_revoked` would allocate on the issuance path,
    ///   which `tests/allocation.rs` gates.
    /// - One map keyed by the identifier is probed with a `&str` the caller already holds, so
    ///   `is_revoked` still allocates nothing, and a `client_id` lookup answers the `Client` scope
    ///   and the `Consent` scopes for that client TOGETHER: two probes cover all three scopes.
    ///
    /// A client id and a family id can be the same string, and that is not a collision: they are
    /// separate FIELDS of the value, so a barrier recorded for one is never read as the other.
    ///
    /// WHAT THE KEYED LOOKUP COSTS, since the `Vec` was chosen on a measurement and replacing it
    /// has to answer the same question. MEASURED with `scripts/size-report.sh` on
    /// aarch64-apple-darwin: the DEFAULT row went from 228,485 to 233,721 bytes, so this shape
    /// costs 5,236 bytes over the scan, which is the two hashbrown instantiations it takes to key
    /// three scopes without allocating to probe them. The row stays inside its recorded budget.
    /// That is the trade this file is willing to make and the earlier one was not: the bytes are
    /// paid once per binary, and the scan was paid once per token.
    ///
    /// Each recorded scope carries TWO instants and they answer different questions. `recorded_at`
    /// is when the revocation happened, and it is what a write is compared against: a grant
    /// established after it is a NEW decision and must not be refused. `until` is when the barrier
    /// may be reaped, and it is only ever read by `sweep_expired`.
    barriers: HashMap<String, ScopeBarriers>,
}

/// Every barrier recorded against ONE identifier string. See [`MemoryInner::barriers`].
///
/// `consents` is a map rather than a list because a mass logout revokes one consent per user of
/// one client, so the number of subjects standing against a single popular `client_id` is exactly
/// as unbounded as the whole collection was.
#[derive(Default)]
struct ScopeBarriers {
    /// Recorded by `delete_client` for this `client_id`.
    client: Option<BarrierTimes>,
    /// Recorded by `revoke_token_family` for this `family_id`.
    family: Option<BarrierTimes>,
    /// Recorded by `revoke_consent`, keyed by the subject who withdrew, for this `client_id`.
    consents: HashMap<String, BarrierTimes>,
}

impl ScopeBarriers {
    /// Whether anything is still recorded here. An entry that answers `false` is a key
    /// `sweep_expired` removes, so the map does not keep a row per identity forever.
    fn is_empty(&self) -> bool {
        self.client.is_none() && self.family.is_none() && self.consents.is_empty()
    }
}

/// One recorded revocation's two instants. See [`MemoryInner::barriers`] for why both are kept.
#[derive(Clone, Copy)]
struct BarrierTimes {
    recorded_at: std::time::SystemTime,
    until: std::time::SystemTime,
}

impl BarrierTimes {
    fn new(recorded_at: std::time::SystemTime, until: std::time::SystemTime) -> Self {
        BarrierTimes { recorded_at, until }
    }

    /// Fold a repeat revocation of the SAME scope into the one already recorded, keeping the later
    /// deadline. A second revocation of the same scope must never SHORTEN the first one's
    /// protection.
    ///
    /// `recorded_at` moves FORWARD on a repeat revocation, and that is not the same choice as the
    /// deadline's. The deadline takes the later of the two because protection must not shrink;
    /// `recorded_at` takes the later because it names the most recent revocation, and a grant
    /// established between the two revocations is one the second revocation was entitled to kill.
    /// Keeping the earlier instant would let that grant through.
    fn merge(&mut self, recorded_at: std::time::SystemTime, until: std::time::SystemTime) {
        if until > self.until {
            self.until = until;
        }
        if recorded_at > self.recorded_at {
            self.recorded_at = recorded_at;
        }
    }

    /// [`BarrierTimes::merge`] into an empty-or-occupied slot.
    fn merge_into(
        slot: &mut Option<BarrierTimes>,
        recorded_at: std::time::SystemTime,
        until: std::time::SystemTime,
    ) {
        match slot {
            Some(existing) => existing.merge(recorded_at, until),
            None => *slot = Some(BarrierTimes::new(recorded_at, until)),
        }
    }

    /// Whether a grant established at `established` is covered by a barrier that compares. Ties
    /// refuse: see [`MemoryInner::is_revoked`].
    fn covers(&self, established: std::time::SystemTime) -> bool {
        established <= self.recorded_at
    }
}

impl MemoryInner {
    /// THE RESURRECTION PREDICATE. One function, consulted by every write that needs it.
    ///
    /// Written once and called from all three rather than inlined at each call site, deliberately:
    /// the barrier-consulting writes are `put_token`, `put_refresh_token` and
    /// `put_pushed_authorization_request`, and this doc said "both" until the 0.9.1 audit — which
    /// mattered, because a host reading the reference store for the list of writes that must
    /// consult a barrier would have taken the pushed request for an exemption. The last
    /// time this crate expressed one operation at three seams (`CompactJws::claim_time`, hand
    /// rolled inside `par.rs` instead of called) the hand-rolled copy was the one that failed
    /// open, and it shipped in 0.9.0. Same operation, one seam.
    ///
    /// The scopes are derived from the RECORD's own fields rather than passed in, so a caller
    /// cannot forget one and cannot name the wrong one. All three are checked: a token belongs to
    /// a client, to a family when it has one, and to a (client, subject) relationship when it has
    /// a subject, and any of the three being revoked is enough to refuse it.
    ///
    /// A barrier's DEADLINE is not read here at all; it is read only by `sweep_expired`. So a
    /// barrier past its deadline STILL REFUSES until the sweep reclaims it, which is the safe
    /// direction: the deadline is
    /// the point past which nothing in flight can still be holding a pre-revocation record, so
    /// refusing slightly longer costs a client one re-authentication and refusing too briefly
    /// costs the revocation itself.
    ///
    /// `grant_established_at` IS THE INSTANT THE GRANT BEHIND THIS WRITE WAS AUTHORIZED — the
    /// code's mint, the device approval, or the instant carried forward through every rotation of
    /// a refresh chain. It is NOT the instant the token is being written, and the difference is
    /// the whole point: a rotation and a code redemption both write at `now`, so `now` would make
    /// every barrier either useless or permanent.
    ///
    /// Two of the three scopes compare against it, and one deliberately does not:
    ///
    /// - `Client` and `Consent` name an identity that can legitimately be established AGAIN. A
    ///   user who withdraws an application and approves it again has made a new decision, and a
    ///   host may re-provision a `client_id` it deleted. A grant established after the revocation
    ///   is that new decision and must be allowed through, or the revocation becomes a lockout
    ///   lasting as long as the longest token this server mints.
    /// - `TokenFamily` is UNCONDITIONAL. A family is dead forever once it is revoked: rotation
    ///   legitimately mints fresh records within an EXISTING family, so a comparison here would
    ///   let exactly the write RFC 9700 s4.14.2 exists to stop — the rotation that completes after
    ///   the cascade — put the family back. A new grant gets a new `family_id`, so nothing
    ///   legitimate is refused by refusing this one always.
    ///
    /// Ties refuse. If a grant was established in the same instant the revocation was recorded,
    /// the ordering is genuinely unknown and refusing is the safe direction, exactly as it is for
    /// the deadline above.
    ///
    /// Allocation: NONE on the accepting path, and no scan either. The comparisons borrow, because
    /// `put_token` runs on every issuance and `tests/allocation.rs` counts what happens there; the
    /// lookups are keyed, because the same method runs on every issuance and
    /// `tests/storage_contract.rs` counts THAT. Two probes cover all three scopes: the `client_id`
    /// entry holds both the `Client` barrier and every `Consent` barrier recorded for that client.
    fn is_revoked(
        &self,
        client_id: &ClientId,
        family_id: Option<&str>,
        subject: Option<&str>,
        grant_established_at: std::time::SystemTime,
    ) -> bool {
        if let Some(scopes) = self.barriers.get(client_id.as_str()) {
            if scopes
                .client
                .is_some_and(|t| t.covers(grant_established_at))
            {
                return true;
            }
            if let Some(subject) = subject {
                if scopes
                    .consents
                    .get(subject)
                    .is_some_and(|t| t.covers(grant_established_at))
                {
                    return true;
                }
            }
        }
        // The family scope is UNCONDITIONAL, so its presence alone refuses; see the doc above. It
        // is looked up under the FAMILY id rather than the client id, which is why one map with
        // two fields per key is the shape rather than one map per scope.
        family_id.is_some_and(|f| {
            self.barriers
                .get(f)
                .is_some_and(|scopes| scopes.family.is_some())
        })
    }

    /// Record a barrier under the identifier it names, replacing any earlier one for the same
    /// scope with the later deadline. The merge rules, and why the two instants move differently,
    /// are [`BarrierTimes::merge_into`]'s.
    fn record_barrier(
        &mut self,
        barrier: RevocationBarrier,
        recorded_at: std::time::SystemTime,
        until: std::time::SystemTime,
    ) {
        // The key string is allocated HERE, on the revocation path, rather than being built to
        // probe with on the issuance path: a revocation happens once per logout, an issuance
        // happens once per token, and `is_revoked` is the one that must not allocate.
        match barrier {
            RevocationBarrier::Client(client_id) => {
                let entry = self
                    .barriers
                    .entry(client_id.as_str().to_string())
                    .or_default();
                BarrierTimes::merge_into(&mut entry.client, recorded_at, until);
            }
            RevocationBarrier::TokenFamily(family_id) => {
                let entry = self.barriers.entry(family_id.into_string()).or_default();
                BarrierTimes::merge_into(&mut entry.family, recorded_at, until);
            }
            RevocationBarrier::Consent { client_id, subject } => {
                let entry = self
                    .barriers
                    .entry(client_id.as_str().to_string())
                    .or_default();
                // Inserted and then merged, rather than merged into an `Option`, so that the
                // merge rules stay in ONE place: the insert wins only when nothing was recorded
                // for this subject, in which case the merge that follows it changes nothing.
                entry
                    .consents
                    .entry(subject.into_string())
                    .or_insert(BarrierTimes::new(recorded_at, until))
                    .merge(recorded_at, until);
            }
        }
    }
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

    /// The whole operation happens under ONE guard, which is what makes the comparison and the
    /// write a single atomic step here. `Ok(false)` and no write when the record is absent or has
    /// moved on; absence is the [`Storage::delete_client`] case and it must stay absent.
    async fn compare_and_swap_client(
        &self,
        expected: &Client,
        updated: Client,
    ) -> Result<bool, StorageError> {
        let mut g = self.lock();
        match g.clients.get(updated.client_id.as_str()) {
            Some(current) if **current == *expected => {}
            // Absent (deleted) or changed (a concurrent update landed first). Both refuse, and
            // absent is the one that matters: an upsert here would put a deleted registration
            // back, with its old credential and its old registration access token hash.
            _ => return Ok(false),
        }
        g.clients
            .insert(updated.client_id.as_str().to_string(), Arc::new(updated));
        Ok(true)
    }

    async fn delete_client(
        &self,
        client_id: &ClientId,
        window: RevocationWindow,
    ) -> Result<bool, StorageError> {
        // Before anything is removed, so a refusal leaves the store untouched rather than
        // half-cascaded. See `reject_empty_scope`.
        reject_empty_scope("client_id", client_id.as_str())?;
        let mut g = self.lock();
        let existed = g.clients.remove(client_id.as_str()).is_some();
        // Recorded under the SAME guard as the cascade below, so there is no instant at which the
        // records are gone and a concurrent issuance could still write more of them. The barrier
        // is recorded even when the registration was already gone: a client deleted twice is a
        // client whose in-flight issuances still need refusing.
        g.record_barrier(
            RevocationBarrier::Client(client_id.clone()),
            window.recorded_at,
            window.until,
        );
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

    /// The whole operation happens under ONE guard, which is what makes it a compare-and-swap
    /// rather than a read followed by a hopeful write, and what a single-process host is entitled
    /// to expect from the reference implementation.
    ///
    /// Both halves of the user-code index contract documented on [`Storage::put_device_grant`] are
    /// enforced here TOO, restated rather than delegated, because a `&mut` guard is already held
    /// and calling the other method would deadlock. That duplication is a hazard worth naming: an
    /// earlier version of this doc claimed the index maintenance was delegated and therefore could
    /// not drift, and it had already drifted, because requirement (1), refusing a user code that is
    /// live for a DIFFERENT device code, was simply absent. A swap could hand one user code to two
    /// grants where a put would have refused. If either method changes, change both.
    async fn compare_and_swap_device_grant(
        &self,
        expected: &DeviceGrantState,
        updated: DeviceGrant,
    ) -> Result<bool, StorageError> {
        let mut g = self.lock();
        match g.device_by_code.get(&updated.device_code) {
            Some(current) if current.state == *expected => {}
            // Absent, or moved on. Absent is the redeemed-or-swept case and must stay absent: a
            // swap that reinstated a consumed grant would make a single-use device code
            // redeemable twice.
            _ => return Ok(false),
        }
        let normalized = crate::device::normalize_user_code(&updated.user_code);
        // Requirement (1), as `put_device_grant` applies it: RFC 8628 s6.1 makes the user code the
        // credential a human types, so two live grants answering to one code is two devices
        // sharing an identity. A REFUSAL rather than `Ok(false)`, because `Ok(false)` means "the
        // state moved on", which the caller answers by giving up quietly; this is a store-level
        // conflict the caller must hear about.
        if let Some(owner) = g.user_code_index.get(&normalized) {
            if owner != &updated.device_code {
                return Err(StorageError::new(
                    "user code is already indexed for a different device_code",
                ));
            }
        }
        if let Some(previous) = g.device_by_code.get(&updated.device_code) {
            let previous_normalized = crate::device::normalize_user_code(&previous.user_code);
            if previous_normalized != normalized {
                g.user_code_index.remove(&previous_normalized);
            }
        }
        g.user_code_index
            .insert(normalized, updated.device_code.clone());
        g.device_by_code
            .insert(updated.device_code.clone(), updated);
        Ok(true)
    }

    async fn put_authorization_code(
        &self,
        record: AuthorizationCodeRecord,
    ) -> Result<(), StorageError> {
        self.lock().codes.insert(record.code.clone(), record);
        Ok(())
    }

    /// One guard, so the comparison and the write cannot be separated. Absence refuses, which is
    /// what keeps a swept or cascaded code from being reinstated.
    async fn compare_and_swap_authorization_code(
        &self,
        expected: &crate::authorization::AuthorizationCodeState,
        updated: AuthorizationCodeRecord,
    ) -> Result<bool, StorageError> {
        let mut g = self.lock();
        match g.codes.get(&updated.code) {
            Some(current) if current.state == *expected => {}
            _ => return Ok(false),
        }
        g.codes.insert(updated.code.clone(), updated);
        Ok(true)
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
    ) -> Result<WriteOutcome, StorageError> {
        let mut g = self.lock();
        // Same one guard and the same one predicate as the two token writes. A pushed request
        // carries no family and no subject, so only the client scope can cover it.
        if g.is_revoked(&record.client_id, None, None, record.pushed_at) {
            return Ok(WriteOutcome::RefusedRevoked);
        }
        g.pushed.insert(record.request_uri.clone(), record);
        Ok(WriteOutcome::Applied)
    }

    #[cfg(feature = "par")]
    async fn take_pushed_authorization_request(
        &self,
        request_uri: &str,
    ) -> Result<Option<crate::par::PushedAuthorizationRequest>, StorageError> {
        // Atomic by construction, like every other `take_*` here: one mutex, one `remove`.
        Ok(self.lock().pushed.remove(request_uri))
    }

    async fn put_token(&self, token: IssuedToken) -> Result<WriteOutcome, StorageError> {
        let mut g = self.lock();
        // The check and the write under ONE guard: that is what makes this atomic rather than a
        // look followed by a hopeful insert. A revocation cannot land between them.
        if g.is_revoked(
            &token.client_id,
            token.family_id.as_deref(),
            token.subject.as_deref(),
            token.grant_established_at,
        ) {
            return Ok(WriteOutcome::RefusedRevoked);
        }
        // The `Arc` costs ONE allocation here, on issuance, and saves seven on every introspection
        // of the token afterwards. A token is issued once and introspected once per protected
        // request it is presented with, so the trade is measured in the direction that pays.
        g.tokens.insert(token.access_token.clone(), Arc::new(token));
        Ok(WriteOutcome::Applied)
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

    async fn put_refresh_token(
        &self,
        record: RefreshTokenRecord,
    ) -> Result<WriteOutcome, StorageError> {
        let mut g = self.lock();
        // Same one guard, same one predicate. This is the write every refusal path of a rotation
        // makes, and the record it is putting back was removed by the caller's own take, so
        // absence proves nothing and the barrier is the only evidence available.
        if g.is_revoked(
            &record.client_id,
            Some(&record.family_id),
            record.subject.as_deref(),
            record.grant_established_at,
        ) {
            return Ok(WriteOutcome::RefusedRevoked);
        }
        g.refresh
            .insert(record.refresh_token.clone(), Arc::new(record));
        Ok(WriteOutcome::Applied)
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

    async fn revoke_token_family(
        &self,
        family_id: &str,
        window: RevocationWindow,
    ) -> Result<u64, StorageError> {
        reject_empty_scope("family_id", family_id)?;
        // A scan is honest for a map with no secondary index, and this runs once per detected
        // compromise rather than per request. A host with a real database indexes `family_id`.
        let mut g = self.lock();
        // BEFORE the removals, under the same guard: the ordering is invisible here because the
        // guard makes the whole method one step, but it is the order a transactional store should
        // use too, so that a partial failure leaves the barrier rather than leaves the gap.
        g.record_barrier(
            RevocationBarrier::TokenFamily(family_id.into()),
            window.recorded_at,
            window.until,
        );
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

    /// One guard again, and the comparison is against what `find_consent` would answer for the
    /// PAIR rather than against the `consent_id`: a withdrawal removes the record the caller read
    /// and any replacement has a different id, so comparing ids would miss the interleaving.
    #[cfg(feature = "consent")]
    async fn compare_and_swap_consent(
        &self,
        expected: Option<&crate::consent::ConsentRecord>,
        updated: crate::consent::ConsentRecord,
    ) -> Result<bool, StorageError> {
        let mut g = self.lock();
        let current = g
            .consents
            .values()
            .find(|c| c.client_id == updated.client_id && c.subject == updated.subject)
            .cloned();
        match (current.as_deref(), expected) {
            // Widening what we read, and it is still there unchanged.
            (Some(live), Some(expected)) if live == expected => {}
            // Creating, and the pair genuinely still has nothing. This is the half that closes the
            // duplicate-record race: the loser of two concurrent first approvals sees the winner's
            // record here and is refused.
            (None, None) => {}
            // Withdrawn, replaced, or created underneath us. Refuse and write nothing.
            _ => return Ok(false),
        }
        // A widen keeps the record's own id (see `record_consent`), so this replaces in place
        // rather than accumulating; a create inserts a fresh one.
        g.consents
            .insert(updated.consent_id.to_string(), Arc::new(updated));
        Ok(true)
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
    async fn revoke_consent(
        &self,
        consent_id: &str,
        window: RevocationWindow,
    ) -> Result<u64, StorageError> {
        // The whole cascade under the ONE mutex, which is this store's version of the single
        // transaction the trait doc asks a real database for: no request can observe a
        // half-withdrawn consent, and nothing can be issued between the lookup and the sweep.
        let mut g = self.lock();
        // PEEKED rather than removed, so the scope check below can run before anything is
        // mutated: a refusal must leave the consent standing rather than withdraw it and then
        // decline to record the barrier that withdrawal depends on.
        let Some(peek) = g.consents.get(consent_id) else {
            // Already withdrawn, or never existed. Both are success; see the trait doc. No barrier
            // either, because there is no (client, subject) pair to name one for.
            return Ok(0);
        };
        reject_empty_scope("client_id", peek.client_id.as_str())?;
        reject_empty_scope("subject", peek.subject.as_ref())?;
        let consent = g
            .consents
            .remove(consent_id)
            .expect("the peek above holds the same guard");
        let client_id = &consent.client_id;
        let subject: &str = consent.subject.as_ref();
        // The cascade below can only reach what is in the store NOW. The barrier is what reaches
        // the issuance that is mid-flight for this pair and has not written yet.
        g.record_barrier(
            RevocationBarrier::Consent {
                client_id: client_id.clone(),
                subject: subject.into(),
            },
            window.recorded_at,
            window.until,
        );
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

    #[cfg(any(feature = "client-assertion", feature = "dpop"))]
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
        #[cfg(any(feature = "client-assertion", feature = "dpop"))]
        {
            let before = g.replay_ids.len();
            g.replay_ids.retain(|_, exp| now < *exp);
            removed += (before - g.replay_ids.len()) as u64;
        }

        // Barriers last, and COUNTED: unlike the user-code index this is a row nothing else ever
        // removes, one per revocation, so a store that never reclaimed them would grow with every
        // logout. `now < until` REAPS a barrier whose deadline is exactly now — the retain keeps
        // only what is strictly ahead of the sweep — which is the same "dead at `now`" boundary
        // every other kind above uses, the boundary the trait states, and the one
        // `oauth-as-postgres` implements as `expires_at_ns <= $1`. The comment here said the
        // opposite until the 0.9.1 audit, describing a store that keeps it; a host implementing
        // the sweep from this reference would have had the two bundled stores disagreeing about
        // the instant a barrier stops standing.
        //
        // COUNTED PER SCOPE, not per map key: one key can hold a client barrier, a family barrier
        // and any number of consent barriers (see `ScopeBarriers`), and what the trait doc says is
        // counted is barriers. A key whose last scope was reaped is then dropped, so the map does
        // not keep a row per identity that was ever revoked.
        g.barriers.retain(|_, scopes| {
            if scopes.client.is_some_and(|t| now >= t.until) {
                scopes.client = None;
                removed += 1;
            }
            if scopes.family.is_some_and(|t| now >= t.until) {
                scopes.family = None;
                removed += 1;
            }
            let before = scopes.consents.len();
            scopes.consents.retain(|_, t| now < t.until);
            removed += (before - scopes.consents.len()) as u64;
            !scopes.is_empty()
        });

        Ok(removed)
    }
}
