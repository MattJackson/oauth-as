// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Proves the exported `Storage` conformance harness can go RED.
//!
//! A conformance harness nobody has watched fail is exactly the thing this project refuses to
//! trust: it is indistinguishable, from the outside, from a harness that returns an empty vector
//! whatever it is handed. So this file implements a store that is WRONG in one specific way at a
//! time, in the ways a host writing an honest-looking implementation actually gets it wrong, runs
//! the harness against it, and asserts that the harness reports exactly the violation that
//! deliberate defect deserves.
//!
//! The green side is here too, and is not a formality: the harness must report NOTHING against
//! `MemoryStorage`, and nothing against `NaiveStore` with every fault switched off. Two
//! independent correct implementations passing is what stops the checks from being a description
//! of `MemoryStorage`'s incidental behaviour rather than of the documented contract.

#![cfg(feature = "test-util")]

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::SystemTime;

use oauth_as::device::normalize_user_code;
use oauth_as::storage_conformance::{StorageConformance, Violation, CHECKS};
use oauth_as::{
    AuthorizationCodeRecord, Client, ClientId, DeviceGrant, IssuedToken, MemoryStorage,
    RefreshTokenRecord, Storage, StorageError,
};

// ---------------------------------------------------------------------- the broken store

/// Which defect this instance carries. All false is a CORRECT store, which the green tests below
/// depend on: every fault is one edit away from the right implementation, which is the point. A
/// host does not write a store that is wrong everywhere, it writes one that is wrong in one place
/// that compiles, type-checks and passes a single-node test suite.
#[derive(Clone, Copy, Default)]
struct Faults {
    /// `take_*` implemented as read, then delete, with the suspension point a shared store has
    /// between the two. The defect this whole harness exists for.
    read_then_delete: bool,
    /// The revocation methods remove the records and record NO barrier. This is the shape every
    /// store had before 0.9.1, and it is the one a host writes by implementing the cascade
    /// faithfully and reading no further: the checks that only look at what is in the store
    /// afterwards all pass, because the cascade itself is correct. Only a write that arrives after
    /// the revocation can see the difference.
    revocation_records_no_barrier: bool,
    /// `put_token` and `put_refresh_token` write unconditionally, ignoring any barrier. The
    /// mirror image of the fault above: the revocation records what it removed, and the write puts
    /// it straight back.
    put_ignores_barriers: bool,
    /// A repeat revocation of one scope OVERWRITES the barrier already standing for it instead of
    /// merging with the later of the two deadlines and the later of the two `recorded_at`s. One
    /// line, and the line a `HashMap::insert` or an `INSERT ... ON CONFLICT DO UPDATE SET` hands a
    /// host for free.
    ///
    /// Nothing could see it before, because every other check in the harness records the SAME
    /// window twice and two equal instants take neither branch of the merge. What it costs is the
    /// slower of two nodes deciding: each computes its window from its own clock, the older
    /// instants land last, and the barrier is rewound to admit a grant the later revocation was
    /// entitled to kill and reaped early enough to reopen the whole window it closed.
    barrier_overwritten_by_the_later_write: bool,
    /// The revocations accept an EMPTY scope. `delete_client("")` then cascades against a
    /// registration nobody has, and records a barrier for `""` that no later write can be compared
    /// against; `revoke_token_family("")` names a family that every RFC 6749 section 4.4 access
    /// token is one careless predicate away from matching. This is the divergence that already
    /// shipped once between the two bundled stores, where one cascaded everything and the other
    /// deleted nothing and returned an error.
    revocation_accepts_an_empty_scope: bool,
    /// All four `compare_and_swap_*` implemented as a read, a comparison and a SEPARATE write,
    /// with the round trip a shared store makes in between.
    ///
    /// It is the defect every one of those four methods names in its own doc — "the comparison and
    /// the write MUST happen as ONE atomic step... a store that reads, compares, then writes has
    /// reintroduced precisely the window this closes, and it will do so silently" — and until the
    /// four race checks existed nothing here could see it, because every swap check was a
    /// sequential put, swap, read back, which this store passes without a mark against it.
    ///
    /// One field for all four rather than four fields, deliberately: it is one mental model a host
    /// applies to every swap it writes, so a store that has it on one method almost always has it
    /// on the rest, and four separate faults would suggest four separate mistakes.
    swaps_read_then_write: bool,
    /// The barrier refuses on IDENTITY ALONE, ignoring `RevocationWindow::recorded_at`. This is
    /// the shape 0.9.1 shipped before the audit found it, and it is the dangerous-looking-safe
    /// direction: every refusal check passes, because refusing more is never caught by a test that
    /// asks whether it refused. What it costs is the identity coming BACK — a user who withdrew an
    /// application and approved it again, or a re-provisioned `client_id`, is locked out until the
    /// barrier is swept.
    barrier_refuses_on_identity_alone: bool,
    /// `sweep_expired` never reclaims a revocation barrier. One row per revocation, and nothing
    /// else removes them, so the table grows for the life of the deployment.
    sweep_forgets_barriers: bool,
    /// `sweep_expired` reclaims a barrier BEFORE its deadline. The dangerous direction: the window
    /// the barrier was recorded to close is reopened, silently, and the store looks tidier for it.
    sweep_reaps_barriers_early: bool,
    /// `compare_and_swap_consent` implemented as an upsert, so a withdrawn consent comes back and
    /// two concurrent first approvals both create a record.
    ///
    /// GATED, like the three checks it drives: without `consent` the method that reads this is
    /// not compiled, so an ungated field here is dead code and `-D warnings` says so.
    #[cfg(feature = "consent")]
    consent_swap_upserts: bool,
    /// Each swap answers `Ok(false)` unconditionally. The mirror of the upsert faults, and the
    /// reason each swap needs an APPLIES check beside its refusal ones: a store that never applies
    /// resurrects nothing and also records nothing, so without this the refusal checks alone would
    /// certify a store that cannot perform an update at all.
    client_swap_refuses_everything: bool,
    /// The same for the authorization code swap.
    code_swap_refuses_everything: bool,
    /// The same for the consent swap.
    #[cfg(feature = "consent")]
    consent_swap_refuses_everything: bool,
    /// Each swap ignores `expected` and writes whenever the record is THERE. Distinct from the
    /// upsert faults, which write when it is NOT: one loses a concurrent update, the other
    /// resurrects a deleted record, and a store can have either without the other.
    client_swap_ignores_expected: bool,
    /// The same for the authorization code swap, where ignoring `expected` is how a redemption
    /// overwrites the trace a detected replay left for it.
    code_swap_ignores_expected: bool,
    /// The same for the consent swap.
    #[cfg(feature = "consent")]
    consent_swap_ignores_expected: bool,
    /// `put_token` and `put_refresh_token` refuse EVERYTHING, which is the mirror of ignoring the
    /// barriers: a store that answers `RefusedRevoked` unconditionally passes both refusal checks
    /// and can never issue a token.
    put_refuses_everything: bool,
    /// `compare_and_swap_authorization_code` implemented as an upsert: it reinstates a code that
    /// a cascade or a sweep removed, and it lets a redemption suspended on the host signer
    /// overwrite the `Replayed` trace a concurrent replay left for it.
    code_swap_upserts: bool,
    /// `compare_and_swap_client` implemented as an upsert: it compares, and then writes whether or
    /// not the row is still there. The exact shape `compare_and_swap_device_grant`'s doc warns
    /// about, on the method where it resurrects a DELETED REGISTRATION with its old credential.
    client_swap_upserts: bool,
    /// `put_device_grant` writes the new index entry and nothing else: no retirement of the old
    /// entry, no refusal when the code belongs to another device.
    index_overwrites: bool,
    /// `take_device_grant` removes the grant and leaves its user-code row behind. The row carries
    /// its own copy of the grant (see `Inner::user_code_index`), so the code a human typed goes on
    /// resolving to a grant that has already been redeemed.
    index_outlives_the_taken_grant: bool,
    /// `compare_and_swap_device_grant` ignores `expected` entirely and writes whenever the row is
    /// there: the shape a host writes as an unconditional `UPDATE ... SET payload = $1 WHERE
    /// device_code = $2` reporting `rows_affected > 0`. It is atomic, it compiles, it returns the
    /// right TYPE, and it silently reinstates the first-decision-wins race the method exists to
    /// close.
    swap_ignores_expected: bool,
    /// `compare_and_swap_device_grant` implemented as a read, a comparison, and an upsert, with no
    /// check that the row is still there when the write lands. This is the WORSE half, because the
    /// obvious mental model of a swap does not include it: a grant redeemed by `take_device_grant`
    /// between the read and the write is put BACK, and a single-use RFC 8628 device code becomes
    /// redeemable twice.
    swap_resurrects_taken_grants: bool,
    /// `compare_and_swap_device_grant` performs the conditional write CORRECTLY and then reports
    /// `Ok(false)` for it: the boolean is wired to the wrong side of the comparison, or is read
    /// from a driver's "rows matched" where the store meant "rows changed", or is the result of a
    /// read-back that asks whether the row still holds `expected` (which is false exactly when the
    /// swap did apply).
    ///
    /// It is the fault nothing here had planted, and its consequence is the one a host will not
    /// guess from the type: the user's decision at the RFC 8628 section 3.3 verification UI IS
    /// recorded, and the caller is told it was not. What the caller does with that is worse than a
    /// lost write. This crate's device flow treats a refused swap as "somebody else decided first"
    /// and reports the grant as already resolved, so an approval that landed is announced as a
    /// denial; a host that retries instead loops forever against a store that will never say yes,
    /// because the state it keeps swapping against has already moved.
    ///
    /// Nothing else in this file could see it: the swap is atomic, it honours `expected`, and it
    /// never resurrects a redeemed grant, so the other two swap checks and every `take_*` check
    /// stay green.
    swap_reports_that_it_did_not_apply: bool,
    /// `compare_and_swap_device_grant` writes the new user-code entry and leaves the old one
    /// behind: the swap half of `index_overwrites`, and the half a host gets wrong by writing the
    /// swap as `UPDATE ... SET user_code_normalized = $2 WHERE device_code = $1` over a
    /// denormalized index it forgot the swap could touch. The superseded RFC 8628 section 6.1 code
    /// goes on resolving to the grant, so the grant answers to two codes at once and the one the
    /// user is no longer being shown still approves it.
    swap_leaves_the_old_user_code_indexed: bool,
    /// `compare_and_swap_device_grant` repoints the index instead of REFUSING a user code that
    /// already belongs to another `device_code`. The put refuses it; this is the duplicate that
    /// was missing from the swap when the swap's own doc claimed it delegated to the put, and it
    /// is the reason that doc now restates both halves in capitals. One human-typed code, two live
    /// grants, and the older grant orphaned: its code now reaches the newer one, and taking the
    /// newer one removes the entry the older one needed.
    swap_repoints_a_duplicate_user_code: bool,
    /// `get_token` and `get_refresh_token` REMOVE what they return. The shape a store reaches for
    /// when the only primitive it has is a take, or when a "get" is written over the same
    /// `SELECT ... FOR UPDATE ... DELETE` the redemption path uses. Every check in the harness read
    /// each key exactly once, so this store certified clean while every RFC 7662 introspection and
    /// every RFC 7009 client check destroyed the credential it was only asking about.
    reads_are_takes: bool,
    /// The instant the GRANT behind a record was authorized is not persisted, and reads back as
    /// the epoch: `grant_established_at` on a token and on a refresh record, `issued_at` on an
    /// authorization code.
    ///
    /// One field for all three kinds rather than three, for the reason `swaps_read_then_write`
    /// gives: it is one belief — that the instant behind the record adds nothing to the row's own
    /// `issued_at` and `expires_at` — applied wherever a record carries one. It is the single time
    /// input every `client` and `consent` barrier comparison is made against, so losing it does
    /// not merely fail a round trip: in this direction every write is refused, and a client with
    /// any standing barrier can never obtain a token again, which is why the ADMITS check fires
    /// alongside the three round trips.
    drops_the_grant_instant: bool,
    /// The barrier consulted by `put_pushed_authorization_request` compares `pushed_at` and
    /// nothing else: the `client_id = $1` conjunct is missing from the WHERE clause, so ANY
    /// standing client barrier refuses EVERY push.
    ///
    /// The dangerous-looking-safe direction again, and it survived every check the harness had:
    /// both PAR writes made while a barrier stood used the barrier's own `client_id`, so a store
    /// with this defect refused exactly the record it was supposed to and certified clean. In
    /// production one administrator's RFC 7592 section 2.3 delete closes the RFC 9126 endpoint for
    /// every client in the deployment, fail-closed and silent, until the barrier is swept.
    #[cfg(feature = "par")]
    par_barrier_ignores_the_client_scope: bool,
    /// `delete_client` and `sweep_expired` remove only CONSUMED authorization codes. Both methods
    /// say "in either state", and a host that keeps replay evidence in mind rather than
    /// outstanding grants writes the predicate this way without noticing: the abandoned
    /// authorization request every user who closes a tab leaves behind is never reclaimed, and a
    /// deleted registration keeps a live, redeemable code.
    ///
    /// One field for both methods rather than two, for the reason `swaps_read_then_write` gives:
    /// it is one mental model about what an authorization code row IS, applied wherever the store
    /// removes them in bulk.
    code_removal_filters_on_state: bool,
    /// `put_device_grant` persists every column except the RFC 8628 section 3.2 polling interval,
    /// which reads back as zero: the ordinary shape of a schema whose column is
    /// `NOT NULL DEFAULT 0` and whose INSERT statement never learned about it. The device then
    /// polls as fast as it can and the server answers `slow_down` to a client that is obeying the
    /// interval it was given, because the interval it was given is not the one the store kept.
    drops_the_device_grant_interval: bool,
    /// `put_authorization_code` persists every column except the RFC 7636 code challenge, so the
    /// code reads back as though PKCE had never been used and is redeemable with no verifier.
    drops_the_code_challenge: bool,
    /// `put_token` persists every column except the RFC 8707 `resource` audience restriction, so
    /// every token this store holds is good at every resource server that trusts the issuer.
    drops_the_token_resource: bool,
    /// `put_device_grant` REFUSES a user code that already belongs to another device, correctly,
    /// and has already repointed the index and written the clashing grant by the time it decides
    /// to. The refusal is honest and the damage is done: the code the first device is displaying
    /// now resolves to the second device's grant.
    refusal_repoints_the_index: bool,
    /// `sweep_expired` reaps every record rather than the dead ones.
    sweep_removes_everything: bool,
    /// `sweep_expired` reaps NOTHING and reports zero: the opposite miss, and the one a host never
    /// notices, because a sweep that removes too little looks exactly like a store with nothing to
    /// remove until the disk fills.
    sweep_removes_nothing: bool,
    /// `sweep_expired` fails when it matched no rows, the way a driver that treats "no rows
    /// affected" as an error does. The host runs this on a timer against a store that is usually
    /// idle, so it is the common case that breaks, not the rare one.
    sweep_errors_when_it_removed_nothing: bool,
    /// `sweep_expired` reads the token table, decides what to keep, RELEASES the lock, and writes
    /// the kept set back. Every token that landed in the gap is silently gone.
    ///
    /// This is the only fault in this file that a store AT REST is identical under: with nothing
    /// else touching the store it reaps exactly the right records and reports exactly the right
    /// count, so every sequential sweep check passes it. It is the shape a host writes when the
    /// sweep is a batch job rather than a statement (read the rows, filter in the application,
    /// write the survivors back), and the damage is a token the store said it had written, handed
    /// to a client, that is not there when the client presents it. `Storage::sweep_expired`
    /// requires the store to be "safe to call concurrently with request handling"; this is what
    /// that sentence is protecting against, and nothing drove it until 0.9.1.
    sweep_rebuilds_the_token_table_from_a_snapshot: bool,
    /// `delete_client` removes the registration row only, leaving everything it was issued live.
    delete_client_leaves_credentials: bool,
    /// `delete_client` answers true whether or not a registration was there, the way an
    /// implementation that returns "the statement ran" rather than "a row went away" does. RFC 7592
    /// section 2.3 is answered from this boolean, so the management endpoint reports 204 for a
    /// client id that never existed.
    delete_client_always_reports_true: bool,
    /// The mirror image, and the direction nothing had planted: `delete_client` removes the
    /// registration and its credentials, correctly, and reports FALSE for it. The shape a host
    /// writes by reading "rows changed" from a driver that reports zero for a cascade it performed
    /// in a trigger, or by reading the count of a second statement that ran after the row was
    /// already gone.
    ///
    /// The check names both halves and only one of them had ever been driven, so the branch that
    /// catches this could have been deleted and the suite would have stayed green. RFC 7592 s2.3 is
    /// answered from this boolean in the other direction now: the deletion HAPPENED, and the
    /// management endpoint tells the administrator it did not by answering 404, so the registration
    /// is reported alive while its every credential is gone.
    delete_client_always_reports_false: bool,
    /// `revoke_token_family` removes the refresh chain and leaves the access tokens.
    family_revocation_spares_access_tokens: bool,
    /// `revoke_token_family` removes EVERY family, not the one named: a predicate that was dropped
    /// or that matched on the wrong column. Reuse detection on one stolen chain then logs out every
    /// client in the deployment.
    family_revocation_takes_every_family: bool,
    /// `delete_token` errors when the token is already gone.
    delete_token_errors_when_absent: bool,
    /// `put_refresh_token` persists every column except `family_id`.
    drops_family_id: bool,
    /// `put_client` persists every column except the credential: the registration reads back as a
    /// PUBLIC client. Nothing errors, and every request that was supposed to prove possession of a
    /// secret is now answered by anyone who knows the client id.
    drops_the_client_secret: bool,
    /// `find_device_grant_by_user_code` normalizes the query on the caller's behalf.
    normalizes_user_codes: bool,
    /// `put_client` is INSERT-only: a second registration under an id that already exists is
    /// dropped rather than replacing the first. The shape an `INSERT ... ON CONFLICT DO NOTHING`
    /// hands a host, one clause away from the upsert `put_client` is documented to be. Every
    /// round-trip check that writes a key once passed it; only `round_trip/client`, which writes a
    /// DIFFERENT registration first and requires the second to win, can see it, and it names the
    /// field that did not survive.
    put_client_insert_only: bool,
    /// `put_pushed_authorization_request` is INSERT-only in the same way: the authorization
    /// endpoint is answered from whichever push happened to land first under a handle.
    #[cfg(feature = "par")]
    put_pushed_insert_only: bool,
    /// `put_consent` is INSERT-only: a widen in place keeps the narrower approval the user gave
    /// first, and every later authorization request is answered from it.
    #[cfg(feature = "consent")]
    put_consent_insert_only: bool,
    /// `put_device_grant` cannot UPDATE an existing `device_code`: a second put under a code that
    /// is already stored fails, the shape an `INSERT` with no `ON CONFLICT` gives a host. The put
    /// that RE-CODES a grant in place is refused, so the user-code index it was supposed to move
    /// never moves, and the harness must not mistake the failed put for an index defect.
    put_device_grant_refuses_to_update: bool,
    /// `put_token` surfaces a `StorageError` when it collides with a concurrent sweep, rather than
    /// letting the issuance through. The server maps that to `server_error`, so the host's
    /// maintenance schedule becomes a source of failed token requests: exactly the
    /// `sweep_expired/safe_under_concurrent_writes` contract, in the direction of a spurious error
    /// rather than a lost write. Keyed on the racer's own token names so only the writes made
    /// DURING the sweep race fail, not the live records planted before it.
    issuance_fails_beside_a_sweep: bool,
    /// Every `compare_and_swap_*` that LOSES its comparison answers `Err(StorageError)` instead of
    /// `Ok(false)`. The `Storage` trait makes contention the store's to resolve: `Ok(false)`
    /// already says "somebody else got there first", so a store that surfaces the conflict as an
    /// error fails a legitimate overlapping request. Invisible to every sequential check, because
    /// nothing loses a comparison without a concurrent writer; only the raced swap checks see it.
    swap_surfaces_contention_as_error: bool,
    /// `compare_and_swap_consent` reports `Ok(true)` for a WIDEN and writes nothing: the UPDATE
    /// branch of an upsert whose `WHERE` clause matched no rows, with the driver's "statement ran"
    /// mistaken for "a row changed". The create still writes, so the pair holds a consent and the
    /// swap's `applies_when_it_matches` read-back — the one check that reads the record back after
    /// a widen rather than trusting the boolean — is the only thing that can see the widen was lost.
    #[cfg(feature = "consent")]
    consent_swap_widen_is_lost: bool,
    /// `put_token` persists every column except the RFC 9449 `jkt` binding.
    #[cfg(feature = "dpop")]
    drops_jkt: bool,
    /// The same drop on the REFRESH record, which is a separate column in a separate table and so
    /// a separate mistake. It is the worse of the two: the refresh record's `jkt` is what the next
    /// rotation copies onto the token it mints, so losing it unbinds every token the chain will
    /// ever produce, not one.
    #[cfg(feature = "dpop")]
    drops_jkt_on_refresh_records: bool,
    /// `put_token` persists every column except the RFC 8705 section 3.1 `x5t#S256` binding. The
    /// mTLS half of `drops_jkt`, and identical in consequence: a certificate-bound token becomes a
    /// bearer token, silently, and an introspecting resource server sees no `cnf` at all rather
    /// than an error.
    #[cfg(feature = "mtls")]
    drops_x5t_s256_on_tokens: bool,
    /// The same drop on the refresh record. Same reasoning as `drops_jkt_on_refresh_records`.
    #[cfg(feature = "mtls")]
    drops_x5t_s256_on_refresh_records: bool,
    /// `put_token` persists every column except the RFC 9396 `authorization_details`. The token
    /// then describes a narrower authorization than the resource owner approved, and a resource
    /// server that reads it falls back to the coarse `scope` string RAR exists to stop relying on.
    #[cfg(feature = "rar")]
    drops_authorization_details_on_tokens: bool,
    /// The same drop on the refresh record, which is what RFC 9396 section 6 narrowing is measured
    /// against on the next rotation: a chain with no details refuses, or silently loses, the rich
    /// authorization every refreshed token should have carried.
    #[cfg(feature = "rar")]
    drops_authorization_details_on_refresh_records: bool,
    /// The same drop on the authorization code, which is the record of what was actually approved.
    #[cfg(feature = "rar")]
    drops_authorization_details_on_codes: bool,
    /// The same drop on the pushed request. RFC 9101 section 6.3 has the authorization endpoint
    /// use ONLY the pushed parameters, so this is a parameter the client was told at push time was
    /// acceptable and then did not get.
    #[cfg(all(feature = "rar", feature = "par"))]
    drops_authorization_details_on_pushed_requests: bool,
    /// `put_pushed_authorization_request` persists every column except the RFC 7636 section 4.3
    /// `code_challenge`. A silent PKCE downgrade on the one request shape whose entire purpose was
    /// to keep the challenge out of the browser.
    #[cfg(feature = "par")]
    drops_the_pushed_code_challenge: bool,
    /// `put_token` persists every column except the RFC 8693 section 4.1 `act` claim, so a
    /// delegated token reads back as though the SUBJECT had made the request directly.
    ///
    /// The one feature-gated column of `IssuedToken` that had no drop fault, in a file whose own
    /// rule is that each fault drops exactly one field from exactly one record kind. RFC 8693
    /// section 1.1 draws the whole distinction between delegation and impersonation with this
    /// claim, and an opaque token carries it nowhere but here: a resource server introspecting a
    /// token this store kept attributes to the user a request an actor made on their behalf, and
    /// no audit trail anywhere records that an actor was involved at all.
    #[cfg(feature = "token-exchange")]
    drops_act_on_tokens: bool,
    /// `put_token` persists every column except the RFC 9470 authentication report, so every token
    /// reads back as though no step-up ever happened.
    #[cfg(feature = "consent")]
    drops_the_authentication_on_tokens: bool,
    /// The same drop on the refresh record, which is what stops a client defeating a `max_age` by
    /// refreshing.
    #[cfg(feature = "consent")]
    drops_the_authentication_on_refresh_records: bool,
    /// The same drop on the authorization code, so the token minted from it reports no `acr` and
    /// no `auth_time` however the host authenticated the user.
    #[cfg(feature = "consent")]
    drops_the_authentication_on_codes: bool,
    /// The same drop on the consent record, which is the authentication the consent was granted
    /// under and the thing a later step-up decision is measured against.
    #[cfg(feature = "consent")]
    drops_the_authentication_on_consents: bool,
    /// `take_refresh_token` PANICS. Not a defect a host writes on purpose, and that is the point:
    /// an index out of bounds, an `unwrap` on a row a migration did not create, a panicking
    /// deserializer. Under `with_spawn` the panic unwinds inside the host's runtime where the
    /// harness cannot see it, so what the harness must NOT do is wait forever for a racer that is
    /// never coming back.
    ///
    /// `take_refresh_token` specifically because the harness calls it from NOWHERE but the racers
    /// (every other read of a refresh record goes through `get_refresh_token`). A panic in
    /// `take_device_grant` would also fire inside the harness's own task, in the swap and
    /// user-code checks, and would abort the run instead of exercising the spawned path this fault
    /// exists to test.
    the_refresh_take_panics: bool,
    /// `claim_replay_id` implemented as look-then-insert, with the suspension point a shared store
    /// has between the two. The RFC 7523 / RFC 9449 half of the same defect.
    #[cfg(any(feature = "client-assertion", feature = "dpop"))]
    look_then_insert_claim: bool,
    /// `claim_replay_id` is keyed on nothing: the first claim takes the one slot the store has (a
    /// unique constraint on the wrong column, a fixed key name), so it is atomic under a race and
    /// still refuses every id that follows.
    #[cfg(any(feature = "client-assertion", feature = "dpop"))]
    claim_is_keyed_on_nothing: bool,
    /// `claim_replay_id` decides who is first ATOMICALLY and then keeps no record of it: the row is
    /// written with a lifetime of zero (a Redis `SET jti 1 NX EX <ttl>` where the ttl computed to
    /// nothing, or an advisory lock a host mistook for the claim itself), so it exists for exactly
    /// as long as the writes racing it and is gone by the time the next request arrives.
    ///
    /// This is the store the sequential half of the check exists for, and until this fault was
    /// planted nothing had ever driven that half: both other claim faults refuse a repeated id
    /// CORRECTLY, so the second-claim branch could have been deleted outright and the whole suite
    /// would still have been green. What it costs is everything RFC 7523 s3 and RFC 9449 s4.3 rest
    /// on: the store passes the race check, certifies clean, and every client assertion and every
    /// DPoP proof it holds can be replayed by anyone who observed one request, as long as the
    /// replay does not arrive in the same instant as the original.
    #[cfg(any(feature = "client-assertion", feature = "dpop"))]
    claim_forgets_what_it_claimed: bool,
    /// `sweep_expired` reclaims every record kind except the claimed replay ids: the table nothing
    /// else deletes from, growing once per authenticated request forever.
    #[cfg(any(feature = "client-assertion", feature = "dpop"))]
    sweep_forgets_replay_ids: bool,
    /// `sweep_expired` reclaims every record kind except the pushed authorization requests. The
    /// exact hole the trait's own enumeration of "dead at `now`" had: a host that implements the
    /// method to the letter of that list never reclaims its PAR table. RFC 9126 s2.1 makes the
    /// push endpoint client authenticated, so this is not an anonymous flood, but one chatty or
    /// compromised client grows the table without bound and nothing anywhere reports it.
    #[cfg(feature = "par")]
    sweep_forgets_pushed_requests: bool,
    /// `consents_for_subject` answers with every consent of the CLIENT the subject has a consent
    /// with, rather than of the subject. The wrong column, and the tempting one: the (client,
    /// subject) index `find_consent` wants is already there, so a listing built by reusing its
    /// leading column compiles, returns the right TYPE, and shows one user another user's grants
    /// on the screen whose whole purpose is to let them revoke things.
    #[cfg(feature = "consent")]
    consents_for_subject_filters_on_the_client: bool,
    /// `consents_for_subject` always answers with an empty list: a predicate that matches nothing
    /// (the subject compared against the wrong column, an index that was never populated). The
    /// user's "applications you have approved" screen is empty, so they can never withdraw
    /// anything, and every other consent check in the harness still passes.
    #[cfg(feature = "consent")]
    consents_for_subject_returns_nothing: bool,
    /// `consents_for_subject` reads a per-subject index that `put_consent` maintains and
    /// `revoke_consent` does not. Two writes on the way in, one on the way out: the user is shown
    /// an application they have already stopped, with a revoke button that reports success forever.
    #[cfg(feature = "consent")]
    consents_for_subject_reads_a_stale_index: bool,
    /// `find_consent` never finds anything: the (client, subject) index the trait asks a store to
    /// keep was never populated, so the lookup falls through. `round_trip/consent` already called
    /// this method and nothing had ever watched that call fail, which is the same shape of hole
    /// `consents_for_subject` was. The consequence is not an error anywhere: remembered consent
    /// simply never applies, so every authorization request re-prompts a user who already approved.
    #[cfg(feature = "consent")]
    find_consent_never_finds: bool,
    /// `revoke_consent` removes the consent row and returns a count, and leaves every credential
    /// it was supposed to take with it. The user is told the application was stopped; it was not.
    #[cfg(feature = "consent")]
    withdrawal_leaves_credentials: bool,
    /// `revoke_consent` removes every record of the CLIENT rather than of the (client, subject)
    /// pair, so withdrawing one user's consent logs out every other user of that application.
    #[cfg(feature = "consent")]
    withdrawal_takes_other_subjects: bool,
    /// `revoke_consent` revokes exactly the right credentials and counts the consent row along with
    /// them. The count is what an operator investigating an incident reads, and the trait is
    /// explicit that the row itself is not one of the credentials.
    #[cfg(feature = "consent")]
    withdrawal_counts_the_consent_row: bool,
}

#[derive(Default)]
struct Inner {
    clients: HashMap<String, std::sync::Arc<Client>>,
    device_by_code: HashMap<String, DeviceGrant>,
    /// The user-code lookup, keyed by NORMALIZED code, holding its OWN COPY of the grant rather
    /// than a pointer into `device_by_code`.
    ///
    /// Denormalized on purpose, and it is what makes `user_code_index/cleared_by_take` observable
    /// at all. A store that joins a pointer table back to the primary table cannot fail that check
    /// however badly it maintains the index: an entry left pointing at a row that is gone resolves
    /// to nothing, which is the right answer by accident. The stores that DO fail it are the ones
    /// where the lookup is its own row, which is the ordinary shape of a Redis or DynamoDB
    /// implementation (`SET usercode:WDJBMJHT <the serialized grant>`), and the one this store
    /// therefore models.
    user_code_index: HashMap<String, DeviceGrant>,
    codes: HashMap<String, AuthorizationCodeRecord>,
    tokens: HashMap<String, std::sync::Arc<IssuedToken>>,
    refresh: HashMap<String, std::sync::Arc<RefreshTokenRecord>>,
    #[cfg(feature = "consent")]
    consents: HashMap<String, std::sync::Arc<oauth_as::ConsentRecord>>,
    /// A second table modelling the per-subject index a real store keeps for
    /// `consents_for_subject`, written by `put_consent` and never cleaned. Only read when
    /// `consents_for_subject_reads_a_stale_index` is set, which is what makes that fault a stale
    /// INDEX rather than a stale copy of the primary table.
    #[cfg(feature = "consent")]
    consents_ever: HashMap<String, std::sync::Arc<oauth_as::ConsentRecord>>,
    #[cfg(any(feature = "client-assertion", feature = "dpop"))]
    replay_ids: HashMap<String, SystemTime>,
    /// The claims `claim_forgets_what_it_claimed` holds for the length of one call and no longer:
    /// the zero-lifetime row, kept apart from `replay_ids` because the whole point of that fault is
    /// that the real table never learns about it (so the sweep finds nothing to reclaim either).
    #[cfg(any(feature = "client-assertion", feature = "dpop"))]
    replay_claims_in_flight: std::collections::HashSet<String>,
    #[cfg(feature = "par")]
    pushed: HashMap<String, oauth_as::par::PushedAuthorizationRequest>,
    /// Recorded revocations. Modelled as its own table, exactly as a real store must, because the
    /// whole point of a barrier is that it outlives the records the revocation removed.
    barriers: HashMap<oauth_as::store::RevocationBarrier, oauth_as::store::RevocationWindow>,
    /// Mirrors `Faults::barrier_refuses_on_identity_alone`. Held here rather than applied at the
    /// call sites because it changes what the PREDICATE means, not whether it is consulted.
    refuses_on_identity_alone: bool,
}

impl Inner {
    /// The resurrection predicate, as a CORRECT store implements it. The faults that make this
    /// store fail the barrier checks are applied at the call sites, not here, so that a reader can
    /// see what right looks like in one place.
    fn is_revoked(
        &self,
        client_id: &ClientId,
        family_id: Option<&str>,
        subject: Option<&str>,
        grant_established_at: SystemTime,
    ) -> bool {
        use oauth_as::store::RevocationBarrier;
        self.barriers.iter().any(|(b, window)| match b {
            // `Client` and `Consent` name an identity that can be established AGAIN, so they
            // refuse only a grant that predates the revocation. `TokenFamily` refuses
            // unconditionally: rotation mints fresh records inside an existing family, and a new
            // grant gets a new family_id. See `RevocationWindow`.
            RevocationBarrier::Client(c) => {
                c == client_id
                    && (self.refuses_on_identity_alone
                        || grant_established_at <= window.recorded_at
                        // A client barrier over a client that no longer exists refuses every grant:
                        // the deletion recorded the barrier and removed the registration as one act,
                        // so an ABSENT client is a deletion no re-provisioning followed, and a grant
                        // stamped a hair after `recorded_at` by a concurrent write must not slip
                        // through. A client the host put back is present, so only the window governs
                        // it -- which is what keeps `refuses_on_identity_alone` a distinct fault.
                        || !self.clients.contains_key(client_id.as_str()))
            }
            RevocationBarrier::TokenFamily(f) => family_id == Some(&**f),
            RevocationBarrier::Consent {
                client_id: c,
                subject: s,
            } => {
                c == client_id
                    && subject == Some(&**s)
                    && (self.refuses_on_identity_alone
                        || grant_established_at <= window.recorded_at)
            }
        })
    }

    /// The same predicate with the `client_id` comparison DROPPED from the `Client` arm: one
    /// missing conjunct in a barrier query, which still compares the record's instant and so still
    /// refuses everything the refusal checks ask about.
    #[cfg(feature = "par")]
    fn is_revoked_by_any_client_barrier(&self, pushed_at: SystemTime) -> bool {
        use oauth_as::store::RevocationBarrier;
        self.barriers.iter().any(|(b, window)| match b {
            RevocationBarrier::Client(_) => pushed_at <= window.recorded_at,
            _ => false,
        })
    }

    /// Record a revocation, MERGING with any barrier already standing for the same scope: the
    /// later deadline wins, and so does the later `recorded_at`.
    ///
    /// A plain `insert` is what this store did, and it is what a `HashMap` and an
    /// `INSERT ... ON CONFLICT DO UPDATE SET` both hand a host for free, which is why the fault
    /// below is one line rather than a rewrite. Neither direction of the merge is cosmetic. Taking
    /// the later deadline is what stops a second revocation SHORTENING the first one's protection;
    /// taking the later `recorded_at` is what stops it admitting a grant established between the
    /// two, which the second revocation was entitled to kill. Two nodes withdrawing the same grant
    /// each compute a window from their own clock, so the write that lands second is regularly the
    /// one carrying the older instants.
    fn record_barrier(
        &mut self,
        barrier: oauth_as::store::RevocationBarrier,
        window: oauth_as::store::RevocationWindow,
        overwrite: bool,
    ) {
        let merged = match self.barriers.get(&barrier) {
            Some(existing) if !overwrite => oauth_as::store::RevocationWindow {
                recorded_at: existing.recorded_at.max(window.recorded_at),
                until: existing.until.max(window.until),
            },
            _ => window,
        };
        self.barriers.insert(barrier, merged);
    }
}

/// Whether a bulk removal of authorization codes takes this one.
///
/// True for every code a correct store is asked to remove, because both `delete_client` and
/// `sweep_expired` say codes go "in either state". The fault narrows it to the codes that have
/// already been redeemed, which is the predicate a host writes while thinking about replay
/// evidence rather than about the outstanding grants an abandoned authorization request leaves
/// behind. A free function because the two bulk removals live on different methods and must apply
/// the same rule.
fn removable(faults: Faults, code: &AuthorizationCodeRecord) -> bool {
    !faults.code_removal_filters_on_state
        || !matches!(code.state, oauth_as::AuthorizationCodeState::Issued)
}

struct NaiveStore {
    faults: Faults,
    inner: Mutex<Inner>,
}

impl NaiveStore {
    fn new(faults: Faults) -> Self {
        NaiveStore {
            inner: Mutex::new(Inner {
                // Carried into `Inner` because it changes what the predicate MEANS rather than
                // whether a call site consults it.
                refuses_on_identity_alone: faults.barrier_refuses_on_identity_alone,
                ..Inner::default()
            }),
            faults,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The write half of `compare_and_swap_device_grant`, once the comparison has already said
    /// yes, with BOTH halves of the user-code index contract the swap owes.
    ///
    /// They are here rather than inline because the swap has two write paths (the correct one and
    /// the read-then-write fault), and a contract implemented in one of them and not the other is
    /// exactly the drift the trait doc describes: the reference implementation's own doc claimed
    /// the swap delegated to the put, it duplicated it instead, and the duplicate was missing the
    /// refusal. Sharing the code is how this store avoids repeating that by accident.
    fn write_swapped_grant(&self, g: &mut Inner, updated: DeviceGrant) -> Result<(), StorageError> {
        let normalized = normalize_user_code(&updated.user_code);
        // A REFUSAL and not `Ok(false)`: `Ok(false)` means "the state moved on", which the caller
        // answers by giving up quietly, and this is a store-level conflict it has to hear about.
        if !self.faults.swap_repoints_a_duplicate_user_code {
            if let Some(owner) = g.user_code_index.get(&normalized) {
                if owner.device_code != updated.device_code {
                    return Err(StorageError::new(
                        "user code belongs to another device_code",
                    ));
                }
            }
        }
        if !self.faults.swap_leaves_the_old_user_code_indexed {
            if let Some(previous) = g.device_by_code.get(&updated.device_code) {
                let previous_normalized = normalize_user_code(&previous.user_code);
                if previous_normalized != normalized {
                    g.user_code_index.remove(&previous_normalized);
                }
            }
        }
        g.user_code_index.insert(normalized, updated.clone());
        g.device_by_code
            .insert(updated.device_code.clone(), updated);
        Ok(())
    }

    /// A revocation scope is a NON-EMPTY identifier, and the refusal happens BEFORE anything is
    /// removed, so a refused call leaves the store exactly as it was. See `RevocationBarrier`: the
    /// empty string does not name an identity a barrier can be recorded for, and a store that
    /// accepted one would cascade against a scope no later write can be compared against.
    fn reject_empty_scope(&self, what: &str, value: &str) -> Result<(), StorageError> {
        if value.is_empty() && !self.faults.revocation_accepts_an_empty_scope {
            return Err(StorageError::new(format!(
                "a revocation needs a non-empty {what}"
            )));
        }
        Ok(())
    }
}

// The field-drop faults, gathered per record kind rather than written inline in each `put_*`.
//
// One function per record because a dropped column is one column of one table: a fault that
// dropped the same field from every record at once would fire several round-trip checks together
// and could not tell a store that lost the token's copy from one that lost the refresh record's,
// which are separate migrations and separate mistakes.
//
// `unused_mut` is allowed rather than worked around: with none of the optional features compiled
// in there is nothing here to drop, and the alternative (a cfg on the binding itself) would say
// less about why.
impl NaiveStore {
    #[allow(unused_mut, unused_variables)]
    fn maybe_drop_token_fields(&self, mut token: IssuedToken) -> IssuedToken {
        if self.faults.drops_the_grant_instant {
            token.grant_established_at = SystemTime::UNIX_EPOCH;
        }
        #[cfg(feature = "dpop")]
        if self.faults.drops_jkt {
            token.jkt = None;
        }
        #[cfg(feature = "mtls")]
        if self.faults.drops_x5t_s256_on_tokens {
            token.x5t_s256 = None;
        }
        #[cfg(feature = "rar")]
        if self.faults.drops_authorization_details_on_tokens {
            token.authorization_details = oauth_as::AuthorizationDetails::none();
        }
        if self.faults.drops_the_token_resource {
            token.resource = Vec::new();
        }
        #[cfg(feature = "token-exchange")]
        if self.faults.drops_act_on_tokens {
            token.act = None;
        }
        #[cfg(feature = "consent")]
        if self.faults.drops_the_authentication_on_tokens {
            token.authentication = None;
        }
        token
    }

    fn maybe_drop_device_grant_fields(&self, mut grant: DeviceGrant) -> DeviceGrant {
        if self.faults.drops_the_device_grant_interval {
            grant.interval = std::time::Duration::from_secs(0);
        }
        grant
    }

    #[allow(unused_mut, unused_variables)]
    fn maybe_drop_refresh_fields(&self, mut record: RefreshTokenRecord) -> RefreshTokenRecord {
        if self.faults.drops_family_id {
            record.family_id = String::new();
        }
        if self.faults.drops_the_grant_instant {
            record.grant_established_at = SystemTime::UNIX_EPOCH;
        }
        #[cfg(feature = "dpop")]
        if self.faults.drops_jkt_on_refresh_records {
            record.jkt = None;
        }
        #[cfg(feature = "mtls")]
        if self.faults.drops_x5t_s256_on_refresh_records {
            record.x5t_s256 = None;
        }
        #[cfg(feature = "rar")]
        if self.faults.drops_authorization_details_on_refresh_records {
            record.authorization_details = oauth_as::AuthorizationDetails::none();
        }
        #[cfg(feature = "consent")]
        if self.faults.drops_the_authentication_on_refresh_records {
            record.authentication = None;
        }
        record
    }

    #[allow(unused_mut, unused_variables)]
    fn maybe_drop_code_fields(
        &self,
        mut record: AuthorizationCodeRecord,
    ) -> AuthorizationCodeRecord {
        if self.faults.drops_the_code_challenge {
            record.code_challenge = String::new();
        }
        if self.faults.drops_the_grant_instant {
            record.issued_at = SystemTime::UNIX_EPOCH;
        }
        #[cfg(feature = "rar")]
        if self.faults.drops_authorization_details_on_codes {
            record.authorization_details = oauth_as::AuthorizationDetails::none();
        }
        #[cfg(feature = "consent")]
        if self.faults.drops_the_authentication_on_codes {
            record.authentication = None;
        }
        record
    }
}

/// The suspension point that makes read-then-delete a double spend rather than a curiosity: a
/// shared store's read is a round trip, and the task yields while it is in flight. Written
/// explicitly here because this test's store is an in-process map that would otherwise never
/// suspend, so without it this file would be testing something no host actually deploys.
struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            return Poll::Ready(());
        }
        self.0 = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

async fn round_trip_to_the_store() {
    YieldOnce(false).await
}

impl Storage for NaiveStore {
    async fn get_client(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<std::sync::Arc<Client>>, StorageError> {
        Ok(self.lock().clients.get(client_id.as_str()).cloned())
    }

    async fn put_client(&self, client: Client) -> Result<(), StorageError> {
        let client = if self.faults.drops_the_client_secret {
            // The shape a host writes when the credential column is added to the struct and not to
            // the INSERT: the row is there, the client authenticates as a public client, and
            // nothing in the request path can tell that a secret was ever registered.
            Client {
                auth: oauth_as::ClientAuth::Public,
                ..client
            }
        } else {
            client
        };
        let mut g = self.lock();
        // INSERT-only: a registration already under this id is kept, and the replacement dropped.
        if self.faults.put_client_insert_only && g.clients.contains_key(client.client_id.as_str()) {
            return Ok(());
        }
        g.clients.insert(
            client.client_id.as_str().to_string(),
            std::sync::Arc::new(client),
        );
        Ok(())
    }

    async fn compare_and_swap_client(
        &self,
        expected: &Client,
        updated: Client,
    ) -> Result<bool, StorageError> {
        if self.faults.swaps_read_then_write {
            // Read, compare, suspend, THEN write: three steps where the contract requires one, so
            // every concurrent caller's comparison is made against the value the record held
            // before any of them wrote.
            let matched = self
                .lock()
                .clients
                .get(updated.client_id.as_str())
                .map(|current| **current == *expected)
                .unwrap_or(false);
            round_trip_to_the_store().await;
            if !matched {
                return Ok(false);
            }
            self.lock().clients.insert(
                updated.client_id.as_str().to_string(),
                std::sync::Arc::new(updated),
            );
            return Ok(true);
        }
        let mut g = self.lock();
        let present = g.clients.get(updated.client_id.as_str());
        if self.faults.client_swap_refuses_everything {
            return Ok(false);
        }
        let matches = match present {
            Some(current) => **current == *expected || self.faults.client_swap_ignores_expected,
            // The fault writes anyway. A correct store must not: absence is what `delete_client`
            // leaves, so an upsert here restores a deleted registration.
            None => self.faults.client_swap_upserts,
        };
        if !matches {
            // A loser that surfaces the conflict as an error rather than answering `Ok(false)`.
            if self.faults.swap_surfaces_contention_as_error {
                return Err(StorageError::new(
                    "write conflict: another writer got there first",
                ));
            }
            return Ok(false);
        }
        g.clients.insert(
            updated.client_id.as_str().to_string(),
            std::sync::Arc::new(updated),
        );
        Ok(true)
    }

    async fn delete_client(
        &self,
        client_id: &ClientId,
        window: oauth_as::store::RevocationWindow,
    ) -> Result<bool, StorageError> {
        self.reject_empty_scope("client_id", client_id.as_str())?;
        let mut g = self.lock();
        if !self.faults.revocation_records_no_barrier {
            g.record_barrier(
                oauth_as::store::RevocationBarrier::Client(client_id.clone()),
                window,
                self.faults.barrier_overwritten_by_the_later_write,
            );
        }
        let existed = g.clients.remove(client_id.as_str()).is_some();
        // Reported instead of `existed` by the fault: the answer is "the statement ran", not "a
        // registration went away".
        let reported = (existed || self.faults.delete_client_always_reports_true)
            && !self.faults.delete_client_always_reports_false;
        if self.faults.delete_client_leaves_credentials {
            return Ok(reported);
        }
        g.tokens.retain(|_, t| &t.client_id != client_id);
        g.refresh.retain(|_, r| &r.client_id != client_id);
        // "In either state", says the trait, and the fault is the predicate that forgets it: an
        // `Issued` code of the deleted registration is a live grant it can still redeem.
        g.codes
            .retain(|_, c| &c.client_id != client_id || !removable(self.faults, c));
        g.device_by_code.retain(|_, d| &d.client_id != client_id);
        g.user_code_index.retain(|_, d| &d.client_id != client_id);
        // RFC 9126 s2.2 binds a `request_uri` to the client that pushed it, so a deleted client's
        // outstanding handles are handles nobody may ever redeem.
        #[cfg(feature = "par")]
        g.pushed.retain(|_, p| &p.client_id != client_id);
        // A consent naming a registration that no longer exists is a standing approval a client
        // provisioned later under the same id would inherit.
        #[cfg(feature = "consent")]
        {
            g.consents.retain(|_, c| &c.client_id != client_id);
            g.consents_ever.retain(|_, c| &c.client_id != client_id);
        }
        Ok(reported)
    }

    async fn put_device_grant(&self, grant: DeviceGrant) -> Result<(), StorageError> {
        let grant = self.maybe_drop_device_grant_fields(grant);
        let mut g = self.lock();
        let normalized = normalize_user_code(&grant.user_code);
        // INSERT with no ON CONFLICT: a device_code already stored cannot be re-put, so the put
        // that re-codes a grant in place fails outright rather than moving its user-code index.
        if self.faults.put_device_grant_refuses_to_update
            && g.device_by_code.contains_key(&grant.device_code)
        {
            return Err(StorageError::new(
                "device_code already exists and this store cannot update it",
            ));
        }
        if self.faults.index_overwrites {
            g.user_code_index.insert(normalized, grant.clone());
            g.device_by_code.insert(grant.device_code.clone(), grant);
            return Ok(());
        }
        if let Some(owner) = g.user_code_index.get(&normalized) {
            if owner.device_code != grant.device_code {
                if self.faults.refusal_repoints_the_index {
                    // The write happened before the check did, which is the ordering a store gets
                    // by upserting first and validating afterwards. The error it returns is the
                    // right error; the row it leaves behind is not.
                    g.user_code_index.insert(normalized, grant.clone());
                    g.device_by_code.insert(grant.device_code.clone(), grant);
                }
                return Err(StorageError::new(
                    "user code belongs to another device_code",
                ));
            }
        }
        if let Some(previous) = g.device_by_code.get(&grant.device_code) {
            let previous_normalized = normalize_user_code(&previous.user_code);
            if previous_normalized != normalized {
                g.user_code_index.remove(&previous_normalized);
            }
        }
        g.user_code_index.insert(normalized, grant.clone());
        g.device_by_code.insert(grant.device_code.clone(), grant);
        Ok(())
    }

    async fn compare_and_swap_device_grant(
        &self,
        expected: &oauth_as::DeviceGrantState,
        updated: DeviceGrant,
    ) -> Result<bool, StorageError> {
        if self.faults.swaps_read_then_write {
            // Read, compare, suspend, THEN write. See `compare_and_swap_client` above.
            let matched = self
                .lock()
                .device_by_code
                .get(&updated.device_code)
                .map(|current| current.state == *expected)
                .unwrap_or(false);
            round_trip_to_the_store().await;
            if !matched {
                return Ok(false);
            }
            let mut g = self.lock();
            // Through the SAME index maintenance as the correct path below, so that this fault is
            // an atomicity defect and nothing else: a store can have the window without also
            // mismanaging the user-code index, and the two must stay separately observable.
            self.write_swapped_grant(&mut g, updated)?;
            return Ok(true);
        }
        // The round trip a shared store makes between the read and the write. Both faults below
        // are only reachable BECAUSE of it, which is the whole point of modelling it.
        if self.faults.swap_ignores_expected || self.faults.swap_resurrects_taken_grants {
            round_trip_to_the_store().await;
        }
        let mut g = self.lock();
        let present = g.device_by_code.contains_key(&updated.device_code);
        let matches = g
            .device_by_code
            .get(&updated.device_code)
            .map(|current| current.state == *expected)
            .unwrap_or(false);
        let write = if self.faults.swap_ignores_expected {
            present
        } else if self.faults.swap_resurrects_taken_grants {
            // Absent reads as "nothing contradicted me", which is exactly what a shim over an
            // insert-or-update does with a row that was redeemed while it was thinking.
            matches || !present
        } else {
            matches
        };
        if !write {
            return Ok(false);
        }
        self.write_swapped_grant(&mut g, updated)?;
        // The write above LANDED. This fault is only about what the caller is told about it.
        Ok(!self.faults.swap_reports_that_it_did_not_apply)
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
        let key = if self.faults.normalizes_user_codes {
            normalize_user_code(normalized_user_code)
        } else {
            normalized_user_code.to_string()
        };
        Ok(self.lock().user_code_index.get(&key).cloned())
    }

    async fn take_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        // The index row is a second write, and the fault is that the take does not make it.
        let clears_the_index = !self.faults.index_outlives_the_taken_grant;
        if self.faults.read_then_delete {
            let grant = self.lock().device_by_code.get(device_code).cloned();
            round_trip_to_the_store().await;
            if let Some(grant) = &grant {
                let mut g = self.lock();
                g.device_by_code.remove(device_code);
                if clears_the_index {
                    g.user_code_index
                        .remove(&normalize_user_code(&grant.user_code));
                }
            }
            return Ok(grant);
        }
        let mut g = self.lock();
        let grant = g.device_by_code.remove(device_code);
        if let Some(grant) = &grant {
            if clears_the_index {
                let normalized = normalize_user_code(&grant.user_code);
                g.user_code_index.remove(&normalized);
            }
        }
        Ok(grant)
    }

    async fn put_authorization_code(
        &self,
        record: AuthorizationCodeRecord,
    ) -> Result<(), StorageError> {
        let record = self.maybe_drop_code_fields(record);
        self.lock().codes.insert(record.code.clone(), record);
        Ok(())
    }

    async fn compare_and_swap_authorization_code(
        &self,
        expected: &oauth_as::authorization::AuthorizationCodeState,
        updated: AuthorizationCodeRecord,
    ) -> Result<bool, StorageError> {
        if self.faults.swaps_read_then_write {
            // Read, compare, suspend, THEN write. See `compare_and_swap_client` above.
            let matched = self
                .lock()
                .codes
                .get(&updated.code)
                .map(|current| current.state == *expected)
                .unwrap_or(false);
            round_trip_to_the_store().await;
            if !matched {
                return Ok(false);
            }
            self.lock().codes.insert(updated.code.clone(), updated);
            return Ok(true);
        }
        let mut g = self.lock();
        let present = g.codes.get(&updated.code);
        if self.faults.code_swap_refuses_everything {
            return Ok(false);
        }
        let matches = match present {
            Some(current) => current.state == *expected || self.faults.code_swap_ignores_expected,
            // The fault writes anyway, which is the upsert shape: a code that a cascade or a
            // sweep removed comes back, and with it the redemption a replay was meant to contain.
            None => self.faults.code_swap_upserts,
        };
        if !matches {
            return Ok(false);
        }
        g.codes.insert(updated.code.clone(), updated);
        Ok(true)
    }

    #[cfg(feature = "par")]
    #[allow(unused_mut)]
    async fn put_pushed_authorization_request(
        &self,
        mut record: oauth_as::par::PushedAuthorizationRequest,
    ) -> Result<oauth_as::store::WriteOutcome, StorageError> {
        if self.faults.drops_the_pushed_code_challenge {
            record.code_challenge = None;
        }
        // The PAR half of "refuses everything", which was missing while the fault was applied to
        // `put_token` and `put_refresh_token` alone: a store that answers `RefusedRevoked` to every
        // push passes the barrier's refusal check and closes the RFC 9126 endpoint for good, and
        // the check that must catch it is `spares_unrelated_records`.
        if self.faults.put_refuses_everything {
            return Ok(oauth_as::store::WriteOutcome::RefusedRevoked);
        }
        #[cfg(feature = "rar")]
        if self.faults.drops_authorization_details_on_pushed_requests {
            record.authorization_details = None;
        }
        let mut g = self.lock();
        let revoked = if self.faults.par_barrier_ignores_the_client_scope {
            g.is_revoked_by_any_client_barrier(record.pushed_at)
        } else {
            g.is_revoked(&record.client_id, None, None, record.pushed_at)
        };
        if !self.faults.put_ignores_barriers && revoked {
            return Ok(oauth_as::store::WriteOutcome::RefusedRevoked);
        }
        // INSERT-only: a second push under a handle already stored is dropped, so the
        // authorization endpoint reads whichever push landed first.
        if self.faults.put_pushed_insert_only && g.pushed.contains_key(&record.request_uri) {
            return Ok(oauth_as::store::WriteOutcome::Applied);
        }
        g.pushed.insert(record.request_uri.clone(), record);
        Ok(oauth_as::store::WriteOutcome::Applied)
    }

    /// Honours the same `read_then_delete` fault as the other takes: a `request_uri` is single use
    /// (RFC 9126 s4), so a store that reads then deletes double-spends it exactly as it would a
    /// refresh token, and the harness should be able to catch it here too.
    #[cfg(feature = "par")]
    async fn take_pushed_authorization_request(
        &self,
        request_uri: &str,
    ) -> Result<Option<oauth_as::par::PushedAuthorizationRequest>, StorageError> {
        if self.faults.read_then_delete {
            let record = self.lock().pushed.get(request_uri).cloned();
            round_trip_to_the_store().await;
            if record.is_some() {
                self.lock().pushed.remove(request_uri);
            }
            return Ok(record);
        }
        Ok(self.lock().pushed.remove(request_uri))
    }

    async fn take_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCodeRecord>, StorageError> {
        if self.faults.read_then_delete {
            let record = self.lock().codes.get(code).cloned();
            round_trip_to_the_store().await;
            if record.is_some() {
                self.lock().codes.remove(code);
            }
            return Ok(record);
        }
        Ok(self.lock().codes.remove(code))
    }

    async fn put_token(
        &self,
        token: IssuedToken,
    ) -> Result<oauth_as::store::WriteOutcome, StorageError> {
        let token = self.maybe_drop_token_fields(token);
        // A write made DURING the sweep race collides with the maintenance job and is surfaced as
        // an error. Keyed on the racer's own token names so the live records planted before the
        // race still write: only issuance overlapping the sweep fails.
        if self.faults.issuance_fails_beside_a_sweep
            && token.access_token.contains("sweep-race-written")
        {
            return Err(StorageError::new(
                "a maintenance sweep is running and this store surfaces the overlap as an error",
            ));
        }
        if self.faults.put_refuses_everything {
            return Ok(oauth_as::store::WriteOutcome::RefusedRevoked);
        }
        let mut g = self.lock();
        if !self.faults.put_ignores_barriers
            && g.is_revoked(
                &token.client_id,
                token.family_id.as_deref(),
                token.subject.as_deref(),
                token.grant_established_at,
            )
        {
            return Ok(oauth_as::store::WriteOutcome::RefusedRevoked);
        }
        g.tokens
            .insert(token.access_token.clone(), std::sync::Arc::new(token));
        Ok(oauth_as::store::WriteOutcome::Applied)
    }

    async fn get_token(
        &self,
        access_token: &str,
    ) -> Result<Option<std::sync::Arc<IssuedToken>>, StorageError> {
        if self.faults.reads_are_takes {
            return Ok(self.lock().tokens.remove(access_token));
        }
        Ok(self.lock().tokens.get(access_token).cloned())
    }

    async fn delete_token(&self, access_token: &str) -> Result<(), StorageError> {
        let removed = self.lock().tokens.remove(access_token);
        if self.faults.delete_token_errors_when_absent && removed.is_none() {
            return Err(StorageError::new("no such token"));
        }
        Ok(())
    }

    async fn put_refresh_token(
        &self,
        record: RefreshTokenRecord,
    ) -> Result<oauth_as::store::WriteOutcome, StorageError> {
        let record = self.maybe_drop_refresh_fields(record);
        if self.faults.put_refuses_everything {
            return Ok(oauth_as::store::WriteOutcome::RefusedRevoked);
        }
        let mut g = self.lock();
        if !self.faults.put_ignores_barriers
            && g.is_revoked(
                &record.client_id,
                Some(&record.family_id),
                record.subject.as_deref(),
                record.grant_established_at,
            )
        {
            return Ok(oauth_as::store::WriteOutcome::RefusedRevoked);
        }
        g.refresh
            .insert(record.refresh_token.clone(), std::sync::Arc::new(record));
        Ok(oauth_as::store::WriteOutcome::Applied)
    }

    async fn get_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<std::sync::Arc<RefreshTokenRecord>>, StorageError> {
        if self.faults.reads_are_takes {
            return Ok(self.lock().refresh.remove(refresh_token));
        }
        Ok(self.lock().refresh.get(refresh_token).cloned())
    }

    async fn take_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshTokenRecord>, StorageError> {
        // Every racer is already past the harness's rendezvous gate by the time it calls in, so
        // this panics with all N racers in flight, which is the situation the latch has to
        // survive: each of them has to release its count on the way out or the harness parks
        // forever waiting for tasks that are already dead.
        assert!(
            !self.faults.the_refresh_take_panics,
            "this store's take_refresh_token panics, which is what the fault is"
        );
        if self.faults.read_then_delete {
            let record = self.lock().refresh.get(refresh_token).cloned();
            round_trip_to_the_store().await;
            if record.is_some() {
                self.lock().refresh.remove(refresh_token);
            }
            return Ok(record.map(|a| (*a).clone()));
        }
        Ok(self
            .lock()
            .refresh
            .remove(refresh_token)
            .map(|a| std::sync::Arc::try_unwrap(a).unwrap_or_else(|a| (*a).clone())))
    }

    async fn revoke_token_family(
        &self,
        family_id: &str,
        window: oauth_as::store::RevocationWindow,
    ) -> Result<u64, StorageError> {
        self.reject_empty_scope("family_id", family_id)?;
        let mut g = self.lock();
        if !self.faults.revocation_records_no_barrier {
            g.record_barrier(
                oauth_as::store::RevocationBarrier::TokenFamily(family_id.into()),
                window,
                self.faults.barrier_overwritten_by_the_later_write,
            );
        }
        if self.faults.family_revocation_takes_every_family {
            let removed = (g.refresh.len() + g.tokens.len()) as u64;
            g.refresh.clear();
            g.tokens.clear();
            return Ok(removed);
        }
        let before = g.refresh.len();
        g.refresh.retain(|_, r| r.family_id != family_id);
        let mut removed = (before - g.refresh.len()) as u64;
        if !self.faults.family_revocation_spares_access_tokens {
            let before = g.tokens.len();
            g.tokens
                .retain(|_, t| t.family_id.as_deref() != Some(family_id));
            removed += (before - g.tokens.len()) as u64;
        }
        Ok(removed)
    }

    #[cfg(feature = "consent")]
    async fn put_consent(&self, mut record: oauth_as::ConsentRecord) -> Result<(), StorageError> {
        if self.faults.drops_the_authentication_on_consents {
            record.authentication = None;
        }
        let record = std::sync::Arc::new(record);
        let mut g = self.lock();
        // INSERT-only: a widen under a consent_id already stored is dropped, so the pair keeps the
        // first, narrower approval and every later authorization request is answered from it.
        if self.faults.put_consent_insert_only
            && g.consents.contains_key(record.consent_id.as_ref())
        {
            return Ok(());
        }
        g.consents.insert(
            record.consent_id.to_string(),
            std::sync::Arc::clone(&record),
        );
        // The second write a store with a per-subject index makes. Kept whatever the faults say,
        // so that `consents_for_subject_reads_a_stale_index` is about the write that is MISSING on
        // the way out rather than about this one.
        g.consents_ever
            .insert(record.consent_id.to_string(), record);
        Ok(())
    }

    #[cfg(feature = "consent")]
    async fn get_consent(
        &self,
        consent_id: &str,
    ) -> Result<Option<std::sync::Arc<oauth_as::ConsentRecord>>, StorageError> {
        Ok(self.lock().consents.get(consent_id).cloned())
    }

    #[cfg(feature = "consent")]
    async fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> Result<Option<std::sync::Arc<oauth_as::ConsentRecord>>, StorageError> {
        if self.faults.find_consent_never_finds {
            return Ok(None);
        }
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
    ) -> Result<Vec<std::sync::Arc<oauth_as::ConsentRecord>>, StorageError> {
        if self.faults.consents_for_subject_returns_nothing {
            return Ok(Vec::new());
        }
        let g = self.lock();
        if self.faults.consents_for_subject_filters_on_the_client {
            // The (client, subject) index read on its LEADING column only: find the client this
            // subject deals with, then answer with everything that client holds, whoever it
            // belongs to.
            let client = match g.consents.values().find(|c| c.subject.as_ref() == subject) {
                Some(c) => c.client_id.clone(),
                None => return Ok(Vec::new()),
            };
            return Ok(g
                .consents
                .values()
                .filter(|c| c.client_id == client)
                .cloned()
                .collect());
        }
        let source = if self.faults.consents_for_subject_reads_a_stale_index {
            &g.consents_ever
        } else {
            &g.consents
        };
        Ok(source
            .values()
            .filter(|c| c.subject.as_ref() == subject)
            .cloned()
            .collect())
    }

    #[cfg(feature = "consent")]
    async fn compare_and_swap_consent(
        &self,
        expected: Option<&oauth_as::ConsentRecord>,
        updated: oauth_as::ConsentRecord,
    ) -> Result<bool, StorageError> {
        if self.faults.swaps_read_then_write {
            // Read, compare, suspend, THEN write. See `compare_and_swap_client` above.
            let live = self
                .lock()
                .consents
                .values()
                .find(|c| c.client_id == updated.client_id && c.subject == updated.subject)
                .cloned();
            let matched = match (live.as_deref(), expected) {
                (Some(current), Some(expected)) => current == expected,
                (None, None) => true,
                _ => false,
            };
            round_trip_to_the_store().await;
            if !matched {
                return Ok(false);
            }
            let mut g = self.lock();
            g.consents.insert(
                updated.consent_id.to_string(),
                std::sync::Arc::new(updated.clone()),
            );
            g.consents_ever
                .insert(updated.consent_id.to_string(), std::sync::Arc::new(updated));
            return Ok(true);
        }
        let mut g = self.lock();
        let live = g
            .consents
            .values()
            .find(|c| c.client_id == updated.client_id && c.subject == updated.subject)
            .cloned();
        if self.faults.consent_swap_refuses_everything {
            return Ok(false);
        }
        match (live.as_deref(), expected) {
            (Some(current), Some(expected)) if current == expected => {}
            (Some(_), _) if self.faults.consent_swap_ignores_expected => {}
            (None, None) => {}
            // The fault writes anyway, and ONLY where the pair holds nothing: a widen whose
            // `expected` names a consent that has been withdrawn is performed rather than refused,
            // so the record the user destroyed is back.
            //
            // Scoped to `(None, _)` deliberately. Written as a bare `_` it also swallowed the
            // (present, mismatched) case, which is `consent_swap_ignores_expected`'s job, and the
            // two faults then produced byte-identical violation sets: the field doc above claims
            // "a store can have either without the other", and until the exact-set tests below
            // were written nothing had ever checked that claim on the consent swap. The client and
            // code swaps were always scoped this way (`None => self.faults.*_swap_upserts`); only
            // this one was not.
            (None, _) if self.faults.consent_swap_upserts => {}
            _ => return Ok(false),
        }
        // The comparison said apply, and the store reports that it did — and writes nothing. A
        // widen (`expected` names a live record) whose UPDATE matched no rows, counted as success.
        if self.faults.consent_swap_widen_is_lost && expected.is_some() {
            return Ok(true);
        }
        g.consents.insert(
            updated.consent_id.to_string(),
            std::sync::Arc::new(updated.clone()),
        );
        g.consents_ever
            .insert(updated.consent_id.to_string(), std::sync::Arc::new(updated));
        Ok(true)
    }

    #[cfg(feature = "consent")]
    async fn revoke_consent(
        &self,
        consent_id: &str,
        window: oauth_as::store::RevocationWindow,
    ) -> Result<u64, StorageError> {
        let mut g = self.lock();
        // PEEKED, so the scope check runs before anything is mutated: a refusal must leave the
        // consent standing rather than withdraw it and then decline to record the barrier the
        // withdrawal depends on.
        let Some(peek) = g.consents.get(consent_id) else {
            return Ok(0);
        };
        self.reject_empty_scope("client_id", peek.client_id.as_str())?;
        self.reject_empty_scope("subject", peek.subject.as_ref())?;
        let consent = g
            .consents
            .remove(consent_id)
            .expect("the peek above holds the same guard");
        if !self.faults.revocation_records_no_barrier {
            g.record_barrier(
                oauth_as::store::RevocationBarrier::Consent {
                    client_id: consent.client_id.clone(),
                    subject: consent.subject.as_ref().into(),
                },
                window,
                self.faults.barrier_overwritten_by_the_later_write,
            );
        }
        // The other half of the two writes `put_consent` made. Skipping it is the whole of
        // `consents_for_subject_reads_a_stale_index`: the primary row is gone, so every other
        // consent check still passes, and only the per-subject listing can see the difference.
        if !self.faults.consents_for_subject_reads_a_stale_index {
            g.consents_ever.remove(consent_id);
        }
        if self.faults.withdrawal_leaves_credentials {
            // The row is gone and a plausible count is returned, so the endpoint answers 200 and
            // the audit log records a withdrawal. Everything it was meant to revoke still works.
            return Ok(5);
        }
        if self.faults.withdrawal_takes_other_subjects {
            let client_id = consent.client_id.clone();
            let before = g.tokens.len() + g.refresh.len() + g.codes.len() + g.device_by_code.len();
            g.tokens.retain(|_, t| t.client_id != client_id);
            g.refresh.retain(|_, r| r.client_id != client_id);
            g.codes.retain(|_, c| c.client_id != client_id);
            g.device_by_code.retain(|_, d| d.client_id != client_id);
            let after = g.tokens.len() + g.refresh.len() + g.codes.len() + g.device_by_code.len();
            return Ok((before - after) as u64 + 1);
        }
        let client_id = consent.client_id.clone();
        let subject: String = consent.subject.to_string();
        let before = g.tokens.len() + g.refresh.len() + g.codes.len() + g.device_by_code.len();
        g.tokens
            .retain(|_, t| !(t.client_id == client_id && t.subject.as_deref() == Some(&*subject)));
        g.refresh
            .retain(|_, r| !(r.client_id == client_id && r.subject.as_deref() == Some(&*subject)));
        g.codes
            .retain(|_, c| !(c.client_id == client_id && c.subject == subject));
        // APPROVED device grants for that subject, and their index entries. A grant the user has
        // approved but the device has not polled yet mints a token seconds after the user said
        // stop, so leaving it is the withdrawal failing in the window that matters most. PENDING
        // grants stay: nobody consented to those, so there is nothing there to withdraw.
        //
        // This arm was missing until the harness grew a check for it, which is the whole argument
        // for the check existing.
        let doomed: Vec<String> = g
            .device_by_code
            .iter()
            .filter(|(_, d)| {
                d.client_id == client_id
                    && matches!(
                        &d.state,
                        oauth_as::DeviceGrantState::Approved { subject: s } if *s == subject
                    )
            })
            .map(|(k, _)| k.clone())
            .collect();
        for device_code in doomed {
            if let Some(grant) = g.device_by_code.remove(&device_code) {
                let normalized = oauth_as::device::normalize_user_code(&grant.user_code);
                g.user_code_index.remove(&normalized);
            }
        }
        let after = g.tokens.len() + g.refresh.len() + g.codes.len() + g.device_by_code.len();
        // The consent row was removed at the top of this method, and counting it here is the whole
        // fault: everything else about this withdrawal is right.
        let counts_the_row = u64::from(self.faults.withdrawal_counts_the_consent_row);
        Ok((before - after) as u64 + counts_the_row)
    }

    #[cfg(any(feature = "client-assertion", feature = "dpop"))]
    async fn claim_replay_id(
        &self,
        id: &str,
        expires_at: SystemTime,
    ) -> Result<bool, StorageError> {
        if self.faults.look_then_insert_claim {
            let seen = self.lock().replay_ids.contains_key(id);
            round_trip_to_the_store().await;
            if seen {
                return Ok(false);
            }
            self.lock().replay_ids.insert(id.to_string(), expires_at);
            return Ok(true);
        }
        if self.faults.claim_forgets_what_it_claimed {
            // Atomic and amnesiac. The decision is taken under one lock with no suspension point in
            // it, so exactly one of a set of concurrent callers is told it claimed the id; the row
            // then lives only until this call returns, which is what a zero TTL or an advisory lock
            // held for the transaction actually gives you. It relies on the same scheduling
            // `look_then_insert_claim` above relies on: the racers reach their decision before the
            // first one resumes past the yield.
            let first = self.lock().replay_claims_in_flight.insert(id.to_string());
            round_trip_to_the_store().await;
            self.lock().replay_claims_in_flight.remove(id);
            return Ok(first);
        }
        if self.faults.claim_is_keyed_on_nothing {
            // One slot for every id there will ever be. Atomic, and useless: the first jti this
            // process sees is claimed and every later one collides with it.
            let mut g = self.lock();
            if !g.replay_ids.is_empty() {
                return Ok(false);
            }
            g.replay_ids.insert(id.to_string(), expires_at);
            return Ok(true);
        }
        let mut g = self.lock();
        if g.replay_ids.contains_key(id) {
            return Ok(false);
        }
        g.replay_ids.insert(id.to_string(), expires_at);
        Ok(true)
    }

    async fn sweep_expired(&self, now: SystemTime) -> Result<u64, StorageError> {
        if self.faults.sweep_removes_nothing {
            return Ok(0);
        }
        // SCOPED, so that no `MutexGuard` is live across the suspension point at the end of this
        // method: `Storage::sweep_expired` returns a `Send` future, and `std::sync::MutexGuard` is
        // not `Send`. Everything in here is synchronous.
        let removed = {
            let mut g = self.lock();
            #[cfg(any(feature = "client-assertion", feature = "dpop"))]
            let claimed = g.replay_ids.len();
            #[cfg(not(any(feature = "client-assertion", feature = "dpop")))]
            let claimed = 0usize;
            #[cfg(feature = "par")]
            let pushed = g.pushed.len();
            #[cfg(not(feature = "par"))]
            let pushed = 0usize;
            if self.faults.sweep_removes_everything {
                let removed = (g.device_by_code.len()
                    + g.codes.len()
                    + g.tokens.len()
                    + g.refresh.len()
                    + claimed
                    + pushed) as u64;
                g.device_by_code.clear();
                g.user_code_index.clear();
                g.codes.clear();
                g.tokens.clear();
                g.refresh.clear();
                #[cfg(any(feature = "client-assertion", feature = "dpop"))]
                g.replay_ids.clear();
                // Reaped along with everything else, or this fault would ALSO be a sweep that forgets
                // the PAR table, and the test below could not tell "removes too much" from "misses a
                // kind": two different defects that must stay distinguishable.
                #[cfg(feature = "par")]
                g.pushed.clear();
                return Ok(removed);
            }
            let mut removed = 0u64;
            let before = g.device_by_code.len();
            g.device_by_code.retain(|_, grant| now < grant.expires_at);
            removed += (before - g.device_by_code.len()) as u64;
            // The index rows expire with the grants they carry: one row per grant, so the same
            // predicate, and the count is taken from the primary table only.
            g.user_code_index.retain(|_, grant| now < grant.expires_at);

            let before = g.codes.len();
            g.codes
                .retain(|_, c| now < c.expires_at || !removable(self.faults, c));
            removed += (before - g.codes.len()) as u64;

            let before = g.tokens.len();
            g.tokens.retain(|_, t| now < t.expires_at);
            removed += (before - g.tokens.len()) as u64;

            let before = g.refresh.len();
            g.refresh.retain(|_, r| match r.expires_at {
                Some(exp) => now < exp,
                None => true,
            });
            removed += (before - g.refresh.len()) as u64;

            // RFC 9126 s4: an expired request_uri is refused, and once it is expired there is nothing
            // left to recognise it for. Nothing but this sweep ever removes one, which is why the
            // fault below is a table that grows forever rather than a tidiness problem.
            #[cfg(feature = "par")]
            if !self.faults.sweep_forgets_pushed_requests {
                g.pushed.retain(|_, p| now < p.expires_at);
                removed += (pushed - g.pushed.len()) as u64;
            }

            // Claimed replay ids are records like any other: the only thing that reclaims them is this
            // sweep, and there is one per authenticated request.
            #[cfg(any(feature = "client-assertion", feature = "dpop"))]
            if !self.faults.sweep_forgets_replay_ids {
                g.replay_ids.retain(|_, exp| now < *exp);
                removed += (claimed - g.replay_ids.len()) as u64;
            }
            // Revocation barriers. Nothing but this sweep removes one and a deployment records one per
            // logout, so a store that misses them grows forever; reaping one EARLY is the opposite
            // defect and the more dangerous of the two, because it silently reopens the window the
            // barrier was recorded to close.
            if !self.faults.sweep_forgets_barriers {
                let barriers_before = g.barriers.len();
                let cutoff = if self.faults.sweep_reaps_barriers_early {
                    now + std::time::Duration::from_secs(3600)
                } else {
                    now
                };
                g.barriers.retain(|_, window| cutoff < window.until);
                removed += (barriers_before - g.barriers.len()) as u64;
            }
            if removed == 0 && self.faults.sweep_errors_when_it_removed_nothing {
                return Err(StorageError::new("no rows affected"));
            }
            removed
        };
        // THE LOST UPDATE, and it is deliberately the last thing this sweep does: the reaping above
        // has already run correctly, so in a quiescent store the snapshot equals the table and this
        // is indistinguishable from a correct sweep. Only a caller writing DURING the suspension
        // point below can see it, which is exactly the property
        // `sweep_expired/safe_under_concurrent_writes` exists to check.
        if self.faults.sweep_rebuilds_the_token_table_from_a_snapshot {
            let snapshot = self.lock().tokens.clone();
            round_trip_to_the_store().await;
            self.lock().tokens = snapshot;
        }
        Ok(removed)
    }
}

// ---------------------------------------------------------------------- helpers

/// The distinct check names in a report, sorted, so a test can assert on the SET of checks that
/// fired rather than on a count of violations that would move whenever a message is reworded.
fn checks_that_fired(violations: &[Violation]) -> Vec<&'static str> {
    let mut names: Vec<&'static str> = violations.iter().map(|v| v.check).collect();
    names.sort_unstable();
    names.dedup();
    names
}

fn detail_of(violations: &[Violation], check: &str) -> String {
    violations
        .iter()
        .filter(|v| v.check == check)
        .map(|v| v.detail.as_str())
        .collect::<Vec<_>>()
        .join(" | ")
}

async fn run_against(faults: Faults) -> Vec<Violation> {
    StorageConformance::new(move || async move { NaiveStore::new(faults) })
        .run()
        .await
}

// ---------------------------------------------------------------------- GREEN: correct stores

#[tokio::test]
async fn the_reference_store_passes_every_check() {
    let violations = StorageConformance::new(|| async { MemoryStorage::new() })
        .run()
        .await;
    assert!(
        violations.is_empty(),
        "MemoryStorage is the reference implementation of the contract and must pass: {violations:#?}"
    );
}

/// The same, driven through the host's runtime as independent tasks, which is the mode a host is
/// told to use. On this crate's own single-threaded dev runtime that is still interleaving rather
/// than parallelism (see the module docs); it is run anyway because the spawned path has its own
/// collection and completion machinery, and an untested path is not a path.
#[tokio::test]
async fn the_reference_store_passes_with_the_racers_on_the_runtime() {
    let violations = StorageConformance::new(|| async { MemoryStorage::new() })
        .with_spawn(|task| {
            tokio::spawn(task);
        })
        .racers(16)
        .run()
        .await;
    assert!(violations.is_empty(), "{violations:#?}");
}

/// A SECOND correct implementation, written independently of `MemoryStorage` in this file. If the
/// checks had quietly become a description of `MemoryStorage`'s incidental behaviour rather than
/// of the documented contract, this is where that would show.
#[tokio::test]
async fn a_second_correct_store_passes_every_check() {
    let violations = run_against(Faults::default()).await;
    assert!(violations.is_empty(), "{violations:#?}");
}

// ---------------------------------------------------------------------- RED: one fault at a time

/// THE headline defect. Read-then-delete compiles, type-checks, and passes any single-node test
/// suite; on two nodes it is refresh token double spend, authorization code replay detection
/// silently disabled, and device grant double issuance. The harness must catch all three.
#[tokio::test]
async fn read_then_delete_takes_are_caught_on_all_three_single_use_records() {
    let violations = run_against(Faults {
        read_then_delete: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "atomic_take/take_authorization_code",
            "atomic_take/take_device_grant",
            #[cfg(feature = "par")]
            "atomic_take/take_pushed_authorization_request",
            "atomic_take/take_refresh_token",
        ],
        "a read-then-delete store must fail exactly the atomicity checks and nothing else: \
         {violations:#?}"
    );
    for check in checks_that_fired(&violations) {
        let detail = detail_of(&violations, check);
        assert!(
            detail.contains("concurrent takes each received"),
            "{check} must report the double spend it found, got: {detail}"
        );
    }
}

/// The same defect, with the racers handed to the runtime rather than polled together, so both
/// modes of the harness are proven able to see it.
#[tokio::test]
async fn read_then_delete_is_caught_with_the_racers_on_the_runtime_too() {
    let violations = StorageConformance::new(|| async {
        NaiveStore::new(Faults {
            read_then_delete: true,
            ..Faults::default()
        })
    })
    .with_spawn(|task| {
        tokio::spawn(task);
    })
    .run()
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "atomic_take/take_authorization_code",
            "atomic_take/take_device_grant",
            #[cfg(feature = "par")]
            "atomic_take/take_pushed_authorization_request",
            "atomic_take/take_refresh_token",
        ],
        "{violations:#?}"
    );
}

/// A swap that ignores `expected` is the whole of the first-decision-wins guarantee gone. It is
/// atomic, so no `take_*` check can see it; only a check that asserts the COMPARISON happened can.
///
/// The race check necessarily goes with it and is asserted by name: a store that never compares
/// tells every one of the eight racers that its write applied, which is a true statement about
/// this store and is not the one this test exists for. The two are still told apart, and the
/// distinction is real — a store can compare in a SEPARATE step (`swaps_read_then_write`) and
/// fail only the race, or not compare at all and fail both.
#[tokio::test]
async fn a_swap_that_ignores_the_expected_state_is_caught() {
    let violations = run_against(Faults {
        swap_ignores_expected: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "compare_and_swap_device_grant/atomic_under_a_race",
            "compare_and_swap_device_grant/honours_expected",
        ],
        "{violations:#?}"
    );
    assert!(
        detail_of(
            &violations,
            "compare_and_swap_device_grant/honours_expected"
        )
        .contains("expected"),
        "the violation must name the parameter that was ignored"
    );
}

/// THE one nobody would think to test for. A shim over an insert-or-update reinstates a grant that
/// was redeemed while it was thinking, so an RFC 8628 single-use device code is redeemable twice.
#[tokio::test]
async fn a_swap_that_resurrects_a_redeemed_grant_is_caught() {
    let violations = run_against(Faults {
        swap_resurrects_taken_grants: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["compare_and_swap_device_grant/never_resurrects"],
        "{violations:#?}"
    );
    assert!(
        detail_of(
            &violations,
            "compare_and_swap_device_grant/never_resurrects"
        )
        .contains("redeemed"),
        "the violation must say the grant came back from the dead, not merely that a bool differed"
    );
}

/// THE SWAP'S half of the user-code index contract, which the trait restates in capitals because
/// it has already drifted once: the reference implementation's doc said the swap delegated to
/// `put_device_grant`, it duplicated it instead, and the duplicate was missing the refusal.
///
/// Neither of these could fire before round 7. Every swap the harness made rebuilt `updated` as
/// `DeviceGrant { state, ..pending }`, so the user code was byte for byte the one already indexed
/// and no swap ever changed it or clashed with another grant's.
#[tokio::test]
async fn a_swap_that_leaves_the_superseded_user_code_indexed_is_caught() {
    let violations = run_against(Faults {
        swap_leaves_the_old_user_code_indexed: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["compare_and_swap_device_grant/retires_the_old_user_code"],
        "{violations:#?}"
    );
    assert!(
        detail_of(
            &violations,
            "compare_and_swap_device_grant/retires_the_old_user_code"
        )
        .contains("OLD user code still resolves"),
        "the violation must say the superseded code still reaches the grant"
    );
}

/// The other half, and the dangerous one: one RFC 8628 section 6.1 user code — the credential a
/// human types — live for two grants at once, because the swap repointed the index where the put
/// would have refused.
#[tokio::test]
async fn a_swap_that_repoints_another_grants_user_code_is_caught() {
    let violations = run_against(Faults {
        swap_repoints_a_duplicate_user_code: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["compare_and_swap_device_grant/refuses_a_duplicate_user_code"],
        "{violations:#?}"
    );
    let detail = detail_of(
        &violations,
        "compare_and_swap_device_grant/refuses_a_duplicate_user_code",
    );
    assert!(
        detail.contains("did not fail") && detail.contains("StorageError"),
        "the violation must say a refusal was owed and what shape it takes, got: {detail}"
    );
    // The refusal was owed AND the damage the repoint did has to be named, or a store that only
    // ever answered `is_ok()` would satisfy the line above while the index it corrupted goes
    // unreported. The repointed code now resolves to the wrong device_code...
    assert!(
        detail.contains("not to the grant that owned it"),
        "the violation must say the clashing code was repointed away from its owner, got: {detail}"
    );
    // ...the swapping grant was rewritten with a user code that belonged to another device...
    assert!(
        detail.contains("was rewritten even though its new user code belonged"),
        "the violation must say the swapping grant took a code that was not free, got: {detail}"
    );
    // ...and "a refusal must leave the store exactly as it was" reaches the state the swap named,
    // which the repoint carried where a refusal must still read the stored `Pending`.
    assert!(
        detail.contains("state of the grant a refused swap targeted"),
        "the violation must say a refused swap left the grant's state unchanged, got: {detail}"
    );
}

/// An INSERT-only `put_client`. Every round-trip check that writes a key once passed it; only the
/// one that writes a DIFFERENT registration under the same id first and requires the second to win
/// can see it. The violation has to NAME the field the store kept from the first write, or a store
/// that dropped every replacement would be reported as one that dropped a specific column.
#[tokio::test]
async fn an_insert_only_put_client_is_caught() {
    let violations = run_against(Faults {
        put_client_insert_only: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/client"],
        "an insert-only put_client must fail only the client round trip: {violations:#?}"
    );
    let detail = detail_of(&violations, "round_trip/client");
    // The two fields `round_trip/client` deliberately differs between the superseded record and
    // the one that must replace it. Both must be named, or a mutation that stopped the harness
    // varying one of them would go unseen.
    assert!(
        detail.contains("field name did not survive"),
        "the kept `name` must be named: {detail}"
    );
    assert!(
        detail.contains("field allowed_scopes did not survive"),
        "the kept `allowed_scopes` must be named: {detail}"
    );
}

/// The same INSERT-only defect on `put_pushed_authorization_request`: the authorization endpoint
/// is answered from whichever push landed first. Only the PAR round trip, which pushes a different
/// record under the handle first, can see it, and it names the field that did not survive.
#[cfg(feature = "par")]
#[tokio::test]
async fn an_insert_only_put_pushed_request_is_caught() {
    let violations = run_against(Faults {
        put_pushed_insert_only: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/pushed_authorization_request"],
        "an insert-only put_pushed_authorization_request must fail only the PAR round trip: \
         {violations:#?}"
    );
    assert!(
        detail_of(&violations, "round_trip/pushed_authorization_request")
            .contains("field state did not survive"),
        "the kept `state` must be named: {:#?}",
        violations
    );
}

/// The same INSERT-only defect on `put_consent`: a widen in place keeps the narrower approval the
/// user gave first. The consent round trip writes a different record under the id first, and the
/// two fields it varies — `scope`, the thing an authorization request is answered against, and
/// `resource`, the RFC 8707 audience — must each be named when the replacement is lost.
#[cfg(feature = "consent")]
#[tokio::test]
async fn an_insert_only_put_consent_is_caught() {
    let violations = run_against(Faults {
        put_consent_insert_only: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/consent"],
        "an insert-only put_consent must fail only the consent round trip: {violations:#?}"
    );
    let detail = detail_of(&violations, "round_trip/consent");
    assert!(
        detail.contains("field scope did not survive"),
        "the kept `scope` must be named: {detail}"
    );
    assert!(
        detail.contains("field resource did not survive"),
        "the kept `resource` must be named: {detail}"
    );
}

/// A `put_device_grant` that cannot UPDATE an existing `device_code`: the re-coding put fails. The
/// user-code index check must NOT then mistake the failed write for an index defect. Its guard
/// runs the index assertions only when BOTH puts landed, so with the second put failing the check
/// reports the failed write and nothing else — a store that ran the index assertions anyway would
/// blame the index for a code that was never rewritten.
#[tokio::test]
async fn a_put_device_grant_that_cannot_update_is_caught() {
    let violations = run_against(Faults {
        put_device_grant_refuses_to_update: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["user_code_index/retires_old_entry"],
        "a put that cannot update must be reported as a failed put, not an index defect: \
         {violations:#?}"
    );
    let detail = detail_of(&violations, "user_code_index/retires_old_entry");
    assert!(
        detail.contains("failed unexpectedly"),
        "the failed re-put must be reported as such: {detail}"
    );
    // The index assertions must NOT have run against a store whose re-coding put never landed: a
    // code that was never rewritten cannot have failed to be retired or to resolve.
    assert!(
        !detail.contains("does not resolve") && !detail.contains("still resolves"),
        "the index must not be judged when the put that would have moved it failed: {detail}"
    );
}

/// A `compare_and_swap_consent` that reports a widen applied and writes nothing. The boolean says
/// yes and the record never grew, so the ONE swap check that reads the record back after a widen
/// rather than trusting the return value is the only thing that can see it.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_consent_widen_that_reports_success_but_writes_nothing_is_caught() {
    let violations = run_against(Faults {
        consent_swap_widen_is_lost: true,
        ..Faults::default()
    })
    .await;

    assert!(
        checks_that_fired(&violations)
            .contains(&"compare_and_swap_consent/applies_when_it_matches"),
        "a widen that reports success and writes nothing must be caught by the read-back: \
         {violations:#?}"
    );
    assert!(
        detail_of(
            &violations,
            "compare_and_swap_consent/applies_when_it_matches"
        )
        .contains("did not change the stored record"),
        "the violation must say the widen the store reported did not land: {violations:#?}"
    );
}

/// A store whose `compare_and_swap_*` answers `Err` instead of `Ok(false)` when it loses its
/// comparison. `Ok(false)` already tells a caller "somebody got there first", so surfacing the
/// overlap as a `StorageError` fails a legitimate request; the trait makes contention the store's
/// to resolve. Only the RACED swap check produces a loser at all, so only it can see this.
#[tokio::test]
async fn a_swap_that_surfaces_contention_as_an_error_is_caught() {
    let violations = run_against(Faults {
        swap_surfaces_contention_as_error: true,
        ..Faults::default()
    })
    .await;

    assert!(
        detail_of(&violations, "compare_and_swap_client/atomic_under_a_race")
            .contains("failed with a StorageError"),
        "the raced swap must report the losers that errored rather than answering Ok(false): \
         {violations:#?}"
    );
}

/// A store whose `put_token` surfaces a `StorageError` when it overlaps a sweep. An issuance may
/// not fail because a maintenance job is running beside it. Only the concurrent-writes check makes
/// a write during a sweep at all, so only it can see it — and it counts the errored racers.
#[tokio::test]
async fn an_issuance_that_fails_beside_a_sweep_is_caught() {
    let violations = run_against(Faults {
        issuance_fails_beside_a_sweep: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["sweep_expired/safe_under_concurrent_writes"],
        "an issuance that errors beside a sweep must fail only the concurrent-writes check: \
         {violations:#?}"
    );
    assert!(
        detail_of(&violations, "sweep_expired/safe_under_concurrent_writes")
            .contains("failed with a StorageError"),
        "the violation must count the issuances the sweep made fail: {violations:#?}"
    );
}

/// A store whose READS are takes. `Storage::get_refresh_token` exists precisely so that a check
/// ABOUT a credential never has to be a read-modify-write ON it, and until round 7 nothing here
/// could tell the difference: every `get_*` call in the harness read a distinct key exactly once.
#[tokio::test]
async fn a_store_whose_reads_destroy_what_they_return_is_caught() {
    let violations = run_against(Faults {
        reads_are_takes: true,
        ..Faults::default()
    })
    .await;

    assert!(
        checks_that_fired(&violations).contains(&"round_trip/token")
            && checks_that_fired(&violations).contains(&"round_trip/refresh_token"),
        "the two round trips are where a destructive read is observable, because they are the only \
         places one key is read twice: {violations:#?}"
    );
    for check in ["round_trip/token", "round_trip/refresh_token"] {
        let detail = detail_of(&violations, check);
        assert!(
            detail.contains("DESTRUCTIVE"),
            "{check} must name the defect rather than report a missing record, got: {detail}"
        );
    }
}

/// A store that never persisted the instant the grant behind a record was authorized. It is the
/// sole time input to every `client` and `consent` barrier comparison, so the three round trips
/// are joined by the barrier check that rests on it.
#[tokio::test]
async fn a_store_that_loses_the_grant_instant_is_caught() {
    let violations = run_against(Faults {
        drops_the_grant_instant: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "revocation_barrier/admits_a_later_grant",
            "round_trip/authorization_code",
            "round_trip/refresh_token",
            "round_trip/token",
        ],
        "{violations:#?}"
    );
    for (check, field) in [
        ("round_trip/token", "grant_established_at"),
        ("round_trip/refresh_token", "grant_established_at"),
        ("round_trip/authorization_code", "issued_at"),
    ] {
        let detail = detail_of(&violations, check);
        assert!(
            detail.contains(field),
            "{check} must name the column that was lost, got: {detail}"
        );
    }
}

/// A PAR barrier that compares the record's instant and forgets whose record it is. Every PAR
/// write this harness made while a barrier stood used the barrier's OWN `client_id` until round 7,
/// so this store refused exactly what `refuses_put_pushed_authorization_request` asked it to and
/// certified clean, while in a deployment one client deletion closes the RFC 9126 push endpoint for
/// everybody until the barrier is swept.
#[cfg(feature = "par")]
#[tokio::test]
async fn a_par_barrier_that_ignores_the_client_it_names_is_caught() {
    let violations = run_against(Faults {
        par_barrier_ignores_the_client_scope: true,
        ..Faults::default()
    })
    .await;

    // It trips `admits_a_later_grant` as well: dropping the `client_id` conjunct also drops the
    // "client no longer exists" arm the correct predicate refuses a deleted-and-gone push on, so
    // the same broken check that spares nothing also admits the request pushed after a deletion.
    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "revocation_barrier/admits_a_later_grant",
            "revocation_barrier/spares_unrelated_records",
        ],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "revocation_barrier/spares_unrelated_records")
            .contains("put_pushed_authorization_request"),
        "the violation must name the write that was wrongly refused, not one of the token writes"
    );
}

/// A bulk removal that takes only the CONSUMED codes. Both `delete_client` and `sweep_expired` say
/// "in either state", and every authorization code this harness planted was `Consumed`, so the
/// predicate a host writes while thinking about replay evidence rather than about outstanding
/// grants was certified clean: the abandoned authorization request every user who closes a tab
/// leaves behind is never reclaimed, and a deleted registration keeps a live, redeemable code.
#[tokio::test]
async fn a_code_removal_that_filters_on_the_codes_state_is_caught() {
    let violations = run_against(Faults {
        code_removal_filters_on_state: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "delete_client/cascades",
            "sweep_expired/count",
            "sweep_expired/removes_dead",
        ],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "delete_client/cascades").contains("UNREDEEMED"),
        "the cascade violation must name the state that survived"
    );
}

#[tokio::test]
async fn a_user_code_index_that_overwrites_is_caught_on_both_halves() {
    let violations = run_against(Faults {
        index_overwrites: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "user_code_index/refusal_writes_nothing",
            "user_code_index/refuses_duplicate",
            "user_code_index/retires_old_entry",
        ],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "user_code_index/retires_old_entry").contains("OLD user code"),
        "the superseded-code half must be named for what it is"
    );
}

#[tokio::test]
async fn a_store_that_normalizes_user_codes_for_the_caller_is_caught() {
    let violations = run_against(Faults {
        normalizes_user_codes: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["user_code_index/store_does_not_normalize"],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "user_code_index/store_does_not_normalize");
    assert!(detail.contains("WDJB-MJHT"), "{detail}");
    assert!(detail.contains("wdjbmjht"), "{detail}");
}

#[tokio::test]
async fn a_sweep_that_removes_live_records_is_caught() {
    let violations = run_against(Faults {
        sweep_removes_everything: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            // A broken sweep fails TWO different claims, and they are not the same bug wearing two
            // names: one is about the records it was asked to reclaim, this one is about the
            // revocation barrier table, which nothing else ever removes a row from. A host that
            // fixed only the first would still grow that table for the life of the deployment.
            "revocation_barrier/swept_at_its_deadline",
            "sweep_expired/count",
            "sweep_expired/keeps_live",
            // THE THIRD claim, and it is a consequence rather than a coincidence: a sweep that
            // reaps everything necessarily reaps the tokens being written beside it. The dedicated
            // fault for this check is `sweep_rebuilds_the_token_table_from_a_snapshot`, which is
            // the store that fails ONLY here; this entry is the overlap, and it is listed so that a
            // reader can see the two checks are about the same records from different directions.
            "sweep_expired/safe_under_concurrent_writes"
        ],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "sweep_expired/keeps_live");
    // Every kind that was alive must be named, not just the first one noticed.
    assert!(detail.contains("device grant"), "{detail}");
    assert!(detail.contains("access token"), "{detail}");
    assert!(detail.contains("refresh record"), "{detail}");
    assert!(detail.contains("authorization code"), "{detail}");
    #[cfg(feature = "par")]
    assert!(detail.contains("pushed authorization request"), "{detail}");
    assert!(
        detail.contains("expires_at is None"),
        "a chain with no absolute lifetime is not dead, and the harness must say so: {detail}"
    );
}

#[tokio::test]
async fn a_family_revocation_that_spares_access_tokens_is_caught() {
    let violations = run_against(Faults {
        family_revocation_spares_access_tokens: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "revoke_token_family/count",
            "revoke_token_family/removes_the_family",
        ],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "revoke_token_family/removes_the_family").contains("4.14.2"),
        "the violation must cite what the remedy is for"
    );
}

#[tokio::test]
async fn a_delete_client_that_leaves_credentials_behind_is_caught() {
    let violations = run_against(Faults {
        delete_client_leaves_credentials: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["delete_client/cascades"],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "delete_client/cascades");
    for expected in [
        "access token",
        "refresh chain",
        "authorization code",
        "device grant",
        "user-code index",
    ] {
        assert!(
            detail.contains(expected),
            "the cascade violation must name the {expected} it found: {detail}"
        );
    }
}

#[tokio::test]
async fn a_delete_token_that_is_not_idempotent_is_caught() {
    let violations = run_against(Faults {
        delete_token_errors_when_absent: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["delete_token/idempotent"],
        "{violations:#?}"
    );
}

/// A dropped column is the quiet one: everything works, right up until a refresh token is stolen
/// and the RFC 9700 section 4.14.2 remedy has nothing to walk. The harness must catch it at the
/// round trip, and the family revocation failing alongside is the consequence made visible.
#[tokio::test]
async fn a_store_that_silently_drops_family_id_is_caught() {
    let violations = run_against(Faults {
        drops_family_id: true,
        ..Faults::default()
    })
    .await;

    let fired = checks_that_fired(&violations);
    assert!(
        fired.contains(&"round_trip/refresh_token"),
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "round_trip/refresh_token");
    assert!(
        detail.contains("family_id") && detail.contains("did not survive the round trip"),
        "the violation must name the field that was dropped: {detail}"
    );
    assert!(
        fired.contains(&"revoke_token_family/removes_the_family"),
        "dropping family_id disables reuse revocation, and the harness sees that too: {fired:?}"
    );
}

/// A dropped DPoP binding is the same quiet class of defect as a dropped `family_id`: every
/// request works, and the sender-constrained token the deployment paid for is a bearer token
/// again. RFC 9449 s6 puts the thumbprint in the token's confirmation claim, so losing it at rest
/// is losing the binding for every resource server that introspects.
#[cfg(feature = "dpop")]
#[tokio::test]
async fn a_store_that_silently_drops_the_dpop_binding_is_caught() {
    let violations = run_against(Faults {
        drops_jkt: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/token"],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "round_trip/token");
    assert!(
        detail.contains("jkt") && detail.contains("did not survive the round trip"),
        "the violation must name the field that was dropped: {detail}"
    );
}

/// The RFC 7523 / RFC 9449 half of the headline defect. A look-then-insert claim tells two
/// concurrent presentations of the SAME assertion that each of them was the first, which is the
/// replay both RFCs exist to refuse, and nothing downstream notices: the replayed request is
/// exactly the request the client meant to send.
#[cfg(any(feature = "client-assertion", feature = "dpop"))]
#[tokio::test]
async fn a_look_then_insert_replay_claim_is_caught() {
    let violations = run_against(Faults {
        look_then_insert_claim: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["atomic_claim/claim_replay_id"],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "atomic_claim/claim_replay_id")
            .contains("concurrent takes each received"),
        "the violation must report the double claim it found"
    );
}

// ---------------------------------------------------------------------- the harness's own limits

/// A "spawner" that runs each racer to completion before returning is not concurrency, and an
/// atomicity result obtained that way proves nothing. The harness must SAY so rather than report
/// a clean run, even when the store underneath is a correct one.
#[tokio::test]
async fn a_sequential_spawner_is_reported_rather_than_mistaken_for_a_pass() {
    let violations = StorageConformance::new(|| async { MemoryStorage::new() })
        .with_spawn(|task| {
            // Each task gets its own thread and its own single-threaded runtime, and is joined
            // before the next one is even created: strictly one at a time, which is exactly the
            // shape the gate exists to detect.
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .expect("current-thread runtime")
                    .block_on(task);
            })
            .join()
            .expect("racer thread");
        })
        .racers(2)
        .run()
        .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["harness/race_setup"],
        "a correct store run through a sequential spawner must report the useless race, and \
         nothing else: {violations:#?}"
    );
}

/// Hosts are invited to group, filter and waive by check name, so a name that is not in the
/// published list would be a waiver that silently never matches.
#[tokio::test]
async fn every_violation_names_a_published_check() {
    let violations = run_against(Faults {
        read_then_delete: true,
        // Every resurrection fault at once, and they compose: a revocation that records nothing,
        // a write that ignores what was recorded, and the two swaps that upsert. Each fires its
        // own check and none masks another, because they sit on different methods.
        revocation_records_no_barrier: true,
        code_swap_upserts: true,
        #[cfg(feature = "consent")]
        consent_swap_upserts: true,
        sweep_forgets_barriers: true,
        // Mutually exclusive with the line above, which is evaluated first: a sweep cannot both
        // skip the barrier table and reap it too eagerly.
        sweep_reaps_barriers_early: false,
        // Mutually exclusive with `put_ignores_barriers`, which is evaluated first, and with any
        // check that needs a token to be written at all.
        put_refuses_everything: false,
        // Mutually exclusive with the three upsert faults above, each of which is evaluated first:
        // a swap cannot both write when it should refuse and refuse when it should write.
        client_swap_refuses_everything: false,
        code_swap_refuses_everything: false,
        #[cfg(feature = "consent")]
        consent_swap_refuses_everything: false,
        // Compatible with the upsert faults: they write when the record is ABSENT, these write
        // when it is present but has changed, so both defects are live at once and both fire.
        client_swap_ignores_expected: true,
        code_swap_ignores_expected: true,
        #[cfg(feature = "consent")]
        consent_swap_ignores_expected: true,
        put_ignores_barriers: true,
        // Mutually exclusive with `put_ignores_barriers` above, which is evaluated first: a store
        // that never consults the barrier cannot also be observed comparing it wrongly.
        barrier_refuses_on_identity_alone: false,
        // Unreachable behind `revocation_records_no_barrier` above: a store that records no
        // barrier at all cannot be observed overwriting one.
        barrier_overwritten_by_the_later_write: false,
        // Independent of every fault above: the refusal happens before any of them is reached.
        revocation_accepts_an_empty_scope: true,
        // Mutually exclusive with the three `*_swap_ignores_expected` faults and with
        // `swap_ignores_expected`, all of which this branch returns before: a swap cannot both
        // compare in a separate step and not compare at all, and the harness would only ever see
        // whichever branch runs.
        swaps_read_then_write: false,
        client_swap_upserts: true,
        index_overwrites: true,
        index_outlives_the_taken_grant: true,
        sweep_removes_everything: true,
        // Mutually exclusive with `sweep_removes_everything`, which returns first, and with each
        // other: a sweep cannot both remove nothing and fail, and the harness would only ever see
        // whichever branch runs.
        sweep_removes_nothing: false,
        sweep_errors_when_it_removed_nothing: false,
        // Unreachable behind `sweep_removes_everything`, which returns before it: the snapshot
        // write-back is the LAST thing a correct-looking sweep does, and this sweep never gets
        // there.
        sweep_rebuilds_the_token_table_from_a_snapshot: false,
        swap_ignores_expected: true,
        // Mutually exclusive with the line above, which is evaluated first.
        swap_resurrects_taken_grants: false,
        // Compatible with `swap_ignores_expected`: it changes only the boolean a swap that DID
        // write reports, so both defects are live at once and both of their checks fire.
        swap_reports_that_it_did_not_apply: true,
        // Both index faults on the swap, and they compose with everything above: the swap's
        // comparison is one decision and what it then does to the user-code index is another.
        swap_leaves_the_old_user_code_indexed: true,
        swap_repoints_a_duplicate_user_code: true,
        // Independent of every drop above: it changes what a READ does, not what a write keeps.
        reads_are_takes: true,
        // Independent of `delete_client_leaves_credentials` in principle, but unreachable behind
        // it here: that fault returns before the cascade's predicates are ever evaluated.
        code_removal_filters_on_state: false,
        // Compatible with every other drop: a different column of the same three records.
        drops_the_grant_instant: true,
        // Unreachable behind `put_ignores_barriers` above, which is evaluated first: a store that
        // never consults the barrier cannot be observed comparing it against the wrong columns.
        #[cfg(feature = "par")]
        par_barrier_ignores_the_client_scope: false,
        drops_the_device_grant_interval: true,
        drops_the_code_challenge: true,
        drops_the_token_resource: true,
        // Unreachable behind `index_overwrites`, which returns before the clash is ever detected.
        refusal_repoints_the_index: false,
        delete_client_leaves_credentials: true,
        delete_client_always_reports_true: true,
        // Mutually exclusive with the line above by construction: the two faults are opposite
        // answers to the same question, and this one would mask the other.
        delete_client_always_reports_false: false,
        family_revocation_spares_access_tokens: true,
        // Mutually exclusive with the line above: this one returns before it.
        family_revocation_takes_every_family: false,
        delete_token_errors_when_absent: true,
        drops_family_id: true,
        drops_the_client_secret: true,
        normalizes_user_codes: true,
        #[cfg(feature = "dpop")]
        drops_jkt: true,
        #[cfg(feature = "dpop")]
        drops_jkt_on_refresh_records: true,
        #[cfg(feature = "mtls")]
        drops_x5t_s256_on_tokens: true,
        #[cfg(feature = "mtls")]
        drops_x5t_s256_on_refresh_records: true,
        #[cfg(feature = "rar")]
        drops_authorization_details_on_tokens: true,
        #[cfg(feature = "rar")]
        drops_authorization_details_on_refresh_records: true,
        #[cfg(feature = "rar")]
        drops_authorization_details_on_codes: true,
        #[cfg(all(feature = "rar", feature = "par"))]
        drops_authorization_details_on_pushed_requests: true,
        #[cfg(feature = "par")]
        drops_the_pushed_code_challenge: true,
        // Compatible with every other token drop: a different column of the same record.
        #[cfg(feature = "token-exchange")]
        drops_act_on_tokens: true,
        #[cfg(feature = "consent")]
        drops_the_authentication_on_tokens: true,
        #[cfg(feature = "consent")]
        drops_the_authentication_on_refresh_records: true,
        #[cfg(feature = "consent")]
        drops_the_authentication_on_codes: true,
        #[cfg(feature = "consent")]
        drops_the_authentication_on_consents: true,
        // NOT set. It is mutually exclusive with `read_then_delete` above, which it would panic
        // before ever reaching, and this test is about the vocabulary of the check names rather
        // than about the spawned path;
        // `a_racer_that_panics_is_reported_rather_than_hanging_the_harness` owns that.
        the_refresh_take_panics: false,
        #[cfg(any(feature = "client-assertion", feature = "dpop"))]
        look_then_insert_claim: true,
        // Mutually exclusive with `look_then_insert_claim`, which returns first.
        #[cfg(any(feature = "client-assertion", feature = "dpop"))]
        claim_is_keyed_on_nothing: false,
        // Mutually exclusive with `look_then_insert_claim` too, for the same reason: whichever
        // branch runs first is the only one the harness can observe.
        #[cfg(any(feature = "client-assertion", feature = "dpop"))]
        claim_forgets_what_it_claimed: false,
        #[cfg(any(feature = "client-assertion", feature = "dpop"))]
        sweep_forgets_replay_ids: true,
        // Unreachable behind `sweep_removes_everything`, which returns before it.
        #[cfg(feature = "par")]
        sweep_forgets_pushed_requests: false,
        #[cfg(feature = "consent")]
        consents_for_subject_filters_on_the_client: true,
        // Mutually exclusive with the line above: the empty answer returns first, and a listing
        // cannot both be empty and be somebody else's.
        #[cfg(feature = "consent")]
        consents_for_subject_returns_nothing: false,
        // Unreachable behind `consents_for_subject_filters_on_the_client`, which returns first.
        #[cfg(feature = "consent")]
        consents_for_subject_reads_a_stale_index: false,
        #[cfg(feature = "consent")]
        find_consent_never_finds: true,
        // Only one of the two withdrawal faults can be set at a time: they are mutually exclusive
        // branches of the same method, and the "leaves credentials" one returns before the other
        // is reachable. Under-revoking is the worse of the two, so it is the one exercised here.
        #[cfg(feature = "consent")]
        withdrawal_leaves_credentials: true,
        #[cfg(feature = "consent")]
        withdrawal_takes_other_subjects: false,
        // Unreachable behind `withdrawal_leaves_credentials`, which returns first.
        #[cfg(feature = "consent")]
        withdrawal_counts_the_consent_row: false,
        // The insert-only and contention faults are omitted from this omnibus: each needs a store
        // that WRITES the record it is asked about (so it can drop the SECOND write, or surface a
        // losing comparison as an error), which the drop-everything faults above have already
        // suppressed. Their own single-fault tests below own the vocabulary they produce.
        put_client_insert_only: false,
        #[cfg(feature = "par")]
        put_pushed_insert_only: false,
        #[cfg(feature = "consent")]
        put_consent_insert_only: false,
        put_device_grant_refuses_to_update: false,
        issuance_fails_beside_a_sweep: false,
        swap_surfaces_contention_as_error: false,
        #[cfg(feature = "consent")]
        consent_swap_widen_is_lost: false,
    })
    .await;

    assert!(
        !violations.is_empty(),
        "a store that is wrong in every way must not pass"
    );
    for violation in &violations {
        assert!(
            CHECKS.contains(&violation.check),
            "{} is not in the published CHECKS list",
            violation.check
        );
        assert!(
            !violation.detail.is_empty(),
            "{} reported no detail, so a host cannot act on it",
            violation.check
        );
        // Display is what a host prints; it has to carry both halves.
        let shown = violation.to_string();
        assert!(shown.contains(violation.check) && shown.contains(&violation.detail));
    }
}

/// A withdrawal that removes the consent row, reports a plausible count, and leaves every
/// credential alive. This is the worst failure mode the consent feature has: the endpoint answers
/// 200, the record is gone, the audit log records a withdrawal, and the application the user just
/// revoked keeps working. Nothing anywhere reports it, which is why the harness has to.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_withdrawal_that_leaves_credentials_alive_is_caught() {
    let violations = run_against(Faults {
        withdrawal_leaves_credentials: true,
        ..Faults::default()
    })
    .await;

    let fired = checks_that_fired(&violations);
    assert!(
        fired.contains(&"revoke_consent/cascades"),
        "a withdrawal that revoked nothing must be caught: {violations:#?}"
    );
    assert!(
        detail_of(&violations, "revoke_consent/cascades").contains("was not"),
        "the violation must say what the user was told versus what happened"
    );
}

/// The opposite fault, which is just as real and easier to write by accident: a withdrawal keyed
/// on the CLIENT rather than the (client, subject) pair. One user withdrawing consent logs out
/// every other user of that application, and the count still looks right.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_withdrawal_that_takes_other_subjects_with_it_is_caught() {
    let violations = run_against(Faults {
        withdrawal_takes_other_subjects: true,
        ..Faults::default()
    })
    .await;

    assert!(
        checks_that_fired(&violations).contains(&"revoke_consent/spares_other_subjects"),
        "over-revoking must be caught, not just under-revoking: {violations:#?}"
    );
}

// ------------------------------------------------------- the checks nobody had watched go red
//
// Every check in `CHECKS` above this line had a fault behind it. These nine did not, which made
// them indistinguishable from checks that cannot fail at all: a harness a host runs against its
// own store to be told it is safe, reporting green from a check that has never been observed to
// report anything else. Each fault below drives ONE named check, and where a fault necessarily
// trips a neighbouring check as well (a sweep that removes nothing cannot report the right count)
// the test says which and asserts both, so the two are still told apart.

/// A take that removes the grant and leaves the user-code row. RFC 8628 s6.1 makes the user code
/// the credential a human types, so a redeemed grant that still answers to it is a second
/// redemption waiting for anyone who saw the code on the screen.
#[tokio::test]
async fn a_take_that_leaves_the_user_code_row_behind_is_caught() {
    let violations = run_against(Faults {
        index_outlives_the_taken_grant: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["user_code_index/cleared_by_take"],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "user_code_index/cleared_by_take").contains("user code"),
        "the violation must name the path the redeemed grant is still reachable by"
    );
}

/// The opposite of the sweep fault that already existed. `sweep_removes_everything` proves
/// `keeps_live` and `count` can fire; nothing proved `removes_dead` could, and a sweep that
/// removes nothing is the miss a host never notices, because an idle store and a broken sweep look
/// identical until the disk fills.
#[tokio::test]
async fn a_sweep_that_removes_nothing_is_caught() {
    let violations = run_against(Faults {
        sweep_removes_nothing: true,
        ..Faults::default()
    })
    .await;

    // `count`, `reclaims_pushed_requests` and `reclaims_replay_ids` necessarily go with it: a
    // sweep that removes nothing cannot report the right number, and the pushed requests and the
    // replay ids are records it did not remove either. Asserted by name so the four are still told
    // apart rather than counted together.
    assert_eq!(
        checks_that_fired(&violations),
        vec![
            // A broken sweep fails TWO different claims, and they are not the same bug wearing two
            // names: one is about the records it was asked to reclaim, this one is about the
            // revocation barrier table, which nothing else ever removes a row from. A host that
            // fixed only the first would still grow that table for the life of the deployment.
            "revocation_barrier/swept_at_its_deadline",
            "sweep_expired/count",
            #[cfg(feature = "par")]
            "sweep_expired/reclaims_pushed_requests",
            #[cfg(any(feature = "client-assertion", feature = "dpop"))]
            "sweep_expired/reclaims_replay_ids",
            "sweep_expired/removes_dead",
        ],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "sweep_expired/removes_dead");
    // Every dead kind must be named, so a store is told which sweep it did not write.
    for expected in [
        "device grant",
        "authorization code",
        "access token",
        "refresh record",
        "user code",
    ] {
        assert!(
            detail.contains(expected),
            "the violation must name the {expected} that survived: {detail}"
        );
    }
}

/// A sweep that fails when it matched no rows. The host runs this on a timer against a store that
/// is usually idle, so the failing case is the common one, and a host that wires the result to an
/// alert learns to ignore the alert.
#[tokio::test]
async fn a_sweep_that_errors_when_there_is_nothing_to_do_is_caught() {
    let violations = run_against(Faults {
        sweep_errors_when_it_removed_nothing: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["sweep_expired/empty_is_zero"],
        "{violations:#?}"
    );
}

/// A sweep that reads the token table, decides what to keep, and writes the kept set back with
/// anything at all happening in between.
///
/// The single-violation assertion below is the whole point of this one. Every other sweep fault in
/// this file is visible to a sequential check, so several of them necessarily trip neighbouring
/// checks. This store reaps precisely the right records and reports precisely the right count: it
/// is a CORRECT sweep by every measure taken while nothing else is running, and the only thing
/// wrong with it is that a `put_token` landing inside its window is discarded. Before
/// `sweep_expired/safe_under_concurrent_writes` existed, this store passed the entire harness.
#[tokio::test]
async fn a_sweep_that_rebuilds_its_table_from_a_snapshot_is_caught() {
    let violations = run_against(Faults {
        sweep_rebuilds_the_token_table_from_a_snapshot: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["sweep_expired/safe_under_concurrent_writes"],
        "{violations:#?}"
    );
}

/// A sweep that reclaims everything except the claimed replay ids. RFC 7523 s3 and RFC 9449 s4.3
/// make a jti single use, so the store keeps one row per authenticated request and this sweep is
/// the only thing that ever deletes one.
#[cfg(any(feature = "client-assertion", feature = "dpop"))]
#[tokio::test]
async fn a_sweep_that_never_reclaims_replay_ids_is_caught() {
    let violations = run_against(Faults {
        sweep_forgets_replay_ids: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["sweep_expired/reclaims_replay_ids"],
        "{violations:#?}"
    );
}

/// A sweep that reclaims everything except the pushed authorization requests: exactly the store a
/// host writes from the trait's own enumeration of "dead at `now`", which listed device grants,
/// codes, access tokens, replay ids and refresh records and did not list this one. RFC 9126 s2.1
/// makes the push endpoint client authenticated, so it is not an anonymous flood; it is one chatty
/// or compromised client growing a table nothing else ever deletes from.
///
/// `count` necessarily goes with it and is asserted by name: a sweep that misses one of the five
/// dead records cannot report five. That is a true statement about this store and it is not the
/// statement this test exists for, so the two stay distinguishable.
#[cfg(feature = "par")]
#[tokio::test]
async fn a_sweep_that_never_reclaims_pushed_requests_is_caught() {
    let violations = run_against(Faults {
        sweep_forgets_pushed_requests: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "sweep_expired/count",
            "sweep_expired/reclaims_pushed_requests",
        ],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "sweep_expired/reclaims_pushed_requests").contains("survived"),
        "the violation must say the expired handle is still there, not merely that a count differed"
    );
}

/// A family revocation that matches every family. RFC 9700 s4.14.2 runs this on evidence that ONE
/// chain was stolen; a predicate that was dropped turns that into a deployment-wide logout, and
/// the operator reading the count sees a bigger number and no reason to doubt it.
#[tokio::test]
async fn a_family_revocation_that_takes_every_family_is_caught() {
    let violations = run_against(Faults {
        family_revocation_takes_every_family: true,
        ..Faults::default()
    })
    .await;

    // `count` goes with it, because a revocation that removed 7 records cannot report the 4 the
    // named family held. Both are asserted by name so the over-revocation is not mistaken for a
    // miscount.
    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "revoke_token_family/count",
            "revoke_token_family/spares_other_families",
        ],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "revoke_token_family/spares_other_families");
    assert!(
        detail.contains("access token of another") && detail.contains("refresh record of another"),
        "both kinds belonging to the untouched family must be named: {detail}"
    );
    assert!(
        detail.contains("no family_id at all"),
        "RFC 6749 s4.4 tokens carry no family and must not be swept up by matching None: {detail}"
    );
}

/// A `delete_client` that answers true whether or not anything was there. RFC 7592 s2.3 is
/// answered from this boolean, so the management endpoint confirms the deletion of a client id
/// that never existed, which is both a lie and an existence oracle.
#[tokio::test]
async fn a_delete_client_that_always_reports_true_is_caught() {
    let violations = run_against(Faults {
        delete_client_always_reports_true: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["delete_client/reports_whether_it_removed"],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "delete_client/reports_whether_it_removed").contains("already gone"),
        "the violation must say which of the two answers was wrong"
    );
}

/// The other half of that check, and the half nothing had ever driven: a `delete_client` that
/// deletes the registration and every credential with it, and answers FALSE. RFC 7592 s2.3 is
/// answered from this boolean, so the administrator is told 404 for a deletion that succeeded, and
/// the registration is reported alive while nothing of it remains.
///
/// The two faults are opposite answers to the same question and each leaves the other's branch
/// unwatched, which is why both are planted: with only the always-true one, the "was present"
/// branch could be deleted outright and this file would still be green.
#[tokio::test]
async fn a_delete_client_that_always_reports_false_is_caught() {
    let violations = run_against(Faults {
        delete_client_always_reports_false: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["delete_client/reports_whether_it_removed"],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "delete_client/reports_whether_it_removed")
            .contains("answered false for a registration that was present"),
        "the violation must say which of the two answers was wrong: this store performed the \
         deletion and denied it, which is the opposite of the one that confirms a deletion it \
         never made"
    );
}

/// A claim that is atomic and still useless: one slot for every id there will ever be. The race
/// check passes, because exactly one racer wins it; the SEQUENTIAL check is the only thing that
/// sees that the second id, belonging to a different client and a different request, is refused as
/// a replay of the first.
#[cfg(any(feature = "client-assertion", feature = "dpop"))]
#[tokio::test]
async fn a_replay_claim_keyed_on_nothing_is_caught_even_though_it_wins_the_race() {
    let violations = run_against(Faults {
        claim_is_keyed_on_nothing: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["claim_replay_id/refuses_a_second_claim"],
        "the RACE check must stay green here, or this proves nothing about the sequential one: \
         {violations:#?}"
    );
    assert!(
        detail_of(&violations, "claim_replay_id/refuses_a_second_claim")
            .contains("never claimed answered false"),
        "the violation must name the half that failed: this store refuses ids it has not seen, \
         which is the opposite of the double-claim the race check looks for"
    );
}

/// A claim that wins the race and remembers nothing: the row is written with a lifetime of zero,
/// so it is gone by the time the replay arrives. The race check passes, because exactly one racer
/// wins it, and the SEQUENTIAL check is the only thing between this store and a deployment where
/// every RFC 7523 s3 assertion and every RFC 9449 s4.3 proof is replayable.
///
/// It is the store the harness's own comment says the sequential half exists for, and it is the one
/// nothing had ever planted: the other two claim faults both refuse a repeated id correctly, so the
/// second-claim branch went red for no store in this file until this test.
#[cfg(any(feature = "client-assertion", feature = "dpop"))]
#[tokio::test]
async fn a_claim_that_wins_the_race_and_records_nothing_is_caught() {
    let violations = run_against(Faults {
        claim_forgets_what_it_claimed: true,
        ..Faults::default()
    })
    .await;

    // The sweep goes with it, and it is the same defect seen from the other end: a store that
    // records no claim has no claim for the sweep to reclaim, so it reports zero where one dead id
    // was standing. Both are asserted by name so the amnesia is not mistaken for a broken sweep,
    // and the RACE check is asserted ABSENT by the same line, which is the whole point of this
    // store: it is atomic, and that buys it nothing.
    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "claim_replay_id/refuses_a_second_claim",
            "sweep_expired/reclaims_replay_ids",
        ],
        "the race check must stay green here, or this proves nothing about the sequential one: \
         {violations:#?}"
    );
    let detail = detail_of(&violations, "claim_replay_id/refuses_a_second_claim");
    assert!(
        detail.contains("the SECOND claim of the same id also answered true"),
        "the violation must name the half that failed: this store admits a repeat of an id it has \
         already handed out, which is the replay itself rather than the refusal of an unseen id: \
         {detail}"
    );
}

/// A withdrawal that revokes exactly the right credentials and reports one too many, because it
/// counted the consent row. The count is what an operator reads while deciding whether a
/// withdrawal did what the user asked, so a number that does not describe the credentials is a
/// wrong answer to the only question being asked.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_withdrawal_that_counts_the_consent_row_is_caught() {
    let violations = run_against(Faults {
        withdrawal_counts_the_consent_row: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["revoke_consent/count"],
        "the cascade itself is correct here, so only the count may fire: {violations:#?}"
    );
    assert!(
        detail_of(&violations, "revoke_consent/count").contains("not counted"),
        "the violation must state the rule the count broke"
    );
}

/// The per-subject consent listing built on the wrong column. `consents_for_subject` was the one
/// consent method nothing in this harness read back, so a store answering it with every consent of
/// the CLIENT was certified clean: the host's "applications you have approved" screen then shows
/// one user another user's grants, and offers them a button that withdraws them.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_consent_listing_keyed_on_the_client_shows_one_user_anothers_grants_and_is_caught() {
    let violations = run_against(Faults {
        consents_for_subject_filters_on_the_client: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["consents_for_subject/lists_that_subjects_consents"],
        "everything else about this store is right, so only the listing may fire: {violations:#?}"
    );
    let detail = detail_of(
        &violations,
        "consents_for_subject/lists_that_subjects_consents",
    );
    assert!(
        detail.contains("consent-theirs") && detail.contains("DIFFERENT resource owner"),
        "the violation must name the other user's record it was handed: {detail}"
    );
}

/// The opposite miss, and the one that is invisible from every other check here: a listing that
/// answers empty. Nothing errors, the consent is stored, remembered consent still works at the
/// authorization endpoint, and the user is simply never shown the application, so the withdrawal
/// cascade the rest of `consent()` verifies can never be reached from the UI.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_consent_listing_that_answers_empty_is_caught() {
    let violations = run_against(Faults {
        consents_for_subject_returns_nothing: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["consents_for_subject/lists_that_subjects_consents"],
        "{violations:#?}"
    );
    assert!(
        detail_of(
            &violations,
            "consents_for_subject/lists_that_subjects_consents"
        )
        .contains("cannot withdraw what the host never shows them"),
        "the violation must say what an empty listing costs the user"
    );
}

/// A per-subject index that `put_consent` maintains and `revoke_consent` does not. The primary row
/// is gone, so every other consent check passes; the listing goes on offering the user an
/// application they have already stopped, with a revoke button that answers `Ok(0)` forever.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_consent_listing_that_reads_a_stale_index_is_caught() {
    let violations = run_against(Faults {
        consents_for_subject_reads_a_stale_index: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["consents_for_subject/lists_that_subjects_consents"],
        "{violations:#?}"
    );
    assert!(
        detail_of(
            &violations,
            "consents_for_subject/lists_that_subjects_consents"
        )
        .contains("after that consent was withdrawn"),
        "the violation must name the half that failed: this store lists a consent that is gone, \
         which is the opposite of the empty listing the check also looks for"
    );
}

/// The (client, subject) lookup that never finds anything. `round_trip/consent` has always called
/// `find_consent`, and nothing had ever watched that call fail, which is the same hole
/// `consents_for_subject` was: a check whose green nobody has seen earned. The defect is silent by
/// construction, because remembered consent failing means a prompt, and a prompt looks like policy.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_find_consent_that_never_finds_the_stored_consent_is_caught() {
    let violations = run_against(Faults {
        find_consent_never_finds: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/consent"],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "round_trip/consent").contains("get_consent can read"),
        "the violation must say the record IS there and this path cannot reach it, or a host \
         cannot tell a lookup from a write"
    );
}

/// A client row that persists without its credential. The registration reads back PUBLIC, so
/// every confidential-client authentication succeeds for anyone holding the client id alone, and
/// there is no error anywhere: the client authenticates, exactly as a public client is supposed
/// to. Field-drop faults existed for the refresh token and the access token; the client, which is
/// the record that decides who is allowed to ask at all, had none.
#[tokio::test]
async fn a_client_that_loses_its_credential_on_the_way_in_is_caught() {
    let violations = run_against(Faults {
        drops_the_client_secret: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/client"],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "round_trip/client");
    assert!(
        detail.contains("field auth") && detail.contains("did not survive the round trip"),
        "the violation must name the field that was dropped: {detail}"
    );
    // The stored secret is a one-way hash and the violation prints what it read back, so this is
    // also where a harness that logged the credential itself would show up.
    assert!(
        !detail.contains("conformance-secret"),
        "a violation must not print the credential it compared: {detail}"
    );
}

/// The RFC 9126 s4 half of the read-then-delete defect. `take_pushed_authorization_request` is the
/// only thing making a `request_uri` single use, so a store that reads then deletes lets two
/// concurrent authorization requests resolve the same pushed request.
#[cfg(feature = "par")]
#[tokio::test]
async fn a_read_then_delete_pushed_request_take_is_caught() {
    let violations = run_against(Faults {
        read_then_delete: true,
        ..Faults::default()
    })
    .await;

    assert!(
        checks_that_fired(&violations).contains(&"atomic_take/take_pushed_authorization_request"),
        "the PAR handle must be held to the same atomicity as the other take_* operations: \
         {violations:#?}"
    );
}

// ---------------------------------------- the fields a fixture's DEFAULT value used to hide
//
// A round-trip check can only see a dropped field if the fixture's value for it differs from what
// a store that dropped it returns. Four fields failed that: the RFC 8705 `x5t#S256` binding (never
// compared at all), the RFC 9396 `authorization_details` (compared nowhere, and empty in every
// fixture), the RFC 9470 authentication report (`None` everywhere), and every field of the pushed
// request (raced, never round-tripped). Each fault below drops exactly one field from exactly one
// record kind, and each names the ONE check it must drive.

/// The mTLS half of `a_store_that_silently_drops_the_dpop_binding_is_caught`. RFC 8705 section 3.1
/// binds the token to the certificate the client presented; a store that loses the thumbprint
/// hands back a token with no `cnf` at all, which an introspecting resource server reads as an
/// ordinary bearer token rather than as an error. Nothing anywhere fails.
#[cfg(feature = "mtls")]
#[tokio::test]
async fn a_store_that_silently_drops_the_mtls_binding_from_a_token_is_caught() {
    let violations = run_against(Faults {
        drops_x5t_s256_on_tokens: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/token"],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "round_trip/token");
    assert!(
        detail.contains("x5t_s256") && detail.contains("did not survive the round trip"),
        "the violation must name the field that was dropped: {detail}"
    );
}

/// The same drop on the refresh record, which is the worse of the two: this is the binding the
/// next rotation copies onto the token it mints, so losing it here unbinds every token the chain
/// will ever produce.
#[cfg(feature = "mtls")]
#[tokio::test]
async fn a_store_that_silently_drops_the_mtls_binding_from_a_refresh_record_is_caught() {
    let violations = run_against(Faults {
        drops_x5t_s256_on_refresh_records: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/refresh_token"],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "round_trip/refresh_token").contains("x5t_s256"),
        "the violation must name the field that was dropped"
    );
}

/// The DPoP binding on the REFRESH record. `drops_jkt` above proved the check on the access token
/// could fire; the refresh record's copy is a different column in a different table and had never
/// been watched fail.
#[cfg(feature = "dpop")]
#[tokio::test]
async fn a_store_that_silently_drops_the_dpop_binding_from_a_refresh_record_is_caught() {
    let violations = run_against(Faults {
        drops_jkt_on_refresh_records: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/refresh_token"],
        "{violations:#?}"
    );
    assert!(detail_of(&violations, "round_trip/refresh_token").contains("jkt"));
}

/// RFC 9396 `authorization_details` dropped from the access token. This crate has itself shipped
/// this defect twice on feature-gated paths, so a host's store having it is not hypothetical, and
/// the fixture's details were the EMPTY default until now, which meant a store that dropped them
/// round-tripped indistinguishably from one that kept them.
#[cfg(feature = "rar")]
#[tokio::test]
async fn a_store_that_silently_drops_rich_authorization_details_from_a_token_is_caught() {
    let violations = run_against(Faults {
        drops_authorization_details_on_tokens: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/token"],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "round_trip/token");
    assert!(
        detail.contains("authorization_details") && detail.contains("conformance-fixture"),
        "the violation must name the field AND print what was stored, or a host cannot tell a \
         dropped column from a reordered one: {detail}"
    );
}

/// RFC 8693 `act` dropped from the access token. It was the ONE feature-gated column of
/// `IssuedToken` the harness compared and no fault here dropped, so the comparison had never been
/// watched fail: a store that lost the column certified clean, and the RFC 8693 s1.1 distinction
/// between delegation and impersonation was decided by a column nobody had checked was written.
/// The token then introspects as the subject acting directly, and the actor disappears from every
/// audit trail downstream.
#[cfg(feature = "token-exchange")]
#[tokio::test]
async fn a_store_that_silently_drops_the_delegation_chain_from_a_token_is_caught() {
    let violations = run_against(Faults {
        drops_act_on_tokens: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/token"],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "round_trip/token");
    assert!(
        detail.contains("act") && detail.contains("actor-conformance"),
        "the violation must name the field AND print the actor that was stored, or a host cannot \
         tell a dropped column from a delegation chain that was never there: {detail}"
    );
}

#[cfg(feature = "rar")]
#[tokio::test]
async fn a_store_that_silently_drops_rich_authorization_details_from_a_refresh_record_is_caught() {
    let violations = run_against(Faults {
        drops_authorization_details_on_refresh_records: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/refresh_token"],
        "{violations:#?}"
    );
    assert!(detail_of(&violations, "round_trip/refresh_token").contains("authorization_details"));
}

#[cfg(feature = "rar")]
#[tokio::test]
async fn a_store_that_silently_drops_rich_authorization_details_from_a_code_is_caught() {
    let violations = run_against(Faults {
        drops_authorization_details_on_codes: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/authorization_code"],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "round_trip/authorization_code").contains("authorization_details")
    );
}

/// RFC 9470 step-up state dropped from an access token. The token then reports no `acr` and no
/// `auth_time` at introspection however strongly the host authenticated the user, so a resource
/// server that challenged for step-up gets an answer that looks like the challenge was ignored.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_store_that_silently_drops_the_authentication_report_from_a_token_is_caught() {
    let violations = run_against(Faults {
        drops_the_authentication_on_tokens: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/token"],
        "{violations:#?}"
    );
    assert!(detail_of(&violations, "round_trip/token").contains("authentication"));
}

/// The same drop on the refresh record. That copy is what stops a client defeating an RFC 9470
/// `max_age` simply by refreshing, so losing it turns every refresh into a fresh login that never
/// happened.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_store_that_silently_drops_the_authentication_report_from_a_refresh_record_is_caught() {
    let violations = run_against(Faults {
        drops_the_authentication_on_refresh_records: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/refresh_token"],
        "{violations:#?}"
    );
    assert!(detail_of(&violations, "round_trip/refresh_token").contains("authentication"));
}

#[cfg(feature = "consent")]
#[tokio::test]
async fn a_store_that_silently_drops_the_authentication_report_from_a_code_is_caught() {
    let violations = run_against(Faults {
        drops_the_authentication_on_codes: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/authorization_code"],
        "{violations:#?}"
    );
    assert!(detail_of(&violations, "round_trip/authorization_code").contains("authentication"));
}

/// The same drop on the CONSENT record. `round_trip/consent` compares the whole record, so the
/// check was already capable of seeing this; what it could not see was a fixture whose
/// `authentication` was `None`, because `None` is what a store that drops the column returns.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_store_that_silently_drops_the_authentication_report_from_a_consent_is_caught() {
    let violations = run_against(Faults {
        drops_the_authentication_on_consents: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/consent"],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "round_trip/consent").contains("differs from the one stored"),
        "the consent check compares the whole record, and must say so"
    );
}

/// The pushed request was the ONE record kind this harness raced and never round-tripped, so a
/// store could drop any column of it and be certified clean. `code_challenge` is the one that
/// matters most: losing it is a silent RFC 7636 downgrade on the request shape whose entire
/// purpose was to keep the challenge out of the browser.
#[cfg(feature = "par")]
#[tokio::test]
async fn a_store_that_silently_drops_the_pushed_code_challenge_is_caught() {
    let violations = run_against(Faults {
        drops_the_pushed_code_challenge: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/pushed_authorization_request"],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "round_trip/pushed_authorization_request");
    assert!(
        detail.contains("code_challenge") && detail.contains("did not survive the round trip"),
        "the violation must name the field that was dropped: {detail}"
    );
}

/// The RAR half of the same hole. RFC 9101 section 6.3 has the authorization endpoint use ONLY the
/// pushed parameters, so a detail validated at push time and then dropped is a parameter the
/// client was told was acceptable and then silently did not get.
#[cfg(all(feature = "par", feature = "rar"))]
#[tokio::test]
async fn a_store_that_silently_drops_the_pushed_authorization_details_is_caught() {
    let violations = run_against(Faults {
        drops_authorization_details_on_pushed_requests: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/pushed_authorization_request"],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "round_trip/pushed_authorization_request")
            .contains("authorization_details")
    );
}

// ---------------------------------------------------- a racer that never comes back

/// A store whose call PANICS under concurrency must produce a REPORT, not a hung test run.
///
/// In spawned mode the racer's panic unwinds inside the host's runtime, where the harness cannot
/// see it; what the harness owns is the latch it waits on, and a racer that never reaches the
/// bottom of its task never released it. The result was that the harness parked forever, so a host
/// whose store panics under concurrency got a test run that hung: the worst diagnostic available,
/// because it names nothing and looks like the harness is broken rather than the store.
///
/// `atomic_take/take_refresh_token` necessarily goes with it and is asserted by name so the two
/// stay distinguishable: with every racer dead, nobody received the record, and the record is
/// still sitting in the store afterwards. That is a true statement about this store, and it is not
/// the statement this test exists for.
#[tokio::test]
async fn a_racer_that_panics_is_reported_rather_than_hanging_the_harness() {
    let violations = StorageConformance::new(|| async {
        NaiveStore::new(Faults {
            the_refresh_take_panics: true,
            ..Faults::default()
        })
    })
    .with_spawn(|task| {
        tokio::spawn(task);
    })
    .racers(4)
    .run()
    .await;

    let fired = checks_that_fired(&violations);
    assert!(
        fired.contains(&"harness/racer_panicked"),
        "a racer that never finished must be reported: {violations:#?}"
    );
    assert!(
        fired.contains(&"atomic_take/take_refresh_token"),
        "and the take it was making is still a take nobody completed: {fired:?}"
    );
    let detail = detail_of(&violations, "harness/racer_panicked");
    assert!(
        detail.contains("4 of 4 racers never finished"),
        "the report must say how many racers were lost, so a host can tell one panicking call \
         from a store that panics on every call: {detail}"
    );
    assert!(
        detail.contains("panicked"),
        "and it must name the likely cause rather than leaving a host to guess: {detail}"
    );
}

// ------------------------------------------ the check nobody had watched go red, and the guard
//
// `compare_and_swap_device_grant/applies_when_the_state_matches` was published in `CHECKS`, run
// against every host's store, and had NO fault behind it anywhere: not in this file, not in
// tests/storage_conformance_gaps.rs, and no field of either `Faults` could make that swap answer
// wrongly on the matching case. So it was a green nobody had ever seen turn red, which is the
// exact defect this whole file was written to make impossible, surviving inside the file that was
// written to end it.
//
// The four faults below it were in the same position and are fixed the same way. What stops the
// next one is not this paragraph but `every_check_has_a_planted_fault` at the bottom.

/// A swap that applies the write and reports that it did not.
///
/// `honours_expected` and `never_resurrects` stay GREEN here, and that is the assertion worth the
/// most: this store is atomic, honours `expected`, and never resurrects a redeemed grant, so
/// neither of them can see the defect. Only a check that asserts the MATCHING case applies can.
///
/// The race check necessarily goes with it and is asserted by name so the two stay
/// distinguishable: a store that never says yes tells all eight racers they lost, which is a true
/// statement about this store and is not the statement this test exists for.
#[tokio::test]
async fn a_swap_that_applies_and_says_it_did_not_is_caught() {
    let violations = run_against(Faults {
        swap_reports_that_it_did_not_apply: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "compare_and_swap_device_grant/applies_when_the_state_matches",
            "compare_and_swap_device_grant/atomic_under_a_race",
        ],
        "{violations:#?}"
    );
    assert!(
        detail_of(
            &violations,
            "compare_and_swap_device_grant/applies_when_the_state_matches"
        )
        .contains("the user's decision at the verification UI"),
        "the violation must say what the host loses, not merely that a bool differed"
    );
}

/// RFC 8628 section 3.2: the interval is what the device obeys, so a store that reads it back as
/// zero turns every device into a polling loop the server then punishes with `slow_down`.
#[tokio::test]
async fn a_store_that_silently_drops_the_polling_interval_is_caught() {
    let violations = run_against(Faults {
        drops_the_device_grant_interval: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/device_grant"],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "round_trip/device_grant").contains("interval"),
        "the violation must name the field that was dropped"
    );
}

/// The code that comes back with no challenge is a code redeemable without a verifier, which is
/// the whole of RFC 7636 gone at rest.
#[tokio::test]
async fn a_store_that_silently_drops_the_code_challenge_is_caught() {
    let violations = run_against(Faults {
        drops_the_code_challenge: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/authorization_code"],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "round_trip/authorization_code").contains("code_challenge"),
        "the violation must name the field that was dropped"
    );
}

/// RFC 8707: a token whose audience restriction was dropped at rest is good at every resource
/// server that trusts this issuer, and nothing on the wire says so.
#[tokio::test]
async fn a_store_that_silently_drops_the_resource_restriction_is_caught() {
    let violations = run_against(Faults {
        drops_the_token_resource: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["round_trip/token"],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "round_trip/token").contains("resource"),
        "the violation must name the field that was dropped"
    );
}

/// The refusal is right and the row it left behind is not: the user code the first device is
/// displaying now resolves to the second device's grant, so the code a human types approves
/// somebody else's request.
#[tokio::test]
async fn a_refusal_that_has_already_repointed_the_index_is_caught() {
    let violations = run_against(Faults {
        refusal_repoints_the_index: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["user_code_index/refusal_writes_nothing"],
        "a put that refuses correctly and writes anyway must be caught by the check that owns \
         the write, and not by the one that owns the refusal: {violations:#?}"
    );
    let detail = detail_of(&violations, "user_code_index/refusal_writes_nothing");
    assert!(
        detail.contains("repointed") || detail.contains("persisted"),
        "the violation must say what was written by a put that should have written nothing: \
         {detail}"
    );
}

// ------------------------------------ the atomicity all four swaps require, and nothing raced
//
// "The comparison and the write MUST happen as ONE atomic step. A store that reads, compares, and
// then writes separately has reintroduced precisely the window this closes, and it will do so
// silently." That sentence is on all four `compare_and_swap_*` methods in the trait. Until the
// four race checks existed, every swap check in the harness was a sequential put, swap, read
// back — which the store below passes on every single one of them.

/// All four swaps done as a read, a comparison and a separate write, with the round trip a shared
/// store makes in between.
///
/// The four race checks are the ONLY thing that fires, and that is the assertion worth the most
/// here: this store applies the swap it should apply, refuses the stale `expected` it should
/// refuse, and never resurrects a record that is gone, so the twelve sequential swap checks stay
/// green while every one of the four methods has the defect its own doc warns about.
#[tokio::test]
async fn swaps_that_compare_and_write_in_separate_steps_are_caught() {
    let violations = run_against(Faults {
        swaps_read_then_write: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "compare_and_swap_authorization_code/atomic_under_a_race",
            "compare_and_swap_client/atomic_under_a_race",
            #[cfg(feature = "consent")]
            "compare_and_swap_consent/atomic_under_a_race",
            "compare_and_swap_device_grant/atomic_under_a_race",
        ],
        "a store whose swaps compare and write in separate steps must fail exactly the four swap \
         race checks and nothing else: {violations:#?}"
    );
    for check in checks_that_fired(&violations) {
        let detail = detail_of(&violations, check);
        assert!(
            detail.contains("were each told they applied"),
            "{check} must report the lost update it found rather than a bare count: {detail}"
        );
    }
}

/// A repeat revocation of one scope that OVERWRITES the barrier already standing for it.
///
/// The store is otherwise correct: it records a barrier for every revocation, it consults it on
/// every write, and it compares the grant instant the right way round. What it does not do is
/// merge, and nothing else in the harness could see that, because every other check records the
/// same window twice and two equal instants take neither branch.
#[tokio::test]
async fn a_repeat_revocation_that_overwrites_the_first_barrier_is_caught() {
    let violations = run_against(Faults {
        barrier_overwritten_by_the_later_write: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["revocation_barrier/repeat_revocation_moves_it"],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "revocation_barrier/repeat_revocation_moves_it");
    // BOTH halves of the merge, because they are two different losses: one admits a grant the
    // second revocation covered, the other reopens the window early.
    assert!(
        detail.contains("BACKWARDS"),
        "the rewound `recorded_at` half must be named: {detail}"
    );
    assert!(
        detail.contains("SHORTENED"),
        "the shortened deadline half must be named too: {detail}"
    );
}

/// A revocation that accepts an EMPTY scope. This divergence already shipped once between the two
/// bundled stores, where `delete_client("")` cascaded everything in memory and deleted nothing
/// through Postgres while returning an error, so a host that tested against one and deployed on
/// the other got neither behaviour.
#[tokio::test]
async fn a_revocation_that_accepts_an_empty_scope_is_caught() {
    let violations = run_against(Faults {
        revocation_accepts_an_empty_scope: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["revocation/refuses_an_empty_scope"],
        "{violations:#?}"
    );
    let detail = detail_of(&violations, "revocation/refuses_an_empty_scope");
    assert!(
        detail.contains("delete_client") && detail.contains("revoke_token_family"),
        "both revocations that take the scope as a parameter must be named: {detail}"
    );
}

// ------------------------------ the swaps the coverage guard alone had been left to speak for

// Ten faults reached `planted_faults()` below and stopped there: the three client swap faults, the
// three code swap faults, the three consent swap faults, and the early barrier sweep. Each of them
// appeared exactly three times in this file, at the `NaiveStore` call site, in the table, and in
// the omnibus store of `every_violation_names_a_published_check`, and nowhere else.
//
// That is one assertion short of what the rest of the file holds itself to. The guard asserts
// `violations.iter().any(|v| v.check == name)`: the name fired. It does not say WHICH of the
// name's `report.fail` sites fired, and it does not say what ELSE fired.
// `compare_and_swap_client/applies_when_it_matches` has five distinct fail sites, so "the name
// fired" narrows a defect to one of five, and the table's own doc claimed the exact sets were
// owned by "the per-fault tests above" when for these ten there were none.
//
// The device grant swap was already held to the exact-set-plus-detail standard
// (`a_swap_that_applies_and_says_it_did_not_is_caught`), so the file had set a standard it did not
// apply to the other three swaps. These ten close that, by the same shape rather than a weaker
// one: the exact set is strictly stronger than a detail substring on the named check, because it
// is the only thing that says a fault did not quietly stop driving one of the checks it used to.
//
// Writing them found one thing the guard could never have: `consent_swap_upserts` and
// `consent_swap_ignores_expected` produced byte-identical violation sets, because the upsert arm
// was written `_` and swallowed the case the other fault owns. Both entries were green, both had
// been green since they were written, and either could have been deleted with no loss. See the
// arm's comment in `compare_and_swap_consent`.

/// RFC 7592 section 2.2 cannot be served at all: every update is refused.
///
/// The mirror of the upsert faults, and the reason each swap needs an APPLIES check next to its
/// refusal ones. This store resurrects nothing and honours every `expected` vacuously, so the two
/// refusal checks certify it.
///
/// `honours_expected` fires here too, and its message is a TRUE statement about the report and a
/// false one about this store: nothing was written, the rename simply never happened, and the
/// harness sees only that the registration does not hold what the earlier apply should have put
/// there. It is asserted by name so the cascade is visible rather than surprising, and the detail
/// asserted below is the one that describes the actual defect.
#[tokio::test]
async fn a_client_swap_that_refuses_every_update_is_caught() {
    let violations = run_against(Faults {
        client_swap_refuses_everything: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "compare_and_swap_client/applies_when_it_matches",
            "compare_and_swap_client/atomic_under_a_race",
            "compare_and_swap_client/honours_expected",
        ],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "compare_and_swap_client/applies_when_it_matches")
            .contains("no RFC 7592 update can ever be recorded"),
        "the violation must name what the host loses: this store cannot perform a client update at \
         all, which is not the same as one that applied and misreported it"
    );
    assert!(
        detail_of(&violations, "compare_and_swap_client/atomic_under_a_race")
            .contains("none of 8 concurrent swaps"),
        "the race detail must distinguish nobody winning from everybody winning: they are opposite \
         defects reported under one name"
    );
}

/// A client swap that compares nothing: it writes whenever the registration is there.
///
/// RFC 7592 section 2.2 updates are read-modify-write, so two administrators editing one
/// registration lose whichever edit landed first, silently and with both told they succeeded.
#[tokio::test]
async fn a_client_swap_that_ignores_the_expected_registration_is_caught() {
    let violations = run_against(Faults {
        client_swap_ignores_expected: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "compare_and_swap_client/atomic_under_a_race",
            "compare_and_swap_client/honours_expected",
        ],
        "the APPLIES check must stay green here: this store does apply matching swaps, and a test \
         that let that check fire would prove nothing about `expected`: {violations:#?}"
    );
    assert!(
        detail_of(&violations, "compare_and_swap_client/honours_expected")
            .contains("two concurrent RFC 7592 updates silently lose one"),
        "the violation must name the lost update rather than reporting that a bool differed"
    );
    assert!(
        detail_of(&violations, "compare_and_swap_client/atomic_under_a_race")
            .contains("8 of 8 concurrent swaps"),
        "the race detail must say that EVERY racer was told it won, which is the read-then-write \
         signature and the opposite of the refuse-everything one"
    );
}

/// A client swap implemented as an upsert: it compares, then writes whether or not the row is
/// there.
///
/// RFC 7592 section 2.3 deletion is how an administrator answers a compromised client, and this
/// store undoes it: a swap against the deleted registration brings it back with its old credential
/// and its old registration access token hash, so whoever holds the stolen token is still holding
/// it.
#[tokio::test]
async fn a_client_swap_that_upserts_a_deleted_registration_is_caught() {
    let violations = run_against(Faults {
        client_swap_upserts: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["compare_and_swap_client/never_resurrects"],
        "this store is atomic, applies matching swaps, and honours `expected` while the row is \
         there: only the resurrection check can see it: {violations:#?}"
    );
    let detail = detail_of(&violations, "compare_and_swap_client/never_resurrects");
    assert!(
        detail.contains(
            "deleting a compromised client is defeatable by whoever holds the stolen \
             token"
        ),
        "the violation must name the credential that came back with the row, not merely that a \
         record reappeared: {detail}"
    );
}

/// An authorization code swap that refuses everything, so RFC 6749 section 4.1.3 redemption can
/// never record what it minted.
///
/// The code record's state machine is written entirely through this method, so a store that never
/// applies has no way to mark a code redeemed, and the replay containment of RFC 6749 section
/// 10.5 has nothing to read.
#[tokio::test]
async fn a_code_swap_that_refuses_every_redemption_is_caught() {
    let violations = run_against(Faults {
        code_swap_refuses_everything: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "compare_and_swap_authorization_code/applies_when_it_matches",
            "compare_and_swap_authorization_code/atomic_under_a_race",
        ],
        "{violations:#?}"
    );
    assert!(
        detail_of(
            &violations,
            "compare_and_swap_authorization_code/applies_when_it_matches"
        )
        .contains("a redemption can never record what it minted"),
        "the violation must name what the host loses"
    );
    assert!(
        detail_of(
            &violations,
            "compare_and_swap_authorization_code/atomic_under_a_race"
        )
        .contains("none of 8 concurrent swaps"),
        "the race detail must distinguish nobody winning from everybody winning"
    );
}

/// An authorization code swap that ignores `expected`.
///
/// This is the one that costs the most: RFC 6749 section 10.5 containment works by a redemption
/// moving the record off the state a concurrent replay left there. A store that writes anyway lets
/// a redemption suspended in the host's signer overwrite the replay's trace and then hand out the
/// very tokens the replay was containing.
#[tokio::test]
async fn a_code_swap_that_ignores_the_expected_state_is_caught() {
    let violations = run_against(Faults {
        code_swap_ignores_expected: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "compare_and_swap_authorization_code/atomic_under_a_race",
            "compare_and_swap_authorization_code/honours_expected",
        ],
        "the APPLIES check must stay green: this store applies matching swaps: {violations:#?}"
    );
    assert!(
        detail_of(
            &violations,
            "compare_and_swap_authorization_code/honours_expected"
        )
        .contains("hands out the very tokens the replay was containing"),
        "the violation must say what a lost comparison costs on this method specifically"
    );
}

/// An authorization code swap implemented as an upsert, so a code that a withdrawal, a client
/// deletion or a sweep removed is written back and is redeemable again.
#[tokio::test]
async fn a_code_swap_that_upserts_a_removed_code_is_caught() {
    let violations = run_against(Faults {
        code_swap_upserts: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["compare_and_swap_authorization_code/never_resurrects"],
        "{violations:#?}"
    );
    let detail = detail_of(
        &violations,
        "compare_and_swap_authorization_code/never_resurrects",
    );
    assert!(
        detail.contains(
            "a code a withdrawal or a client deletion cascaded away is redeemable \
             again"
        ),
        "the violation must name the cascade the resurrection defeats: {detail}"
    );
}

/// A consent swap that refuses everything, so a first approval can never be recorded and the
/// authorization endpoint prompts the same user for the same scopes forever.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_consent_swap_that_refuses_every_approval_is_caught() {
    let violations = run_against(Faults {
        consent_swap_refuses_everything: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["compare_and_swap_consent/applies_when_it_matches"],
        "the refusal checks are all vacuously satisfied by a store that never writes, which is why \
         the APPLIES check exists and why it must be the only one here: {violations:#?}"
    );
    assert!(
        detail_of(
            &violations,
            "compare_and_swap_consent/applies_when_it_matches"
        )
        .contains("a first approval can never be recorded"),
        "the violation must name the approval that is lost"
    );
}

/// A consent swap that writes whenever the pair holds a consent, whatever `expected` said.
///
/// The pair ends up holding TWO live consents, and a user withdrawing one is told they revoked an
/// application that the other still authorizes. The resurrection failures that follow are that
/// same duplicate outliving the withdrawal, so they are asserted here rather than treated as a
/// second defect.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_consent_swap_that_ignores_the_expected_consent_is_caught() {
    let violations = run_against(Faults {
        consent_swap_ignores_expected: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec![
            "compare_and_swap_consent/atomic_under_a_race",
            "compare_and_swap_consent/honours_expected",
            "compare_and_swap_consent/never_resurrects",
        ],
        "{violations:#?}"
    );
    assert!(
        detail_of(&violations, "compare_and_swap_consent/honours_expected")
            .contains("the pair now has two"),
        "the violation must say that the pair ends up holding two live consents, which is the \
         thing a user cannot see and cannot withdraw"
    );
}

/// A consent swap implemented as an upsert, and the ONLY fault of the three that is about a pair
/// holding nothing: a widen whose `expected` names a consent the user withdrew is performed rather
/// than refused, so the record they destroyed answers every later authorization request.
///
/// The exact set below is what separates this fault from `consent_swap_ignores_expected`. Until
/// the upsert arm was scoped to `(None, _)` the two produced identical sets and this assertion
/// would have failed, which is the whole reason to assert the set rather than the name.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_consent_swap_that_upserts_a_withdrawn_consent_is_caught() {
    let violations = run_against(Faults {
        consent_swap_upserts: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["compare_and_swap_consent/never_resurrects"],
        "this store honours `expected` while the consent is there and is atomic under a race: only \
         the resurrection check can see it: {violations:#?}"
    );
    let detail = detail_of(&violations, "compare_and_swap_consent/never_resurrects");
    assert!(
        detail.contains("a widen applied against a consent that had been WITHDRAWN")
            && detail.contains("a withdrawn consent is live again after a swap"),
        "BOTH halves must fire: the swap answering `Ok(true)` is the report, and `find_consent` \
         answering with the record afterwards is the consequence, and a store could produce either \
         without the other: {detail}"
    );
}

/// A sweep that reclaims a revocation barrier BEFORE its deadline.
///
/// The dangerous direction, and the one that looks like tidiness: the barrier exists to refuse a
/// write that was already in flight when the revocation landed, so reclaiming it early reopens
/// exactly the window it was recorded to close, and the store looks cleaner for it.
#[tokio::test]
async fn a_sweep_that_reaps_a_barrier_before_its_deadline_is_caught() {
    let violations = run_against(Faults {
        sweep_reaps_barriers_early: true,
        ..Faults::default()
    })
    .await;

    assert_eq!(
        checks_that_fired(&violations),
        vec!["revocation_barrier/kept_before_its_deadline"],
        "the sweep is otherwise correct, and the count it reports is correct too: only the barrier \
         deadline check can see this: {violations:#?}"
    );
    assert!(
        detail_of(&violations, "revocation_barrier/kept_before_its_deadline")
            .contains("the window the barrier exists to close has been reopened early"),
        "the violation must say the window reopened, not that a row count differed: an operator \
         reading this needs to know a revoked credential can be written again"
    );
}

// ---------------------------------------------------------- the coverage guard

/// How one published check is driven RED. Almost every check is driven by a store fault; the two
/// `harness/*` checks are not about the store at all, so they carry their own driver rather than
/// being forced into a `Faults` field that would not mean anything.
#[derive(Clone, Copy)]
enum Plant {
    /// One `Faults` value, run the ordinary cooperative way.
    Store(Faults),
    /// A CORRECT store, run through a spawner that runs its racers strictly one at a time.
    SequentialSpawner,
    /// A store whose racer panics, handed to a real runtime, where the panic unwinds out of the
    /// harness's sight.
    PanickingRacer,
}

async fn drive(plant: Plant) -> Vec<Violation> {
    match plant {
        Plant::Store(faults) => run_against(faults).await,
        Plant::SequentialSpawner => {
            StorageConformance::new(|| async { MemoryStorage::new() })
                .with_spawn(|task| {
                    std::thread::spawn(move || {
                        tokio::runtime::Builder::new_current_thread()
                            .build()
                            .expect("current-thread runtime")
                            .block_on(task);
                    })
                    .join()
                    .expect("racer thread");
                })
                .racers(2)
                .run()
                .await
        }
        Plant::PanickingRacer => {
            StorageConformance::new(|| async {
                NaiveStore::new(Faults {
                    the_refresh_take_panics: true,
                    ..Faults::default()
                })
            })
            .with_spawn(|task| {
                tokio::spawn(task);
            })
            .racers(4)
            .run()
            .await
        }
    }
}

/// A `Faults` with one field set, since that is all a table entry ever needs.
macro_rules! plant {
    ($field:ident) => {
        Plant::Store(Faults {
            $field: true,
            ..Faults::default()
        })
    };
}

/// THE ONE LIST: every check the harness publishes, paired with the fault that drives it red.
///
/// It is the only place a check name and the thing that makes it fail are written down together,
/// and `every_check_has_a_planted_fault` RUNS all of it. Comparing `CHECKS` against a list of
/// NAMES would prove only that somebody had typed the name: an entry whose fault had rotted, or
/// whose `#[test]` had been deleted, would pass in silence. That is the shape of overclaim this
/// file exists to refuse, so the guard drives every entry rather than reading it.
///
/// Several entries name a fault that necessarily trips a NEIGHBOURING check too (a sweep that
/// removes nothing cannot report the right count). That is fine here: this guard asserts the named
/// check is AMONG what fired, and the per-fault tests above own the exact sets.
///
/// That last sentence was an overclaim for a long time. Ten faults in this table had no test above
/// them at all: the three client swap faults, the three code swap faults, the three consent swap
/// faults, and `sweep_reaps_barriers_early`. For those ten, "the name fired" was the only thing
/// anybody had ever asserted, and `compare_and_swap_client/applies_when_it_matches` alone has five
/// distinct `report.fail` sites, so it narrowed a defect to one of five and said nothing about
/// what else the fault had stopped driving. It is true now, and it is worth keeping true: a new
/// entry here without a test above it puts the sentence back into overclaim.
fn planted_faults() -> Vec<(&'static str, Plant)> {
    #[allow(unused_mut)]
    let mut planted: Vec<(&'static str, Plant)> = vec![
        ("harness/race_setup", Plant::SequentialSpawner),
        ("harness/racer_panicked", Plant::PanickingRacer),
        ("round_trip/client", plant!(drops_the_client_secret)),
        (
            "round_trip/device_grant",
            plant!(drops_the_device_grant_interval),
        ),
        (
            "round_trip/authorization_code",
            plant!(drops_the_code_challenge),
        ),
        ("round_trip/token", plant!(drops_the_token_resource)),
        ("round_trip/refresh_token", plant!(drops_family_id)),
        ("atomic_take/take_device_grant", plant!(read_then_delete)),
        ("atomic_take/take_refresh_token", plant!(read_then_delete)),
        (
            "atomic_take/take_authorization_code",
            plant!(read_then_delete),
        ),
        (
            "compare_and_swap_device_grant/applies_when_the_state_matches",
            plant!(swap_reports_that_it_did_not_apply),
        ),
        (
            "compare_and_swap_device_grant/honours_expected",
            plant!(swap_ignores_expected),
        ),
        (
            "compare_and_swap_device_grant/never_resurrects",
            plant!(swap_resurrects_taken_grants),
        ),
        (
            "compare_and_swap_device_grant/retires_the_old_user_code",
            plant!(swap_leaves_the_old_user_code_indexed),
        ),
        (
            "compare_and_swap_device_grant/refuses_a_duplicate_user_code",
            plant!(swap_repoints_a_duplicate_user_code),
        ),
        (
            "user_code_index/retires_old_entry",
            plant!(index_overwrites),
        ),
        (
            "user_code_index/refuses_duplicate",
            plant!(index_overwrites),
        ),
        (
            "user_code_index/refusal_writes_nothing",
            plant!(refusal_repoints_the_index),
        ),
        (
            "user_code_index/cleared_by_take",
            plant!(index_outlives_the_taken_grant),
        ),
        (
            "user_code_index/store_does_not_normalize",
            plant!(normalizes_user_codes),
        ),
        ("sweep_expired/removes_dead", plant!(sweep_removes_nothing)),
        ("sweep_expired/keeps_live", plant!(sweep_removes_everything)),
        ("sweep_expired/count", plant!(sweep_removes_nothing)),
        (
            "sweep_expired/empty_is_zero",
            plant!(sweep_errors_when_it_removed_nothing),
        ),
        (
            "sweep_expired/safe_under_concurrent_writes",
            plant!(sweep_rebuilds_the_token_table_from_a_snapshot),
        ),
        (
            "revoke_token_family/removes_the_family",
            plant!(family_revocation_spares_access_tokens),
        ),
        (
            "revoke_token_family/spares_other_families",
            plant!(family_revocation_takes_every_family),
        ),
        (
            "revoke_token_family/count",
            plant!(family_revocation_spares_access_tokens),
        ),
        (
            "delete_client/cascades",
            plant!(delete_client_leaves_credentials),
        ),
        (
            "delete_client/reports_whether_it_removed",
            plant!(delete_client_always_reports_true),
        ),
        // TWICE, for the reason the replay claim is: the check names two answers and a fault for
        // one leaves the other's branch unwatched. This entry drives the "was present" half.
        (
            "delete_client/reports_whether_it_removed",
            plant!(delete_client_always_reports_false),
        ),
        (
            "delete_token/idempotent",
            plant!(delete_token_errors_when_absent),
        ),
    ];

    #[cfg(any(feature = "client-assertion", feature = "dpop"))]
    planted.extend([
        (
            "atomic_claim/claim_replay_id",
            plant!(look_then_insert_claim),
        ),
        (
            "claim_replay_id/refuses_a_second_claim",
            plant!(claim_is_keyed_on_nothing),
        ),
        // TWICE, and deliberately: this name carries two independent refusals, and a fault for one
        // of them leaves the other unwatched. `claim_is_keyed_on_nothing` drives the branch that
        // refuses an id the store has never seen; this one drives the branch that ADMITS a repeat,
        // which is the replay itself and the reason the check is named what it is.
        (
            "claim_replay_id/refuses_a_second_claim",
            plant!(claim_forgets_what_it_claimed),
        ),
        (
            "sweep_expired/reclaims_replay_ids",
            plant!(sweep_forgets_replay_ids),
        ),
    ]);

    // The RFC 8693 delegation chain: one more column of the same record, and the only feature-gated
    // one the round trip compared with nothing planted behind it.
    #[cfg(feature = "token-exchange")]
    planted.push(("round_trip/token", plant!(drops_act_on_tokens)));

    #[cfg(feature = "par")]
    planted.extend([
        (
            "atomic_take/take_pushed_authorization_request",
            plant!(read_then_delete),
        ),
        (
            "round_trip/pushed_authorization_request",
            plant!(drops_the_pushed_code_challenge),
        ),
        (
            "sweep_expired/reclaims_pushed_requests",
            plant!(sweep_forgets_pushed_requests),
        ),
        // The SEVENTH site: the one write on a revocable record that the 0.9.1 enumeration missed
        // altogether, and that had no check of its own until the `delete_client` cascade grew one.
        (
            "revocation_barrier/refuses_put_pushed_authorization_request",
            plant!(put_ignores_barriers),
        ),
    ]);

    #[cfg(feature = "consent")]
    planted.extend([
        ("round_trip/consent", plant!(find_consent_never_finds)),
        (
            "consents_for_subject/lists_that_subjects_consents",
            plant!(consents_for_subject_returns_nothing),
        ),
        (
            "revoke_consent/cascades",
            plant!(withdrawal_leaves_credentials),
        ),
        (
            "revoke_consent/spares_other_subjects",
            plant!(withdrawal_takes_other_subjects),
        ),
        (
            "revoke_consent/count",
            plant!(withdrawal_counts_the_consent_row),
        ),
        (
            "compare_and_swap_consent/applies_when_it_matches",
            plant!(consent_swap_refuses_everything),
        ),
        (
            "compare_and_swap_consent/honours_expected",
            plant!(consent_swap_ignores_expected),
        ),
        (
            "compare_and_swap_consent/never_resurrects",
            plant!(consent_swap_upserts),
        ),
        (
            "compare_and_swap_consent/atomic_under_a_race",
            plant!(swaps_read_then_write),
        ),
    ]);

    // THE RESURRECTION RULE. Each of these is a store that passes every cascade check in the
    // harness and still loses every revocation it makes, which is exactly why the checks had to
    // be added: the cascade is correct, and the write that undoes it arrives afterwards.
    planted.extend([
        (
            "revocation_barrier/refuses_put_token",
            plant!(put_ignores_barriers),
        ),
        (
            "revocation_barrier/refuses_put_refresh_token",
            plant!(put_ignores_barriers),
        ),
        (
            "revocation_barrier/spares_unrelated_records",
            plant!(put_refuses_everything),
        ),
        (
            "revocation_barrier/admits_a_later_grant",
            plant!(barrier_refuses_on_identity_alone),
        ),
        (
            "revocation_barrier/repeat_revocation_moves_it",
            plant!(barrier_overwritten_by_the_later_write),
        ),
        (
            "revocation_barrier/swept_at_its_deadline",
            plant!(sweep_forgets_barriers),
        ),
        (
            "revocation_barrier/kept_before_its_deadline",
            plant!(sweep_reaps_barriers_early),
        ),
        (
            "revocation/refuses_an_empty_scope",
            plant!(revocation_accepts_an_empty_scope),
        ),
        (
            "compare_and_swap_device_grant/atomic_under_a_race",
            plant!(swaps_read_then_write),
        ),
        (
            "compare_and_swap_client/atomic_under_a_race",
            plant!(swaps_read_then_write),
        ),
        (
            "compare_and_swap_authorization_code/atomic_under_a_race",
            plant!(swaps_read_then_write),
        ),
        (
            "compare_and_swap_client/applies_when_it_matches",
            plant!(client_swap_refuses_everything),
        ),
        (
            "compare_and_swap_client/honours_expected",
            plant!(client_swap_ignores_expected),
        ),
        (
            "compare_and_swap_client/never_resurrects",
            plant!(client_swap_upserts),
        ),
        (
            "compare_and_swap_authorization_code/applies_when_it_matches",
            plant!(code_swap_refuses_everything),
        ),
        (
            "compare_and_swap_authorization_code/honours_expected",
            plant!(code_swap_ignores_expected),
        ),
        (
            "compare_and_swap_authorization_code/never_resurrects",
            plant!(code_swap_upserts),
        ),
    ]);

    planted
}

/// The checks `CHECKS` publishes that this BUILD cannot run, and the ONLY reason a name is
/// allowed to have no planted fault.
///
/// `CHECKS` is deliberately unconditional (see its documentation: a host's waiver list should not
/// have to be feature-conditional to be valid), but the checks behind these names are compiled out
/// when their feature is off, so no fault can drive them red here. The exemption is therefore a
/// consequence of that design and not a waiver anybody chose, and it is stated as a RULE with the
/// feature that governs it: turn the feature on and the name is required again, which is what
/// `cargo test --all-features` does. Every name here is pinned against `CHECKS` below, so a rename
/// breaks this list rather than silently widening it.
fn not_runnable_in_this_build() -> Vec<&'static str> {
    #[allow(unused_mut)]
    let mut names: Vec<&'static str> = Vec::new();
    #[cfg(not(any(feature = "client-assertion", feature = "dpop")))]
    names.extend([
        "atomic_claim/claim_replay_id",
        "claim_replay_id/refuses_a_second_claim",
        "sweep_expired/reclaims_replay_ids",
    ]);
    #[cfg(not(feature = "par"))]
    names.extend([
        "atomic_take/take_pushed_authorization_request",
        "round_trip/pushed_authorization_request",
        "sweep_expired/reclaims_pushed_requests",
        "revocation_barrier/refuses_put_pushed_authorization_request",
    ]);
    #[cfg(not(feature = "consent"))]
    names.extend([
        "compare_and_swap_consent/applies_when_it_matches",
        "compare_and_swap_consent/honours_expected",
        "compare_and_swap_consent/never_resurrects",
        "compare_and_swap_consent/atomic_under_a_race",
        "round_trip/consent",
        "consents_for_subject/lists_that_subjects_consents",
        "revoke_consent/cascades",
        "revoke_consent/spares_other_subjects",
        "revoke_consent/count",
    ]);
    names
}

/// THE GUARD, and it means what it is called: for every check this harness publishes and this
/// build runs, a fault is planted AND driven, here, and observed to make that check go red.
///
/// It exists because a check with no fault behind it had already shipped in the published `CHECKS`
/// list, twice: nine of them once (see the section above), and
/// `compare_and_swap_device_grant/applies_when_the_state_matches` again after that. A host who
/// runs this harness against their own store reads a green from every name in `CHECKS`, so a name
/// nobody has watched fail is a green that means nothing, about a stranger's store, reported by
/// us.
///
/// All three directions are asserted. A check with no entry is a check nobody has watched fail. An
/// entry naming a check `CHECKS` does not contain is a fault aimed at nothing, which is how a
/// table stays green while the thing it guards was renamed out from under it. And every entry is
/// RUN, because "has a planted fault" must not degrade into "has a name in a list".
#[tokio::test]
async fn every_check_has_a_planted_fault() {
    let planted = planted_faults();
    let exempt = not_runnable_in_this_build();

    let mut rotted: Vec<&str> = exempt
        .iter()
        .copied()
        .filter(|name| !CHECKS.contains(name))
        .collect();
    rotted.sort_unstable();
    assert!(
        rotted.is_empty(),
        "these names are exempted as not-compiled-in-this-build but are not in CHECKS at all, so \
         the exemption list has rotted and may now be hiding a real gap: {rotted:?}"
    );

    let mut missing: Vec<&str> = CHECKS
        .iter()
        .copied()
        .filter(|c| !exempt.contains(c))
        .filter(|c| !planted.iter().any(|(name, _)| name == c))
        .collect();
    missing.sort_unstable();
    assert!(
        missing.is_empty(),
        "these published checks have no planted fault, so nobody has watched them fail and every \
         host running this harness gets a green from them that means nothing: {missing:?}"
    );

    let mut aimed_at_nothing: Vec<&str> = planted
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| !CHECKS.contains(name))
        .collect();
    aimed_at_nothing.sort_unstable();
    assert!(
        aimed_at_nothing.is_empty(),
        "these entries name a check the harness does not publish, so the fault proves nothing: \
         {aimed_at_nothing:?}"
    );

    // And RUN every one. Without this, "has a planted fault" would mean "has a name in a list",
    // and a fault that no longer worked would never say so.
    for (name, plant) in planted {
        let violations = drive(plant).await;
        assert!(
            violations.iter().any(|v| v.check == name),
            "the planted fault for {name} did not make it go red; the harness reported {:?}",
            checks_that_fired(&violations)
        );
    }
}
