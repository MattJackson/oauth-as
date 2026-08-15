// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A RUNNABLE conformance harness for the [`Storage`] contract, behind the `test-util` cargo
//! feature (off by default), for a HOST to run from its OWN test suite against its OWN store.
//!
//! Nothing here is re-exported at the crate root, on purpose: `Violation` and `CHECKS` are generic
//! words that only mean something next to the thing they describe, and a host names this surface
//! once, in a test.
//!
//! # Why this exists
//!
//! [`crate::store`] documents the contract in prose, and prose is the version of a contract that
//! nobody has to keep. The load-bearing clause is that `take_device_grant`,
//! `take_refresh_token` and `take_authorization_code` are ATOMIC remove-and-return. A host that
//! implements them as read-then-delete gets three failures that a single-node test suite cannot
//! see and that production will not report:
//!
//! - REFRESH TOKEN DOUBLE SPEND. Two nodes read the same record, both delete it, both rotate. The
//!   attacker and the honest client each end up holding a live chain, and because the honest
//!   client is never locked out, the one observable signal that would have revealed the theft
//!   (RFC 9700 section 4.14.2 reuse detection) never fires.
//! - AUTHORIZATION CODE REPLAY DETECTION SILENTLY DISABLED. Two nodes take the same `Issued`
//!   record, both mint, both write back `Consumed`, last write wins. The server believes the code
//!   was spent once.
//! - DEVICE GRANT DOUBLE ISSUANCE, the same shape at the RFC 8628 redemption.
//!
//! `Storage::claim_replay_id` (compiled in with `client-assertion` or `dpop`) is the same defect
//! shape and is checked the same way: RFC 7523 section 3 and RFC 9449 section 4.3 both make a
//! `jti` single use, and a read-then-write claim tells two concurrent presentations of the SAME
//! assertion that each of them was the first.
//!
//! Nothing inside this crate can detect any of that: the server calls `take_*` and is entitled to
//! believe the answer. So the check has to run where the host's store is, which is what this
//! module is for.
//!
//! # Using it
//!
//! ```toml
//! [dev-dependencies]
//! oauth-as = { version = "*", features = ["test-util"] }
//! ```
//!
//! ```no_run
//! use oauth_as::storage_conformance::StorageConformance;
//!
//! # async fn my_store() -> oauth_as::MemoryStorage { oauth_as::MemoryStorage::new() }
//! # async fn doc() {
//! // The factory MUST return a store that is EMPTY: several checks count records, and a
//! // leftover row from a previous check is indistinguishable from a store that failed to
//! // remove one.
//! let violations = StorageConformance::new(|| async { my_store().await })
//!     // Hand the racers to your own runtime. On a multi-threaded one this is what makes the
//!     // atomicity checks a real race rather than an interleaving.
//!     .with_spawn(|task| {
//!         tokio::spawn(task);
//!     })
//!     .run()
//!     .await;
//! assert!(violations.is_empty(), "{violations:#?}");
//! # }
//! ```
//!
//! It RETURNS the violations rather than panicking, so a host can report them the way it likes:
//! assert on emptiness, print them, feed them to its own reporter, or accept a documented subset.
//! Every violation names a check from [`CHECKS`] plus a human-readable detail.
//!
//! # What the concurrency checks can and cannot prove
//!
//! Read this before quoting a green run at anyone. The honest summary is that this harness proves
//! a store is atomic ACROSS AWAIT POINTS, and cannot prove it is atomic across machines.
//!
//! WHAT IT DOES. Each `take_*` check builds N racing futures. Every racer first parks on a
//! rendezvous gate and does not touch the store until all N have arrived, so the takes are all in
//! flight at once rather than being run one after another. Then:
//!
//! - With [`StorageConformance::with_spawn`], the racers are handed to the HOST'S runtime as
//!   independent tasks. On a multi-threaded runtime that is a genuine data race on real threads,
//!   which is the strongest form of this check and the one worth running in a host's CI.
//! - Without a spawner, the racers are polled concurrently on the caller's own task by a
//!   join combinator in this module. That is interleaving, not parallelism.
//!
//! WHAT THE COOPERATIVE (no spawner) MODE STILL CATCHES, and why it is not a token gesture: a
//! read-then-delete implementation over a network store awaits between the read and the delete,
//! because the read is a round trip. At that await the racer yields, the next racer is polled and
//! performs its own read, and every racer observes the value before any of them removes it. So
//! interleaving is enough to catch the real-world shape of this bug in any store whose operations
//! actually suspend.
//!
//! WHAT NEITHER MODE CAN PROVE:
//!
//! - It cannot prove a store is atomic across PROCESSES or NODES, which is the deployment where
//!   the bug bites. Two racers inside one test process share whatever in-process lock the store
//!   holds; a mutex around a read-then-delete pair will pass this harness and still double-spend
//!   from two nodes. If the store's atomicity comes from a process-local lock rather than from
//!   the DATABASE (`DELETE ... RETURNING`, a conditional update, a compare-and-set), this harness
//!   will not tell you. Run it against the store the way it is deployed, and read the query.
//! - The cooperative mode cannot catch a store that performs read-then-delete with NO suspension
//!   point in between (a purely synchronous `async fn` over an in-process map). Such a store is
//!   in practice atomic anyway, since nothing can interleave with it, but the check passing is
//!   not evidence about the shared-store implementation the host will deploy.
//! - Passing once is not passing always. A race that loses is still a race; N is 8 by default and
//!   raisable with [`StorageConformance::racers`], and a host that cares should run this
//!   repeatedly rather than once.
//! - Nothing here observes the store's isolation level, its retry behaviour, or what it does when
//!   the connection drops mid-operation.
//!
//! If the rendezvous gate cannot be satisfied (a `with_spawn` that runs tasks strictly one after
//! another to completion, so no two racers are ever in flight), the harness reports
//! `harness/race_setup` and the atomicity results in that run mean nothing. That is deliberately a
//! reported violation rather than a silent pass.
//!
//! # Cost when you do not enable it
//!
//! Nothing. `test-util` adds no dependency and no code to a default build; the whole module is
//! behind the feature.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, SystemTime};

use crate::authorization::{AuthorizationCodeRecord, AuthorizationCodeState, CodeChallengeMethod};
use crate::client::{Client, ClientAuth, ClientId, DynamicRegistration, SecretHash};
use crate::device::{normalize_user_code, DeviceGrant, DeviceGrantState};
use crate::grant::GrantType;
use crate::scope::ScopeSet;
use crate::store::{Storage, StorageError, WriteOutcome};
use crate::token::{IssuedToken, RefreshTokenRecord, RefreshTokenState};

/// One way in which a store failed the [`Storage`] contract.
///
/// `check` is one of [`CHECKS`], so a host can group, filter or waive by a stable name; `detail`
/// says what was observed and what was required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// The check that failed; always a member of [`CHECKS`].
    pub check: &'static str,
    /// What went wrong, in terms of what was stored and what came back.
    pub detail: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.check, self.detail)
    }
}

/// Every check name [`StorageConformance::run`] can report, so a host can assert that a name it
/// filters on still exists rather than silently waiving a check that was renamed.
///
/// The `claim_replay_id` names are listed unconditionally even though the checks themselves only
/// run when `client-assertion` or `dpop` is compiled in: a host's waiver list should not have to
/// be feature-conditional to be valid.
pub const CHECKS: &[&str] = &[
    HARNESS_RACE_SETUP,
    HARNESS_RACER_PANICKED,
    ROUND_TRIP_CLIENT,
    ROUND_TRIP_DEVICE_GRANT,
    ROUND_TRIP_AUTHORIZATION_CODE,
    ROUND_TRIP_TOKEN,
    ROUND_TRIP_REFRESH_TOKEN,
    ATOMIC_TAKE_DEVICE_GRANT,
    SWAP_APPLIES_ON_MATCH,
    SWAP_HONOURS_EXPECTED,
    SWAP_NEVER_RESURRECTS,
    SWAP_RETIRES_OLD_USER_CODE,
    SWAP_REFUSES_DUPLICATE_USER_CODE,
    ATOMIC_TAKE_REFRESH_TOKEN,
    ATOMIC_TAKE_AUTHORIZATION_CODE,
    INDEX_RETIRES_OLD_USER_CODE,
    INDEX_REFUSES_DUPLICATE_USER_CODE,
    INDEX_REFUSAL_WRITES_NOTHING,
    INDEX_CLEARED_BY_TAKE,
    INDEX_NO_NORMALIZATION,
    SWEEP_REMOVES_DEAD,
    SWEEP_KEEPS_LIVE,
    SWEEP_COUNT,
    SWEEP_EMPTY_IS_ZERO,
    SWEEP_CONCURRENT_WRITES,
    SWEEP_RECLAIMS_PUSHED_REQUESTS,
    REVOKE_FAMILY_REMOVES,
    REVOKE_FAMILY_SPARES_OTHERS,
    REVOKE_FAMILY_COUNT,
    DELETE_CLIENT_CASCADES,
    DELETE_CLIENT_REPORTS,
    DELETE_TOKEN_IDEMPOTENT,
    ATOMIC_CLAIM_REPLAY_ID,
    CLAIM_REPLAY_ID_REFUSES_SECOND,
    SWEEP_RECLAIMS_REPLAY_IDS,
    ATOMIC_TAKE_PUSHED_REQUEST,
    ROUND_TRIP_PUSHED_REQUEST,
    ROUND_TRIP_CONSENT,
    CONSENTS_FOR_SUBJECT,
    REVOKE_CONSENT_CASCADES,
    REVOKE_CONSENT_SPARES_OTHERS,
    REVOKE_CONSENT_COUNT,
    BARRIER_REFUSES_TOKEN,
    BARRIER_REFUSES_REFRESH,
    BARRIER_REFUSES_PUSHED_REQUEST,
    BARRIER_SPARES_UNRELATED,
    BARRIER_ADMITS_A_LATER_GRANT,
    BARRIER_REPEAT_REVOCATION_MOVES_IT,
    BARRIER_SWEPT_AT_DEADLINE,
    BARRIER_KEPT_BEFORE_DEADLINE,
    REVOCATION_REFUSES_EMPTY_SCOPE,
    CLIENT_SWAP_APPLIES,
    CLIENT_SWAP_HONOURS_EXPECTED,
    CLIENT_SWAP_NEVER_RESURRECTS,
    CLIENT_SWAP_ATOMIC,
    CODE_SWAP_APPLIES,
    CODE_SWAP_HONOURS_EXPECTED,
    CODE_SWAP_NEVER_RESURRECTS,
    CODE_SWAP_ATOMIC,
    CONSENT_SWAP_APPLIES,
    CONSENT_SWAP_HONOURS_EXPECTED,
    CONSENT_SWAP_NEVER_RESURRECTS,
    CONSENT_SWAP_ATOMIC,
    SWAP_ATOMIC,
];

// ------------------------------------------------------- the resurrection rule (0.9.1)
//
// A WRITE MUST NOT RESURRECT STATE THAT A REVOCATION REMOVED. See the `crate::store` module docs
// for the rule in full. These are the checks a HOST needs, and until 0.9.1 there were none: the
// rule was implemented and tested inside this crate while `check_storage` told a stranger's store
// nothing about it at all.
//
// The failure they catch is invisible to every other check in this file, and that is the point. A
// store can pass the whole cascade suite and still lose every revocation it makes, because a
// cascade only reaches what is IN the store when it runs, and the write that undoes it arrives
// afterwards from a request that was already in flight.

/// A barrier recorded by a revocation must refuse a later `put_token` for a covered record.
const BARRIER_REFUSES_TOKEN: &str = "revocation_barrier/refuses_put_token";
/// The same for `put_refresh_token`, which is the write every rotation refusal path makes.
const BARRIER_REFUSES_REFRESH: &str = "revocation_barrier/refuses_put_refresh_token";
/// And the same for the pushed request, which is the SEVENTH site the 0.9.1 enumeration missed.
const BARRIER_REFUSES_PUSHED_REQUEST: &str =
    "revocation_barrier/refuses_put_pushed_authorization_request";
/// And it must refuse only what it covers: a store that refuses everything also fails.
const BARRIER_SPARES_UNRELATED: &str = "revocation_barrier/spares_unrelated_records";
/// A `client` or `consent` barrier must ADMIT a grant established after the revocation.
const BARRIER_ADMITS_A_LATER_GRANT: &str = "revocation_barrier/admits_a_later_grant";
/// A second revocation of one scope must not SHORTEN the first, nor rewind its `recorded_at`.
const BARRIER_REPEAT_REVOCATION_MOVES_IT: &str = "revocation_barrier/repeat_revocation_moves_it";
/// Barriers are rows nothing else removes, so the sweep must reclaim them, and count them.
const BARRIER_SWEPT_AT_DEADLINE: &str = "revocation_barrier/swept_at_its_deadline";
/// Reaping one EARLY reopens the window it was recorded to close.
const BARRIER_KEPT_BEFORE_DEADLINE: &str = "revocation_barrier/kept_before_its_deadline";
/// The empty string does not name an identity, so no revocation may be recorded for it.
const REVOCATION_REFUSES_EMPTY_SCOPE: &str = "revocation/refuses_an_empty_scope";

const CLIENT_SWAP_APPLIES: &str = "compare_and_swap_client/applies_when_it_matches";
const CLIENT_SWAP_HONOURS_EXPECTED: &str = "compare_and_swap_client/honours_expected";
const CLIENT_SWAP_NEVER_RESURRECTS: &str = "compare_and_swap_client/never_resurrects";

const CODE_SWAP_APPLIES: &str = "compare_and_swap_authorization_code/applies_when_it_matches";
const CODE_SWAP_HONOURS_EXPECTED: &str = "compare_and_swap_authorization_code/honours_expected";
const CODE_SWAP_NEVER_RESURRECTS: &str = "compare_and_swap_authorization_code/never_resurrects";

const CONSENT_SWAP_APPLIES: &str = "compare_and_swap_consent/applies_when_it_matches";
const CONSENT_SWAP_HONOURS_EXPECTED: &str = "compare_and_swap_consent/honours_expected";
const CONSENT_SWAP_NEVER_RESURRECTS: &str = "compare_and_swap_consent/never_resurrects";

// ------------------------------------------------- the atomicity all four swaps REQUIRE
//
// "The comparison and the write MUST happen as ONE atomic step. A store that reads, compares, and
// then writes separately has reintroduced precisely the window this closes, and it will do so
// silently." That sentence is on all four `compare_and_swap_*` methods, and until these four
// checks existed NOTHING raced any of them: every swap check was a sequential put, swap, read
// back, which a read-then-compare-then-write store passes without a mark against it.
//
// The interleaving is the one `compare_and_swap_device_grant`'s own doc says the deleted default
// shim was deleted for: a poll whose read saw `Pending` lands its write after the user clicked
// deny, and RFC 8628 section 3.3's first-decision-wins guarantee is void. The other three are the
// same shape on records where the loser is an RFC 7592 update, a detected authorization code
// replay, and a consent withdrawal.
//
// Shaped exactly like the `take_*` races, so `judge_race` can judge them: N racers swap ONE
// `expected` to N DISTINCT `updated` values, `Ok(true)` maps to the winner and `Ok(false)` to a
// loser, and exactly one racer may win — because the first write moves the record off `expected`
// and every later comparison must therefore fail.
const SWAP_ATOMIC: &str = "compare_and_swap_device_grant/atomic_under_a_race";
const CLIENT_SWAP_ATOMIC: &str = "compare_and_swap_client/atomic_under_a_race";
const CODE_SWAP_ATOMIC: &str = "compare_and_swap_authorization_code/atomic_under_a_race";
const CONSENT_SWAP_ATOMIC: &str = "compare_and_swap_consent/atomic_under_a_race";

const HARNESS_RACE_SETUP: &str = "harness/race_setup";
const HARNESS_RACER_PANICKED: &str = "harness/racer_panicked";
const ROUND_TRIP_CLIENT: &str = "round_trip/client";
const ROUND_TRIP_DEVICE_GRANT: &str = "round_trip/device_grant";
const ROUND_TRIP_AUTHORIZATION_CODE: &str = "round_trip/authorization_code";
const ROUND_TRIP_TOKEN: &str = "round_trip/token";
const ROUND_TRIP_REFRESH_TOKEN: &str = "round_trip/refresh_token";
const ATOMIC_TAKE_DEVICE_GRANT: &str = "atomic_take/take_device_grant";
const SWAP_APPLIES_ON_MATCH: &str = "compare_and_swap_device_grant/applies_when_the_state_matches";
const SWAP_HONOURS_EXPECTED: &str = "compare_and_swap_device_grant/honours_expected";
const SWAP_NEVER_RESURRECTS: &str = "compare_and_swap_device_grant/never_resurrects";
/// The two halves of the `put_device_grant` user-code index contract that the SWAP owes as well.
const SWAP_RETIRES_OLD_USER_CODE: &str = "compare_and_swap_device_grant/retires_the_old_user_code";
const SWAP_REFUSES_DUPLICATE_USER_CODE: &str =
    "compare_and_swap_device_grant/refuses_a_duplicate_user_code";
const ATOMIC_TAKE_REFRESH_TOKEN: &str = "atomic_take/take_refresh_token";
const ATOMIC_TAKE_AUTHORIZATION_CODE: &str = "atomic_take/take_authorization_code";
const INDEX_RETIRES_OLD_USER_CODE: &str = "user_code_index/retires_old_entry";
const INDEX_REFUSES_DUPLICATE_USER_CODE: &str = "user_code_index/refuses_duplicate";
const INDEX_REFUSAL_WRITES_NOTHING: &str = "user_code_index/refusal_writes_nothing";
const INDEX_CLEARED_BY_TAKE: &str = "user_code_index/cleared_by_take";
const INDEX_NO_NORMALIZATION: &str = "user_code_index/store_does_not_normalize";
const SWEEP_REMOVES_DEAD: &str = "sweep_expired/removes_dead";
const SWEEP_KEEPS_LIVE: &str = "sweep_expired/keeps_live";
const SWEEP_COUNT: &str = "sweep_expired/count";
const SWEEP_EMPTY_IS_ZERO: &str = "sweep_expired/empty_is_zero";
const SWEEP_RECLAIMS_PUSHED_REQUESTS: &str = "sweep_expired/reclaims_pushed_requests";
const SWEEP_CONCURRENT_WRITES: &str = "sweep_expired/safe_under_concurrent_writes";
const REVOKE_FAMILY_REMOVES: &str = "revoke_token_family/removes_the_family";
const REVOKE_FAMILY_SPARES_OTHERS: &str = "revoke_token_family/spares_other_families";
const REVOKE_FAMILY_COUNT: &str = "revoke_token_family/count";
const DELETE_CLIENT_CASCADES: &str = "delete_client/cascades";
const DELETE_CLIENT_REPORTS: &str = "delete_client/reports_whether_it_removed";
const DELETE_TOKEN_IDEMPOTENT: &str = "delete_token/idempotent";
const ATOMIC_CLAIM_REPLAY_ID: &str = "atomic_claim/claim_replay_id";
const CLAIM_REPLAY_ID_REFUSES_SECOND: &str = "claim_replay_id/refuses_a_second_claim";
const SWEEP_RECLAIMS_REPLAY_IDS: &str = "sweep_expired/reclaims_replay_ids";
const ATOMIC_TAKE_PUSHED_REQUEST: &str = "atomic_take/take_pushed_authorization_request";
const ROUND_TRIP_PUSHED_REQUEST: &str = "round_trip/pushed_authorization_request";
const ROUND_TRIP_CONSENT: &str = "round_trip/consent";
const CONSENTS_FOR_SUBJECT: &str = "consents_for_subject/lists_that_subjects_consents";
const REVOKE_CONSENT_CASCADES: &str = "revoke_consent/cascades";
const REVOKE_CONSENT_SPARES_OTHERS: &str = "revoke_consent/spares_other_subjects";
const REVOKE_CONSENT_COUNT: &str = "revoke_consent/count";

/// A racer handed to the host's runtime by [`StorageConformance::with_spawn`].
///
/// Boxed because the harness builds N of them and the host's spawner takes one concrete type;
/// `Send` because a multi-threaded runtime may move it between threads, which is exactly the
/// property that makes the spawned mode a real race.
pub type Task = Pin<Box<dyn Future<Output = ()> + Send>>;

type SpawnFn = Arc<dyn Fn(Task) + Send + Sync>;
type BoxTake<T> = Pin<Box<dyn Future<Output = Result<Option<T>, StorageError>> + Send>>;
/// What the racers hand back: one take's answer per racer, in completion order.
type TakeResults<T> = Vec<Result<Option<T>, StorageError>>;

/// The default number of racers per `take_*` check.
const DEFAULT_RACERS: usize = 8;

/// How many times a racer will re-poll while waiting at the rendezvous gate before giving up and
/// declaring the race unsatisfiable. Arrival needs no I/O (the gate is reached before the store is
/// touched), so a spawner that runs its tasks concurrently at all satisfies this in a handful of
/// polls; the budget exists only so a spawner that runs tasks strictly sequentially reports
/// `harness/race_setup` instead of hanging the host's test suite forever.
const GATE_POLL_BUDGET: u32 = 10_000;

/// The [`Storage`] conformance harness. See the module docs, particularly the honest account of
/// what the concurrency checks can and cannot prove.
pub struct StorageConformance<F> {
    new_store: F,
    spawn: Option<SpawnFn>,
    racers: usize,
}

impl<F> StorageConformance<F> {
    /// Build a harness over a factory that returns a FRESH, EMPTY store each time it is called.
    ///
    /// Empty matters: checks count records, and a row left over from an earlier check is
    /// indistinguishable from one the store failed to remove. A factory over a real database
    /// should truncate, or use a fresh schema, rather than reuse.
    pub fn new(new_store: F) -> Self {
        StorageConformance {
            new_store,
            spawn: None,
            racers: DEFAULT_RACERS,
        }
    }

    /// Run the racing takes as independent tasks on the HOST'S runtime, for example
    /// `|task| { tokio::spawn(task); }`.
    ///
    /// This is the mode worth running in CI: on a multi-threaded runtime it makes the `take_*`
    /// checks a genuine parallel race rather than an interleaving. The spawner MUST actually run
    /// the future it is given; one that drops it will hang the checks.
    pub fn with_spawn(mut self, spawn: impl Fn(Task) + Send + Sync + 'static) -> Self {
        self.spawn = Some(Arc::new(spawn));
        self
    }

    /// How many callers race each `take_*`. Eight by default. Values below 2 are raised to 2,
    /// since one racer cannot race.
    pub fn racers(mut self, racers: usize) -> Self {
        self.racers = racers.max(2);
        self
    }
}

impl<F, Fut, S> StorageConformance<F>
where
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
    S: Storage + 'static,
{
    /// Run every check and return the violations found. An empty vector means the store satisfied
    /// every property this harness can observe, which is NOT the same as "the store is correct":
    /// read the module docs on what the concurrency checks cannot see.
    pub async fn run(&self) -> Vec<Violation> {
        let mut report = Report::default();
        self.round_trip_client(&mut report).await;
        self.round_trip_device_grant(&mut report).await;
        self.round_trip_authorization_code(&mut report).await;
        self.round_trip_token(&mut report).await;
        self.round_trip_refresh_token(&mut report).await;
        self.atomic_take_device_grant(&mut report).await;
        self.compare_and_swap_device_grant(&mut report).await;
        self.compare_and_swap_device_grant_user_code_index(&mut report)
            .await;
        self.atomic_take_refresh_token(&mut report).await;
        self.atomic_take_authorization_code(&mut report).await;
        self.user_code_index(&mut report).await;
        self.sweep(&mut report).await;
        self.revoke_family(&mut report).await;
        self.delete_client(&mut report).await;
        self.delete_token(&mut report).await;
        #[cfg(any(feature = "client-assertion", feature = "dpop"))]
        self.claim_replay_id(&mut report).await;
        #[cfg(feature = "par")]
        self.round_trip_pushed_request(&mut report).await;
        #[cfg(feature = "par")]
        self.atomic_take_pushed_request(&mut report).await;
        #[cfg(feature = "consent")]
        self.consent(&mut report).await;
        self.revocation_barrier(&mut report).await;
        self.barrier_admits_a_later_grant(&mut report).await;
        self.compare_and_swap_client(&mut report).await;
        self.compare_and_swap_authorization_code(&mut report).await;
        #[cfg(feature = "consent")]
        self.compare_and_swap_consent(&mut report).await;
        self.compare_and_swap_device_grant_race(&mut report).await;
        self.compare_and_swap_client_race(&mut report).await;
        self.compare_and_swap_authorization_code_race(&mut report)
            .await;
        #[cfg(feature = "consent")]
        self.compare_and_swap_consent_race(&mut report).await;
        self.sweep_under_concurrent_writes(&mut report).await;
        self.revocation_refuses_an_empty_scope(&mut report).await;
        self.barrier_repeat_revocation_moves_it(&mut report).await;
        report.violations
    }

    /// RFC 7523 section 3 and RFC 9449 section 4.3 both make a `jti` single use, and
    /// `claim_replay_id` is the only thing enforcing it. Same defect shape as the `take_*`
    /// operations, with a worse failure mode: a `take_*` that hands the value out twice at least
    /// produces two token responses somebody might notice, while a claim-if-absent that answers
    /// "you are first" to two callers produces exactly the request the client meant to send,
    /// twice, and nothing anywhere records that it happened.
    #[cfg(any(feature = "client-assertion", feature = "dpop"))]
    async fn claim_replay_id(&self, report: &mut Report) {
        let store = self.store().await;
        let deadline = at(300);

        let results = self
            .race(report, |gate| {
                let store = Arc::clone(&store);
                Box::pin(async move {
                    gate.wait().await;
                    // Mapped to the shape `judge_race` reads: the caller that is told it claimed
                    // the id is the winner, exactly as the caller that receives a taken record is.
                    store
                        .claim_replay_id("jti-race", deadline)
                        .await
                        .map(|claimed| if claimed { Some(()) } else { None })
                })
            })
            .await;
        self.judge_race(
            report,
            ATOMIC_CLAIM_REPLAY_ID,
            "claim on a single-use jti",
            results,
        );

        // Sequential, and it has to hold too: a store can be atomic under a race and still forget
        // what it claimed a moment later.
        let store = self.store().await;
        let first = report.ok(
            CLAIM_REPLAY_ID_REFUSES_SECOND,
            "claim_replay_id",
            store.claim_replay_id("jti-once", deadline).await,
        );
        if first == Some(false) {
            report.fail(
                CLAIM_REPLAY_ID_REFUSES_SECOND,
                "the FIRST claim of an unseen id answered false, so every artifact carrying a jti \
                 is refused as a replay of itself",
            );
        }
        if let Some(second) = report.ok(
            CLAIM_REPLAY_ID_REFUSES_SECOND,
            "claim_replay_id (again)",
            store.claim_replay_id("jti-once", deadline).await,
        ) {
            if second {
                report.fail(
                    CLAIM_REPLAY_ID_REFUSES_SECOND,
                    "the SECOND claim of the same id also answered true: the id is not recorded, \
                     so a client assertion or DPoP proof can be replayed by anyone who observed \
                     one request",
                );
            }
        }
        // A DIFFERENT id must still be claimable: a store that answers false to everything after
        // the first claim would pass the check above and refuse every subsequent request.
        if let Some(other) = report.ok(
            CLAIM_REPLAY_ID_REFUSES_SECOND,
            "claim_replay_id (a different id)",
            store.claim_replay_id("jti-other", deadline).await,
        ) {
            if !other {
                report.fail(
                    CLAIM_REPLAY_ID_REFUSES_SECOND,
                    "a claim of an id that was never claimed answered false",
                );
            }
        }

        // Claims are records too, and the only thing that reclaims them is the host's sweep. A
        // store that never expires them grows once per authenticated request, forever.
        let store = self.store().await;
        let now = at(0);
        if report
            .ok(
                SWEEP_RECLAIMS_REPLAY_IDS,
                "claim_replay_id",
                store.claim_replay_id("jti-sweep", now).await,
            )
            .is_none()
        {
            return;
        }
        if let Some(removed) = report.ok(
            SWEEP_RECLAIMS_REPLAY_IDS,
            "sweep_expired",
            store.sweep_expired(now).await,
        ) {
            if removed != 1 {
                report.fail(
                    SWEEP_RECLAIMS_REPLAY_IDS,
                    format!(
                        "sweep_expired reported {removed} removed with exactly one dead replay id \
                         in the store: claimed ids are records the sweep must reclaim, or the \
                         table grows once per authenticated request forever"
                    ),
                );
            }
        }
    }

    async fn store(&self) -> Arc<S> {
        Arc::new((self.new_store)().await)
    }

    // -------------------------------------------------------------- the resurrection rule

    /// A barrier must refuse a grant that PREDATES it and admit one established AFTER it.
    ///
    /// The other barrier checks give their revocation a `recorded_at` far enough out to cover
    /// everything, because they are about the refusal. That makes them blind to the direction
    /// tested here: a store that ignores `RevocationWindow::recorded_at` entirely, or compares it
    /// the wrong way round, passes every one of them.
    ///
    /// It is not a tidiness check. `client` and `consent` barriers name an identity that can
    /// legitimately be established again — a user re-approving an application, a host
    /// re-provisioning a `client_id` it deleted — and a store that refuses on identity alone locks
    /// that identity out until the barrier is swept, which is as long as the longest token the
    /// server mints. The user re-approves, sees the application listed as authorised, and cannot
    /// obtain a token from it for the life of a refresh token.
    ///
    /// `TokenFamily` is deliberately NOT tested this way, because it is deliberately
    /// unconditional: rotation mints fresh records inside an existing family, so comparing there
    /// would admit the very write RFC 9700 s4.14.2 containment exists to refuse.
    async fn barrier_admits_a_later_grant(&self, report: &mut Report) {
        let store = self.store().await;
        let client = ClientId::new("client-relifecycle");

        // REGISTERED first, so the deletion below is the one this check is named for: a client
        // that was there and is removed. Deleting one that was never stored is a different
        // property with a different failure mode, and `revocation_barrier` owns it.
        if report
            .ok(
                BARRIER_ADMITS_A_LATER_GRANT,
                "put_client",
                store.put_client(sample_client(client.as_str())).await,
            )
            .is_none()
        {
            return;
        }

        if report
            .ok(
                BARRIER_ADMITS_A_LATER_GRANT,
                "delete_client",
                store
                    .delete_client(
                        &client,
                        crate::store::RevocationWindow {
                            recorded_at: at_before(0),
                            until: barrier_until(),
                        },
                    )
                    .await,
            )
            .is_none()
        {
            return;
        }

        // Established BEFORE the deletion: the in-flight write the barrier exists to refuse.
        let mut stale = sample_token("at-grant-before-deletion", client.as_str(), None);
        stale.grant_established_at = at_before(60);
        match store.put_token(stale).await {
            Ok(WriteOutcome::RefusedRevoked) => {}
            Ok(WriteOutcome::Applied) => report.fail(
                BARRIER_ADMITS_A_LATER_GRANT,
                "put_token wrote a token whose grant was established BEFORE the client was \
                 deleted: that is the in-flight write the barrier exists to refuse, so the \
                 deletion is undone by a request that was already running when it ran",
            ),
            Err(e) => report.fail(
                BARRIER_ADMITS_A_LATER_GRANT,
                format!("put_token failed unexpectedly: {e}"),
            ),
        }

        // Established AFTER it, WHILE THE CLIENT IS STILL DELETED: refused. A grant instant later
        // than the revocation is only a "new decision" if the identity came back; a client the host
        // removed and did not put back is gone, and every grant for it is dead however its instant
        // compares. A concurrent write can stamp a `grant_established_at` a hair after the
        // revocation's `recorded_at` -- `a_pushed_request_cannot_land_behind_a_client_deletion` in
        // oauth-as-postgres shows exactly that -- so a store that admits a later grant on the
        // timestamp ALONE lets a deleted client's credentials return.
        let mut orphan = sample_token("at-grant-after-deletion-still-gone", client.as_str(), None);
        orphan.grant_established_at = at(60);
        match store.put_token(orphan).await {
            Ok(WriteOutcome::RefusedRevoked) => {}
            Ok(WriteOutcome::Applied) => report.fail(
                BARRIER_ADMITS_A_LATER_GRANT,
                "put_token wrote a token for a client that was DELETED and not re-provisioned, on \
                 the strength of a grant instant later than the revocation. A concurrent write can \
                 stamp exactly that instant, so a deleted client's credentials come back: refuse a \
                 client-scope grant whenever the client no longer exists",
            ),
            Err(e) => report.fail(
                BARRIER_ADMITS_A_LATER_GRANT,
                format!("put_token failed unexpectedly: {e}"),
            ),
        }

        // AND IT MUST NAME ONE CLIENT. A store whose client-scope predicate ignores `client_id` --
        // a barrier table queried without its scope column, a predicate matched on the barrier KIND
        // -- refuses this too. The grant predates the deletion, exactly as the windowed refusal
        // above does, so identity is the only thing that tells them apart. RFC 7592 s2.3 deletes
        // ONE registration; a store that got this wrong stops every client in the deployment
        // refreshing for the barrier's whole life, on a path an administrator drives by hand.
        let mut bystander = sample_token(
            "at-another-clients-grant-before-the-deletion",
            "client-not-the-one-deleted",
            None,
        );
        bystander.grant_established_at = at_before(60);
        match store.put_token(bystander).await {
            Ok(WriteOutcome::Applied) => {}
            Ok(WriteOutcome::RefusedRevoked) => report.fail(
                BARRIER_SPARES_UNRELATED,
                "put_token refused a token belonging to a DIFFERENT client than the one deleted: \
                 the client barrier is not comparing its scope against the record's `client_id` at \
                 all, so one RFC 7592 s2.3 deletion has stopped every client this server has",
            ),
            Err(e) => report.fail(
                BARRIER_SPARES_UNRELATED,
                format!("put_token failed unexpectedly: {e}"),
            ),
        }

        // RE-PROVISIONED: the host registers the id again, and NOW a later grant must be served.
        // This is the property that keeps a client barrier from locking an id out for its whole
        // life -- a re-registered client, or a user who withdrew an application and approved it
        // again, must be admitted -- and it is the OTHER half of the concurrent-write fix: the
        // window still governs a client that exists, so a genuine re-provisioning is not refused.
        if report
            .ok(
                BARRIER_ADMITS_A_LATER_GRANT,
                "put_client (re-provision)",
                store.put_client(sample_client(client.as_str())).await,
            )
            .is_none()
        {
            return;
        }
        let mut fresh = sample_token("at-grant-after-reprovisioning", client.as_str(), None);
        fresh.grant_established_at = at(60);
        match store.put_token(fresh).await {
            Ok(WriteOutcome::Applied) => {}
            Ok(WriteOutcome::RefusedRevoked) => report.fail(
                BARRIER_ADMITS_A_LATER_GRANT,
                "put_token refused a token whose grant was established AFTER the client was \
                 re-provisioned: a re-registered client is locked out until the barrier is swept, \
                 as long as the longest token this server mints. A client that EXISTS is judged by \
                 RevocationWindow::recorded_at alone",
            ),
            Err(e) => report.fail(
                BARRIER_ADMITS_A_LATER_GRANT,
                format!("put_token failed unexpectedly: {e}"),
            ),
        }

        // The pushed request is judged the same way, both halves. Deleted-and-gone refuses a push
        // authored after the revocation (the RFC 9126 s2.2 resurrection); re-provisioned admits it,
        // or the endpoint answers `server_error` for a live registration until the barrier sweeps.
        #[cfg(feature = "par")]
        {
            let store2 = self.store().await;
            let deleted = ClientId::new("client-par-deleted-and-gone");
            if store2
                .put_client(sample_client(deleted.as_str()))
                .await
                .is_ok()
                && store2
                    .delete_client(
                        &deleted,
                        crate::store::RevocationWindow {
                            recorded_at: at_before(0),
                            until: barrier_until(),
                        },
                    )
                    .await
                    .is_ok()
            {
                let mut pushed_orphan = sample_pushed_request(
                    "urn:ietf:params:oauth:request_uri:pushed-while-client-gone",
                );
                pushed_orphan.client_id = deleted.clone();
                pushed_orphan.pushed_at = at(60);
                match store2.put_pushed_authorization_request(pushed_orphan).await {
                    Ok(WriteOutcome::RefusedRevoked) => {}
                    Ok(WriteOutcome::Applied) => report.fail(
                        BARRIER_ADMITS_A_LATER_GRANT,
                        "put_pushed_authorization_request wrote a request for a client that was \
                         deleted and not re-provisioned, on a `pushed_at` later than the \
                         revocation. A concurrent push stamps exactly that, so a deleted client's \
                         request_uri survives (RFC 9126 s2.2)",
                    ),
                    Err(e) => report.fail(
                        BARRIER_ADMITS_A_LATER_GRANT,
                        format!("put_pushed_authorization_request failed unexpectedly: {e}"),
                    ),
                }
            }

            let mut pushed_after = sample_pushed_request(
                "urn:ietf:params:oauth:request_uri:pushed-after-reprovisioning",
            );
            pushed_after.client_id = client.clone();
            pushed_after.pushed_at = at(60);
            match store.put_pushed_authorization_request(pushed_after).await {
                Ok(WriteOutcome::Applied) => {}
                Ok(WriteOutcome::RefusedRevoked) => report.fail(
                    BARRIER_ADMITS_A_LATER_GRANT,
                    "put_pushed_authorization_request refused a request pushed for a client the \
                     host RE-PROVISIONED: the RFC 9126 endpoint answers server_error for a live \
                     registration until the barrier is swept",
                ),
                Err(e) => report.fail(
                    BARRIER_ADMITS_A_LATER_GRANT,
                    format!("put_pushed_authorization_request failed unexpectedly: {e}"),
                ),
            }
        }
    }

    /// THE RESURRECTION RULE, from the outside.
    ///
    /// A revocation removes what is in the store WHEN IT RUNS. A request that was already holding
    /// one of those records writes afterwards, and without a barrier that write puts it back. The
    /// cascade checks in this file cannot see this: they revoke, then look, and everything is
    /// correctly gone. The defect is entirely in what happens NEXT.
    ///
    /// Driven through `revoke_token_family` because that is the narrowest scope and so the
    /// sharpest test: a store that records a client-wide barrier when asked for a family one would
    /// pass the refusal half and fail `spares_unrelated_records`.
    async fn revocation_barrier(&self, report: &mut Report) {
        let store = self.store().await;

        // A family, revoked, with the barrier standing well past everything else this harness
        // uses for time.
        if report
            .ok(
                BARRIER_REFUSES_TOKEN,
                "revoke_token_family",
                store
                    .revoke_token_family("fam-barrier", barrier_window())
                    .await,
            )
            .is_none()
        {
            return;
        }

        // The write an issuance already in flight for that family is about to make.
        match store
            .put_token(sample_token(
                "at-after-revocation",
                "client-conformance",
                Some("fam-barrier"),
            ))
            .await
        {
            Ok(WriteOutcome::RefusedRevoked) => {}
            Ok(WriteOutcome::Applied) => report.fail(
                BARRIER_REFUSES_TOKEN,
                "put_token wrote an access token for a family that had just been revoked: an \
                 issuance already in flight when the revocation ran completes behind it, so RFC \
                 9700 s4.14.2 containment reports success and the token it was containing is live",
            ),
            Err(e) => report.fail(
                BARRIER_REFUSES_TOKEN,
                format!("put_token failed unexpectedly: {e}"),
            ),
        }

        // AND UNCONDITIONALLY, which is the one place this crate deliberately does NOT compare
        // against `recorded_at`. Rotation legitimately mints fresh records inside an EXISTING
        // family, so a family barrier that admitted a later-established grant would admit exactly
        // the write RFC 9700 s4.14.2 containment exists to refuse: the rotation that completes
        // after the cascade. Nothing legitimate is lost, because a new grant gets a new family_id.
        //
        // Every other record this harness plants predates the barrier, so a store that wrongly
        // applied the grant-instant comparison to the family scope refused them all for the wrong
        // reason and passed. This one is established a minute AFTER the revocation.
        let mut later_in_the_family = sample_token(
            "at-after-revocation-later-grant",
            "client-conformance",
            Some("fam-barrier"),
        );
        later_in_the_family.grant_established_at = at(60);
        match store.put_token(later_in_the_family).await {
            Ok(WriteOutcome::RefusedRevoked) => {}
            Ok(WriteOutcome::Applied) => report.fail(
                BARRIER_REFUSES_TOKEN,
                "put_token wrote a token for a REVOKED family because its grant instant was after \
                 the revocation. The family scope refuses UNCONDITIONALLY: a rotation carries the \
                 grant instant forward but mints its records at `now`, so comparing here readmits \
                 the rotation that completes behind the cascade, which is the whole of what RFC \
                 9700 s4.14.2 containment is for. Compare `recorded_at` for the client and consent \
                 scopes only",
            ),
            Err(e) => report.fail(
                BARRIER_REFUSES_TOKEN,
                format!("put_token failed unexpectedly: {e}"),
            ),
        }

        // The same for the refresh record, which is the write EVERY refusal path of a rotation
        // makes, on a record `take_refresh_token` has already removed.
        match store
            .put_refresh_token(sample_refresh(
                "rt-after-revocation",
                "client-conformance",
                "fam-barrier",
            ))
            .await
        {
            Ok(WriteOutcome::RefusedRevoked) => {}
            Ok(WriteOutcome::Applied) => report.fail(
                BARRIER_REFUSES_REFRESH,
                "put_refresh_token restored a refresh record for a family that had just been \
                 revoked: the user was told the grant was revoked and the client still holds a \
                 rotatable chain",
            ),
            Err(e) => report.fail(
                BARRIER_REFUSES_REFRESH,
                format!("put_refresh_token failed unexpectedly: {e}"),
            ),
        }

        // AND IT MUST REFUSE ONLY WHAT IT COVERS. Without this a store that answered
        // `RefusedRevoked` to everything would pass both checks above and issue nothing, ever.
        match store
            .put_token(sample_token(
                "at-unrelated",
                "client-conformance",
                Some("fam-other"),
            ))
            .await
        {
            Ok(WriteOutcome::Applied) => {}
            Ok(WriteOutcome::RefusedRevoked) => report.fail(
                BARRIER_SPARES_UNRELATED,
                "put_token refused a token from a DIFFERENT family: the barrier is matching too \
                 widely, so one revocation has stopped this client issuing anything at all",
            ),
            Err(e) => report.fail(
                BARRIER_SPARES_UNRELATED,
                format!("put_token failed unexpectedly: {e}"),
            ),
        }

        // A REVOCATION OF SOMETHING THAT WAS NEVER THERE STILL RECORDS ITS BARRIER. The shape a
        // host reaches for is `if rows_deleted > 0 { insert_barrier(..) }`, which satisfies every
        // other word of `delete_client` and drops the protection in exactly the interleaving that
        // needs it: absence of the registration row proves nothing about an issuance that is
        // holding a `Client` it read before the deletion ran, and a second delete arriving from
        // another node finds nothing to remove and must still refuse that issuance.
        let never_registered = ClientId::new("client-never-registered");
        if report
            .ok(
                BARRIER_REFUSES_TOKEN,
                "delete_client (a client that was never stored)",
                store
                    .delete_client(&never_registered, barrier_window())
                    .await,
            )
            .is_some()
        {
            match store
                .put_token(sample_token(
                    "at-for-a-client-that-was-never-registered",
                    never_registered.as_str(),
                    None,
                ))
                .await
            {
                Ok(WriteOutcome::RefusedRevoked) => {}
                Ok(WriteOutcome::Applied) => report.fail(
                    BARRIER_REFUSES_TOKEN,
                    "delete_client recorded NO barrier because there was no registration to \
                     remove, so a write covered by that deletion was accepted. Deleting a client \
                     that is already gone answers Ok(false) and must still record the barrier: the \
                     issuance the deletion is racing is holding a registration it read earlier, \
                     and the empty result set says nothing about it",
                ),
                Err(e) => report.fail(
                    BARRIER_REFUSES_TOKEN,
                    format!("put_token failed unexpectedly: {e}"),
                ),
            }
        }

        // A barrier is a row nothing else removes, one per revocation, so an unswept store grows
        // by one every time a user logs out. It must be reclaimed, and COUNTED, or a host
        // implementing `sweep_expired` to the letter of its enumeration never reclaims the table.
        //
        // One second BEFORE the deadline first: reaping early reopens the window the barrier was
        // recorded to close, which is the failure that costs a revocation rather than a row.
        let before = report.ok(
            BARRIER_KEPT_BEFORE_DEADLINE,
            "sweep_expired",
            store
                .sweep_expired(barrier_until() - Duration::from_secs(1))
                .await,
        );
        if before.is_some() {
            match store
                .put_refresh_token(sample_refresh(
                    "rt-still-refused",
                    "client-conformance",
                    "fam-barrier",
                ))
                .await
            {
                Ok(WriteOutcome::RefusedRevoked) => {}
                Ok(WriteOutcome::Applied) => report.fail(
                    BARRIER_KEPT_BEFORE_DEADLINE,
                    "a sweep BEFORE the barrier deadline reclaimed it, so a write that the \
                     revocation should still be refusing was accepted: the window the barrier \
                     exists to close has been reopened early",
                ),
                Err(e) => report.fail(
                    BARRIER_KEPT_BEFORE_DEADLINE,
                    format!("put_refresh_token failed unexpectedly: {e}"),
                ),
            }
        }

        // And AT the deadline it goes, and is counted.
        let Some(removed) = report.ok(
            BARRIER_SWEPT_AT_DEADLINE,
            "sweep_expired",
            store.sweep_expired(barrier_until()).await,
        ) else {
            return;
        };
        if removed == 0 {
            report.fail(
                BARRIER_SWEPT_AT_DEADLINE,
                "sweep_expired reclaimed nothing at the barrier deadline: a barrier is a row \
                 nothing else ever removes, so a store that does not sweep them grows by one per \
                 revocation forever",
            );
        }
    }

    /// A second revocation of ONE scope must not weaken the first, in either of the two instants a
    /// [`crate::store::RevocationWindow`] carries.
    ///
    /// Nothing else in this harness records two DIFFERENT windows for one scope: every other check
    /// passes the same constant window twice, and two equal instants take neither branch of the
    /// merge. So a store that upserts the row — which is the obvious implementation, and the one
    /// both a `HashMap::insert` and an `INSERT ... ON CONFLICT DO UPDATE SET` give you for free —
    /// passes everything else in this file while losing whichever of the two writes lands first.
    ///
    /// The earlier window is recorded SECOND, because that is the ordering that actually happens:
    /// two nodes withdraw the same grant, each computes its window from its own clock, and the
    /// slower node's write arrives last carrying the older instants. Both halves cost something
    /// real. A rewound `recorded_at` admits a grant established between the two revocations, which
    /// the later revocation was entitled to kill. A shortened `until` reaps the barrier early and
    /// reopens the whole window it was recorded to close.
    async fn barrier_repeat_revocation_moves_it(&self, report: &mut Report) {
        let c = BARRIER_REPEAT_REVOCATION_MOVES_IT;
        let store = self.store().await;
        let client = ClientId::new("client-revoked-twice");
        if report
            .ok(
                c,
                "put_client",
                store.put_client(sample_client(client.as_str())).await,
            )
            .is_none()
        {
            return;
        }

        let later = crate::store::RevocationWindow {
            recorded_at: at(100),
            until: barrier_until(),
        };
        let earlier = crate::store::RevocationWindow {
            recorded_at: at_before(0),
            until: at(200),
        };
        if report
            .ok(
                c,
                "delete_client",
                store.delete_client(&client, later).await,
            )
            .is_none()
        {
            return;
        }
        if report
            .ok(
                c,
                "delete_client (a second revocation, with an EARLIER window)",
                store.delete_client(&client, earlier).await,
            )
            .is_none()
        {
            return;
        }

        // RE-PROVISION the client, so the halves below turn on `recorded_at` and nothing else. A
        // client barrier also refuses a grant whose client no longer exists, and both deletions
        // above removed this one; without putting it back, every `between`/`predating` grant is
        // refused on ABSENCE and neither the rewound `recorded_at` nor a shortened deadline could
        // be seen. The host legitimately re-registers a deleted id, and it is the `recorded_at`
        // merge this check is named for that must still govern the re-registered client's grants.
        if report
            .ok(
                c,
                "put_client (re-provision, so the merge is what is tested)",
                store.put_client(sample_client(client.as_str())).await,
            )
            .is_none()
        {
            return;
        }

        // `recorded_at` must be the LATER of the two. A grant established between the two
        // revocations is one the second-recorded-but-later revocation was entitled to kill.
        let mut between = sample_token("at-between-two-revocations", client.as_str(), None);
        between.grant_established_at = at(50);
        match store.put_token(between).await {
            Ok(WriteOutcome::RefusedRevoked) => {}
            Ok(WriteOutcome::Applied) => report.fail(
                c,
                "after two revocations of one client, a token whose grant was established BETWEEN \
                 them was written. The second revocation carried an EARLIER `recorded_at` and this \
                 store took it, so the repeat revocation moved the barrier BACKWARDS and admitted \
                 exactly the grant the first one covered. `recorded_at` must take the later of the \
                 two, or a store whose two nodes race loses whichever revocation commits first",
            ),
            Err(e) => report.fail(c, format!("put_token failed unexpectedly: {e}")),
        }

        // And `until` must be the later of the two as well: a sweep past the SECOND window's
        // deadline and well short of the first's must leave the barrier standing.
        //
        // One dead record is planted for that sweep to find, so that a store whose sweep errors
        // when it matched no rows — a real fault, owned by `sweep_expired/empty_is_zero` — is not
        // also reported here under a name that would send a host looking at its barrier table.
        let mut fodder = sample_token("at-dead-sweep-fodder", "client-sweep-fodder", None);
        fodder.expires_at = at_before(1);
        if report
            .ok(
                c,
                "put_token (a dead record for the sweep)",
                store.put_token(fodder).await,
            )
            .is_none()
        {
            return;
        }
        if report
            .ok(
                c,
                "sweep_expired (past the second window's deadline, short of the first's)",
                store.sweep_expired(at(300)).await,
            )
            .is_none()
        {
            return;
        }
        let mut predating = sample_token("at-predating-both-revocations", client.as_str(), None);
        predating.grant_established_at = at_before(60);
        match store.put_token(predating).await {
            Ok(WriteOutcome::RefusedRevoked) => {}
            Ok(WriteOutcome::Applied) => report.fail(
                c,
                "a second revocation of one client SHORTENED the first one's deadline: sweeping \
                 past the second window's `until`, which is far short of the first's, reclaimed \
                 the barrier, and a write the first revocation was still covering was accepted. A \
                 repeat revocation must never shrink the protection already recorded",
            ),
            Err(e) => report.fail(c, format!("put_token failed unexpectedly: {e}")),
        }
    }

    /// An empty identifier is REFUSED, by every store.
    ///
    /// The empty string does not name an identity a barrier can be recorded for, so a store that
    /// accepts one has cascaded against a scope no later write can be compared to. This is not a
    /// tidiness rule and it is not hypothetical: it was found by running the same call through
    /// both bundled stores, where `delete_client("")` cascaded everything in memory and — because
    /// the barrier insert ran first — deleted NOTHING through Postgres while returning an error.
    /// A divergence like that is worse than either behaviour on its own, because a host that
    /// tested against one backend and deployed on the other got neither.
    ///
    /// Only the two revocations that TAKE the scope as a parameter are probed. `revoke_consent`
    /// owes the same refusal, and its trait doc says so, but the scope it would refuse comes from
    /// the stored consent rather than from the call, so reaching it means persisting a consent
    /// with an empty `client_id` or `subject` — a record no store is obliged to accept in the
    /// first place, which would make a refusal here indistinguishable from a refusal there.
    async fn revocation_refuses_an_empty_scope(&self, report: &mut Report) {
        let c = REVOCATION_REFUSES_EMPTY_SCOPE;
        let store = self.store().await;
        // Something for a wrongly-accepted revocation to have removed. A refusal must leave the
        // store exactly as it was, which is why the refusal has to come BEFORE the cascade.
        if report
            .ok(
                c,
                "put_token",
                store
                    .put_token(sample_token(
                        "at-empty-scope",
                        "client-empty-scope",
                        Some("fam-empty-scope"),
                    ))
                    .await,
            )
            .is_none()
        {
            return;
        }

        if let Ok(removed) = store
            .delete_client(&ClientId::new(""), barrier_window())
            .await
        {
            report.fail(
                c,
                format!(
                    "delete_client accepted an EMPTY client_id and answered Ok({removed}). The \
                     empty string names no registration, so there is nothing for the cascade to \
                     mean and nothing a later write can be compared against; a store that keys \
                     barriers by value must refuse it rather than record one for \"\""
                ),
            );
        }
        if let Ok(removed) = store.revoke_token_family("", barrier_window()).await {
            report.fail(
                c,
                format!(
                    "revoke_token_family accepted an EMPTY family_id and answered Ok({removed}). \
                     RFC 6749 section 4.4 tokens carry no family at all, so a store that treats \
                     \"\" as a family is one careless call away from a predicate that matches them"
                ),
            );
        }

        // AND THE STORE IS UNTOUCHED — but by a NARROWER argument than the one written here for
        // several rounds, which claimed this caught "a store that cascades first and validates
        // afterwards". It cannot. The only planted record names `client-empty-scope` and
        // `fam-empty-scope`, so a cascade run faithfully with the EMPTY scope matches nothing and
        // the token survives whichever order that store did its two steps in.
        //
        // What this probe genuinely detects is the store that treats "" as a WILDCARD rather than
        // as a value — an unparameterised predicate, a `LIKE ''`, a `retain` whose closure is
        // written the wrong way round for an empty key — which is the shape that empties the whole
        // table on one careless call, and is the reason an empty scope is refused at all. Catching
        // the ordering as well would need a record the empty scope actually names, meaning a token
        // whose `client_id` is the empty string, and no store is obliged to accept one: a refusal
        // on the way IN would be indistinguishable from the refusal being probed. That is the same
        // argument this check's own doc gives for leaving `revoke_consent` out.
        if let Some(found) = report.ok(c, "get_token", store.get_token("at-empty-scope").await) {
            if found.is_none() {
                report.fail(
                    c,
                    "a revocation refused for naming an empty scope had already removed records \
                     by the time it refused: the caller is told the call failed and the store is \
                     the one the failed call left behind",
                );
            }
        }
    }

    /// `compare_and_swap_client`, the RFC 7592 s2.2 half of the rule.
    ///
    /// The resurrection this closes: an update reads a registration, awaits a policy decision, and
    /// writes the whole record back. A s2.3 DELETE landing in that window was undone by a blind
    /// put, restoring the client with its old credential and its old registration access token
    /// hash, which makes deleting a compromised registration defeatable by whoever holds the
    /// stolen token.
    async fn compare_and_swap_client(&self, report: &mut Report) {
        let store = self.store().await;
        let original = sample_client("client-swap");
        if report
            .ok(
                CLIENT_SWAP_APPLIES,
                "put_client",
                store.put_client(original.clone()).await,
            )
            .is_none()
        {
            return;
        }

        // The expectation is what the store ACTUALLY HOLDS, read back, not what was written. A
        // store that mutates a record on the way in (dropping a field, normalising a string) has a
        // round-trip defect that `round_trip/client` already owns and names; without this read
        // that defect would fire here a second time under a swap name, and a host would chase two
        // bugs where there is one. Same reasoning as `index_already_dirty` in the device-grant
        // swap check above.
        let Some(original) = report.ok(
            CLIENT_SWAP_APPLIES,
            "get_client",
            store.get_client(&ClientId::new("client-swap")).await,
        ) else {
            return;
        };
        let Some(original) = original.map(|a| (*a).clone()) else {
            report.fail(
                CLIENT_SWAP_APPLIES,
                "the registration written a moment ago is not there to swap against",
            );
            return;
        };

        // Matches: applies.
        let mut renamed = original.clone();
        renamed.name = Some("renamed by the swap".to_string());
        match store
            .compare_and_swap_client(&original, renamed.clone())
            .await
        {
            Ok(true) => {}
            Ok(false) => report.fail(
                CLIENT_SWAP_APPLIES,
                "a swap whose expected record is exactly what is stored reported that it did not \
                 apply, so no RFC 7592 update can ever be recorded",
            ),
            Err(e) => report.fail(
                CLIENT_SWAP_APPLIES,
                format!("compare_and_swap_client failed unexpectedly: {e}"),
            ),
        }

        // Stale expectation: refused, and nothing written.
        let mut clobber = original.clone();
        clobber.name = Some("clobbered".to_string());
        match store.compare_and_swap_client(&original, clobber).await {
            Ok(false) => {}
            Ok(true) => report.fail(
                CLIENT_SWAP_HONOURS_EXPECTED,
                "a swap applied against a registration that had already changed: two concurrent \
                 RFC 7592 updates silently lose one, and the loser is whichever landed first",
            ),
            Err(e) => report.fail(
                CLIENT_SWAP_HONOURS_EXPECTED,
                format!("compare_and_swap_client failed unexpectedly: {e}"),
            ),
        }
        match store.get_client(&ClientId::new("client-swap")).await {
            Ok(Some(live)) if live.name.as_deref() == Some("renamed by the swap") => {}
            Ok(Some(_)) => report.fail(
                CLIENT_SWAP_HONOURS_EXPECTED,
                "a refused swap wrote anyway: `Ok(false)` must mean nothing changed",
            ),
            Ok(None) => report.fail(
                CLIENT_SWAP_HONOURS_EXPECTED,
                "the registration vanished during a refused swap",
            ),
            Err(e) => report.fail(
                CLIENT_SWAP_HONOURS_EXPECTED,
                format!("get_client failed unexpectedly: {e}"),
            ),
        }

        // ABSENT: the case that matters. A swap must never insert.
        if report
            .ok(
                CLIENT_SWAP_NEVER_RESURRECTS,
                "delete_client",
                store
                    .delete_client(&ClientId::new("client-swap"), barrier_window())
                    .await,
            )
            .is_none()
        {
            return;
        }
        match store
            .compare_and_swap_client(&renamed, renamed.clone())
            .await
        {
            Ok(false) => {}
            Ok(true) => report.fail(
                CLIENT_SWAP_NEVER_RESURRECTS,
                "a swap against a DELETED registration reported that it applied: `Ok(false)` is \
                 the only correct answer for a row that is not there",
            ),
            Err(e) => report.fail(
                CLIENT_SWAP_NEVER_RESURRECTS,
                format!("compare_and_swap_client failed unexpectedly: {e}"),
            ),
        }
        match store.get_client(&ClientId::new("client-swap")).await {
            Ok(None) => {}
            Ok(Some(_)) => report.fail(
                CLIENT_SWAP_NEVER_RESURRECTS,
                "a swap brought back a deleted registration, with its old credential and its old \
                 registration access token hash: deleting a compromised client is defeatable by \
                 whoever holds the stolen token",
            ),
            Err(e) => report.fail(
                CLIENT_SWAP_NEVER_RESURRECTS,
                format!("get_client failed unexpectedly: {e}"),
            ),
        }
    }

    /// `compare_and_swap_authorization_code`, which is how a redemption suspended across the
    /// host's signer finds out that a replay was detected while it slept.
    async fn compare_and_swap_authorization_code(&self, report: &mut Report) {
        let store = self.store().await;
        let issued = sample_authorization_code("code-swap");
        if report
            .ok(
                CODE_SWAP_APPLIES,
                "put_authorization_code",
                store.put_authorization_code(issued.clone()).await,
            )
            .is_none()
        {
            return;
        }
        // Read back for the same reason the client swap does: a store that mutates the record on
        // the way in has a round-trip defect that belongs to `round_trip/authorization_code`.
        let Some(issued) = report.ok(
            CODE_SWAP_APPLIES,
            "take_authorization_code",
            store.take_authorization_code("code-swap").await,
        ) else {
            return;
        };
        let Some(issued) = issued else {
            report.fail(
                CODE_SWAP_APPLIES,
                "the authorization code written a moment ago is not there to swap against",
            );
            return;
        };
        if report
            .ok(
                CODE_SWAP_APPLIES,
                "put_authorization_code",
                store.put_authorization_code(issued.clone()).await,
            )
            .is_none()
        {
            return;
        }
        let consumed_state = AuthorizationCodeState::Consumed {
            access_token: Some("at-from-code".to_string()),
            refresh_token: None,
        };
        let mut consumed = issued.clone();
        consumed.state = consumed_state.clone();

        match store
            .compare_and_swap_authorization_code(&issued.state, consumed.clone())
            .await
        {
            Ok(true) => {}
            Ok(false) => report.fail(
                CODE_SWAP_APPLIES,
                "a swap whose expected state is exactly what is stored reported that it did not \
                 apply, so a redemption can never record what it minted",
            ),
            Err(e) => report.fail(
                CODE_SWAP_APPLIES,
                format!("compare_and_swap_authorization_code failed unexpectedly: {e}"),
            ),
        }

        // The state has moved on: refused. This is the interleaving the method exists for, with a
        // replay having marked the record while the redemption was signing.
        let mut replayed = issued.clone();
        replayed.state = AuthorizationCodeState::Replayed {
            access_token: Some("at-from-code".to_string()),
            refresh_token: None,
        };
        if report
            .ok(
                CODE_SWAP_HONOURS_EXPECTED,
                "put_authorization_code",
                store.put_authorization_code(replayed).await,
            )
            .is_some()
        {
            match store
                .compare_and_swap_authorization_code(&consumed_state, consumed.clone())
                .await
            {
                Ok(false) => {}
                Ok(true) => report.fail(
                    CODE_SWAP_HONOURS_EXPECTED,
                    "a swap applied over a state that had already moved on: a redemption \
                     suspended in the host's signer overwrites the trace a detected replay left \
                     for it, and hands out the very tokens the replay was containing",
                ),
                Err(e) => report.fail(
                    CODE_SWAP_HONOURS_EXPECTED,
                    format!("compare_and_swap_authorization_code failed unexpectedly: {e}"),
                ),
            }
        }

        // ABSENT: swept, or cascaded away by delete_client or revoke_consent. Must stay gone.
        if report
            .ok(
                CODE_SWAP_NEVER_RESURRECTS,
                "take_authorization_code",
                store.take_authorization_code("code-swap").await,
            )
            .is_none()
        {
            return;
        }
        match store
            .compare_and_swap_authorization_code(&consumed_state, consumed)
            .await
        {
            Ok(false) => {}
            Ok(true) => report.fail(
                CODE_SWAP_NEVER_RESURRECTS,
                "a swap against an authorization code that is not there reported that it applied",
            ),
            Err(e) => report.fail(
                CODE_SWAP_NEVER_RESURRECTS,
                format!("compare_and_swap_authorization_code failed unexpectedly: {e}"),
            ),
        }
        match store.take_authorization_code("code-swap").await {
            Ok(None) => {}
            Ok(Some(_)) => report.fail(
                CODE_SWAP_NEVER_RESURRECTS,
                "a swap reinstated an authorization code that had been removed: a code a \
                 withdrawal or a client deletion cascaded away is redeemable again",
            ),
            Err(e) => report.fail(
                CODE_SWAP_NEVER_RESURRECTS,
                format!("take_authorization_code failed unexpectedly: {e}"),
            ),
        }
    }

    /// `compare_and_swap_consent`. The comparison is against what `find_consent` answers for the
    /// PAIR, not against a `consent_id`, because a withdrawal removes the record the caller read.
    #[cfg(feature = "consent")]
    async fn compare_and_swap_consent(&self, report: &mut Report) {
        let store = self.store().await;
        let original = sample_consent("consent-swap", "subject-swap");

        // Creating, against a pair that holds nothing.
        match store.compare_and_swap_consent(None, original.clone()).await {
            Ok(true) => {}
            Ok(false) => report.fail(
                CONSENT_SWAP_APPLIES,
                "a create against a (client, subject) pair that holds no consent reported that it \
                 did not apply, so a first approval can never be recorded",
            ),
            Err(e) => report.fail(
                CONSENT_SWAP_APPLIES,
                format!("compare_and_swap_consent failed unexpectedly: {e}"),
            ),
        }

        // Read back, for the same reason as the two swaps above.
        let original = match store
            .find_consent(&ClientId::new("client-conformance"), "subject-swap")
            .await
        {
            Ok(Some(live)) => (*live).clone(),
            // NOT a failure of this check. A store whose `find_consent` cannot see what
            // `compare_and_swap_consent` just wrote has a lookup defect, and `round_trip/consent`
            // and `find_consent`'s own checks own it. Reporting it again here would give a host
            // two names for one bug and send them looking for a second one. Same reasoning as
            // `index_already_dirty` in the device-grant swap check.
            Ok(None) => return,
            Err(e) => {
                report.fail(
                    CONSENT_SWAP_APPLIES,
                    format!("find_consent failed unexpectedly: {e}"),
                );
                return;
            }
        };

        // WIDENING, against exactly what the store holds: it must APPLY, and the wider record must
        // be what the next reader sees.
        //
        // This was the missing direction, and its absence was invisible: the three calls this
        // check used to make were (None, create) which must apply, (None, duplicate) which must
        // refuse, and (Some, widen-after-withdrawal) which must refuse — not one of them a `Some`
        // that MATCHES. A store answering `Ok(false)` to every `Some(..)` passed all three while
        // `compare_and_swap_consent/applies_when_it_matches` reported nothing, despite its name.
        // What that costs is not an error anywhere: a widen that never lands means the record
        // never grows, so the user is prompted again on every authorization request that asks for
        // one more scope, forever, on a store certified clean.
        let mut widened = original.clone();
        widened.extend(&scopes("read write admin"), &[]);
        match store
            .compare_and_swap_consent(Some(&original), widened.clone())
            .await
        {
            Ok(true) => {}
            Ok(false) => report.fail(
                CONSENT_SWAP_APPLIES,
                "a widen whose expected record is exactly what is stored reported that it did not \
                 apply, so a consent can never be broadened in place and the user is re-prompted \
                 on every authorization request that asks for a scope they have already approved",
            ),
            Err(e) => report.fail(
                CONSENT_SWAP_APPLIES,
                format!("compare_and_swap_consent failed unexpectedly: {e}"),
            ),
        }
        // Read back rather than assumed: a swap that reports success and writes nothing is a
        // distinct defect from one that refuses, and it fails in the same silent direction.
        let original = match store
            .find_consent(&ClientId::new("client-conformance"), "subject-swap")
            .await
        {
            Ok(Some(live)) if live.scope == widened.scope => (*live).clone(),
            Ok(Some(live)) => {
                report.fail(
                    CONSENT_SWAP_APPLIES,
                    format!(
                        "a widen that reported success did not change the stored record: the pair \
                         still holds scope {:?} rather than the widened {:?}",
                        live.scope, widened.scope
                    ),
                );
                (*live).clone()
            }
            Ok(None) => return,
            Err(e) => {
                report.fail(
                    CONSENT_SWAP_APPLIES,
                    format!("find_consent failed unexpectedly: {e}"),
                );
                return;
            }
        };

        // Creating AGAIN, against a pair that now holds one: refused. This is the half that keeps
        // one live consent per pair, so two concurrent first approvals cannot each create a record.
        let duplicate = sample_consent("consent-swap-duplicate", "subject-swap");
        match store.compare_and_swap_consent(None, duplicate).await {
            Ok(false) => {}
            Ok(true) => report.fail(
                CONSENT_SWAP_HONOURS_EXPECTED,
                "a create applied against a pair that already holds a consent: the pair now has \
                 two, and a user withdrawing one is told they revoked an application that is \
                 still authorized by the other",
            ),
            Err(e) => report.fail(
                CONSENT_SWAP_HONOURS_EXPECTED,
                format!("compare_and_swap_consent failed unexpectedly: {e}"),
            ),
        }

        // WITHDRAWN, then widened: refused. The direction the server's own doc used to call benign
        // and never considered.
        if report
            .ok(
                CONSENT_SWAP_NEVER_RESURRECTS,
                "revoke_consent",
                store.revoke_consent("consent-swap", barrier_window()).await,
            )
            .is_none()
        {
            return;
        }
        // Widened again, by a RESOURCE this time, so the record genuinely differs from the one
        // that was withdrawn and a store answering `Ok(true)` here cannot be excused as having
        // written what was already there.
        let mut widened_again = original.clone();
        widened_again.extend(
            &scopes("read write admin"),
            &["https://rs-three.example/".to_string()],
        );
        match store
            .compare_and_swap_consent(Some(&original), widened_again)
            .await
        {
            Ok(false) => {}
            Ok(true) => report.fail(
                CONSENT_SWAP_NEVER_RESURRECTS,
                "a widen applied against a consent that had been WITHDRAWN: the user was told \
                 they revoked an application and every later authorization request is still \
                 answered from the record they destroyed",
            ),
            Err(e) => report.fail(
                CONSENT_SWAP_NEVER_RESURRECTS,
                format!("compare_and_swap_consent failed unexpectedly: {e}"),
            ),
        }
        match store
            .find_consent(&ClientId::new("client-conformance"), "subject-swap")
            .await
        {
            Ok(None) => {}
            Ok(Some(_)) => report.fail(
                CONSENT_SWAP_NEVER_RESURRECTS,
                "a withdrawn consent is live again after a swap",
            ),
            Err(e) => report.fail(
                CONSENT_SWAP_NEVER_RESURRECTS,
                format!("find_consent failed unexpectedly: {e}"),
            ),
        }
    }

    // --------------------------------------------------- the swaps, RACED against themselves

    /// Exactly one racer may be told its swap applied.
    ///
    /// More than one IS the lost update: the first write moves the record off `expected`, so every
    /// later comparison must fail, and a store that told two callers otherwise performed the
    /// comparison and the write as separate steps. What is lost between them is whatever the
    /// previous winner decided. None means no swap landed at all, which is the same root failing
    /// in the opposite direction.
    ///
    /// Separate from [`StorageConformance::judge_race`] rather than reusing it, because that one's
    /// wording is about an atomic remove-and-return and a host reading "the value was lost" for a
    /// swap would go looking for the wrong thing.
    fn judge_swap_race(
        &self,
        report: &mut Report,
        check: &'static str,
        what: &str,
        results: TakeResults<()>,
    ) {
        let winners = results.iter().filter(|r| matches!(r, Ok(Some(_)))).count();
        let errors = results.iter().filter(|r| r.is_err()).count();
        if winners > 1 {
            report.fail(
                check,
                format!(
                    "{winners} of {} concurrent swaps of {what}, every one of them naming the SAME \
                     expected value, were each told they applied. Only the first can be right: the \
                     first write moves the record off `expected`, so every comparison after it must \
                     fail. This store performs the comparison and the write as separate steps, and \
                     what is lost between them is whatever the previous writer decided",
                    results.len()
                ),
            );
        } else if winners == 0 {
            report.fail(
                check,
                format!(
                    "none of {} concurrent swaps of {what} applied, though the record was stored \
                     with exactly the expected value beforehand: the write was lost rather than \
                     granted to one caller, so the decision the winner made is recorded nowhere",
                    results.len()
                ),
            );
        }
        if errors > 0 {
            report.fail(
                check,
                format!(
                    "{errors} of {} concurrent swaps of {what} failed with a StorageError. The \
                     server maps that to server_error, so an ordinary overlap between two writers \
                     fails a legitimate request; a store using optimistic concurrency must retry \
                     internally rather than surface the conflict, because `Ok(false)` already says \
                     \"somebody else got there first\" and the caller knows what to do with it. \
                     This is the `Storage` trait's rule that contention is the store's to resolve, \
                     not the caller's",
                    results.len()
                ),
            );
        }
    }

    /// RFC 8628 section 3.3 first-decision-wins, under the concurrency it is actually decided
    /// under: the polling device and the verification UI are different requests on different
    /// nodes. Every racer offers a DIFFERENT approval, so a store that lets two through has thrown
    /// away a decision a human made rather than merely written the same bytes twice.
    async fn compare_and_swap_device_grant_race(&self, report: &mut Report) {
        let store = self.store().await;
        let pending = DeviceGrant {
            state: DeviceGrantState::Pending,
            ..sample_device_grant("dc-swap-race", "SWPR-AAAA")
        };
        if report
            .ok(
                SWAP_ATOMIC,
                "put_device_grant",
                store.put_device_grant(pending.clone()).await,
            )
            .is_none()
        {
            return;
        }
        let seq = AtomicUsize::new(0);
        let results = self
            .race(report, |gate| {
                let store = Arc::clone(&store);
                let decided = DeviceGrant {
                    state: DeviceGrantState::Approved {
                        subject: format!("subject-racer-{}", seq.fetch_add(1, Ordering::SeqCst)),
                    },
                    ..pending.clone()
                };
                Box::pin(async move {
                    gate.wait().await;
                    // `Ok(true)` is the winner, exactly as a taken record is: mapped here so
                    // `judge_swap_race` counts the same shape the `take_*` checks produce.
                    store
                        .compare_and_swap_device_grant(&DeviceGrantState::Pending, decided)
                        .await
                        .map(|applied| if applied { Some(()) } else { None })
                })
            })
            .await;
        self.judge_swap_race(report, SWAP_ATOMIC, "one Pending device grant", results);
    }

    /// The RFC 7592 section 2.2 half. Two management updates of one registration overlap; the
    /// loser must be told it lost, or the metadata document that landed first is silently gone.
    async fn compare_and_swap_client_race(&self, report: &mut Report) {
        let store = self.store().await;
        let id = ClientId::new("client-swap-race");
        if report
            .ok(
                CLIENT_SWAP_ATOMIC,
                "put_client",
                store.put_client(sample_client(id.as_str())).await,
            )
            .is_none()
        {
            return;
        }
        // Read back rather than reusing what was written, for the reason the sequential client
        // swap gives: a store that mutates the record on the way in has a round-trip defect that
        // `round_trip/client` owns, and every racer failing its comparison here would report it a
        // second time as a lost swap.
        let Some(Some(original)) = report.ok(
            CLIENT_SWAP_ATOMIC,
            "get_client",
            store.get_client(&id).await,
        ) else {
            return;
        };
        let original = (*original).clone();
        let seq = AtomicUsize::new(0);
        let results = self
            .race(report, |gate| {
                let store = Arc::clone(&store);
                let mut updated = original.clone();
                updated.name = Some(format!(
                    "renamed by racer {}",
                    seq.fetch_add(1, Ordering::SeqCst)
                ));
                let expected = original.clone();
                Box::pin(async move {
                    gate.wait().await;
                    store
                        .compare_and_swap_client(&expected, updated)
                        .await
                        .map(|applied| if applied { Some(()) } else { None })
                })
            })
            .await;
        self.judge_swap_race(report, CLIENT_SWAP_ATOMIC, "one registration", results);
    }

    /// The interleaving this swap exists for, run as a real overlap: a redemption suspended in the
    /// host's signer and a replay arriving behind it both write the same code record. Exactly one
    /// may land, or the trace the replay left is overwritten by the redemption it was containing.
    async fn compare_and_swap_authorization_code_race(&self, report: &mut Report) {
        let store = self.store().await;
        if report
            .ok(
                CODE_SWAP_ATOMIC,
                "put_authorization_code",
                store
                    .put_authorization_code(sample_authorization_code("code-swap-race"))
                    .await,
            )
            .is_none()
        {
            return;
        }
        // Taken and put back, so the `expected` state is what the store ACTUALLY holds; see the
        // sequential code swap for why that read matters.
        let Some(Some(issued)) = report.ok(
            CODE_SWAP_ATOMIC,
            "take_authorization_code",
            store.take_authorization_code("code-swap-race").await,
        ) else {
            return;
        };
        if report
            .ok(
                CODE_SWAP_ATOMIC,
                "put_authorization_code (put back for the race)",
                store.put_authorization_code(issued.clone()).await,
            )
            .is_none()
        {
            return;
        }
        let seq = AtomicUsize::new(0);
        let results = self
            .race(report, |gate| {
                let store = Arc::clone(&store);
                let mut updated = issued.clone();
                updated.state = AuthorizationCodeState::Replayed {
                    access_token: Some(format!("at-racer-{}", seq.fetch_add(1, Ordering::SeqCst))),
                    refresh_token: None,
                };
                let expected = issued.state.clone();
                Box::pin(async move {
                    gate.wait().await;
                    store
                        .compare_and_swap_authorization_code(&expected, updated)
                        .await
                        .map(|applied| if applied { Some(()) } else { None })
                })
            })
            .await;
        self.judge_swap_race(
            report,
            CODE_SWAP_ATOMIC,
            "one authorization code record",
            results,
        );
    }

    /// Two overlapping widens of one consent. The loser must be refused, or the narrower of two
    /// concurrent decisions can land second and the user is granted a scope nobody approved last.
    #[cfg(feature = "consent")]
    async fn compare_and_swap_consent_race(&self, report: &mut Report) {
        let store = self.store().await;
        if report
            .ok(
                CONSENT_SWAP_ATOMIC,
                "compare_and_swap_consent (create)",
                store
                    .compare_and_swap_consent(
                        None,
                        sample_consent("consent-swap-race", "subject-swap-race"),
                    )
                    .await,
            )
            .is_none()
        {
            return;
        }
        // NOT a failure of this check when the pair reads back empty: a store whose `find_consent`
        // cannot see what the swap just wrote has a lookup defect that `round_trip/consent` owns.
        let Some(Some(original)) = report.ok(
            CONSENT_SWAP_ATOMIC,
            "find_consent",
            store
                .find_consent(&ClientId::new("client-conformance"), "subject-swap-race")
                .await,
        ) else {
            return;
        };
        let original = (*original).clone();
        let seq = AtomicUsize::new(0);
        let results = self
            .race(report, |gate| {
                let store = Arc::clone(&store);
                let mut updated = original.clone();
                // A DISTINCT instant per racer, so the records genuinely differ and a store that
                // applied two of them has kept the wrong one rather than the same one twice.
                updated.granted_at = at(seq.fetch_add(1, Ordering::SeqCst) as u64);
                let expected = original.clone();
                Box::pin(async move {
                    gate.wait().await;
                    store
                        .compare_and_swap_consent(Some(&expected), updated)
                        .await
                        .map(|applied| if applied { Some(()) } else { None })
                })
            })
            .await;
        self.judge_swap_race(report, CONSENT_SWAP_ATOMIC, "one live consent", results);
    }

    // ------------------------------------------------------------------ round-trip fidelity

    /// A store that silently drops a field passes any test that only checks the key came back.
    /// The fields that matter most here are named in their own checks below: `family_id` is what
    /// RFC 9700 section 4.14.2 reuse revocation walks, and `resource` is the RFC 8707 audience
    /// restriction, so a store that loses either produces tokens that are wider than what was
    /// granted while still looking correct.
    ///
    /// Each of these also proves the "insert or REPLACE" half of its `put_*`, by writing the key
    /// TWICE with different contents and requiring the second write to win. An INSERT-only store
    /// is not a hypothetical shape: `INSERT ... ON CONFLICT DO NOTHING` is one clause away from
    /// the upsert a host meant to write, it raises no error, and every one of these checks passed
    /// it while each key was written exactly once.
    async fn round_trip_client(&self, report: &mut Report) {
        let store = self.store().await;
        let want = sample_client("client-round-trip");
        // Written over a DIFFERENT registration under the same key, because `put_client` is
        // documented as an upsert and re-provisioning a `client_id` the host chose is a legitimate
        // thing to do after deleting it. Two fields differ, so an INSERT-only store is named by
        // the field the violation prints rather than left to be guessed at.
        let superseded = Client {
            name: Some("the registration this put must REPLACE".to_string()),
            allowed_scopes: scopes("read"),
            ..want.clone()
        };
        if report
            .ok(
                ROUND_TRIP_CLIENT,
                "put_client (the registration the next put must replace)",
                store.put_client(superseded).await,
            )
            .is_none()
        {
            return;
        }
        if report
            .ok(
                ROUND_TRIP_CLIENT,
                "put_client",
                store.put_client(want.clone()).await,
            )
            .is_none()
        {
            return;
        }
        let Some(got) = report.ok(
            ROUND_TRIP_CLIENT,
            "get_client",
            store.get_client(&want.client_id).await,
        ) else {
            return;
        };
        let Some(got) = report.some(ROUND_TRIP_CLIENT, "get_client", got) else {
            return;
        };
        let c = ROUND_TRIP_CLIENT;
        report.same(c, "client_id", &want.client_id, &got.client_id);
        report.same(c, "auth", &want.auth, &got.auth);
        report.same(c, "grant_types", &want.grant_types, &got.grant_types);
        report.same(c, "redirect_uris", &want.redirect_uris, &got.redirect_uris);
        report.same(
            c,
            "allowed_scopes",
            &want.allowed_scopes,
            &got.allowed_scopes,
        );
        report.same(
            c,
            "default_scopes",
            &want.default_scopes,
            &got.default_scopes,
        );
        report.same(c, "name", &want.name, &got.name);
        report.same(c, "registration", &want.registration, &got.registration);
    }

    /// RFC 8628 section 3.3: the user's decision at the verification UI is FIRST-DECISION-WINS, and
    /// `Storage::compare_and_swap_device_grant` is the only thing that makes it so. Three unrelated
    /// actors write one device grant (the polling device, and the user approving or denying), so
    /// without a real compare-and-swap the last writer wins by accident and a DENIAL a human
    /// actually made is silently reverted to `Pending` by a poll that read the grant a moment
    /// earlier.
    ///
    /// A store gets this wrong in two ways, and neither is visible to any other check here, because
    /// both are perfectly ATOMIC. The first is dropping the comparison: `UPDATE ... SET payload =
    /// $1 WHERE device_code = $2`, reporting `rows_affected > 0`, which is one statement, races
    /// nothing, and reinstates exactly the lost update the method exists to prevent.
    ///
    /// The second is the one nobody thinks to test for, and it is worse: a read, a comparison, and
    /// an INSERT-OR-UPDATE. `take_device_grant` is single-use redemption, so a grant redeemed
    /// between that read and that write is gone; an upsert does not fail and does not no-op against
    /// a row that is not there, it puts the grant BACK. An RFC 8628 device code that has already
    /// been exchanged for a token becomes exchangeable a second time. The trait says a swap must
    /// never bring a redeemed grant back; this is the check that holds a store to it.
    async fn compare_and_swap_device_grant(&self, report: &mut Report) {
        let store = self.store().await;
        // Pending, because that is the state both the poll and the verification UI swap AGAINST.
        let pending = DeviceGrant {
            state: DeviceGrantState::Pending,
            ..sample_device_grant("dc-swap", "SWAP-AAAA")
        };
        if report
            .ok(
                SWAP_APPLIES_ON_MATCH,
                "put_device_grant",
                store.put_device_grant(pending.clone()).await,
            )
            .is_none()
        {
            return;
        }

        // 1. The swap a correct store MUST apply: the state is the one the caller read.
        let denied = DeviceGrant {
            state: DeviceGrantState::Denied,
            ..pending.clone()
        };
        let Some(applied) = report.ok(
            SWAP_APPLIES_ON_MATCH,
            "compare_and_swap_device_grant",
            store
                .compare_and_swap_device_grant(&DeviceGrantState::Pending, denied.clone())
                .await,
        ) else {
            return;
        };
        if !applied {
            report.fail(
                SWAP_APPLIES_ON_MATCH,
                "a swap whose expected state matched the stored state reported that it did not \
                 apply; the user's decision at the verification UI would never be recorded",
            );
        }
        match store.get_device_grant(&pending.device_code).await {
            Ok(Some(got)) if got.state == DeviceGrantState::Denied => {}
            Ok(other) => report.fail(
                SWAP_APPLIES_ON_MATCH,
                format!(
                    "a swap that reported success did not change the stored state: read back \
                     {:?}",
                    other.map(|g| g.state)
                ),
            ),
            Err(e) => report.fail(
                SWAP_APPLIES_ON_MATCH,
                format!("get_device_grant failed unexpectedly: {e}"),
            ),
        }

        // 2. The swap a correct store MUST refuse. The stored state has moved on to `Denied`, so a
        // poll still holding `Pending` from its own earlier read must not land. This is the whole
        // of RFC 8628 section 3.3's first-decision-wins property, and a store that ignores
        // `expected` passes every other check in this harness while failing it.
        let repending = DeviceGrant {
            state: DeviceGrantState::Pending,
            ..pending.clone()
        };
        let Some(applied) = report.ok(
            SWAP_HONOURS_EXPECTED,
            "compare_and_swap_device_grant",
            store
                .compare_and_swap_device_grant(&DeviceGrantState::Pending, repending)
                .await,
        ) else {
            return;
        };
        if applied {
            report.fail(
                SWAP_HONOURS_EXPECTED,
                "a swap whose expected state was STALE reported that it applied: the store is not \
                 comparing `expected` against the stored state at all, so the user's decision is \
                 reverted by whichever writer arrives last",
            );
        }
        match store.get_device_grant(&pending.device_code).await {
            Ok(Some(got)) if got.state == DeviceGrantState::Denied => {}
            Ok(other) => report.fail(
                SWAP_HONOURS_EXPECTED,
                format!(
                    "a swap with a stale `expected` overwrote the stored state: the user denied \
                     this grant and it now reads {:?}",
                    other.map(|g| g.state)
                ),
            ),
            Err(e) => report.fail(
                SWAP_HONOURS_EXPECTED,
                format!("get_device_grant failed unexpectedly: {e}"),
            ),
        }

        // 3. Resurrection. The grant is REDEEMED, exactly as `take_device_grant` leaves it after a
        // successful token request, and a swap that was in flight when that happened now lands.
        if report
            .ok(
                SWAP_NEVER_RESURRECTS,
                "take_device_grant",
                store.take_device_grant(&pending.device_code).await,
            )
            .is_none()
        {
            return;
        }
        // Whether the index was ALREADY dirty before the swap ran. A store whose `take` leaves the
        // user-code row behind has a different defect, which `user_code_index/cleared_by_take`
        // owns; without this the swap check would report it a second time under its own name and a
        // host would chase two bugs where there is one.
        let index_already_dirty = matches!(
            store
                .find_device_grant_by_user_code(&normalize_user_code(&pending.user_code))
                .await,
            Ok(Some(_))
        );
        let Some(applied) = report.ok(
            SWAP_NEVER_RESURRECTS,
            "compare_and_swap_device_grant",
            store
                .compare_and_swap_device_grant(&DeviceGrantState::Denied, denied)
                .await,
        ) else {
            return;
        };
        if applied {
            report.fail(
                SWAP_NEVER_RESURRECTS,
                "a swap against a device_code that had already been redeemed reported that it \
                 applied: `Ok(false)` is the only correct answer for a row that is not there",
            );
        }
        match store.get_device_grant(&pending.device_code).await {
            Ok(None) => {}
            Ok(Some(_)) => report.fail(
                SWAP_NEVER_RESURRECTS,
                "a swap brought back a device grant that had been redeemed: the store is writing \
                 through an insert-or-update, so an RFC 8628 single-use device code is now \
                 redeemable a second time",
            ),
            Err(e) => report.fail(
                SWAP_NEVER_RESURRECTS,
                format!("get_device_grant failed unexpectedly: {e}"),
            ),
        }
        // The user-code half of the same resurrection: a store keeping the index as its own row
        // (the ordinary Redis or DynamoDB shape) can put the grant back THERE while the primary
        // lookup stays clean, and the verification UI reads this path.
        match store
            .find_device_grant_by_user_code(&normalize_user_code(&pending.user_code))
            .await
        {
            Ok(None) => {}
            Ok(Some(_)) if index_already_dirty => {}
            Ok(Some(_)) => report.fail(
                SWAP_NEVER_RESURRECTS,
                "a swap put a redeemed grant back into the user-code index: the code a human \
                 typed resolves to a grant that has already been exchanged for a token",
            ),
            Err(e) => report.fail(
                SWAP_NEVER_RESURRECTS,
                format!("find_device_grant_by_user_code failed unexpectedly: {e}"),
            ),
        }
    }

    /// THE USER-CODE INDEX CONTRACT, ON THE SWAP RATHER THAN ON THE PUT.
    ///
    /// `Storage::compare_and_swap_device_grant` restates both halves of
    /// `Storage::put_device_grant`'s index contract in capitals rather than referring to them,
    /// because this trait has already watched them drift: the reference implementation's own doc
    /// claimed the swap DELEGATED to the put; it did not, it duplicated it, and the duplicate was
    /// missing the refusal. Nothing in this harness could see that. Every other swap it makes
    /// builds `updated` as `DeviceGrant { state: .., ..pending }`, so the user code is byte for
    /// byte the one already indexed and neither half is ever reached.
    ///
    /// What that hides is a store whose swap is a plain `UPDATE ... SET user_code_normalized = $2
    /// WHERE device_code = $1` with no unique index behind it. It certifies clean here and then
    /// hands one RFC 8628 section 6.1 user code — the credential a human types at the verification
    /// page — to two live grants, while the code the first device is still displaying goes on
    /// resolving to it. A host reaches the swap on this path whenever the verification UI or a
    /// poll rewrites a grant whose code was re-drawn.
    async fn compare_and_swap_device_grant_user_code_index(&self, report: &mut Report) {
        // HALF ONE: a swap that CHANGES the user code must retire the old entry, exactly as a put
        // that changes it must (`user_code_index/retires_old_entry` owns the put).
        let store = self.store().await;
        let pending = DeviceGrant {
            state: DeviceGrantState::Pending,
            ..sample_device_grant("dc-swap-idx", "SWPA-AAAA")
        };
        if report
            .ok(
                SWAP_RETIRES_OLD_USER_CODE,
                "put_device_grant",
                store.put_device_grant(pending.clone()).await,
            )
            .is_none()
        {
            return;
        }
        let recoded = DeviceGrant {
            state: DeviceGrantState::Denied,
            user_code: "SWPB-BBBB".to_string(),
            ..pending.clone()
        };
        let Some(applied) = report.ok(
            SWAP_RETIRES_OLD_USER_CODE,
            "compare_and_swap_device_grant (same device_code, new user code)",
            store
                .compare_and_swap_device_grant(&DeviceGrantState::Pending, recoded)
                .await,
        ) else {
            return;
        };
        // A swap that answered `Ok(false)` to a matching `expected` is a defect
        // `compare_and_swap_device_grant/applies_when_the_state_matches` owns and names; judging
        // the index of a write the store says it never made would report that one bug a second
        // time under a second name, and a host would chase two. Same reasoning as
        // `index_already_dirty` in the resurrection check above.
        if applied {
            // The swap carried a NEW state as well as a new user code, and a store that moved the
            // index but did not persist the state has recorded a decision the caller never made.
            // Read it back: a swap that reports success has to have written what it was handed.
            if let Some(Some(got)) = report.ok(
                SWAP_RETIRES_OLD_USER_CODE,
                "get_device_grant after the re-coding swap",
                store.get_device_grant(&pending.device_code).await,
            ) {
                report.same(
                    SWAP_RETIRES_OLD_USER_CODE,
                    "state",
                    &DeviceGrantState::Denied,
                    &got.state,
                );
            }
            if let Some(found) = report.ok(
                SWAP_RETIRES_OLD_USER_CODE,
                "find_device_grant_by_user_code(new)",
                store.find_device_grant_by_user_code("SWPBBBBB").await,
            ) {
                if found.is_none() {
                    report.fail(
                        SWAP_RETIRES_OLD_USER_CODE,
                        "after a swap changed the user code, the NEW code does not resolve: the \
                         swap wrote the grant and not the index, so the verification page cannot \
                         reach a device that is waiting",
                    );
                }
            }
            if let Some(found) = report.ok(
                SWAP_RETIRES_OLD_USER_CODE,
                "find_device_grant_by_user_code(old)",
                store.find_device_grant_by_user_code("SWPAAAAA").await,
            ) {
                if found.is_some() {
                    report.fail(
                        SWAP_RETIRES_OLD_USER_CODE,
                        "the OLD user code still resolves after a swap changed it: a code the user \
                         was shown and that has been superseded can still be used to approve the \
                         grant, and the grant now answers to two codes at once",
                    );
                }
            }
        }

        // HALF TWO: a swap whose user code is already indexed for a DIFFERENT `device_code` must
        // fail with a `StorageError` and write nothing. A REFUSAL and not `Ok(false)`, because
        // `Ok(false)` means "the state moved on", which a caller answers by giving up quietly;
        // this is a store-level conflict the caller has to hear about, and the server's user-code
        // collision retry loop is only meaningful because the store can answer it without a race.
        let store = self.store().await;
        let first = DeviceGrant {
            state: DeviceGrantState::Pending,
            ..sample_device_grant("dc-swap-idx-first", "SWPC-CCCC")
        };
        let second = DeviceGrant {
            state: DeviceGrantState::Pending,
            ..sample_device_grant("dc-swap-idx-second", "SWPD-DDDD")
        };
        for grant in [first.clone(), second.clone()] {
            if report
                .ok(
                    SWAP_REFUSES_DUPLICATE_USER_CODE,
                    "put_device_grant",
                    store.put_device_grant(grant).await,
                )
                .is_none()
            {
                return;
            }
        }
        let clash = DeviceGrant {
            state: DeviceGrantState::Denied,
            user_code: first.user_code.clone(),
            ..second.clone()
        };
        if store
            .compare_and_swap_device_grant(&DeviceGrantState::Pending, clash)
            .await
            .is_ok()
        {
            report.fail(
                SWAP_REFUSES_DUPLICATE_USER_CODE,
                "a swap onto a user code already indexed for another device_code did not fail: it \
                 must answer a StorageError, not Ok(_). Repointing the index gives two devices one \
                 identity and orphans the older grant, and the put refuses exactly this while the \
                 swap — which the verification UI and the polling device both reach — let it \
                 through",
            );
        }
        // And the refusal wrote NOTHING. A store that writes and then errors has left the clash
        // behind while telling the caller it did not: the code the first device is displaying now
        // reaches the second device's grant, which is worse than either outcome on its own.
        if let Some(found) = report.ok(
            SWAP_REFUSES_DUPLICATE_USER_CODE,
            "find_device_grant_by_user_code after the refused swap",
            store.find_device_grant_by_user_code("SWPCCCCC").await,
        ) {
            match found {
                Some(g) if g.device_code == first.device_code => {}
                Some(g) => report.fail(
                    SWAP_REFUSES_DUPLICATE_USER_CODE,
                    format!(
                        "the user code now resolves to device_code {:?}, not to the grant that \
                         owned it: the index was repointed by a swap that should have written \
                         nothing",
                        g.device_code
                    ),
                ),
                None => report.fail(
                    SWAP_REFUSES_DUPLICATE_USER_CODE,
                    "the user code resolves to nothing after a clashing swap: the refused write \
                     removed the index entry belonging to the grant that already owned it",
                ),
            }
        }
        if let Some(found) = report.ok(
            SWAP_REFUSES_DUPLICATE_USER_CODE,
            "get_device_grant after the refused swap",
            store.get_device_grant(&second.device_code).await,
        ) {
            match found {
                Some(g) if g.user_code == second.user_code => {}
                Some(g) => report.fail(
                    SWAP_REFUSES_DUPLICATE_USER_CODE,
                    format!(
                        "the swapping grant was rewritten even though its new user code belonged \
                         to another device_code: it now carries {:?}",
                        g.user_code
                    ),
                ),
                None => report.fail(
                    SWAP_REFUSES_DUPLICATE_USER_CODE,
                    "the swapping grant is gone after a refused swap: a refusal must leave the \
                     store exactly as it was",
                ),
            }
        }
        // "Exactly as it was" reaches the STATE too, not the user code alone: a swap that rewrote
        // the grant and then reported a refusal has moved a decision the caller was told it left
        // untouched. The clashing swap named `Denied`, so a store that let it through carries that
        // where a refusal must still read the `Pending` the grant was stored with.
        if let Some(Some(g)) = report.ok(
            SWAP_REFUSES_DUPLICATE_USER_CODE,
            "get_device_grant (state) after the refused swap",
            store.get_device_grant(&second.device_code).await,
        ) {
            report.same(
                SWAP_REFUSES_DUPLICATE_USER_CODE,
                "state of the grant a refused swap targeted",
                &second.state,
                &g.state,
            );
        }
    }

    async fn round_trip_device_grant(&self, report: &mut Report) {
        let store = self.store().await;
        let want = sample_device_grant("dc-round-trip", "RTRT-AAAA");
        if report
            .ok(
                ROUND_TRIP_DEVICE_GRANT,
                "put_device_grant",
                store.put_device_grant(want.clone()).await,
            )
            .is_none()
        {
            return;
        }
        let Some(got) = report.ok(
            ROUND_TRIP_DEVICE_GRANT,
            "get_device_grant",
            store.get_device_grant(&want.device_code).await,
        ) else {
            return;
        };
        let Some(got) = report.some(ROUND_TRIP_DEVICE_GRANT, "get_device_grant", got) else {
            return;
        };
        let c = ROUND_TRIP_DEVICE_GRANT;
        report.same(c, "device_code", &want.device_code, &got.device_code);
        report.same(c, "user_code", &want.user_code, &got.user_code);
        report.same(c, "client_id", &want.client_id, &got.client_id);
        report.same(c, "scope", &want.scope, &got.scope);
        report.same(c, "state", &want.state, &got.state);
        report.same(c, "created_at", &want.created_at, &got.created_at);
        report.same(c, "expires_at", &want.expires_at, &got.expires_at);
        report.same(c, "interval", &want.interval, &got.interval);
        report.same(c, "last_poll_at", &want.last_poll_at, &got.last_poll_at);

        // The same record has to come back through the OTHER read path as well: a store that
        // maintains a second table for the index and populates it from a subset of the columns
        // would pass the primary lookup and hand the verification UI a different grant.
        let Some(found) = report.ok(
            c,
            "find_device_grant_by_user_code",
            store
                .find_device_grant_by_user_code(&normalize_user_code(&want.user_code))
                .await,
        ) else {
            return;
        };
        match found {
            Some(found) => report.same(c, "by-user-code record", &want, &found),
            None => report.fail(
                c,
                "a grant that was just put is not reachable by its normalized user code",
            ),
        }
    }

    async fn round_trip_authorization_code(&self, report: &mut Report) {
        let store = self.store().await;
        let want = sample_authorization_code("code-round-trip");
        if report
            .ok(
                ROUND_TRIP_AUTHORIZATION_CODE,
                "put_authorization_code",
                store.put_authorization_code(want.clone()).await,
            )
            .is_none()
        {
            return;
        }
        // There is no non-destructive read for a code, by design: the server takes it and puts a
        // CONSUMED record back, which is what makes a replay recognisable.
        let Some(got) = report.ok(
            ROUND_TRIP_AUTHORIZATION_CODE,
            "take_authorization_code",
            store.take_authorization_code(&want.code).await,
        ) else {
            return;
        };
        let Some(got) = report.some(
            ROUND_TRIP_AUTHORIZATION_CODE,
            "take_authorization_code",
            got,
        ) else {
            return;
        };
        let c = ROUND_TRIP_AUTHORIZATION_CODE;
        report.same(c, "code", &want.code, &got.code);
        report.same(c, "client_id", &want.client_id, &got.client_id);
        report.same(c, "redirect_uri", &want.redirect_uri, &got.redirect_uri);
        // RFC 6749 section 4.1.3 makes the token endpoint's `redirect_uri` parameter required "if
        // the `redirect_uri` parameter was included in the authorization request", and this one
        // boolean is the whole of what a redemption has to answer that with. `redirect_uri` above
        // cannot stand in for it, because that field is filled in either way. A store that drops
        // the column reads back the `true` default and refuses every client entitled by section
        // 3.1.2.3 to omit the parameter — the ordinary shape for a client with exactly one
        // registered URI — blaming a mismatch that never happened.
        report.same(
            c,
            "redirect_uri_was_explicit",
            &want.redirect_uri_was_explicit,
            &got.redirect_uri_was_explicit,
        );
        report.same(c, "scope", &want.scope, &got.scope);
        report.same(c, "subject", &want.subject, &got.subject);
        report.same(
            c,
            "code_challenge",
            &want.code_challenge,
            &got.code_challenge,
        );
        report.same(
            c,
            "code_challenge_method",
            &want.code_challenge_method,
            &got.code_challenge_method,
        );
        report.same(c, "resource", &want.resource, &got.resource);
        // When the code was authored, which is what the token minted from it carries forward as
        // its `grant_established_at` and therefore what every barrier comparison downstream is
        // made against. A store that fills it from `now()` on read hands the redemption a grant
        // instant later than any revocation that has already been recorded, so the cascade the
        // user asked for is undone by the redemption it raced; a store that reads it back as
        // UNIX_EPOCH refuses redemptions nobody revoked. `expires_at` above cannot stand in for
        // it: they are separate columns and this crate stamps them from separate inputs.
        report.same(c, "issued_at", &want.issued_at, &got.issued_at);
        report.same(c, "expires_at", &want.expires_at, &got.expires_at);
        // `Consumed` carries what the code minted, which is what a replay revokes. A store that
        // flattens the state to a boolean loses the thing the remedy needs.
        report.same(c, "state", &want.state, &got.state);
        // RFC 9396 section 5: the code IS the record of what the resource owner approved, so a
        // store that drops the details here mints a token for a narrower authorization than the
        // user granted, and the client is told nothing about the difference.
        #[cfg(feature = "rar")]
        report.same(
            c,
            "authorization_details",
            &want.authorization_details,
            &got.authorization_details,
        );
        // RFC 9470 section 6.2: the authentication the host reported at the authorization request,
        // which is what the token minted from this code reports as `auth_time` and `acr`. Dropped,
        // a client that answered an `insufficient_user_authentication` challenge gets a token that
        // claims no step-up happened.
        #[cfg(feature = "consent")]
        report.same(
            c,
            "authentication",
            &want.authentication,
            &got.authentication,
        );
    }

    async fn round_trip_token(&self, report: &mut Report) {
        let store = self.store().await;
        let want = sample_token("at-round-trip", "client-round-trip", Some("fam-round-trip"));
        if report
            .ok(
                ROUND_TRIP_TOKEN,
                "put_token",
                store.put_token(want.clone()).await,
            )
            .is_none()
        {
            return;
        }
        let Some(got) = report.ok(
            ROUND_TRIP_TOKEN,
            "get_token",
            store.get_token(&want.access_token).await,
        ) else {
            return;
        };
        let Some(got) = report.some(ROUND_TRIP_TOKEN, "get_token", got) else {
            return;
        };
        let c = ROUND_TRIP_TOKEN;
        report.same(c, "access_token", &want.access_token, &got.access_token);
        report.same(c, "client_id", &want.client_id, &got.client_id);
        report.same(c, "subject", &want.subject, &got.subject);
        report.same(c, "scope", &want.scope, &got.scope);
        // RFC 8707: the audience the token is restricted to. Dropped here, every token is good at
        // every resource server that trusts this issuer.
        report.same(c, "resource", &want.resource, &got.resource);
        report.same(c, "issued_at", &want.issued_at, &got.issued_at);
        // `grant_established_at` is the SOLE time input to the revocation barrier for this record
        // kind, and it is NOT `issued_at` above: a rotation mints at `now` and carries the grant
        // instant forward unchanged, which is the whole reason the two are separate columns. A
        // store that fills it from `now()` on read, or that never wrote the column at all, is
        // certified clean here and then ADMITS every write a `client` or `consent` barrier exists
        // to refuse, because the barrier sees a grant established after the revocation. The mirror
        // image — a column read back as UNIX_EPOCH — turns every refresh rotation for a client
        // with any standing barrier into a permanent `invalid_grant`. Same argument as `pushed_at`
        // on the pushed request, on the record kind where a lost instant costs the most.
        report.same(
            c,
            "grant_established_at",
            &want.grant_established_at,
            &got.grant_established_at,
        );
        report.same(c, "expires_at", &want.expires_at, &got.expires_at);
        // RFC 9700 section 4.14.2: without this, a detected reuse cannot reach the access tokens
        // the thief already minted.
        report.same(c, "family_id", &want.family_id, &got.family_id);
        // RFC 9449 section 6: the DPoP binding. Dropped, the token is a bearer token again.
        #[cfg(feature = "dpop")]
        report.same(c, "jkt", &want.jkt, &got.jkt);
        // RFC 8705 section 3.1: the mTLS binding, which is the OTHER way this crate sender
        // constrains a token and which is dropped by exactly the same kind of missing column. It
        // went unchecked here for longer than `jkt` did, which is the argument for checking it: a
        // store certified clean by this harness while dropping `x5t_s256` silently unbinds every
        // certificate-bound token it holds, and the caller that introspects (the token's own
        // client, or since 0.9.2 the resource server it is addressed to) gets a token with no
        // `cnf` at all, which reads as a plain bearer token rather than as an error.
        #[cfg(feature = "mtls")]
        report.same(c, "x5t_s256", &want.x5t_s256, &got.x5t_s256);
        // RFC 9396 section 5: what the resource owner actually approved, beyond the scope string.
        // This crate has twice shipped a path that dropped it, so a store that does the same is
        // precisely the defect this harness exists to catch. A token whose details are gone is a
        // token the resource server can only fall back to `scope` for, which is the coarse
        // permission RAR was adopted to stop relying on.
        #[cfg(feature = "rar")]
        report.same(
            c,
            "authorization_details",
            &want.authorization_details,
            &got.authorization_details,
        );
        // RFC 8693 section 4.1: WHO authority was delegated to. An opaque token carries this
        // nowhere but here, so a store that drops the column answers RFC 7662 introspection with a
        // token that reads as the SUBJECT acting directly. A resource server then attributes to
        // the user a request the actor made on their behalf, which is exactly the distinction
        // section 1.1 draws between delegation and impersonation, decided by a missing column.
        #[cfg(feature = "token-exchange")]
        report.same(c, "act", &want.act, &got.act);
        // RFC 9470 section 6.2: the `auth_time` and `acr` an introspecting caller reads to
        // decide whether the authentication behind this token is strong or fresh enough. Dropped,
        // every token looks like it was minted with no step-up at all.
        #[cfg(feature = "consent")]
        report.same(
            c,
            "authentication",
            &want.authentication,
            &got.authentication,
        );
        // AND IT IS STILL THERE AFTERWARDS. `get_token` is a READ and not a take, and until this
        // line nothing here could tell the difference: every other `get_*` call in this file reads
        // a distinct key exactly once, so a store whose reads REMOVE what they return passed the
        // whole harness. `compare_and_swap_client` happens to read a registration twice, which is
        // the only reason `get_client` was covered; these two were not.
        //
        // `Storage::get_refresh_token` argues it as a security property and the same argument
        // covers the token: RFC 7009 section 2.1 requires revocation to verify that the token was
        // issued to the requesting client, and doing that by taking the record and putting it back
        // is a destructive operation on a credential the caller was never entitled to touch — if
        // the restoring write fails, the victim's credential is gone for good while the endpoint
        // still answers 200. RFC 7662 introspection reads the same record on every introspection
        // call, so a destructive read there empties the store one legitimate request at a time.
        match store.get_token(&want.access_token).await {
            Ok(Some(_)) => {}
            Ok(None) => report.fail(
                c,
                "a second get_token for the same access token found nothing: the read is \
                 DESTRUCTIVE, so every introspection or revocation that merely asked about a token \
                 has revoked it, and the client holding it is refused with no explanation anywhere",
            ),
            Err(e) => report.fail(c, format!("get_token failed unexpectedly: {e}")),
        }
    }

    async fn round_trip_refresh_token(&self, report: &mut Report) {
        let store = self.store().await;
        let want = sample_refresh("rt-round-trip", "client-round-trip", "fam-round-trip");
        if report
            .ok(
                ROUND_TRIP_REFRESH_TOKEN,
                "put_refresh_token",
                store.put_refresh_token(want.clone()).await,
            )
            .is_none()
        {
            return;
        }
        let Some(got) = report.ok(
            ROUND_TRIP_REFRESH_TOKEN,
            "get_refresh_token",
            store.get_refresh_token(&want.refresh_token).await,
        ) else {
            return;
        };
        let Some(got) = report.some(ROUND_TRIP_REFRESH_TOKEN, "get_refresh_token", got) else {
            return;
        };
        let c = ROUND_TRIP_REFRESH_TOKEN;
        report.same(c, "refresh_token", &want.refresh_token, &got.refresh_token);
        report.same(c, "client_id", &want.client_id, &got.client_id);
        report.same(c, "subject", &want.subject, &got.subject);
        report.same(c, "scope", &want.scope, &got.scope);
        report.same(c, "resource", &want.resource, &got.resource);
        // The barrier's time input again, and it matters MORE here than on the access token: this
        // is the instant the chain remembers and every rotation copies forward, never restamps, so
        // a store that loses it does not misjudge one write, it misjudges every write the chain
        // will ever make. Lost in the fail-open direction the withdrawal a user was told about is
        // undone by the rotation it raced; lost in the other, a client with any standing barrier
        // can never refresh again and the failure reads as `invalid_grant`.
        report.same(
            c,
            "grant_established_at",
            &want.grant_established_at,
            &got.grant_established_at,
        );
        report.same(c, "expires_at", &want.expires_at, &got.expires_at);
        report.same(c, "family_id", &want.family_id, &got.family_id);
        // `Spent` is the whole basis of reuse detection: a store that reads every record back as
        // `Active` turns the RFC 9700 section 4.14.2 remedy off.
        report.same(c, "state", &want.state, &got.state);
        // RFC 9449 section 5: carried across rotation and checked on redemption.
        #[cfg(feature = "dpop")]
        report.same(c, "jkt", &want.jkt, &got.jkt);
        // RFC 8705 section 3.1, and it matters MORE on the refresh record than on the access
        // token: this is the binding the next rotation copies onto the token it mints, so a store
        // that loses it here does not merely unbind one token, it unbinds every token the chain
        // will ever produce.
        #[cfg(feature = "mtls")]
        report.same(c, "x5t_s256", &want.x5t_s256, &got.x5t_s256);
        // RFC 9396 section 6: the refresh record is what the narrowing on the next rotation is
        // measured against. Dropped, the grant carries no details for a rotation to narrow, and
        // the refreshed token silently loses the rich authorization the user approved.
        #[cfg(feature = "rar")]
        report.same(
            c,
            "authorization_details",
            &want.authorization_details,
            &got.authorization_details,
        );
        // RFC 9470: carried across rotation so a client cannot defeat a `max_age` by refreshing.
        #[cfg(feature = "consent")]
        report.same(
            c,
            "authentication",
            &want.authentication,
            &got.authentication,
        );
        // AND IT IS STILL THERE AFTERWARDS, for the reason `Storage::get_refresh_token` states in
        // full: this method exists SO THAT a check about a refresh token never has to be built out
        // of a read-modify-write on it. A store that implements it as a take is the exact shape
        // that doc refuses, and it read as correct to every check in this harness, because no
        // other one asks the same store for the same key twice. What it costs is the victim's
        // chain: RFC 7009 section 2.1 verification on a token that turns out to belong to another
        // client has already destroyed it, and the endpoint answers 200 either way.
        match store.get_refresh_token(&want.refresh_token).await {
            Ok(Some(_)) => {}
            Ok(None) => report.fail(
                c,
                "a second get_refresh_token for the same token found nothing: the read is \
                 DESTRUCTIVE, so a revocation request that merely verified the requesting client \
                 has ended a chain it was not entitled to touch, and the user is logged out by a \
                 request that reported success",
            ),
            Err(e) => report.fail(c, format!("get_refresh_token failed unexpectedly: {e}")),
        }
    }

    // ------------------------------------------------------------------ atomicity

    async fn atomic_take_device_grant(&self, report: &mut Report) {
        let store = self.store().await;
        let grant = sample_device_grant("dc-race", "RACE-AAAA");
        if report
            .ok(
                ATOMIC_TAKE_DEVICE_GRANT,
                "put_device_grant",
                store.put_device_grant(grant).await,
            )
            .is_none()
        {
            return;
        }
        let results = self
            .race(report, |gate| {
                let store = Arc::clone(&store);
                Box::pin(async move {
                    gate.wait().await;
                    store.take_device_grant("dc-race").await
                })
            })
            .await;
        self.judge_race(report, ATOMIC_TAKE_DEVICE_GRANT, "device grant", results);

        // And it is gone by every path afterwards, not merely unavailable to the losers.
        if let Some(again) = report.ok(
            ATOMIC_TAKE_DEVICE_GRANT,
            "get_device_grant after take",
            store.get_device_grant("dc-race").await,
        ) {
            if again.is_some() {
                report.fail(
                    ATOMIC_TAKE_DEVICE_GRANT,
                    "the grant is still readable after take_device_grant returned it",
                );
            }
        }
    }

    async fn atomic_take_refresh_token(&self, report: &mut Report) {
        let store = self.store().await;
        let record = sample_refresh("rt-race", "client-race", "fam-race");
        if report
            .ok(
                ATOMIC_TAKE_REFRESH_TOKEN,
                "put_refresh_token",
                store.put_refresh_token(record).await,
            )
            .is_none()
        {
            return;
        }
        let results = self
            .race(report, |gate| {
                let store = Arc::clone(&store);
                Box::pin(async move {
                    gate.wait().await;
                    store.take_refresh_token("rt-race").await
                })
            })
            .await;
        self.judge_race(report, ATOMIC_TAKE_REFRESH_TOKEN, "refresh record", results);

        if let Some(again) = report.ok(
            ATOMIC_TAKE_REFRESH_TOKEN,
            "get_refresh_token after take",
            store.get_refresh_token("rt-race").await,
        ) {
            if again.is_some() {
                report.fail(
                    ATOMIC_TAKE_REFRESH_TOKEN,
                    "the record is still readable after take_refresh_token returned it",
                );
            }
        }
    }

    async fn atomic_take_authorization_code(&self, report: &mut Report) {
        let store = self.store().await;
        let record = sample_authorization_code("code-race");
        if report
            .ok(
                ATOMIC_TAKE_AUTHORIZATION_CODE,
                "put_authorization_code",
                store.put_authorization_code(record).await,
            )
            .is_none()
        {
            return;
        }
        let results = self
            .race(report, |gate| {
                let store = Arc::clone(&store);
                Box::pin(async move {
                    gate.wait().await;
                    store.take_authorization_code("code-race").await
                })
            })
            .await;
        self.judge_race(
            report,
            ATOMIC_TAKE_AUTHORIZATION_CODE,
            "authorization code record",
            results,
        );

        if let Some(again) = report.ok(
            ATOMIC_TAKE_AUTHORIZATION_CODE,
            "take_authorization_code after take",
            store.take_authorization_code("code-race").await,
        ) {
            if again.is_some() {
                report.fail(
                    ATOMIC_TAKE_AUTHORIZATION_CODE,
                    "a second take_authorization_code returned the record again",
                );
            }
        }
    }

    /// The pushed request has to come back out of the store as it went in, field for field.
    ///
    /// It was the ONE record kind this harness raced and never round-tripped, which made the PAR
    /// path the only one where a store could drop a column and be certified clean. That is the
    /// worst record to have the hole in: RFC 9126 section 2.1 has the AS validate the parameters
    /// at push time, and RFC 9101 section 6.3 has the authorization endpoint use ONLY the pushed
    /// parameters, so a parameter that is validated and then lost is a parameter the client was
    /// told was acceptable and then silently did not get. Losing `code_challenge` in particular is
    /// a silent PKCE downgrade on a request whose whole purpose was to keep it out of the browser.
    ///
    /// There is no non-destructive read for a handle, by design (RFC 9126 section 4 makes it
    /// single use), so the round trip is put-then-take, exactly as the authorization code's is.
    #[cfg(feature = "par")]
    async fn round_trip_pushed_request(&self, report: &mut Report) {
        let store = self.store().await;
        let want = sample_pushed_request("urn:ietf:params:oauth:request_uri:round-trip");
        // Over a DIFFERENT record under the same handle first: the method is "insert or replace",
        // and an INSERT-only store answers the authorization endpoint with the parameters of
        // whichever push happened to land first.
        let superseded = crate::par::PushedAuthorizationRequest {
            state: Some("the pushed request this put must REPLACE".to_string()),
            ..want.clone()
        };
        if report
            .ok(
                ROUND_TRIP_PUSHED_REQUEST,
                "put_pushed_authorization_request (the record the next put must replace)",
                store.put_pushed_authorization_request(superseded).await,
            )
            .is_none()
        {
            return;
        }
        if report
            .ok(
                ROUND_TRIP_PUSHED_REQUEST,
                "put_pushed_authorization_request",
                store.put_pushed_authorization_request(want.clone()).await,
            )
            .is_none()
        {
            return;
        }
        let Some(got) = report.ok(
            ROUND_TRIP_PUSHED_REQUEST,
            "take_pushed_authorization_request",
            store
                .take_pushed_authorization_request(&want.request_uri)
                .await,
        ) else {
            return;
        };
        let Some(got) = report.some(
            ROUND_TRIP_PUSHED_REQUEST,
            "take_pushed_authorization_request",
            got,
        ) else {
            return;
        };
        let c = ROUND_TRIP_PUSHED_REQUEST;
        report.same(c, "request_uri", &want.request_uri, &got.request_uri);
        // RFC 9126 section 2.2 binds the handle to the client that pushed it, and section 7.5 is
        // the attack that binding prevents; a store that loses it lets a stranger's `/authorize`
        // resolve somebody else's pushed request.
        report.same(c, "client_id", &want.client_id, &got.client_id);
        report.same(c, "response_type", &want.response_type, &got.response_type);
        report.same(c, "redirect_uri", &want.redirect_uri, &got.redirect_uri);
        report.same(c, "scope", &want.scope, &got.scope);
        report.same(c, "state", &want.state, &got.state);
        // RFC 7636 section 4.3: dropped here, the authorization endpoint reads a request with no
        // challenge and the code it mints is redeemable without a verifier.
        report.same(
            c,
            "code_challenge",
            &want.code_challenge,
            &got.code_challenge,
        );
        report.same(
            c,
            "code_challenge_method",
            &want.code_challenge_method,
            &got.code_challenge_method,
        );
        report.same(c, "resource", &want.resource, &got.resource);
        report.same(c, "expires_at", &want.expires_at, &got.expires_at);
        // `pushed_at` is the SOLE time input to the revocation barrier for this record kind, and
        // it was the one field of the one record this harness never compared. A host storing the
        // request as columns fills it with `now()` on read and is certified clean, while in
        // production the cross-client put-back that should be barrier-refused is ADMITTED, because
        // the barrier sees a request authored after the deletion. The mirror image — a store that
        // writes UNIX_EPOCH — refuses every push while any client barrier stands, which is a
        // silent, fail-closed PAR outage. The analogous instant is `grant_established_at` on a
        // token and a refresh record, and `issued_at` on an authorization code; all three were
        // uncompared alongside this one until round 7, so the whole family is checked now.
        report.same(c, "pushed_at", &want.pushed_at, &got.pushed_at);
        #[cfg(feature = "rar")]
        report.same(
            c,
            "authorization_details",
            &want.authorization_details,
            &got.authorization_details,
        );
        // RFC 9470 section 4. This crate has already shipped a bug where these two were dropped on
        // the PAR path, which disabled step-up for every PAR deployment; a store that drops them
        // reproduces that bug from the other side, and nothing else would report it.
        #[cfg(feature = "consent")]
        report.same(c, "acr_values", &want.acr_values, &got.acr_values);
        #[cfg(feature = "consent")]
        report.same(c, "max_age", &want.max_age, &got.max_age);
    }

    /// RFC 9126 section 4 makes a `request_uri` single use, and
    /// `take_pushed_authorization_request` is the ONLY thing enforcing it. Same defect shape as
    /// the other `take_*` operations: a store that reads then deletes lets two concurrent
    /// `/authorize` hits on one handle both resolve, so one pushed request authorizes twice.
    ///
    /// Worth checking separately rather than assuming a store that got the other three right got
    /// this one right too: this method arrived with the PAR feature, later than the rest, which is
    /// exactly the shape of thing a host adds in a hurry against an existing trait impl.
    #[cfg(feature = "par")]
    async fn atomic_take_pushed_request(&self, report: &mut Report) {
        let store = self.store().await;
        let record = sample_pushed_request("urn:ietf:params:oauth:request_uri:race");
        if report
            .ok(
                ATOMIC_TAKE_PUSHED_REQUEST,
                "put_pushed_authorization_request",
                store.put_pushed_authorization_request(record).await,
            )
            .is_none()
        {
            return;
        }
        let results = self
            .race(report, |gate| {
                let store = Arc::clone(&store);
                Box::pin(async move {
                    gate.wait().await;
                    store
                        .take_pushed_authorization_request("urn:ietf:params:oauth:request_uri:race")
                        .await
                })
            })
            .await;
        self.judge_race(
            report,
            ATOMIC_TAKE_PUSHED_REQUEST,
            "pushed authorization request",
            results,
        );

        if let Some(again) = report.ok(
            ATOMIC_TAKE_PUSHED_REQUEST,
            "take_pushed_authorization_request after take",
            store
                .take_pushed_authorization_request("urn:ietf:params:oauth:request_uri:race")
                .await,
        ) {
            if again.is_some() {
                report.fail(
                    ATOMIC_TAKE_PUSHED_REQUEST,
                    "a second take_pushed_authorization_request returned the handle again",
                );
            }
        }
    }

    /// Consent round trip, and the withdrawal cascade.
    ///
    /// The cascade is the one worth the most care in this whole harness. Withdrawal is what a user
    /// is told stops an application acting for them, so a store that removes the consent row and
    /// leaves the credentials alive has told the user something false, and nothing anywhere
    /// reports it: the endpoint answered 200, the row is gone, and the tokens keep working. That
    /// is strictly worse than a withdrawal that visibly fails.
    ///
    /// So this seeds one of every record kind the contract enumerates for the consent being
    /// withdrawn, AND one of each for a DIFFERENT subject of the same client, then requires the
    /// first set gone, the second set untouched, and the count to match. A store that revokes too
    /// much fails here just as a store that revokes too little does; over-revoking would log a
    /// different user out of an application they never withdrew.
    #[cfg(feature = "consent")]
    async fn consent(&self, report: &mut Report) {
        let store = self.store().await;

        let mine = sample_consent("consent-mine", "subject-conformance");
        let theirs = sample_consent("consent-theirs", "subject-other");
        // Over a DIFFERENT record under the same `consent_id` first: `put_consent` is "insert or
        // replace", and the server widens a consent in place, so an INSERT-only store keeps the
        // approval the user gave first and answers every later authorization request from it.
        let superseded = crate::consent::ConsentRecord {
            scope: scopes("read"),
            resource: Vec::new(),
            ..mine.clone()
        };
        if report
            .ok(
                ROUND_TRIP_CONSENT,
                "put_consent (the record the next put must replace)",
                store.put_consent(superseded).await,
            )
            .is_none()
        {
            return;
        }
        if report
            .ok(
                ROUND_TRIP_CONSENT,
                "put_consent",
                store.put_consent(mine.clone()).await,
            )
            .is_none()
        {
            return;
        }
        if report
            .ok(
                ROUND_TRIP_CONSENT,
                "put_consent (second subject)",
                store.put_consent(theirs.clone()).await,
            )
            .is_none()
        {
            return;
        }

        // Round trip by id, and by the (client, subject) lookup the remembered-consent path uses.
        // A store whose index disagrees with what it stored answers one and not the other.
        if let Some(Some(back)) = report.ok(
            ROUND_TRIP_CONSENT,
            "get_consent",
            store.get_consent("consent-mine").await,
        ) {
            if *back != mine {
                report.fail(
                    ROUND_TRIP_CONSENT,
                    "get_consent returned a record that differs from the one stored",
                );
            }
            // Field by field as well, so the violation NAMES the column an INSERT-only store kept
            // from the superseded record rather than leaving a host to diff two consents. `scope`
            // is what an authorization request is answered against and `resource` is the RFC 8707
            // audience it was approved for; a widen that did not land loses one or the other.
            report.same(ROUND_TRIP_CONSENT, "scope", &mine.scope, &back.scope);
            report.same(
                ROUND_TRIP_CONSENT,
                "resource",
                &mine.resource,
                &back.resource,
            );
        } else {
            report.fail(ROUND_TRIP_CONSENT, "get_consent did not return the record");
        }
        if let Some(found) = report.ok(
            ROUND_TRIP_CONSENT,
            "find_consent",
            store
                .find_consent(&ClientId::new("client-conformance"), "subject-conformance")
                .await,
        ) {
            match found {
                Some(f) if f.consent_id == mine.consent_id => {}
                Some(_) => report.fail(
                    ROUND_TRIP_CONSENT,
                    "find_consent returned a different consent than the one for that subject",
                ),
                None => report.fail(
                    ROUND_TRIP_CONSENT,
                    "find_consent did not find a consent that get_consent can read",
                ),
            }
        }

        // The per-subject listing, which is the ONE consent method nothing else here reads back.
        // It is what a host builds its "applications you have approved" screen on, and both ways
        // of getting it wrong are silent. A predicate on the wrong column (the client rather than
        // the subject, which is the index the AUTHORIZATION path wants and the tempting one to
        // reuse) shows one user another user's grants. A listing that answers empty shows the user
        // nothing to withdraw, which makes the whole withdrawal cascade the rest of this check
        // verifies unreachable from the UI: the user cannot revoke what they are never shown.
        //
        // Both consents belong to the SAME client and differ only in subject, so a store filtering
        // on the client cannot pass by coincidence.
        if let Some(listed) = report.ok(
            CONSENTS_FOR_SUBJECT,
            "consents_for_subject",
            store.consents_for_subject("subject-conformance").await,
        ) {
            let ids: Vec<&str> = listed.iter().map(|r| r.consent_id.as_ref()).collect();
            if !ids.contains(&"consent-mine") {
                report.fail(
                    CONSENTS_FOR_SUBJECT,
                    format!(
                        "consents_for_subject listed {ids:?} for a subject holding consent-mine: a \
                         user cannot withdraw what the host never shows them, so a listing that \
                         misses a live consent makes revocation unreachable from the UI"
                    ),
                );
            }
            if ids.contains(&"consent-theirs") {
                report.fail(
                    CONSENTS_FOR_SUBJECT,
                    format!(
                        "consents_for_subject listed {ids:?}, which includes a DIFFERENT resource \
                         owner's consent for the same client: the predicate is on the client id \
                         rather than the subject, so one user is shown another user's grants and \
                         can withdraw them"
                    ),
                );
            }
        }

        // Everything the withdrawal must reach, for the consent being withdrawn and for a
        // bystander subject of the SAME client.
        // The subject has to be overridden on every record, not just the device grant: the shared
        // sample builders all carry one subject, and a "different subject" fixture that is
        // secretly the same subject would make the spares-others check pass for the wrong reason.
        let seed = |subject: &str, tag: &str| {
            let mut token = sample_token(&format!("at-{tag}"), "client-conformance", Some(tag));
            token.subject = Some(subject.to_string());
            let mut refresh = sample_refresh(&format!("rt-{tag}"), "client-conformance", tag);
            refresh.subject = Some(subject.to_string());
            let mut code = sample_authorization_code(&format!("code-{tag}"));
            code.subject = subject.to_string();
            (
                token,
                refresh,
                code,
                sample_approved_device_grant(&format!("dc-{tag}"), &format!("UC{tag}"), subject),
            )
        };
        let (at_mine, rt_mine, code_mine, grant_mine) = seed("subject-conformance", "mine");
        let (at_theirs, rt_theirs, code_theirs, grant_theirs) = seed("subject-other", "theirs");
        for (t, r, c, g) in [
            (&at_mine, &rt_mine, &code_mine, &grant_mine),
            (&at_theirs, &rt_theirs, &code_theirs, &grant_theirs),
        ] {
            // EVERY seed is reported, and each one names the put that did not land. The three
            // below had their `Result` discarded, which made a store that silently failed to
            // persist a fixture PASS this check for the wrong reason: the assertions afterwards
            // are all "the record is gone", and a record that was never written is gone. This is
            // the exported harness, so that false pass would not have misled this repository, it
            // would have certified a stranger's broken store.
            let seeded = report
                .ok(
                    REVOKE_CONSENT_CASCADES,
                    "seeding the records a withdrawal must reach: put_token",
                    store.put_token(t.clone()).await,
                )
                .and(report.ok(
                    REVOKE_CONSENT_CASCADES,
                    "seeding the records a withdrawal must reach: put_refresh_token",
                    store.put_refresh_token(r.clone()).await,
                ))
                .and(report.ok(
                    REVOKE_CONSENT_CASCADES,
                    "seeding the records a withdrawal must reach: put_authorization_code",
                    store.put_authorization_code(c.clone()).await,
                ))
                .and(report.ok(
                    REVOKE_CONSENT_CASCADES,
                    "seeding the records a withdrawal must reach: put_device_grant",
                    store.put_device_grant(g.clone()).await,
                ));
            if seeded.is_none() {
                return;
            }
        }

        // A PENDING grant of the SAME client and the SAME subject. The contract says it is left
        // alone — "nobody has consented to it yet, so there is nothing there to withdraw" — and
        // every grant this harness planted until now was Approved, so a store that keyed the
        // device-grant arm of its cascade on the client alone, or that ignored the state
        // altogether, removed it and was certified clean. What it costs is a login the user is in
        // the middle of: they open the verification page, type the code they were shown, and are
        // told there is no such code, because a withdrawal of a DIFFERENT grant reaped it.
        let pending = DeviceGrant {
            state: DeviceGrantState::Pending,
            ..sample_device_grant("dc-pending-mine", "PEND-MINE")
        };
        if report
            .ok(
                REVOKE_CONSENT_SPARES_OTHERS,
                "seeding a PENDING device grant the withdrawal must leave alone",
                store.put_device_grant(pending).await,
            )
            .is_none()
        {
            return;
        }

        let removed = match report.ok(
            REVOKE_CONSENT_CASCADES,
            "revoke_consent",
            store.revoke_consent("consent-mine", barrier_window()).await,
        ) {
            Some(n) => n,
            None => return,
        };

        // The four the contract enumerates, plus the consent row itself.
        for (what, gone) in [
            (
                "the access token",
                matches!(store.get_token(&at_mine.access_token).await, Ok(None)),
            ),
            (
                "the refresh record",
                matches!(
                    store.get_refresh_token(&rt_mine.refresh_token).await,
                    Ok(None)
                ),
            ),
            (
                "the unredeemed authorization code",
                matches!(
                    store.take_authorization_code(&code_mine.code).await,
                    Ok(None)
                ),
            ),
            (
                "the approved device grant",
                matches!(
                    store.get_device_grant(&grant_mine.device_code).await,
                    Ok(None)
                ),
            ),
            // The index entry, which is not a record and is not counted, but which the contract
            // requires to be retired WITH the grant. `delete_client`'s cascade and the sweep were
            // both held to this and the withdrawal was not, so a store that kept the entry took
            // that user code out of circulation for good: `put_device_grant` must refuse a code
            // already indexed for a different `device_code`, and the server's generation loop
            // cannot see the collision coming, because the lookup it makes resolves to nothing.
            (
                "the user-code index entry of the approved device grant",
                matches!(
                    store
                        .find_device_grant_by_user_code(&normalize_user_code(&grant_mine.user_code))
                        .await,
                    Ok(None)
                ),
            ),
            (
                "the consent record",
                matches!(store.get_consent("consent-mine").await, Ok(None)),
            ),
        ] {
            if !gone {
                report.fail(
                    REVOKE_CONSENT_CASCADES,
                    format!(
                        "revoke_consent left {what} alive, so the user was told this application \
                         was stopped and it was not"
                    ),
                );
            }
        }

        // And nothing belonging to the other subject moved.
        for (what, alive) in [
            (
                "access token",
                matches!(store.get_token(&at_theirs.access_token).await, Ok(Some(_))),
            ),
            (
                "refresh record",
                matches!(
                    store.get_refresh_token(&rt_theirs.refresh_token).await,
                    Ok(Some(_))
                ),
            ),
            (
                "device grant",
                matches!(
                    store.get_device_grant(&grant_theirs.device_code).await,
                    Ok(Some(_))
                ),
            ),
            // Their index entry too, for the reason the doomed one is checked: only the REMOVING
            // direction was ever asserted, so a store that rebuilds the index on any bulk removal
            // and loses a row passed. After the first withdrawal every OTHER user code in the
            // deployment would resolve to nothing, and RFC 8628 verification would be dead with a
            // green certification behind it.
            (
                "user-code index entry",
                matches!(
                    store
                        .find_device_grant_by_user_code(&normalize_user_code(
                            &grant_theirs.user_code
                        ))
                        .await,
                    Ok(Some(_))
                ),
            ),
            // Their authorization code. Neither cascade in this harness read one back for the
            // party it must spare, so a store whose withdrawal dropped the `subject` predicate on
            // the codes table killed every grant in flight for every user of that client.
            (
                "authorization code",
                matches!(
                    store.take_authorization_code(&code_theirs.code).await,
                    Ok(Some(_))
                ),
            ),
            // The PENDING grant of the withdrawing user's own pair: nobody has consented to it, so
            // there is nothing there to withdraw.
            (
                "PENDING device grant of the same subject",
                matches!(store.get_device_grant("dc-pending-mine").await, Ok(Some(_))),
            ),
            (
                "consent record",
                matches!(store.get_consent("consent-theirs").await, Ok(Some(_))),
            ),
        ] {
            if !alive {
                report.fail(
                    REVOKE_CONSENT_SPARES_OTHERS,
                    format!(
                        "revoke_consent removed the {what} it was required to spare, ending a \
                         grant nobody withdrew"
                    ),
                );
            }
        }

        // AND THE WITHDRAWAL RECORDED A BARRIER. Everything above is about what the cascade
        // reached; this is about the rotation and the code redemption that were already in flight
        // for this pair when the user clicked withdraw, and that write AFTERWARDS. Nothing in this
        // harness exercised the `Consent` barrier at all: it was required by `revoke_consent` and
        // driven by no check, so a store that recorded the other two scopes and not this one was
        // certified clean, and a user who is told "you have revoked this application" still has a
        // working token — the exact failure this feature exists to prevent.
        //
        // A family the barrier does NOT name, so the consent scope is the only thing that can
        // refuse these two.
        let mut orphan = sample_token(
            "at-issued-after-the-withdrawal",
            "client-conformance",
            Some("fam-after-withdrawal"),
        );
        orphan.subject = Some("subject-conformance".to_string());
        match store.put_token(orphan).await {
            Ok(WriteOutcome::RefusedRevoked) => {}
            Ok(WriteOutcome::Applied) => report.fail(
                BARRIER_REFUSES_TOKEN,
                "put_token wrote an access token for the (client, subject) pair whose consent had \
                 just been withdrawn. The cascade only reaches what is in the store when it runs; \
                 an authorization code redemption or a rotation already in flight for this pair \
                 completes behind it, and the user who was told the application was stopped is \
                 holding a live token issued after they stopped it",
            ),
            Err(e) => report.fail(
                BARRIER_REFUSES_TOKEN,
                format!("put_token failed unexpectedly: {e}"),
            ),
        }
        let mut orphan_refresh = sample_refresh(
            "rt-restored-after-the-withdrawal",
            "client-conformance",
            "fam-after-withdrawal",
        );
        orphan_refresh.subject = Some("subject-conformance".to_string());
        match store.put_refresh_token(orphan_refresh).await {
            Ok(WriteOutcome::RefusedRevoked) => {}
            Ok(WriteOutcome::Applied) => report.fail(
                BARRIER_REFUSES_REFRESH,
                "put_refresh_token restored a refresh record for a withdrawn consent. This is the \
                 write every refusal path of a rotation makes, on a record `take_refresh_token` \
                 has already removed, so absence proves nothing and the barrier is the only \
                 evidence there is: without it the withdrawal is undone by the rotation it raced",
            ),
            Err(e) => report.fail(
                BARRIER_REFUSES_REFRESH,
                format!("put_refresh_token failed unexpectedly: {e}"),
            ),
        }
        // And it names ONE pair. The other subject of the same client withdrew nothing.
        let mut bystanders_token = sample_token(
            "at-for-the-other-subject-after-the-withdrawal",
            "client-conformance",
            Some("fam-after-withdrawal"),
        );
        bystanders_token.subject = Some("subject-other".to_string());
        match store.put_token(bystanders_token).await {
            Ok(WriteOutcome::Applied) => {}
            Ok(WriteOutcome::RefusedRevoked) => report.fail(
                BARRIER_SPARES_UNRELATED,
                "put_token refused a token for a DIFFERENT resource owner of the same client after \
                 one user withdrew their consent: the consent barrier is matching on the client \
                 alone, so one person clicking withdraw stops every other user of that application \
                 from obtaining a token until the barrier is swept",
            ),
            Err(e) => report.fail(
                BARRIER_SPARES_UNRELATED,
                format!("put_token failed unexpectedly: {e}"),
            ),
        }

        // And the listing has to agree with the withdrawal. A store keeping a per-subject index as
        // its own rows updates two things on a put and must update two things on a remove; the
        // half that is forgotten is the second one, and the symptom is a screen that offers a user
        // an application they already stopped, with a revoke button that reports success forever.
        if let Some(listed) = report.ok(
            CONSENTS_FOR_SUBJECT,
            "consents_for_subject after revoke_consent",
            store.consents_for_subject("subject-conformance").await,
        ) {
            let ids: Vec<&str> = listed.iter().map(|r| r.consent_id.as_ref()).collect();
            if ids.contains(&"consent-mine") {
                report.fail(
                    CONSENTS_FOR_SUBJECT,
                    format!(
                        "consents_for_subject still listed {ids:?} after that consent was \
                         withdrawn: the per-subject listing is a stale index, so the user is shown \
                         an application they have already stopped"
                    ),
                );
            }
        }

        // FOUR: the trait doc is explicit that the consent record itself is not counted, so this
        // is the four credentials. The count is what an operator investigating an incident reads,
        // so a store that reports a number it did not remove is lying to the one person who needs
        // the truth.
        if removed != 4 {
            report.fail(
                REVOKE_CONSENT_COUNT,
                format!(
                    "revoke_consent removed 4 credentials but reported {removed} (the consent \
                     record itself is not counted)"
                ),
            );
        }

        if let Some(second) = report.ok(
            REVOKE_CONSENT_COUNT,
            "revoke_consent (second call)",
            store.revoke_consent("consent-mine", barrier_window()).await,
        ) {
            if second != 0 {
                report.fail(
                    REVOKE_CONSENT_COUNT,
                    format!("withdrawing an already-withdrawn consent reported {second}, not 0"),
                );
            }
        }
    }

    /// Exactly one racer may receive the value. More than one IS the double-spend; none means the
    /// value was lost, which is a different bug with the same root (a non-atomic pair of steps).
    fn judge_race<T>(
        &self,
        report: &mut Report,
        check: &'static str,
        what: &str,
        results: TakeResults<T>,
    ) {
        // COUNTING the results is the only part of this that depends on `T`. The three verdicts
        // are arithmetic on those counts and three long strings, so they live in one non-generic
        // function instead of being recompiled, strings and all, once per raced record type.
        //
        // WORTH IT HERE AND NOT EVERYWHERE, and the difference is worth stating because the
        // opposite experiment was run and lost. This function and `race` are generic over a CLOSURE
        // type as well as a record type, so every call site gets its own instantiation with nothing
        // for the linker to fold, and each carries hundreds of bytes of prose. `Report::ok`,
        // `Report::some` and `Report::same` look like the same opportunity at ~250 call sites and
        // are NOT: outlining those cost 8,628 bytes rather than saving any. See the comment above
        // `impl Report`.
        //
        // MEASURED 2026-08-13, `scripts/size-report.sh` `test-util` row, aarch64-apple-darwin,
        // rustc 1.97.0: this and the `race` epilogue below are worth 2,940 bytes together.
        let winners = results.iter().filter(|r| matches!(r, Ok(Some(_)))).count();
        let errors = results.iter().filter(|r| r.is_err()).count();
        judge_race_counts(report, check, what, winners, errors, results.len());
    }

    /// Build `racers` futures from `make`, all parked on one rendezvous gate, and run them
    /// concurrently: on the host's runtime when a spawner was installed, otherwise polled together
    /// on this task. See the module docs for what each mode does and does not prove.
    async fn race<T, M>(&self, report: &mut Report, make: M) -> TakeResults<T>
    where
        // Every record this races over is a plain owned value; see `JoinAll` on why `Unpin` costs
        // nothing here.
        T: Send + Unpin + 'static,
        M: Fn(Arc<Gate>) -> BoxTake<T>,
    {
        let n = self.racers;
        let gate = Gate::new(n);
        let futures: Vec<BoxTake<T>> = (0..n).map(|_| make(Arc::clone(&gate))).collect();
        // Racers that never reached their own end. See `RacerGuard`: this is what turns a store
        // that panics under concurrency into a REPORT rather than a hung test run.
        let abandoned = Arc::new(AtomicUsize::new(0));

        let results = match &self.spawn {
            Some(spawn) => {
                let collected: Arc<Mutex<TakeResults<T>>> =
                    Arc::new(Mutex::new(Vec::with_capacity(n)));
                let latch = Latch::new(n);
                for fut in futures {
                    let collected = Arc::clone(&collected);
                    let latch = Arc::clone(&latch);
                    let abandoned = Arc::clone(&abandoned);
                    spawn(Box::pin(async move {
                        let mut guard = RacerGuard {
                            latch,
                            abandoned,
                            finished: false,
                        };
                        let outcome = fut.await;
                        // A poisoned lock means another racer panicked; the recovered guard is
                        // sound here because the vector is only ever pushed to.
                        collected
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(outcome);
                        guard.finished = true;
                    }));
                }
                latch.wait().await;
                let mut guard = collected.lock().unwrap_or_else(|e| e.into_inner());
                std::mem::take(&mut *guard)
            }
            None => JoinAll::new(futures).await,
        };

        // Same reasoning as `judge_race`, and the same measurement: two verdicts that are functions
        // of two numbers and a flag, reported from one place rather than from inside every
        // `(T, M)` this is instantiated at.
        race_setup_verdict(
            report,
            abandoned.load(Ordering::SeqCst),
            n,
            gate.unsatisfied(),
        );
        results
    }

    // ------------------------------------------------------------------ user-code index

    async fn user_code_index(&self, report: &mut Report) {
        // HALF ONE: a put that CHANGES a grant's user code must retire the old index entry, or the
        // superseded code goes on resolving to the grant.
        let store = self.store().await;
        let ok_first = report
            .ok(
                INDEX_RETIRES_OLD_USER_CODE,
                "put_device_grant",
                store
                    .put_device_grant(sample_device_grant("dc-idx", "AAAA-AAAA"))
                    .await,
            )
            .is_some();
        let ok_second = report
            .ok(
                INDEX_RETIRES_OLD_USER_CODE,
                "put_device_grant (same device_code, new user code)",
                store
                    .put_device_grant(sample_device_grant("dc-idx", "BBBB-BBBB"))
                    .await,
            )
            .is_some();
        if ok_first && ok_second {
            if let Some(found) = report.ok(
                INDEX_RETIRES_OLD_USER_CODE,
                "find_device_grant_by_user_code(new)",
                store.find_device_grant_by_user_code("BBBBBBBB").await,
            ) {
                if found.is_none() {
                    report.fail(
                        INDEX_RETIRES_OLD_USER_CODE,
                        "after a put changed the user code, the NEW code does not resolve",
                    );
                }
            }
            if let Some(found) = report.ok(
                INDEX_RETIRES_OLD_USER_CODE,
                "find_device_grant_by_user_code(old)",
                store.find_device_grant_by_user_code("AAAAAAAA").await,
            ) {
                if found.is_some() {
                    report.fail(
                        INDEX_RETIRES_OLD_USER_CODE,
                        "the OLD user code still resolves after a put changed it: a code the user \
                         was shown and that has been superseded can still be used to approve the \
                         grant",
                    );
                }
            }
        }

        // A take clears the index with the record, in one step. Otherwise a redeemed grant stays
        // reachable by the code a human typed.
        if report
            .ok(
                INDEX_CLEARED_BY_TAKE,
                "take_device_grant",
                store.take_device_grant("dc-idx").await,
            )
            .is_some()
        {
            if let Some(found) = report.ok(
                INDEX_CLEARED_BY_TAKE,
                "find_device_grant_by_user_code after take",
                store.find_device_grant_by_user_code("BBBBBBBB").await,
            ) {
                if found.is_some() {
                    report.fail(
                        INDEX_CLEARED_BY_TAKE,
                        "a taken grant is still reachable by its user code",
                    );
                }
            }
        }

        // HALF TWO: a put whose user code is already indexed for a DIFFERENT device_code must be
        // REFUSED. RFC 8628 section 6.1 makes the user code the credential a human types, so two
        // live grants answering to one code is two devices sharing an identity.
        let store = self.store().await;
        if report
            .ok(
                INDEX_REFUSES_DUPLICATE_USER_CODE,
                "put_device_grant",
                store
                    .put_device_grant(sample_device_grant("dc-first", "CCCC-CCCC"))
                    .await,
            )
            .is_none()
        {
            return;
        }
        let clash = store
            .put_device_grant(sample_device_grant("dc-second", "CCCC-CCCC"))
            .await;
        if clash.is_ok() {
            report.fail(
                INDEX_REFUSES_DUPLICATE_USER_CODE,
                "putting a second grant with a user code already indexed for another device_code \
                 succeeded; it must fail with a StorageError. Repointing the index gives two \
                 devices one identity and orphans the older grant, and it makes the server's \
                 user-code collision retry loop meaningless, since only the store can answer \
                 \"is this code taken\" without a race",
            );
        }

        // The refusal must also be a no-op: a store that writes and then errors leaves the second
        // grant half-present, which is worse than either outcome.
        if let Some(found) = report.ok(
            INDEX_REFUSAL_WRITES_NOTHING,
            "find_device_grant_by_user_code after the refused put",
            store.find_device_grant_by_user_code("CCCCCCCC").await,
        ) {
            match found {
                Some(g) if g.device_code == "dc-first" => {}
                Some(g) => report.fail(
                    INDEX_REFUSAL_WRITES_NOTHING,
                    format!(
                        "the user code now resolves to device_code {:?}, not to the grant that \
                         owned it: the index was repointed by a put that should have written \
                         nothing",
                        g.device_code
                    ),
                ),
                None => report.fail(
                    INDEX_REFUSAL_WRITES_NOTHING,
                    "the user code resolves to nothing after a clashing put: the refused write \
                     removed the index entry belonging to the grant that already owned it",
                ),
            }
        }
        if let Some(found) = report.ok(
            INDEX_REFUSAL_WRITES_NOTHING,
            "get_device_grant(dc-second)",
            store.get_device_grant("dc-second").await,
        ) {
            if found.is_some() {
                report.fail(
                    INDEX_REFUSAL_WRITES_NOTHING,
                    "the clashing grant was persisted even though its user code belonged to \
                     another device_code",
                );
            }
        }

        // Lookups are by NORMALIZED code, and the store does not normalize for the caller. The
        // server normalizes before it ever calls in (RFC 8628 section 6.1); a store that also
        // normalizes would make two different keys collide and would silently accept the display
        // form, which is precisely the input an attacker controls.
        let store = self.store().await;
        if report
            .ok(
                INDEX_NO_NORMALIZATION,
                "put_device_grant",
                store
                    .put_device_grant(sample_device_grant("dc-norm", "WDJB-MJHT"))
                    .await,
            )
            .is_none()
        {
            return;
        }
        if let Some(found) = report.ok(
            INDEX_NO_NORMALIZATION,
            "find_device_grant_by_user_code(normalized)",
            store.find_device_grant_by_user_code("WDJBMJHT").await,
        ) {
            if found.is_none() {
                report.fail(
                    INDEX_NO_NORMALIZATION,
                    "the normalized user code does not resolve, so the store is not indexing what \
                     it was given",
                );
            }
        }
        for probe in ["WDJB-MJHT", "wdjbmjht"] {
            if let Some(found) = report.ok(
                INDEX_NO_NORMALIZATION,
                "find_device_grant_by_user_code(unnormalized)",
                store.find_device_grant_by_user_code(probe).await,
            ) {
                if found.is_some() {
                    report.fail(
                        INDEX_NO_NORMALIZATION,
                        format!(
                            "the store resolved {probe:?}, which is not the normalized key it was \
                             given: it normalizes on the caller's behalf, so two distinct index \
                             keys collide and a lookup the server never intended succeeds"
                        ),
                    );
                }
            }
        }
    }

    // ------------------------------------------------------------------ sweep_expired

    async fn sweep(&self, report: &mut Report) {
        let store = self.store().await;
        let now = at(0);

        // Dead at `now` means `expires_at <= now`, so the boundary record (expires_at == now) is
        // planted deliberately: a store using `<` keeps a record the server treats as expired.
        let mut dead_grant = sample_device_grant("dc-dead", "DEAD-AAAA");
        dead_grant.expires_at = now;
        let mut live_grant = sample_device_grant("dc-live", "LIVE-AAAA");
        live_grant.expires_at = at(600);

        let mut dead_code = sample_authorization_code("code-dead");
        dead_code.expires_at = at_before(1);
        // ISSUED, and this is the only unredeemed code the harness plants. `sweep_expired` and
        // `delete_client` both say codes are removed "in either state", and every fixture here was
        // `Consumed`, so a store whose sweep carried a `WHERE state = 'consumed'` — the natural
        // shape for a schema that stores replay evidence in its own table, or for a sweep written
        // while thinking about replay detection — reclaimed nothing it was asked to and was
        // certified clean. An abandoned authorization request is the ordinary case, not the rare
        // one: every user who closes the tab leaves one, and nothing else ever removes it.
        dead_code.state = AuthorizationCodeState::Issued;
        let mut live_code = sample_authorization_code("code-live");
        live_code.expires_at = at(600);

        let mut dead_token = sample_token("at-dead", "client-sweep", Some("fam-sweep"));
        dead_token.expires_at = at_before(1);
        let mut live_token = sample_token("at-live", "client-sweep", Some("fam-sweep"));
        live_token.expires_at = at(600);

        // RFC 9126 section 4: an expired `request_uri` MUST be rejected, and once it is expired
        // there is nothing left to recognise it for, so nothing but this sweep ever reclaims one.
        // Planted at the boundary for the same reason the device grant is. The PAR endpoint is
        // client authenticated, so an unswept pushed-request table is not an anonymous flood, but
        // one chatty or compromised client grows it without bound, and a store certified by this
        // harness with no PAR record in the fixture would be certified for a sweep it never wrote.
        #[cfg(feature = "par")]
        let mut dead_pushed = sample_pushed_request(PUSHED_SWEPT);
        #[cfg(feature = "par")]
        {
            dead_pushed.expires_at = now;
        }
        #[cfg(feature = "par")]
        let mut live_pushed = sample_pushed_request(PUSHED_KEPT);
        #[cfg(feature = "par")]
        {
            live_pushed.expires_at = at(600);
        }

        let mut dead_refresh = sample_refresh("rt-dead", "client-sweep", "fam-sweep");
        dead_refresh.expires_at = Some(now);
        let mut live_refresh = sample_refresh("rt-live", "client-sweep", "fam-sweep");
        live_refresh.expires_at = Some(at(600));
        // `None` is a chain with no absolute lifetime and is NOT dead, however old it is.
        let mut endless_refresh = sample_refresh("rt-endless", "client-sweep", "fam-sweep");
        endless_refresh.expires_at = None;

        let c = SWEEP_REMOVES_DEAD;
        let mut planted = true;
        for grant in [dead_grant, live_grant] {
            planted &= report
                .ok(c, "put_device_grant", store.put_device_grant(grant).await)
                .is_some();
        }
        for code in [dead_code, live_code] {
            planted &= report
                .ok(
                    c,
                    "put_authorization_code",
                    store.put_authorization_code(code).await,
                )
                .is_some();
        }
        for token in [dead_token, live_token] {
            planted &= report
                .ok(c, "put_token", store.put_token(token).await)
                .is_some();
        }
        for record in [dead_refresh, live_refresh, endless_refresh] {
            planted &= report
                .ok(
                    c,
                    "put_refresh_token",
                    store.put_refresh_token(record).await,
                )
                .is_some();
        }
        #[cfg(feature = "par")]
        for record in [dead_pushed, live_pushed] {
            planted &= report
                .ok(
                    c,
                    "put_pushed_authorization_request",
                    store.put_pushed_authorization_request(record).await,
                )
                .is_some();
        }
        if !planted {
            return;
        }

        let Some(removed) = report.ok(c, "sweep_expired", store.sweep_expired(now).await) else {
            return;
        };

        // One grant, one code, one access token, one refresh, and under `par` one pushed request.
        // Derived from the fixture rather than written into the message as a literal: the count
        // assertion is only honest while it names the records that are actually planted, and it
        // stopped being honest the moment the PAR fixture was missing from the list above.
        #[cfg(feature = "par")]
        let (dead_records, planted_records) = (5u64, 11);
        #[cfg(not(feature = "par"))]
        let (dead_records, planted_records) = (4u64, 9);
        if removed != dead_records {
            report.fail(
                SWEEP_COUNT,
                format!(
                    "sweep_expired reported {removed} records removed, but exactly {dead_records} \
                     of the {planted_records} planted records were dead at `now`. The count is \
                     what a host schedules its sweep on, so a wrong one is a store that looks idle \
                     while it grows"
                ),
            );
        }

        if let Some(found) = report.ok(
            c,
            "get_device_grant",
            store.get_device_grant("dc-dead").await,
        ) {
            if found.is_some() {
                report.fail(c, "an expired device grant survived the sweep");
            }
        }
        if let Some(found) = report.ok(
            c,
            "find_device_grant_by_user_code",
            store.find_device_grant_by_user_code("DEADAAAA").await,
        ) {
            if found.is_some() {
                report.fail(
                    c,
                    "the user code of a swept grant still resolves: the index outlived the record \
                     it points at",
                );
            }
        }
        if let Some(found) = report.ok(
            c,
            "take_authorization_code",
            store.take_authorization_code("code-dead").await,
        ) {
            if found.is_some() {
                report.fail(c, "an expired authorization code survived the sweep");
            }
        }
        if let Some(found) = report.ok(c, "get_token", store.get_token("at-dead").await) {
            if found.is_some() {
                report.fail(c, "an expired access token survived the sweep");
            }
        }
        if let Some(found) = report.ok(
            c,
            "get_refresh_token",
            store.get_refresh_token("rt-dead").await,
        ) {
            if found.is_some() {
                report.fail(c, "an expired refresh record survived the sweep");
            }
        }
        // Its own check name rather than a line in `removes_dead`, for the reason
        // `reclaims_replay_ids` has one: this record kind exists only under a feature, so a host
        // filtering or waiving by name can talk about it without its waiver list depending on how
        // this crate was compiled. RFC 9126 section 4 makes the handle useless once it is expired,
        // so a store that never reclaims one keeps a dead capability string forever.
        #[cfg(feature = "par")]
        if let Some(found) = report.ok(
            SWEEP_RECLAIMS_PUSHED_REQUESTS,
            "take_pushed_authorization_request",
            store.take_pushed_authorization_request(PUSHED_SWEPT).await,
        ) {
            if found.is_some() {
                report.fail(
                    SWEEP_RECLAIMS_PUSHED_REQUESTS,
                    "an expired pushed authorization request survived the sweep: nothing else in \
                     this crate ever reclaims one, so the table grows once per pushed request that \
                     was never redeemed, forever",
                );
            }
        }

        let k = SWEEP_KEEPS_LIVE;
        if let Some(found) = report.ok(
            k,
            "get_device_grant",
            store.get_device_grant("dc-live").await,
        ) {
            if found.is_none() {
                report.fail(k, "the sweep removed a device grant that had not expired");
            }
        }
        if let Some(found) = report.ok(k, "get_token", store.get_token("at-live").await) {
            if found.is_none() {
                report.fail(k, "the sweep removed an access token that had not expired");
            }
        }
        if let Some(found) = report.ok(
            k,
            "get_refresh_token",
            store.get_refresh_token("rt-live").await,
        ) {
            if found.is_none() {
                report.fail(k, "the sweep removed a refresh record that had not expired");
            }
        }
        if let Some(found) = report.ok(
            k,
            "get_refresh_token(no absolute expiry)",
            store.get_refresh_token("rt-endless").await,
        ) {
            if found.is_none() {
                report.fail(
                    k,
                    "the sweep removed a refresh record whose expires_at is None. A chain with no \
                     absolute lifetime is not dead, and treating None as \"expired at the epoch\" \
                     silently logs every such client out",
                );
            }
        }
        if let Some(found) = report.ok(
            k,
            "take_authorization_code(live)",
            store.take_authorization_code("code-live").await,
        ) {
            if found.is_none() {
                report.fail(
                    k,
                    "the sweep removed an authorization code that had not expired",
                );
            }
        }
        // A sweep that reaps a live handle is an authorization request the client pushed, was told
        // was accepted, and cannot complete: RFC 9126 section 2.2 gives the handle a lifetime, and
        // it is the AS that promised it.
        #[cfg(feature = "par")]
        if let Some(found) = report.ok(
            k,
            "take_pushed_authorization_request(live)",
            store.take_pushed_authorization_request(PUSHED_KEPT).await,
        ) {
            if found.is_none() {
                report.fail(
                    k,
                    "the sweep removed a pushed authorization request that had not expired",
                );
            }
        }

        // Safe to call when there is nothing to do. The host runs this on a timer, so an error or
        // a nonzero answer on an idle store is noise a host will learn to ignore.
        let store = self.store().await;
        if let Some(removed) = report.ok(
            SWEEP_EMPTY_IS_ZERO,
            "sweep_expired on an empty store",
            store.sweep_expired(now).await,
        ) {
            if removed != 0 {
                report.fail(
                    SWEEP_EMPTY_IS_ZERO,
                    format!("sweep_expired on an empty store reported {removed} records removed"),
                );
            }
        }
    }

    /// THE SWEEP RUNS WHILE THE SERVER IS SERVING, which is the half of that sentence nothing
    /// checked.
    ///
    /// [`Storage::sweep_expired`] requires two things of a store, in one clause: "It must be safe to
    /// call concurrently with request handling, and safe to call when there is nothing to do
    /// (answering 0)". `sweep_expired/empty_is_zero` owns the second. The first had no check at all,
    /// and it is the one a host is more likely to get wrong, because the sweep is the only method in
    /// this trait that touches EVERY table and the only one a host writes as a batch job.
    ///
    /// The failure shape this is aimed at is the natural way to write a sweep and not an exotic one:
    /// read the table, decide what to keep, write the kept set back. Under a single mutex held for
    /// the whole operation that is correct. Snapshot outside the lock, or rebuild-and-replace, and
    /// every write that landed between the read and the write is gone. Those writes are token
    /// issuances: the store answers `Applied`, the server hands the client a token, and the record
    /// is not there when the client presents it. Nothing logs anything, and it happens once per
    /// sweep interval rather than under load, so it looks like a client bug.
    ///
    /// The instant is chosen so that NOTHING is dead: a correct sweep answers `Ok(0)` and removes
    /// nothing at all. That makes the sweep's expiry predicate irrelevant here (`removes_dead` and
    /// `keeps_live` own it) and every missing record afterwards attributable to the overlap.
    ///
    /// What it can and cannot see is the module docs' account for every race in this harness: an
    /// interleaving without a spawner, a genuine parallel race with
    /// [`StorageConformance::with_spawn`], and in neither case a proof of absence.
    async fn sweep_under_concurrent_writes(&self, report: &mut Report) {
        let c = SWEEP_CONCURRENT_WRITES;
        let store = self.store().await;
        let n = self.racers;
        // Live at `now`, and planted BEFORE the race: these are what a rebuild-and-replace sweep
        // legitimately keeps, so their survival is not the assertion. They are here so the table the
        // sweep reads is not empty, which is the case where a snapshot and a live read agree by
        // accident.
        for i in 0..n {
            let mut planted = sample_token(
                &format!("at-sweep-race-planted-{i}"),
                "client-sweep-race",
                None,
            );
            planted.expires_at = at(600);
            if report
                .ok(
                    c,
                    "put_token (live, before the race)",
                    store.put_token(planted).await,
                )
                .is_none()
            {
                return;
            }
        }

        // The sweep's own answer, carried out of the race rather than through it: `race` judges one
        // value per racer and the sweeper is not writing a token, so it has nowhere to put a count.
        // The sweep's own answer, and its own FAILURE, both kept out of `results`: a sweep that
        // errors on an idle store is `sweep_expired/empty_is_zero`'s finding and must not be
        // reported a second time here under a different name.
        let answered: Arc<Mutex<Option<Result<u64, StorageError>>>> = Arc::new(Mutex::new(None));
        let seq = AtomicUsize::new(0);
        let results = self
            .race(report, |gate| {
                let store = Arc::clone(&store);
                let answered = Arc::clone(&answered);
                // `make` is called once per racer, in order, before any of them runs, so racer
                // ZERO is the sweeper and the rest are the request handlers it has to survive.
                let index = seq.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    if index == 0 {
                        gate.wait().await;
                        let swept = store.sweep_expired(at(0)).await;
                        *answered.lock().unwrap_or_else(|e| e.into_inner()) = Some(swept);
                        return Ok(None);
                    }
                    let mut token = sample_token(
                        &format!("at-sweep-race-written-{index}"),
                        "client-sweep-race",
                        None,
                    );
                    token.expires_at = at(600);
                    gate.wait().await;
                    // APPLIED is a promise. Whatever the sweep was doing at the time, a record the
                    // store said it wrote has to be there afterwards.
                    let outcome = store.put_token(token).await?;
                    Ok(if outcome.is_applied() {
                        Some(index)
                    } else {
                        None
                    })
                })
            })
            .await;

        let mut errors = 0usize;
        let mut applied = Vec::new();
        for result in results {
            match result {
                Ok(Some(index)) => applied.push(index),
                Ok(None) => {}
                Err(_) => errors += 1,
            }
        }
        if errors > 0 {
            report.fail(
                c,
                format!(
                    "{errors} of the {} concurrent put_token calls failed with a StorageError \
                     while a sweep was in flight. An issuance may not fail because a maintenance \
                     job is running beside it: the server maps that to server_error, so the host's \
                     sweep schedule becomes a source of failed token requests",
                    n - 1
                ),
            );
        }

        match &*answered.lock().unwrap_or_else(|e| e.into_inner()) {
            Some(Ok(0)) => {}
            Some(Ok(removed)) => report.fail(
                c,
                format!(
                    "the sweep removed {removed} records at an instant when every record in the \
                     store was live. It is reaping what the writes beside it were adding, so a \
                     token this store reported as written is already gone"
                ),
            ),
            // Deliberately silent: an idle sweep that errors is exactly what
            // `sweep_expired/empty_is_zero` reports, and naming it twice would make one defect look
            // like two to a host reading the report.
            Some(Err(_)) => {}
            None => report.fail(
                c,
                "the sweep never reported an answer, so the race never ran it".to_string(),
            ),
        }

        let mut lost = Vec::new();
        for index in &applied {
            let key = format!("at-sweep-race-written-{index}");
            match report.ok(c, "get_token", store.get_token(&key).await) {
                Some(None) => lost.push(key),
                Some(Some(_)) => {}
                None => return,
            }
        }
        for i in 0..n {
            let key = format!("at-sweep-race-planted-{i}");
            match report.ok(c, "get_token", store.get_token(&key).await) {
                Some(None) => lost.push(key),
                Some(Some(_)) => {}
                None => return,
            }
        }
        if !lost.is_empty() {
            report.fail(
                c,
                format!(
                    "{} live access tokens were gone after a sweep that ran alongside {} \
                     concurrent put_token calls: {:?}. Every one of them was either already \
                     stored or reported Applied, so this store loses writes that overlap a sweep. \
                     The usual cause is reading the table, deciding what to keep and writing the \
                     kept set back, with anything at all happening outside the lock in between",
                    lost.len(),
                    n - 1,
                    lost
                ),
            );
        }
    }

    // ------------------------------------------------------------------ revoke_token_family

    async fn revoke_family(&self, report: &mut Report) {
        let c = REVOKE_FAMILY_REMOVES;
        let store = self.store().await;
        let mut planted = true;
        for (key, family) in [("at-a1", "fam-a"), ("at-a2", "fam-a"), ("at-b", "fam-b")] {
            planted &= report
                .ok(
                    c,
                    "put_token",
                    store
                        .put_token(sample_token(key, "client-fam", Some(family)))
                        .await,
                )
                .is_some();
        }
        // RFC 6749 section 4.4 client credentials produce no refresh chain, so their access tokens
        // carry no family. Planted to prove the revocation does not sweep them up by matching
        // `None` against the family id.
        planted &= report
            .ok(
                c,
                "put_token(no family)",
                store
                    .put_token(sample_token("at-nofam", "client-fam", None))
                    .await,
            )
            .is_some();
        for (key, family) in [("rt-a1", "fam-a"), ("rt-a2", "fam-a"), ("rt-b", "fam-b")] {
            planted &= report
                .ok(
                    c,
                    "put_refresh_token",
                    store
                        .put_refresh_token(sample_refresh(key, "client-fam", family))
                        .await,
                )
                .is_some();
        }
        if !planted {
            return;
        }

        let Some(removed) = report.ok(
            c,
            "revoke_token_family",
            store.revoke_token_family("fam-a", barrier_window()).await,
        ) else {
            return;
        };
        if removed != 4 {
            report.fail(
                REVOKE_FAMILY_COUNT,
                format!(
                    "revoke_token_family reported {removed} removed, but the family held 4 \
                     records (2 access tokens and 2 refresh records)"
                ),
            );
        }
        for key in ["at-a1", "at-a2"] {
            if let Some(found) = report.ok(c, "get_token", store.get_token(key).await) {
                if found.is_some() {
                    report.fail(
                        c,
                        format!(
                            "access token {key} carrying the revoked family_id survived. RFC 9700 \
                             section 4.14.2 requires revoking the tokens issued for that \
                             authorization grant, not just the refresh chain, so the thief's \
                             already-minted access tokens stay live"
                        ),
                    );
                }
            }
        }
        for key in ["rt-a1", "rt-a2"] {
            if let Some(found) =
                report.ok(c, "get_refresh_token", store.get_refresh_token(key).await)
            {
                if found.is_some() {
                    report.fail(
                        c,
                        format!("refresh record {key} carrying the revoked family_id survived"),
                    );
                }
            }
        }

        let s = REVOKE_FAMILY_SPARES_OTHERS;
        if let Some(found) = report.ok(s, "get_token", store.get_token("at-b").await) {
            if found.is_none() {
                report.fail(s, "revoking one family removed an access token of another");
            }
        }
        if let Some(found) = report.ok(
            s,
            "get_refresh_token",
            store.get_refresh_token("rt-b").await,
        ) {
            if found.is_none() {
                report.fail(s, "revoking one family removed a refresh record of another");
            }
        }
        if let Some(found) = report.ok(s, "get_token(no family)", store.get_token("at-nofam").await)
        {
            if found.is_none() {
                report.fail(
                    s,
                    "revoking a family removed an access token that carries no family_id at all",
                );
            }
        }

        // It runs on evidence of compromise and must not be turned into an error by a concurrent
        // revocation that got there first.
        match store.revoke_token_family("fam-a", barrier_window()).await {
            Ok(0) => {}
            Ok(n) => report.fail(
                REVOKE_FAMILY_COUNT,
                format!("revoking an already-revoked family reported {n} removed, expected 0"),
            ),
            Err(e) => report.fail(
                c,
                format!(
                    "revoking an already-revoked family failed with {e}. Removing records that are \
                     already gone is success: this runs on evidence of compromise"
                ),
            ),
        }
    }

    // ------------------------------------------------------------------ delete_client

    async fn delete_client(&self, report: &mut Report) {
        let c = DELETE_CLIENT_CASCADES;
        let store = self.store().await;
        let doomed = ClientId::new("client-doomed");
        let bystander = ClientId::new("client-bystander");

        let mut planted = true;
        for id in [&doomed, &bystander] {
            planted &= report
                .ok(
                    c,
                    "put_client",
                    store.put_client(sample_client(id.as_str())).await,
                )
                .is_some();
            let mut grant = sample_device_grant(
                &format!("dc-{}", id.as_str()),
                if id == &doomed {
                    "DOOM-AAAA"
                } else {
                    "BYST-AAAA"
                },
            );
            grant.client_id = id.clone();
            planted &= report
                .ok(c, "put_device_grant", store.put_device_grant(grant).await)
                .is_some();
            let mut code = sample_authorization_code(&format!("code-{}", id.as_str()));
            code.client_id = id.clone();
            planted &= report
                .ok(
                    c,
                    "put_authorization_code",
                    store.put_authorization_code(code).await,
                )
                .is_some();
            // AND ONE THAT HAS NOT BEEN REDEEMED. `delete_client` says codes go "in either
            // state", and every code this harness planted was `Consumed`, so a cascade carrying a
            // state predicate — one written while thinking about replay evidence rather than about
            // outstanding grants — removed nothing it was asked to and certified clean. This is
            // the state that matters most on this path: an `Issued` code is a live grant the
            // deleted registration can still redeem, and RFC 7592 section 2.3 says deleting the
            // registration invalidates what it holds.
            let mut unredeemed =
                sample_authorization_code(&format!("code-unredeemed-{}", id.as_str()));
            unredeemed.client_id = id.clone();
            unredeemed.state = AuthorizationCodeState::Issued;
            planted &= report
                .ok(
                    c,
                    "put_authorization_code (unredeemed)",
                    store.put_authorization_code(unredeemed).await,
                )
                .is_some();
            planted &= report
                .ok(
                    c,
                    "put_token",
                    store
                        .put_token(sample_token(
                            &format!("at-{}", id.as_str()),
                            id.as_str(),
                            Some("fam-cascade"),
                        ))
                        .await,
                )
                .is_some();
            planted &= report
                .ok(
                    c,
                    "put_refresh_token",
                    store
                        .put_refresh_token(sample_refresh(
                            &format!("rt-{}", id.as_str()),
                            id.as_str(),
                            "fam-cascade",
                        ))
                        .await,
                )
                .is_some();
            // RFC 9126 section 2.2 binds a `request_uri` to the client that pushed it, so a
            // deleted client's outstanding handles are handles nobody may ever redeem. This kind
            // was in the trait's cascade list and in neither bundled store's check, because the
            // harness planted none.
            #[cfg(feature = "par")]
            {
                let mut pushed = sample_pushed_request(&pushed_request_uri(id));
                pushed.client_id = id.clone();
                planted &= report
                    .ok(
                        c,
                        "put_pushed_authorization_request",
                        store.put_pushed_authorization_request(pushed).await,
                    )
                    .is_some();
            }
            // The least obvious kind and the one that is NOT optional: `client_id` is chosen by
            // the host, so a consent left behind is a standing approval that a client provisioned
            // later under the same id inherits, with its scope and its resource set, without the
            // user ever being asked. Both bundled stores removed it while the trait's enumeration
            // did not name it, which is exactly the hole this harness could not see.
            #[cfg(feature = "consent")]
            {
                let mut consent =
                    sample_consent(&format!("consent-{}", id.as_str()), "subject-conformance");
                consent.client_id = id.clone();
                planted &= report
                    .ok(c, "put_consent", store.put_consent(consent).await)
                    .is_some();
            }
        }
        if !planted {
            return;
        }

        let Some(existed) = report.ok(
            DELETE_CLIENT_REPORTS,
            "delete_client",
            store.delete_client(&doomed, barrier_window()).await,
        ) else {
            return;
        };
        if !existed {
            report.fail(
                DELETE_CLIENT_REPORTS,
                "delete_client answered false for a registration that was present",
            );
        }

        if let Some(found) = report.ok(c, "get_client", store.get_client(&doomed).await) {
            if found.is_some() {
                report.fail(c, "the registration survived delete_client");
            }
        }
        // RFC 7592 section 2.3: deleting a registration invalidates what that registration holds.
        // A store that removed only the row leaves a client that no longer exists still calling
        // resource servers until every credential it holds expires on its own.
        if let Some(found) = report.ok(c, "get_token", store.get_token("at-client-doomed").await) {
            if found.is_some() {
                report.fail(
                    c,
                    "an access token issued to the deleted client survived: a client that no \
                     longer exists can still call resource servers",
                );
            }
        }
        if let Some(found) = report.ok(
            c,
            "get_refresh_token",
            store.get_refresh_token("rt-client-doomed").await,
        ) {
            if found.is_some() {
                report.fail(
                    c,
                    "a refresh chain of the deleted client survived, so the deleted client can \
                     mint fresh access tokens indefinitely",
                );
            }
        }
        if let Some(found) = report.ok(
            c,
            "take_authorization_code",
            store.take_authorization_code("code-client-doomed").await,
        ) {
            if found.is_some() {
                report.fail(c, "an authorization code of the deleted client survived");
            }
        }
        if let Some(found) = report.ok(
            c,
            "take_authorization_code (unredeemed)",
            store
                .take_authorization_code("code-unredeemed-client-doomed")
                .await,
        ) {
            if found.is_some() {
                report.fail(
                    c,
                    "an UNREDEEMED authorization code of the deleted client survived, so the \
                     cascade is filtering on the code's state. That code is a live grant: the \
                     deleted registration redeems it and receives an access token and a refresh \
                     chain minutes after RFC 7592 section 2.3 said it no longer exists",
                );
            }
        }
        if let Some(found) = report.ok(
            c,
            "get_device_grant",
            store.get_device_grant("dc-client-doomed").await,
        ) {
            if found.is_some() {
                report.fail(c, "a device grant of the deleted client survived");
            }
        }
        if let Some(found) = report.ok(
            c,
            "find_device_grant_by_user_code",
            store.find_device_grant_by_user_code("DOOMAAAA").await,
        ) {
            if found.is_some() {
                report.fail(
                    c,
                    "the user-code index entry of the deleted client's device grant survived",
                );
            }
        }
        #[cfg(feature = "par")]
        if let Some(found) = report.ok(
            c,
            "take_pushed_authorization_request",
            store
                .take_pushed_authorization_request(&pushed_request_uri(&doomed))
                .await,
        ) {
            if found.is_some() {
                report.fail(
                    c,
                    "a pushed authorization request of the deleted client survived: RFC 9126 \
                     section 2.2 binds the handle to the client that pushed it, so what is left is \
                     a live `request_uri` nobody may ever redeem, holding authorization parameters \
                     for a registration that no longer exists",
                );
            }
        }
        #[cfg(feature = "consent")]
        if let Some(found) = report.ok(
            c,
            "get_consent",
            store.get_consent("consent-client-doomed").await,
        ) {
            if found.is_some() {
                report.fail(
                    c,
                    "a consent record of the deleted client survived. The user is shown an \
                     application that no longer exists and cannot meaningfully withdraw it, and \
                     because `client_id` is chosen by the HOST, a client provisioned later under \
                     the same id inherits that standing approval — its scope and its resource set \
                     — without the user ever being asked",
                );
            }
        }

        // AND THE BARRIER REACHES THE PUSHED REQUEST TOO. The cascade above only removes what is
        // in the store when it runs, and this is the site the 0.9.1 enumeration missed: the
        // cross-client refusal in `validate_pushed_authorization_request` must TAKE the record
        // before it can read the `client_id` bound into it, so a deletion landing in that window
        // finds nothing to cascade and the put-back restores a handle belonging to a client that
        // no longer exists. Same shape as `put_token` and `put_refresh_token`, on the one write
        // this trait added late.
        #[cfg(feature = "par")]
        {
            let mut again = sample_pushed_request(&pushed_request_uri(&doomed));
            again.client_id = doomed.clone();
            match store.put_pushed_authorization_request(again).await {
                Ok(WriteOutcome::RefusedRevoked) => {}
                Ok(WriteOutcome::Applied) => report.fail(
                    BARRIER_REFUSES_PUSHED_REQUEST,
                    "put_pushed_authorization_request restored a handle for a client that had just \
                     been deleted. The record was pushed BEFORE the deletion, so the barrier covers \
                     it; a store that writes it anyway hands a deleted registration a live \
                     `request_uri`, and if the host re-provisions that `client_id` — which the \
                     trait explicitly permits — the handle resolves against the NEW registration \
                     carrying a `code_challenge` its owner never pushed",
                ),
                Err(e) => report.fail(
                    BARRIER_REFUSES_PUSHED_REQUEST,
                    format!("put_pushed_authorization_request failed unexpectedly: {e}"),
                ),
            }
        }

        // The bystander is untouched: a cascade that matches too widely is as wrong as one that
        // matches too narrowly, and far harder to notice.
        if let Some(found) = report.ok(
            c,
            "get_client(bystander)",
            store.get_client(&bystander).await,
        ) {
            if found.is_none() {
                report.fail(c, "delete_client removed a DIFFERENT client's registration");
            }
        }
        if let Some(found) = report.ok(
            c,
            "get_token(bystander)",
            store.get_token("at-client-bystander").await,
        ) {
            if found.is_none() {
                report.fail(c, "delete_client removed another client's access token");
            }
        }
        if let Some(found) = report.ok(
            c,
            "get_refresh_token(bystander)",
            store.get_refresh_token("rt-client-bystander").await,
        ) {
            if found.is_none() {
                report.fail(c, "delete_client removed another client's refresh record");
            }
        }
        if let Some(found) = report.ok(
            c,
            "get_device_grant(bystander)",
            store.get_device_grant("dc-client-bystander").await,
        ) {
            if found.is_none() {
                report.fail(c, "delete_client removed another client's device grant");
            }
        }
        // The bystander's user-code INDEX, not just its grant. "Of the grants removed" has two
        // directions and only the removal was checked: a store that rebuilds the index on any bulk
        // removal, with the rebuild missing a row, passes every other line here and leaves the
        // bystander's user code resolving to nothing. RFC 8628 section 6.1 makes that code the
        // credential a human types, so it is the flow that stops, silently, for a client nobody
        // touched.
        if let Some(found) = report.ok(
            c,
            "find_device_grant_by_user_code(bystander)",
            store.find_device_grant_by_user_code("BYSTAAAA").await,
        ) {
            if found.is_none() {
                report.fail(
                    c,
                    "delete_client removed another client's user-code index entry: the grant is \
                     still there and the code the user was shown no longer reaches it, so the \
                     verification page answers \"no such code\" for a device that is waiting",
                );
            }
        }
        // The bystander's authorization CODE. Neither cascade in this harness read one back for
        // the party it must spare, so a store whose cascade dropped the `client_id` predicate on
        // the codes table — one missing `AND` — removed every outstanding code in the deployment
        // on every client deletion and was certified clean. Taken rather than peeked, because
        // there is no non-destructive read for a code; nothing after this needs it.
        if let Some(found) = report.ok(
            c,
            "take_authorization_code(bystander)",
            store.take_authorization_code("code-client-bystander").await,
        ) {
            if found.is_none() {
                report.fail(
                    c,
                    "delete_client removed another client's authorization code: a grant that was \
                     in flight for a client nobody deleted is gone, and the user sees a redemption \
                     fail as `invalid_grant` with nothing anywhere explaining it",
                );
            }
        }
        if let Some(found) = report.ok(
            c,
            "take_authorization_code(bystander, unredeemed)",
            store
                .take_authorization_code("code-unredeemed-client-bystander")
                .await,
        ) {
            if found.is_none() {
                report.fail(
                    c,
                    "delete_client removed another client's UNREDEEMED authorization code: a user \
                     who is mid-authorization for a client nobody deleted has their redemption \
                     refused as `invalid_grant`",
                );
            }
        }
        #[cfg(feature = "par")]
        if let Some(found) = report.ok(
            c,
            "take_pushed_authorization_request(bystander)",
            store
                .take_pushed_authorization_request(&pushed_request_uri(&bystander))
                .await,
        ) {
            if found.is_none() {
                report.fail(
                    c,
                    "delete_client removed another client's pushed authorization request",
                );
            }
        }
        // AND THE PAR BARRIER MUST NAME ONE CLIENT. Both PAR writes this harness makes while a
        // barrier stands use the barrier's OWN `client_id`, so a store whose barrier query dropped
        // the `client_id = $1` conjunct still compares `pushed_at`, refuses exactly the record the
        // refusal check expects it to, and certifies clean — while every RFC 9126 push in the
        // deployment fails for the life of any client barrier. The push below predates the
        // deletion, exactly as the refused one above does, so identity is the only thing that can
        // tell them apart, and the symptom of getting it wrong is `server_error` on an endpoint an
        // administrator's single RFC 7592 s2.3 delete has just closed for everybody. Same argument
        // as the bystander token in `barrier_admits_a_later_grant`, on the write that had none.
        #[cfg(feature = "par")]
        {
            let mut bystanders_push = sample_pushed_request(
                "urn:ietf:params:oauth:request_uri:pushed-by-a-client-nobody-deleted",
            );
            bystanders_push.client_id = bystander.clone();
            match store
                .put_pushed_authorization_request(bystanders_push)
                .await
            {
                Ok(WriteOutcome::Applied) => {}
                Ok(WriteOutcome::RefusedRevoked) => report.fail(
                    BARRIER_SPARES_UNRELATED,
                    "put_pushed_authorization_request refused a push from a DIFFERENT client than \
                     the one deleted: the client barrier is not comparing its scope against the \
                     record's `client_id`, so one deletion has stopped every client in this \
                     deployment pushing an authorization request until the barrier is swept",
                ),
                Err(e) => report.fail(
                    BARRIER_SPARES_UNRELATED,
                    format!("put_pushed_authorization_request failed unexpectedly: {e}"),
                ),
            }
        }
        #[cfg(feature = "consent")]
        if let Some(found) = report.ok(
            c,
            "get_consent(bystander)",
            store.get_consent("consent-client-bystander").await,
        ) {
            if found.is_none() {
                report.fail(
                    c,
                    "delete_client removed another client's consent record, so a user is shown \
                     that they never approved an application they did",
                );
            }
        }

        // Removing a client that is already gone is Ok(false), not an error.
        match store.delete_client(&doomed, barrier_window()).await {
            Ok(true) => report.fail(
                DELETE_CLIENT_REPORTS,
                "delete_client answered true for a registration that was already gone",
            ),
            Ok(false) => {}
            Err(e) => report.fail(
                DELETE_CLIENT_REPORTS,
                format!("deleting an absent registration failed with {e}, expected Ok(false)"),
            ),
        }
    }

    // ------------------------------------------------------------------ delete_token

    async fn delete_token(&self, report: &mut Report) {
        let c = DELETE_TOKEN_IDEMPOTENT;
        let store = self.store().await;
        if report
            .ok(
                c,
                "put_token",
                store
                    .put_token(sample_token("at-del", "client-del", None))
                    .await,
            )
            .is_none()
        {
            return;
        }
        if report
            .ok(c, "delete_token", store.delete_token("at-del").await)
            .is_none()
        {
            return;
        }
        if let Some(found) = report.ok(c, "get_token", store.get_token("at-del").await) {
            if found.is_some() {
                report.fail(c, "the token is still readable after delete_token");
            }
        }
        // RFC 7009 section 2.2: an invalid token does not cause an error response, so a repeated
        // revocation (which a client is entitled to send) must not fail.
        if let Err(e) = store.delete_token("at-del").await {
            report.fail(
                c,
                format!("deleting an already-deleted token failed with {e}, expected Ok(())"),
            );
        }
        if let Err(e) = store.delete_token("at-never-existed").await {
            report.fail(
                c,
                format!("deleting a token that never existed failed with {e}, expected Ok(())"),
            );
        }
    }
}

/// Convenience over [`StorageConformance`] for a host with a single-threaded test runtime and no
/// spawner to offer. Read the module docs on what the cooperative mode proves before relying on
/// this one rather than [`StorageConformance::with_spawn`].
pub async fn check_storage<F, Fut, S>(new_store: F) -> Vec<Violation>
where
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
    S: Storage + 'static,
{
    StorageConformance::new(new_store).run().await
}

// ---------------------------------------------------------------------- reporting

#[derive(Default)]
struct Report {
    violations: Vec<Violation>,
}

// `ok`, `some` and `same` ARE GENERIC AND ARE DELIBERATELY LEFT THAT WAY, and the repeated
// `format!("... failed unexpectedly: {e}")` in this module's `match` arms is DELIBERATELY REPEATED.
// Read this before "fixing" either, because both fixes were written and measured and both are
// regressions.
//
// The reasoning that says to outline them sounds right. These three are called around 250 times at
// a different `T` almost every time, and each instantiation carries its own copy of a `format!`
// whose output does not vary with `T` in any way the reader of a violation could tell. So each was
// rewritten to do only the `T`-dependent part (the comparison, or the match on the `Result`) and
// hand the failure to a `#[cold] #[inline(never)]` non-generic body, with `same` taking
// `&dyn fmt::Debug` so its formatting compiled once. Separately, the 40 identical "failed
// unexpectedly" sites were collapsed into one shared function.
//
// MEASURED 2026-08-13, `scripts/size-report.sh` `test-util` row, aarch64-apple-darwin, rustc
// 1.97.0, against a 455,289-byte baseline:
//
//   * outlining `ok`/`some`/`same`:                             463,917, or 8,628 bytes WORSE
//   * one shared "failed unexpectedly", `#[inline(never)]`:     458,186, or 2,897 bytes WORSE
//   * one shared "failed unexpectedly", left inlinable:         462,338, or 7,049 bytes WORSE
//
// Under this profile (`lto = "fat"`, `codegen-units = 1`, `opt-level = 3`) the formatting these
// sites share is ALREADY being folded: the literal pieces dedupe in `__cstring`, and the failure
// arm of a comparison that is almost never true is dead code the optimizer deletes outright.
// Outlining replaces free dead code with ~250 live call sites that each marshal arguments across a
// boundary the optimizer is then forbidden to erase, and, for `same`, materializes a `Debug` vtable
// for every field type it is used on.
//
// `judge_race`/`race` ARE outlined, and are worth 2,940 bytes, because they are generic over a
// CLOSURE type: a guaranteed fresh instantiation per call site with nothing for the linker to fold,
// and hundreds of bytes of prose per copy rather than tens of bytes of argument setup. That is the
// shape to look for. "It is generic and it formats" is not.
impl Report {
    fn fail(&mut self, check: &'static str, detail: impl Into<String>) {
        self.violations.push(Violation {
            check,
            detail: detail.into(),
        });
    }

    /// Unwrap a storage result, recording an unexpected failure as a violation rather than
    /// panicking: this harness reports, it does not abort the host's test process.
    fn ok<T>(&mut self, check: &'static str, what: &str, r: Result<T, StorageError>) -> Option<T> {
        match r {
            Ok(v) => Some(v),
            Err(e) => {
                self.fail(check, format!("{what} failed unexpectedly: {e}"));
                None
            }
        }
    }

    fn some<T>(&mut self, check: &'static str, what: &str, v: Option<T>) -> Option<T> {
        if v.is_none() {
            self.fail(
                check,
                format!("{what} returned None for a record that was just stored"),
            );
        }
        v
    }

    /// Compare one field of a round-tripped record. Field by field rather than whole-record, so
    /// the violation names the field that was dropped instead of printing two records and leaving
    /// the reader to diff them.
    fn same<T: PartialEq + fmt::Debug>(
        &mut self,
        check: &'static str,
        field: &str,
        want: &T,
        got: &T,
    ) {
        if want != got {
            self.fail(
                check,
                format!("field {field} did not survive the round trip: stored {want:?}, read back {got:?}"),
            );
        }
    }
}

/// The verdict on one raced `take_*`, over the COUNTS rather than over the records, so there is one
/// copy of it however many record types get raced. See `StorageConformance::judge_race`, which is
/// where the reasoning and the measurement are.
///
/// Exactly one racer may receive the value. More than one IS the double-spend; none means the value
/// was lost, which is a different bug with the same root (a non-atomic pair of steps).
fn judge_race_counts(
    report: &mut Report,
    check: &'static str,
    what: &str,
    winners: usize,
    errors: usize,
    total: usize,
) {
    if winners > 1 {
        report.fail(
            check,
            format!(
                "{winners} of {total} concurrent takes each received the {what}: the operation is \
                 not an atomic remove-and-return, so this store double-spends single-use \
                 credentials under concurrency"
            ),
        );
    } else if winners == 0 {
        report.fail(
            check,
            format!(
                "none of {total} concurrent takes received the {what}, though it was stored \
                 beforehand: the value was lost rather than handed to exactly one caller"
            ),
        );
    }
    if errors > 0 {
        report.fail(
            check,
            format!(
                "{errors} of {total} concurrent takes failed with a StorageError. The server maps \
                 that to server_error, so a legitimate redemption fails under ordinary \
                 contention; a store using optimistic concurrency must retry internally \
                 rather than surface the conflict. This is the `Storage` trait's rule that \
                 contention is the store's to resolve, not the caller's: `Ok(None)` is how a \
                 take says the record was not there to take, and a StorageError is not"
            ),
        );
    }
}

/// Whether the race was a race at all, and whether every racer came back. Both are properties of
/// the HARNESS run rather than of any record type, so, like [`judge_race_counts`], this is compiled
/// once instead of once per `(T, M)` that `StorageConformance::race` is instantiated at.
fn race_setup_verdict(report: &mut Report, abandoned: usize, n: usize, gate_unsatisfied: bool) {
    if abandoned > 0 {
        report.fail(
            HARNESS_RACER_PANICKED,
            format!(
                "{abandoned} of {n} racers never finished: the store's call panicked, or the \
                 spawner dropped the task before it completed. Whatever the results of this \
                 check say, a store that panics under concurrent access fails the request that \
                 hit it, and on a host that aborts on panic it takes the process with it. The \
                 panic message itself is on the spawner's own reporting path, not here"
            ),
        );
    }

    if gate_unsatisfied {
        report.fail(
            HARNESS_RACE_SETUP,
            format!(
                "the {n} racers never overlapped: each gave up waiting for the others, which \
                 means they ran one after another and the atomicity results in this run prove \
                 nothing. A `with_spawn` that runs its task to completion inline does this; \
                 hand the futures to a real runtime instead"
            ),
        );
    }
}

// ---------------------------------------------------------------------- concurrency primitives
//
// Hand-written because this crate has no async runtime and no futures library, and gains neither
// for a test-only feature. All three are small enough to read.

/// A rendezvous the racers park on so their `take_*` calls are all in flight at once. Without it,
/// a runtime is free to run each spawned task to completion before starting the next, and a
/// read-then-delete store would pass by never overlapping with itself.
pub(crate) struct Gate {
    target: usize,
    arrived: AtomicUsize,
    open: AtomicBool,
    /// True when a racer gave up waiting: the run's atomicity results prove nothing.
    unsatisfied: AtomicBool,
    waiters: Mutex<Vec<Waker>>,
}

impl Gate {
    pub(crate) fn new(target: usize) -> Arc<Self> {
        Arc::new(Gate {
            target,
            arrived: AtomicUsize::new(0),
            open: AtomicBool::new(false),
            unsatisfied: AtomicBool::new(false),
            waiters: Mutex::new(Vec::new()),
        })
    }

    pub(crate) fn wait(self: &Arc<Self>) -> GateWait {
        GateWait {
            gate: Arc::clone(self),
            counted: false,
            budget: GATE_POLL_BUDGET,
        }
    }

    pub(crate) fn unsatisfied(&self) -> bool {
        self.unsatisfied.load(Ordering::SeqCst)
    }

    fn wake_all(&self) {
        let mut waiters = self.waiters.lock().unwrap_or_else(|e| e.into_inner());
        for waker in waiters.drain(..) {
            waker.wake();
        }
    }
}

pub(crate) struct GateWait {
    gate: Arc<Gate>,
    counted: bool,
    budget: u32,
}

impl Future for GateWait {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if !self.counted {
            self.counted = true;
            if self.gate.arrived.fetch_add(1, Ordering::SeqCst) + 1 >= self.gate.target {
                self.gate.open.store(true, Ordering::SeqCst);
                self.gate.wake_all();
                return Poll::Ready(());
            }
        }
        if self.gate.open.load(Ordering::SeqCst) {
            return Poll::Ready(());
        }
        if self.budget == 0 {
            // Nobody else is coming: the racers are being run one at a time. Recorded rather than
            // hung, and reported as `harness/race_setup` so the run is not mistaken for a pass.
            self.gate.unsatisfied.store(true, Ordering::SeqCst);
            return Poll::Ready(());
        }
        self.budget -= 1;
        // Both a registered waker (for a racer parked on another thread) and a self-wake (so a
        // cooperatively polled racer is re-polled and the budget actually counts down).
        self.gate
            .waiters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(cx.waker().clone());
        if self.gate.open.load(Ordering::SeqCst) {
            return Poll::Ready(());
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// Counts spawned racers to completion. Waker-based rather than spinning: past the gate a racer is
/// doing the store's real work, which may be a network round trip.
pub(crate) struct Latch {
    remaining: AtomicUsize,
    waker: Mutex<Option<Waker>>,
}

impl Latch {
    pub(crate) fn new(target: usize) -> Arc<Self> {
        Arc::new(Latch {
            remaining: AtomicUsize::new(target),
            waker: Mutex::new(None),
        })
    }

    pub(crate) fn done(&self) {
        if self.remaining.fetch_sub(1, Ordering::SeqCst) == 1 {
            if let Some(waker) = self.waker.lock().unwrap_or_else(|e| e.into_inner()).take() {
                waker.wake();
            }
        }
    }

    pub(crate) fn wait(self: &Arc<Self>) -> LatchWait {
        LatchWait {
            latch: Arc::clone(self),
        }
    }
}

/// Releases one count of the [`Latch`] when a spawned racer's task ends, HOWEVER it ends.
///
/// The reason it is a `Drop` guard rather than a call at the bottom of the task: a racer whose
/// store call panics never reaches the bottom of the task, so a plain `latch.done()` there leaves
/// the latch one short and [`StorageConformance::run`] parked forever. A host whose store panics
/// under concurrency would then get a hung test run, which is the worst diagnostic available: it
/// names nothing, it points at nothing, and it looks like the harness is broken rather than the
/// store. `Drop` runs during the unwind, so the latch is released and the harness reports.
///
/// `finished` distinguishes the two ways a task can end. It is set as the LAST statement of the
/// task, so an unwind (or a spawner that dropped the future before it completed) leaves it false
/// and the racer is counted as abandoned.
struct RacerGuard {
    latch: Arc<Latch>,
    abandoned: Arc<AtomicUsize>,
    finished: bool,
}

impl Drop for RacerGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.abandoned.fetch_add(1, Ordering::SeqCst);
        }
        self.latch.done();
    }
}

pub(crate) struct LatchWait {
    latch: Arc<Latch>,
}

impl Future for LatchWait {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.latch.remaining.load(Ordering::SeqCst) == 0 {
            return Poll::Ready(());
        }
        *self.latch.waker.lock().unwrap_or_else(|e| e.into_inner()) = Some(cx.waker().clone());
        // Re-check after registering, or a racer that finished in between would leave this parked
        // with nobody left to wake it.
        if self.latch.remaining.load(Ordering::SeqCst) == 0 {
            return Poll::Ready(());
        }
        Poll::Pending
    }
}

/// Polls every racer on ONE task, in order, on every wake. This is the cooperative mode: it
/// interleaves rather than parallelizes, which is enough to catch a read-then-delete store that
/// suspends between the read and the delete (any store that talks to a database does).
pub(crate) struct JoinAll<T> {
    futures: Vec<Option<Pin<Box<dyn Future<Output = T> + Send>>>>,
    done: Vec<Option<T>>,
}

impl<T> JoinAll<T> {
    pub(crate) fn new(futures: Vec<Pin<Box<dyn Future<Output = T> + Send>>>) -> Self {
        let mut done = Vec::with_capacity(futures.len());
        done.resize_with(futures.len(), || None);
        JoinAll {
            futures: futures.into_iter().map(Some).collect(),
            done,
        }
    }
}

// `T: Unpin` is not a restriction in practice: T is the take's `Result`, and the futures
// themselves are boxed (and so `Unpin`) precisely so this combinator can be written without
// unsafe code.
impl<T: Unpin> Future for JoinAll<T> {
    type Output = Vec<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Vec<T>> {
        let JoinAll { futures, done } = self.get_mut();
        let mut pending = false;
        for (slot, out) in futures.iter_mut().zip(done.iter_mut()) {
            if let Some(fut) = slot {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(v) => {
                        *out = Some(v);
                        *slot = None;
                    }
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            return Poll::Pending;
        }
        Poll::Ready(done.iter_mut().filter_map(Option::take).collect())
    }
}

// ---------------------------------------------------------------------- fixtures
//
// Every field carries a DISTINCTIVE value, because the failure this harness exists to catch is a
// store that silently drops one. Timestamps are whole seconds from a fixed base rather than
// `SystemTime::now()`: sweeps are then deterministic, and a store whose column has one-second
// resolution is not failed for something that is not a contract violation.

const BASE_SECS: u64 = 1_800_000_000;

fn at(offset_secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(BASE_SECS + offset_secs)
}

fn at_before(offset_secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(BASE_SECS - offset_secs)
}

/// The window every revocation in this harness records.
///
/// `until` is comfortably beyond every other timestamp the fixtures use, so a barrier is live for
/// the whole of any check that records one, and a store that reaps barriers too eagerly fails the
/// checks that depend on them rather than passing by accident. The sweep checks pick their own
/// deadline deliberately, because reaping a barrier is exactly what they are about.
///
/// `recorded_at` is NOW, which is AFTER the fixtures' `grant_established_at` (they use
/// `at_before(10)`). That ordering is what makes the refusal checks below test a refusal at all: a
/// store that compared the wrong way round, or that ignored the comparison, would still refuse
/// these and pass. The check that a LATER grant is ADMITTED is what pins the comparison, and it is
/// stated separately.
fn barrier_window() -> crate::store::RevocationWindow {
    crate::store::RevocationWindow {
        recorded_at: at_before(0),
        until: barrier_until(),
    }
}

fn barrier_until() -> SystemTime {
    at(1_000_000)
}

fn scopes(s: &str) -> ScopeSet {
    // The literals below are this module's own and are all valid RFC 6749 section 3.3 tokens.
    ScopeSet::parse(s).unwrap_or_else(|_| ScopeSet::empty())
}

/// The RFC 9396 section 2 `authorization_details` every record fixture carries, as the raw text a
/// client would push.
///
/// Non-empty on purpose, and that is the whole point of it existing. An empty
/// `AuthorizationDetails` is the DEFAULT, so a fixture carrying one cannot tell a store that
/// preserves the field from a store that drops it: both read back empty. This crate has already
/// been bitten twice by RAR details being dropped on a feature-gated path, which is exactly the
/// defect a host's store can have and exactly what this harness exists to make visible.
///
/// One element with several section 2.2 common fields, so a store that truncates the JSON, keeps
/// only the `type`, or round-trips it through a lossy column is caught as well as one that drops
/// the column outright.
#[cfg(feature = "rar")]
const AUTHORIZATION_DETAILS_JSON: &str = r#"[{"type":"conformance-fixture","locations":["https://rs-one.example/"],"actions":["read","write"],"identifier":"account-4711"}]"#;

/// The parsed form of [`AUTHORIZATION_DETAILS_JSON`]. Parsed rather than constructed because
/// `AuthorizationDetail`'s members are the RFC's, not this module's, and the parser is the only
/// thing that has to agree with them.
///
/// A parse failure would leave the fixture EMPTY and the round-trip check unable to see a dropped
/// field, which is silent, so `the_fixtures_carry_the_fields_the_round_trip_checks_exist_for` in
/// `src/tests/storage_conformance.rs` pins it as non-empty rather than trusting the literal.
#[cfg(feature = "rar")]
fn sample_authorization_details() -> crate::rar::AuthorizationDetails {
    crate::rar::AuthorizationDetails::parse(AUTHORIZATION_DETAILS_JSON)
        .unwrap_or_else(|_| crate::rar::AuthorizationDetails::none())
}

/// What the host reported about how it authenticated the user, on every record that carries it.
///
/// `Some`, not `None`, for the reason [`sample_authorization_details`] is non-empty: `None` is the
/// default, so a `None` fixture certifies a store that drops the field. RFC 9470 section 6.2 is
/// answered from this, so a store that loses it has disabled step-up authentication for the whole
/// deployment while every request continues to succeed.
///
/// `acr` is set as well as `auth_time`: a store that persists the timestamp and drops the class
/// (two columns, one migration) satisfies `max_age` and silently fails every `acr_values` request.
#[cfg(feature = "consent")]
fn sample_authentication() -> Option<Box<crate::consent::Authentication>> {
    Some(Box::new(crate::consent::Authentication {
        auth_time: at_before(120),
        acr: Some("urn:conformance:acr:multi-factor".into()),
    }))
}

fn sample_client(client_id: &str) -> Client {
    Client {
        client_id: ClientId::new(client_id),
        auth: ClientAuth::ConfidentialSecretHash {
            hash: SecretHash::sha256("conformance-secret"),
        },
        grant_types: vec![
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::DeviceCode,
        ],
        redirect_uris: vec![
            "https://app.example/cb".to_string(),
            "https://app.example/cb2".to_string(),
        ],
        allowed_scopes: scopes("read write admin"),
        default_scopes: scopes("read"),
        name: Some("conformance client".to_string()),
        registration: Some(Box::new(DynamicRegistration {
            registration_access_token_hash: SecretHash::sha256("conformance-rat"),
            client_id_issued_at: Some(BASE_SECS),
            client_secret_expires_at: Some(0),
            token_endpoint_auth_method: "client_secret_basic".to_string(),
        })),
    }
}

fn sample_device_grant(device_code: &str, user_code: &str) -> DeviceGrant {
    DeviceGrant {
        device_code: device_code.to_string(),
        user_code: user_code.to_string(),
        client_id: ClientId::new("client-conformance"),
        scope: scopes("read write"),
        state: DeviceGrantState::Approved {
            subject: "subject-conformance".to_string(),
        },
        created_at: at_before(30),
        expires_at: at(600),
        interval: Duration::from_secs(7),
        last_poll_at: Some(at_before(5)),
    }
}

/// An APPROVED device grant for `subject`. Approved rather than pending on purpose: the consent
/// cascade must reach a grant the user already approved but whose device has not polled yet,
/// which is precisely the window where a withdrawal that misses it hands out a token AFTER the
/// user withdrew. A pending grant is not part of any consent and must survive.
#[cfg(feature = "consent")]
fn sample_approved_device_grant(device_code: &str, user_code: &str, subject: &str) -> DeviceGrant {
    DeviceGrant {
        state: DeviceGrantState::Approved {
            subject: subject.to_string(),
        },
        ..sample_device_grant(device_code, user_code)
    }
}

/// A consent for `subject`, with a scope and a resource so `covers` has something to answer about
/// and a round trip has something to lose.
#[cfg(feature = "consent")]
fn sample_consent(consent_id: &str, subject: &str) -> crate::consent::ConsentRecord {
    crate::consent::ConsentRecord {
        consent_id: consent_id.into(),
        client_id: ClientId::new("client-conformance"),
        subject: subject.into(),
        scope: scopes("read write"),
        resource: vec!["https://rs-one.example/".to_string()],
        granted_at: at_before(60),
        // See `sample_authentication`. `None` here would have made `round_trip/consent` unable to
        // see a store that drops the RFC 9470 step-up state the consent was granted under.
        authentication: sample_authentication(),
    }
}

/// The two handles the sweep check plants. Named constants because each is written twice (the
/// plant and the read-back) and a typo between the two would make the check pass by asking about a
/// handle nobody stored.
/// The `request_uri` the `delete_client` cascade check plants for one client. A function rather
/// than three literals for the reason the two constants below are named: the plant, the
/// gone-after-the-cascade read and the still-there read must agree, and a typo between them would
/// make the check pass by asking about a handle nobody stored.
#[cfg(feature = "par")]
fn pushed_request_uri(client_id: &ClientId) -> String {
    format!(
        "urn:ietf:params:oauth:request_uri:cascade-{}",
        client_id.as_str()
    )
}

#[cfg(feature = "par")]
const PUSHED_SWEPT: &str = "urn:ietf:params:oauth:request_uri:sweep-dead";
#[cfg(feature = "par")]
const PUSHED_KEPT: &str = "urn:ietf:params:oauth:request_uri:sweep-live";

/// A pushed authorization request, complete enough that a store dropping a field on the way
/// through is visible rather than plausible.
#[cfg(feature = "par")]
fn sample_pushed_request(request_uri: &str) -> crate::par::PushedAuthorizationRequest {
    crate::par::PushedAuthorizationRequest {
        // Before any barrier this harness records, so a planted request is one a client
        // revocation is entitled to refuse.
        pushed_at: at_before(10),
        request_uri: request_uri.to_string(),
        client_id: ClientId::new("client-conformance"),
        response_type: Some("code".to_string()),
        redirect_uri: Some("https://app.example/cb".to_string()),
        scope: Some("read write".to_string()),
        state: Some("state-conformance".to_string()),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
        code_challenge_method: Some("S256".to_string()),
        resource: vec!["https://rs-one.example/".to_string()],
        // Populated for the same reason `acr_values` and `max_age` below are: RFC 9101 section 6.3
        // has the authorization endpoint use ONLY the pushed parameters, so a detail lost between
        // the push and the read is a detail the client was told was acceptable and then did not
        // get. `None` is the default and could not have shown that.
        #[cfg(feature = "rar")]
        authorization_details: Some(AUTHORIZATION_DETAILS_JSON.to_string()),
        // RFC 9470 s4. Populated rather than `None` for this fixture's stated reason: a store that
        // drops one of them on the way through has disabled step-up for every PAR request, and the
        // point of this record is that such a drop is visible.
        #[cfg(feature = "consent")]
        acr_values: Some("urn:acr:phr".to_string()),
        #[cfg(feature = "consent")]
        max_age: Some("300".to_string()),
        expires_at: at(60),
    }
}

fn sample_authorization_code(code: &str) -> AuthorizationCodeRecord {
    AuthorizationCodeRecord {
        code: code.to_string(),
        client_id: ClientId::new("client-conformance"),
        redirect_uri: "https://app.example/cb".to_string(),
        // FALSE, which is the value a store that drops the column cannot produce: the serde
        // default is `true`, so a `true` fixture would round-trip indistinguishably from a record
        // whose column was never written. Same rule as `sample_authorization_details` and
        // `sample_authentication`. What a lost column costs is RFC 6749 section 4.1.3 in the
        // fail-closed direction: the token endpoint demands a `redirect_uri` the client was
        // entitled by section 3.1.2.3 to omit, and refuses the redemption blaming a mismatch that
        // never happened.
        redirect_uri_was_explicit: false,
        scope: scopes("read write"),
        subject: "subject-conformance".to_string(),
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string(),
        code_challenge_method: CodeChallengeMethod::S256,
        resource: vec![
            "https://rs-one.example/".to_string(),
            "https://rs-two.example/".to_string(),
        ],
        #[cfg(feature = "rar")]
        authorization_details: sample_authorization_details(),
        // BEFORE any barrier this harness records, so a code the harness plants is one a
        // revocation is entitled to refuse the redemption of.
        issued_at: at_before(10),
        expires_at: at(60),
        state: AuthorizationCodeState::Consumed {
            access_token: Some("at-minted-by-this-code".to_string()),
            refresh_token: Some("rt-minted-by-this-code".to_string()),
        },
        #[cfg(feature = "consent")]
        authentication: sample_authentication(),
    }
}

fn sample_token(access_token: &str, client_id: &str, family_id: Option<&str>) -> IssuedToken {
    IssuedToken {
        access_token: access_token.to_string(),
        client_id: ClientId::new(client_id),
        subject: Some("subject-conformance".to_string()),
        scope: scopes("read write"),
        resource: vec![
            "https://rs-one.example/".to_string(),
            "https://rs-two.example/".to_string(),
        ],
        #[cfg(feature = "rar")]
        authorization_details: sample_authorization_details(),
        issued_at: at_before(10),
        // The GRANT predates any barrier the harness records, which is what makes the refusal
        // checks below test the refusal rather than the comparison.
        //
        // And it is DISTINCT from `issued_at` above, by this module's fixture rule: the two are
        // separate columns because a rotation mints at `now` and carries the grant instant
        // forward, so a fixture that made them equal could not tell a store that persists this
        // column from one that fills it in from the token's own issue time — which is the store
        // that admits every write a barrier exists to refuse, because a rotation completing behind
        // a revocation looks to it like a grant established after that revocation.
        grant_established_at: at_before(20),
        expires_at: at(3600),
        family_id: family_id.map(str::to_string),
        // RFC 8693 s4.1: who authority was delegated TO. DISTINCTIVE rather than `None`, per this
        // module's fixture rule, because a store that silently drops it leaves a resource server
        // unable to tell "A acting for B" from "B", which is the whole distinction RFC 8693 s1.1
        // draws and the only reason a deployment chooses delegation.
        // NESTED, one link deep, for the same reason it is not `None`: section 4.1 makes the
        // nesting itself the ordering of the delegation, so a store that keeps the outermost actor
        // and flattens what is inside it loses WHO acted before, and a flat fixture could not tell
        // that store from a correct one.
        #[cfg(feature = "token-exchange")]
        act: Some(Box::new(crate::token_exchange::ActClaim {
            sub: "actor-conformance".to_string(),
            client_id: Some("client-actor-conformance".to_string()),
            act: Some(Box::new(crate::token_exchange::ActClaim {
                sub: "actor-conformance-prior".to_string(),
                client_id: None,
                act: None,
            })),
        })),
        // RFC 9449 s6: the key this token is bound to. A store that drops it turns a
        // sender-constrained token back into a bearer token, and nothing on the token plane
        // notices, because a token that verifies with no binding is exactly what a bearer token
        // is.
        #[cfg(feature = "dpop")]
        jkt: Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I".into()),
        // RFC 8705 s3.1: the client certificate this token is bound to. Dropping it has the same
        // consequence as dropping `jkt` above, by the other mechanism: a certificate-bound token
        // silently becomes a bearer token, and nothing on the token plane can tell.
        #[cfg(feature = "mtls")]
        x5t_s256: Some(Box::new(crate::mtls::CertificateThumbprint::from_der(
            b"conformance-fixture-certificate",
        ))),
        #[cfg(feature = "consent")]
        authentication: sample_authentication(),
    }
}

fn sample_refresh(refresh_token: &str, client_id: &str, family_id: &str) -> RefreshTokenRecord {
    RefreshTokenRecord {
        refresh_token: refresh_token.to_string(),
        client_id: ClientId::new(client_id),
        subject: Some("subject-conformance".to_string()),
        scope: scopes("read write"),
        resource: vec![
            "https://rs-one.example/".to_string(),
            "https://rs-two.example/".to_string(),
        ],
        #[cfg(feature = "rar")]
        authorization_details: sample_authorization_details(),
        // Carried, never restamped: the chain remembers the decision that started it, and the
        // harness plants it before any barrier it records. Distinct from every other instant this
        // fixture carries, for the reason `sample_token` gives.
        grant_established_at: at_before(20),
        expires_at: Some(at(86_400)),
        family_id: family_id.to_string(),
        state: RefreshTokenState::Spent,
        // RFC 9449 s5. Dropped here, a stolen refresh token can be re-bound to the thief's key on
        // the next rotation, which leaves the attacker holding a provable token and the victim
        // holding the key that gets refused.
        #[cfg(feature = "dpop")]
        jkt: Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I".into()),
        // RFC 8705 s3.1: the client certificate this token is bound to. Dropping it has the same
        // consequence as dropping `jkt` above, by the other mechanism: a certificate-bound token
        // silently becomes a bearer token, and nothing on the token plane can tell.
        #[cfg(feature = "mtls")]
        x5t_s256: Some(Box::new(crate::mtls::CertificateThumbprint::from_der(
            b"conformance-fixture-certificate",
        ))),
        #[cfg(feature = "consent")]
        authentication: sample_authentication(),
    }
}

#[cfg(test)]
#[path = "tests/storage_conformance.rs"]
mod tests;
