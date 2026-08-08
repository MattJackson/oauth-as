// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A RUNNABLE conformance harness for the [`Storage`] contract, behind the `test-util` cargo
//! feature (off by default), for a HOST to run from its OWN test suite against its OWN store.
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
//! `Storage::claim_replay_id` (compiled in with `client_assertion` or `dpop`) is the same defect
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
use crate::store::{Storage, StorageError};
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
/// run when `client_assertion` or `dpop` is compiled in: a host's waiver list should not have to
/// be feature-conditional to be valid.
pub const CHECKS: &[&str] = &[
    HARNESS_RACE_SETUP,
    ROUND_TRIP_CLIENT,
    ROUND_TRIP_DEVICE_GRANT,
    ROUND_TRIP_AUTHORIZATION_CODE,
    ROUND_TRIP_TOKEN,
    ROUND_TRIP_REFRESH_TOKEN,
    ATOMIC_TAKE_DEVICE_GRANT,
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
    REVOKE_FAMILY_REMOVES,
    REVOKE_FAMILY_SPARES_OTHERS,
    REVOKE_FAMILY_COUNT,
    DELETE_CLIENT_CASCADES,
    DELETE_CLIENT_REPORTS,
    DELETE_TOKEN_IDEMPOTENT,
    ATOMIC_CLAIM_REPLAY_ID,
    CLAIM_REPLAY_ID_REFUSES_SECOND,
    SWEEP_RECLAIMS_REPLAY_IDS,
];

const HARNESS_RACE_SETUP: &str = "harness/race_setup";
const ROUND_TRIP_CLIENT: &str = "round_trip/client";
const ROUND_TRIP_DEVICE_GRANT: &str = "round_trip/device_grant";
const ROUND_TRIP_AUTHORIZATION_CODE: &str = "round_trip/authorization_code";
const ROUND_TRIP_TOKEN: &str = "round_trip/token";
const ROUND_TRIP_REFRESH_TOKEN: &str = "round_trip/refresh_token";
const ATOMIC_TAKE_DEVICE_GRANT: &str = "atomic_take/take_device_grant";
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
const REVOKE_FAMILY_REMOVES: &str = "revoke_token_family/removes_the_family";
const REVOKE_FAMILY_SPARES_OTHERS: &str = "revoke_token_family/spares_other_families";
const REVOKE_FAMILY_COUNT: &str = "revoke_token_family/count";
const DELETE_CLIENT_CASCADES: &str = "delete_client/cascades";
const DELETE_CLIENT_REPORTS: &str = "delete_client/reports_whether_it_removed";
const DELETE_TOKEN_IDEMPOTENT: &str = "delete_token/idempotent";
const ATOMIC_CLAIM_REPLAY_ID: &str = "atomic_claim/claim_replay_id";
const CLAIM_REPLAY_ID_REFUSES_SECOND: &str = "claim_replay_id/refuses_a_second_claim";
const SWEEP_RECLAIMS_REPLAY_IDS: &str = "sweep_expired/reclaims_replay_ids";

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

    /// How many callers race each `take_*`. Default [`DEFAULT_RACERS`]. Values below 2 are raised
    /// to 2, since one racer cannot race.
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
        self.atomic_take_refresh_token(&mut report).await;
        self.atomic_take_authorization_code(&mut report).await;
        self.user_code_index(&mut report).await;
        self.sweep(&mut report).await;
        self.revoke_family(&mut report).await;
        self.delete_client(&mut report).await;
        self.delete_token(&mut report).await;
        #[cfg(any(feature = "client_assertion", feature = "dpop"))]
        self.claim_replay_id(&mut report).await;
        report.violations
    }

    /// RFC 7523 section 3 and RFC 9449 section 4.3 both make a `jti` single use, and
    /// `claim_replay_id` is the only thing enforcing it. Same defect shape as the `take_*`
    /// operations, with a worse failure mode: a `take_*` that hands the value out twice at least
    /// produces two token responses somebody might notice, while a claim-if-absent that answers
    /// "you are first" to two callers produces exactly the request the client meant to send,
    /// twice, and nothing anywhere records that it happened.
    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
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

    // ------------------------------------------------------------------ round-trip fidelity

    /// A store that silently drops a field passes any test that only checks the key came back.
    /// The fields that matter most here are named in their own checks below: `family_id` is what
    /// RFC 9700 section 4.14.2 reuse revocation walks, and `resource` is the RFC 8707 audience
    /// restriction, so a store that loses either produces tokens that are wider than what was
    /// granted while still looking correct.
    async fn round_trip_client(&self, report: &mut Report) {
        let store = self.store().await;
        let want = sample_client("client-round-trip");
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
        report.same(c, "expires_at", &want.expires_at, &got.expires_at);
        // `Consumed` carries what the code minted, which is what a replay revokes. A store that
        // flattens the state to a boolean loses the thing the remedy needs.
        report.same(c, "state", &want.state, &got.state);
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
        report.same(c, "expires_at", &want.expires_at, &got.expires_at);
        // RFC 9700 section 4.14.2: without this, a detected reuse cannot reach the access tokens
        // the thief already minted.
        report.same(c, "family_id", &want.family_id, &got.family_id);
        // RFC 9449 section 6: the DPoP binding. Dropped, the token is a bearer token again.
        #[cfg(feature = "dpop")]
        report.same(c, "jkt", &want.jkt, &got.jkt);
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
        report.same(c, "expires_at", &want.expires_at, &got.expires_at);
        report.same(c, "family_id", &want.family_id, &got.family_id);
        // `Spent` is the whole basis of reuse detection: a store that reads every record back as
        // `Active` turns the RFC 9700 section 4.14.2 remedy off.
        report.same(c, "state", &want.state, &got.state);
        // RFC 9449 section 5: carried across rotation and checked on redemption.
        #[cfg(feature = "dpop")]
        report.same(c, "jkt", &want.jkt, &got.jkt);
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

    /// Exactly one racer may receive the value. More than one IS the double-spend; none means the
    /// value was lost, which is a different bug with the same root (a non-atomic pair of steps).
    fn judge_race<T>(
        &self,
        report: &mut Report,
        check: &'static str,
        what: &str,
        results: TakeResults<T>,
    ) {
        let winners = results.iter().filter(|r| matches!(r, Ok(Some(_)))).count();
        let errors = results.iter().filter(|r| r.is_err()).count();
        if winners > 1 {
            report.fail(
                check,
                format!(
                    "{winners} of {} concurrent takes each received the {what}: the operation is \
                     not an atomic remove-and-return, so this store double-spends single-use \
                     credentials under concurrency",
                    results.len()
                ),
            );
        } else if winners == 0 {
            report.fail(
                check,
                format!(
                    "none of {} concurrent takes received the {what}, though it was stored \
                     beforehand: the value was lost rather than handed to exactly one caller",
                    results.len()
                ),
            );
        }
        if errors > 0 {
            report.fail(
                check,
                format!(
                    "{errors} of {} concurrent takes failed with a StorageError. The server maps \
                     that to server_error, so a legitimate redemption fails under ordinary \
                     contention; a store using optimistic concurrency must retry internally \
                     rather than surface the conflict",
                    results.len()
                ),
            );
        }
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

        let results = match &self.spawn {
            Some(spawn) => {
                let collected: Arc<Mutex<TakeResults<T>>> =
                    Arc::new(Mutex::new(Vec::with_capacity(n)));
                let latch = Latch::new(n);
                for fut in futures {
                    let collected = Arc::clone(&collected);
                    let latch = Arc::clone(&latch);
                    spawn(Box::pin(async move {
                        let outcome = fut.await;
                        // A poisoned lock means another racer panicked; the recovered guard is
                        // sound here because the vector is only ever pushed to.
                        collected
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(outcome);
                        latch.done();
                    }));
                }
                latch.wait().await;
                let mut guard = collected.lock().unwrap_or_else(|e| e.into_inner());
                std::mem::take(&mut *guard)
            }
            None => JoinAll::new(futures).await,
        };

        if gate.unsatisfied() {
            report.fail(
                HARNESS_RACE_SETUP,
                format!(
                    "the {n} racers never overlapped: each gave up waiting for the others, which \
                     means they ran one after another and the atomicity results in this run prove \
                     nothing. A `with_spawn` that runs its task to completion inline does this; \
                     hand the futures to a real runtime instead",
                ),
            );
        }
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
        let mut live_code = sample_authorization_code("code-live");
        live_code.expires_at = at(600);

        let mut dead_token = sample_token("at-dead", "client-sweep", Some("fam-sweep"));
        dead_token.expires_at = at_before(1);
        let mut live_token = sample_token("at-live", "client-sweep", Some("fam-sweep"));
        live_token.expires_at = at(600);

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
        if !planted {
            return;
        }

        let Some(removed) = report.ok(c, "sweep_expired", store.sweep_expired(now).await) else {
            return;
        };

        // Exactly four records were dead: one grant, one code, one access token, one refresh.
        if removed != 4 {
            report.fail(
                SWEEP_COUNT,
                format!(
                    "sweep_expired reported {removed} records removed, but exactly 4 of the 9 \
                     planted records were dead at `now`. The count is what a host schedules its \
                     sweep on, so a wrong one is a store that looks idle while it grows"
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
            store.revoke_token_family("fam-a").await,
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
        match store.revoke_token_family("fam-a").await {
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
        }
        if !planted {
            return;
        }

        let Some(existed) = report.ok(
            DELETE_CLIENT_REPORTS,
            "delete_client",
            store.delete_client(&doomed).await,
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

        // Removing a client that is already gone is Ok(false), not an error.
        match store.delete_client(&doomed).await {
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

fn scopes(s: &str) -> ScopeSet {
    // The literals below are this module's own and are all valid RFC 6749 section 3.3 tokens.
    ScopeSet::parse(s).unwrap_or_else(|_| ScopeSet::empty())
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

fn sample_authorization_code(code: &str) -> AuthorizationCodeRecord {
    AuthorizationCodeRecord {
        code: code.to_string(),
        client_id: ClientId::new("client-conformance"),
        redirect_uri: "https://app.example/cb".to_string(),
        scope: scopes("read write"),
        subject: "subject-conformance".to_string(),
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string(),
        code_challenge_method: CodeChallengeMethod::S256,
        resource: vec![
            "https://rs-one.example/".to_string(),
            "https://rs-two.example/".to_string(),
        ],
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        expires_at: at(60),
        state: AuthorizationCodeState::Consumed {
            access_token: "at-minted-by-this-code".to_string(),
            refresh_token: Some("rt-minted-by-this-code".to_string()),
        },
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
        authorization_details: Default::default(),
        issued_at: at_before(10),
        expires_at: at(3600),
        family_id: family_id.map(str::to_string),
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
        authorization_details: Default::default(),
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
    }
}

#[cfg(test)]
#[path = "tests/storage_conformance.rs"]
mod tests;
