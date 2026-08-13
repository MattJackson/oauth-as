// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Pins the `Storage` trait contract documented in `src/store.rs` against `MemoryStorage`, the
//! reference implementation. That doc comment asserts, in prose:
//!
//! - `take_*` operations are ATOMIC remove-and-return: under concurrent redemption exactly one
//!   caller receives the value. This is the property that makes single-use artifacts (device
//!   codes, rotating refresh tokens, authorization codes) actually single use.
//! - `put_device_grant` upserts by `device_code` and must keep the user-code index consistent.
//! - User-code lookups are by NORMALIZED code. The store normalizes the code it is GIVEN, so the
//!   index is keyed by the normalized form however the grant spells its `user_code`; it does not
//!   normalize the QUERY, so a lookup is of the exact key it is handed. The server crosses that
//!   boundary before it ever calls into `Storage`.
//!
//! These tests exist because a prose contract with no test is a contract nobody has to keep.
//!
//! # What the atomicity tests here can and cannot prove
//!
//! The suite's tokio is a DEV dependency with `rt`, `macros` and `time` and no `rt-multi-thread`,
//! so `#[tokio::test]` is a current-thread runtime and nothing here runs in parallel on two cores.
//! Simply spawning eight tasks and counting the winners therefore proves nothing on its own: a
//! future with no suspension point inside it runs to completion in a single poll whatever it does,
//! so a READ-THEN-DELETE implementation would have scored exactly the same "one winner" as the
//! atomic one and the assertion would have been reporting the scheduler rather than the store.
//!
//! What IS observable, and is what these tests pin, is whether the remove-and-return is INTERRUPTED
//! part way: an implementation that reads, awaits, and only then deletes leaves a window in which
//! every other redeemer sees the value. [`race`] opens exactly that window if it is there, and
//! [`the_race_harness_detects_a_take_that_is_not_atomic`] is the harness's own teeth — it hands
//! `race` a take deliberately written with the forbidden shape and requires all eight racers to
//! win. Without that check a green "exactly one winner" would be unfalsifiable.
//!
//! Stated as plainly as it can be: a rewrite of `MemoryStorage::take_*` into a synchronous
//! `get(); remove();` pair — two lock acquisitions, no `.await` between them — is NOT caught here,
//! and no single-threaded harness can catch it. What IS caught is the shape every store that is
//! not a `HashMap` behind a `Mutex` actually has: a read that goes somewhere, comes back, and is
//! followed by a separate delete. `src/storage_conformance.rs` is where that case is put to a
//! host's own runtime, and its module docs carry the same honest account for the same reason.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use oauth_as::{
    AuthorizationCodeRecord, ClientId, DeviceGrant, DeviceGrantState, IssuedToken, MemoryStorage,
    RefreshTokenRecord, RevocationWindow, ScopeSet, Storage, WriteOutcome,
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
    RefreshTokenRecord::new(
        token,
        ClientId::new("some-client"),
        Some("user-1".into()),
        scope(),
        "family-1",
    )
}

fn sample_authorization_code(code: &str) -> AuthorizationCodeRecord {
    AuthorizationCodeRecord::new(
        code,
        ClientId::new("some-client"),
        "https://app.example/cb",
        scope(),
        "user-1",
        "a".repeat(43),
        SystemTime::now() + Duration::from_secs(60),
    )
}

/// THE HARNESS. `n` tasks are spawned, each calling `take` once on the same key, and this counts
/// how many of them receive a value.
///
/// Spawning is what makes the window openable: every racer is a separate task, so a `take` that
/// suspends part way through hands control to the next racer with the value still readable, and
/// they all win. A `take` that never suspends between reading and removing cannot be interleaved
/// with anything and exactly one can win. That difference — not parallelism, which this runtime
/// does not have — is what the count reports. See
/// [`the_race_harness_detects_a_take_that_is_not_atomic`], which requires the harness to score the
/// forbidden shape as eight.
async fn race<T, Fut>(n: usize, take: impl Fn() -> Fut) -> usize
where
    T: Send + 'static,
    Fut: Future<Output = Option<T>> + Send + 'static,
{
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        handles.push(tokio::spawn(take()));
    }
    let mut winners = 0;
    for h in handles {
        if h.await.unwrap().is_some() {
            winners += 1;
        }
    }
    winners
}

/// A store whose `take` is written the way the `src/store.rs` contract forbids: it READS, then
/// suspends, and only then removes. Nothing in this crate is implemented this way; it exists so
/// [`race`] can be shown to catch the shape, because an "exactly one winner" assertion that no
/// implementation could fail is not an assertion.
///
/// It is not a `Storage`: the harness takes a future, not a trait object, so what the map is made
/// of does not matter. What matters is the `.await` between the read and the delete, which is the
/// only thing about a take that a single-threaded executor can observe at all.
#[derive(Default)]
struct NonAtomicStore(Mutex<HashMap<String, String>>);

impl NonAtomicStore {
    fn with(key: &str, value: &str) -> Arc<Self> {
        let store = Arc::new(NonAtomicStore::default());
        store
            .0
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_string());
        store
    }

    async fn take(self: Arc<Self>, key: String) -> Option<String> {
        let found = self.0.lock().unwrap().get(&key).cloned();
        // THE WINDOW. A store that reads its row in one round trip and deletes it in another has
        // one of these whether it wrote a `yield_now` or not.
        tokio::task::yield_now().await;
        if found.is_some() {
            self.0.lock().unwrap().remove(&key);
        }
        found
    }
}

/// THE TEETH. Eight racers over a deliberately non-atomic take, and all eight must win.
///
/// If this ever reported one, the three assertions below would be measuring nothing: they would be
/// passing because no take of any shape can lose a race on this harness, rather than because
/// `MemoryStorage` keeps the contract.
#[tokio::test]
async fn the_race_harness_detects_a_take_that_is_not_atomic() {
    let store = NonAtomicStore::with("k", "v");
    let winners = race(8, || store.clone().take("k".to_string())).await;
    assert_eq!(
        winners, 8,
        "a take that suspends between reading and removing must let every racer through, or this \
         file's atomicity assertions cannot fail"
    );
}

/// RFC 8628's single-use device code redemption is only true if `take_device_grant` completes its
/// remove-and-return without a suspension point in the middle. Eight tasks race to take the same
/// grant; exactly one may receive it, per the `src/store.rs` contract note on `take_*`.
#[tokio::test]
async fn take_device_grant_delivers_the_value_exactly_once_under_concurrency() {
    let storage = Arc::new(MemoryStorage::new());
    storage
        .put_device_grant(sample_device_grant("dc-1", "WDJB-MJHT"))
        .await
        .unwrap();

    let winners = race(8, || {
        let s = storage.clone();
        async move { s.take_device_grant("dc-1").await.unwrap() }
    })
    .await;
    assert_eq!(
        winners, 1,
        "exactly one concurrent take_device_grant must succeed"
    );

    // And it is genuinely gone afterward, for every path (not just the losing tasks).
    assert!(storage.get_device_grant("dc-1").await.unwrap().is_none());
    assert!(storage.take_device_grant("dc-1").await.unwrap().is_none());
}

/// OAuth 2.1 single-use refresh rotation depends on the same property: `take_refresh_token` must
/// hand the record to exactly one of several concurrent redeemers.
#[tokio::test]
async fn take_refresh_token_delivers_the_value_exactly_once_under_concurrency() {
    let storage = Arc::new(MemoryStorage::new());
    let _ = storage
        .put_refresh_token(sample_refresh_token("rt-1"))
        .await
        .unwrap();

    let winners = race(8, || {
        let s = storage.clone();
        async move { s.take_refresh_token("rt-1").await.unwrap() }
    })
    .await;
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

    let winners = race(8, || {
        let s = storage.clone();
        async move { s.take_authorization_code("code-1").await.unwrap() }
    })
    .await;
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

/// `src/store.rs` documents that `put_device_grant` "must keep any user-code index consistent",
/// and half of that is the case a naive "insert the new mapping" implementation gets wrong:
/// re-putting the SAME `device_code` with a DIFFERENT `user_code` must RETIRE the old user-code
/// mapping, not merely add the new one. Leaving it behind means a code the user was shown, and
/// which has since been superseded, goes on approving the grant.
///
/// `MemoryStorage::put_device_grant` used to do exactly that: it inserted
/// `normalize(new_user_code) -> device_code` and removed nothing. No `server.rs` path changes a
/// grant's `user_code` after creation (the state transitions only ever touch `state`), so the
/// defect was latent rather than reachable through `AuthorizationServer` — which is precisely why
/// it needed a test of its own rather than being noticed by an end-to-end one. The retirement is
/// there now, and this pins it.
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

/// THE SECOND LINE OF DEFENCE, which is worth pinning separately because it is what made the bug
/// above latent rather than exploitable.
///
/// `MemoryStorage` keeps its index as a POINTER (normalized code -> `device_code`) and
/// `find_device_grant_by_user_code` joins through the primary map, so an entry left pointing at a
/// row that `take_device_grant` has removed resolves to nothing: the right answer, by accident.
/// A store whose index is its OWN row carrying its own copy of the grant — the ordinary Redis or
/// DynamoDB shape, and the one `tests/storage_conformance_selftest.rs` models — has no such
/// accident, which is why `user_code_index/cleared_by_take` is a check in the exported harness
/// rather than a property this file could take for granted for everybody.
///
/// Both codes are probed, the superseded one and the live one, because the two failures are
/// different: the first would mean the retirement above did not happen, the second would mean the
/// take did not clear the entry it owns.
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

/// `src/store.rs`: the store does not normalize the QUERY. So a lookup using the display form
/// (with its hyphen, or the wrong case) is a DIFFERENT string to the store and must miss, even
/// though the grant it would have found was itself indexed by its normalized code, and even though
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

// ------------------------------- the harness may only accuse a store of rules the trait states

/// Collapse a Rust source file to one line of single-spaced tokens, and splice the string
/// continuations back together, so a phrase can be searched for without regard to where rustfmt
/// broke the line it lives on.
///
/// `"a \` + newline + ` b"` is the shape every long message in `storage_conformance.rs` has; after
/// `split_whitespace` it is the tokens `a`, `\`, `b`, and dropping the lone backslash puts the
/// sentence back. Nothing else in these files uses a bare `\` token.
fn normalized(source: &str) -> String {
    source
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" \\ ", " ")
}

/// A CONFORMANCE HARNESS MAY ONLY FAIL A STORE ON A RULE THE TRAIT STATES.
///
/// `storage_conformance` fails a store whose concurrent `take_*` or `compare_and_swap_*` calls
/// return a `StorageError`, telling it that "a store using optimistic concurrency must retry
/// internally rather than surface the conflict". That is a real requirement, and until the 0.9.1
/// audit that sentence existed NOWHERE ELSE: not on `compare_and_swap_*`, not on `take_*`, not on
/// `StorageError`. The trait specified atomicity, `Ok(false)` on absence and the no-upsert rule,
/// and said nothing at all about transient contention.
///
/// Which makes it the one kind of finding a host cannot act on. A store on PostgreSQL at
/// `SERIALIZABLE`, on CockroachDB or on etcd will legitimately raise a conflict under exactly the
/// concurrency the check manufactures, and would be told it is non-conforming by a harness whose
/// rule it could not have read beforehand and cannot look up afterwards.
///
/// So the accusation has to CITE something. This scan is what keeps the citation and the rule
/// pointing at each other: every accusation the harness makes on this subject must carry the
/// rule's name, and the rule's name must appear in the trait doc a host reads. Neither half can be
/// deleted without the other going red.
#[test]
fn the_contention_rule_the_harness_cites_is_a_rule_the_trait_states() {
    // Short enough to survive rustfmt on both sides, and specific enough that it cannot appear by
    // accident.
    const RULE: &str = "contention is the store's to resolve, not the caller's";
    // What the harness ACCUSES with. Matched separately from the citation so that removing the
    // citation cannot make this scan pass by finding nothing to check.
    const ACCUSATION: &str = "must retry internally rather than surface the conflict";

    let trait_doc = normalized(include_str!("../src/store.rs"));
    let harness = normalized(include_str!("../src/storage_conformance.rs"));

    assert!(
        trait_doc.contains(RULE),
        "src/store.rs no longer states the contention rule by the name the harness cites it by \
         ({RULE:?}), so a store failed on it has been given a finding it cannot look up"
    );

    let accusations = harness.matches(ACCUSATION).count();
    assert!(
        accusations > 0,
        "src/storage_conformance.rs no longer accuses a store of {ACCUSATION:?}; if the wording \
         moved, move this scan with it rather than leaving it matching nothing"
    );
    assert_eq!(
        harness.matches(RULE).count(),
        accusations,
        "{accusations} accusation(s) about surfacing contention, but not all of them cite the \
         trait rule by name ({RULE:?}). An accusation that cites nothing is one the store cannot \
         argue with"
    );
}

// ------------------------------------------- a standing revocation must not price every issuance

/// THE BARRIER LOOKUP IS ON THE ISSUANCE PATH, so its cost is paid by every token this server
/// mints, for as long as the barrier stands.
///
/// `revocation_window()` takes the LONGEST of the configured lifetimes, and `refresh_reuse_window`
/// defaults to thirty days, so "how many barriers are standing" is "how many revocations happened
/// in the last month" at the shipped defaults. A `delete_client` per revoked registration, a
/// `revoke_token_family` per detected reuse and a `revoke_consent` per logout all land in the same
/// collection, and nothing but [`Storage::sweep_expired`] removes them.
///
/// This crate has already ruled a linear lookup here unacceptable, in its own words, in
/// `oauth-as-postgres/migrations/0005_revocation_barriers.sql`: "without them every token issued
/// costs a sequential scan of every revocation the deployment has ever recorded and not yet
/// swept". That is a statement about the OPERATION, not about PostgreSQL, and `MemoryStorage` is
/// `pub`, not test gated, and documented as the reference every host reads. So the same property
/// is required of it here.
///
/// WHY THE MARGIN IS SO WIDE. This is a wall-clock measurement and wall clocks on a shared CI
/// runner are noisy, so the bound has to survive a scheduling hiccup without going red. It can
/// afford to: the defect this catches is not a percentage, it is a factor of the barrier count.
/// MEASURED on this file's own fixture with the pre-fix `Vec` scan: 50,000 barriers took 2,000
/// issuances from 2.08 ms to 600.47 ms, which is 288 times the zero-barrier cost, and recording
/// the barriers took eight seconds on its own because the recording is a scan too. A 25x bound is
/// an order of magnitude clear of the noise and an order of magnitude clear of the defect, and
/// there is nothing in between the two for it to sit in.
///
/// The timed issuances name a client NOTHING revoked, deliberately: a barrier that matches can
/// short-circuit a scan, so the honest measurement is the one where every standing barrier has to
/// be considered and rejected.
#[tokio::test]
async fn a_standing_barrier_does_not_price_every_later_issuance() {
    // Enough barriers that a per-issuance scan of them is unmistakable next to the hash lookups
    // `put_token` already makes, and few enough that recording them stays a second or two.
    const BARRIERS: usize = 50_000;
    // Enough issuances that one scheduler preemption cannot dominate the total.
    const ISSUANCES: usize = 2_000;

    async fn time_issuances(storage: &MemoryStorage, tag: &str) -> Duration {
        let now = SystemTime::now();
        let started = std::time::Instant::now();
        for i in 0..ISSUANCES {
            let mut token = IssuedToken::new(
                format!("{tag}-at-{i}"),
                ClientId::new("client-nothing-revoked"),
                Some("user-1".into()),
                scope(),
                now,
                now + Duration::from_secs(600),
            );
            // After every barrier below was recorded, so this is a live grant and the write must
            // be applied rather than refused: a refusal would be measuring the wrong path.
            token.grant_established_at = now;
            assert_eq!(
                storage.put_token(token).await.unwrap(),
                WriteOutcome::Applied,
                "the timed issuances must be applied, not refused"
            );
        }
        started.elapsed()
    }

    // The same store shape in both measurements, so the only difference is the barriers. Warmed
    // first, because the first call into a fresh process pays for page faults and lazy statics
    // that have nothing to do with what is being measured.
    let unrevoked = MemoryStorage::new();
    time_issuances(&unrevoked, "warmup").await;
    let baseline = time_issuances(&unrevoked, "baseline").await;

    let revoked = MemoryStorage::new();
    let recorded_at = SystemTime::now();
    let window = RevocationWindow {
        recorded_at,
        until: recorded_at + Duration::from_secs(30 * 24 * 60 * 60),
    };
    // `delete_client` on an empty store: the cascade has nothing to remove, so what this loop
    // costs is what RECORDING a barrier costs, which is the other half of the same defect.
    for i in 0..BARRIERS {
        revoked
            .delete_client(&ClientId::new(format!("client-revoked-{i}")), window)
            .await
            .unwrap();
    }
    let with_barriers = time_issuances(&revoked, "with-barriers").await;

    assert!(
        with_barriers < baseline * 25,
        "{BARRIERS} standing revocation barriers made {ISSUANCES} issuances take \
         {with_barriers:?}, against {baseline:?} with none standing. The barrier lookup is linear \
         in the number of revocations, so every token this server mints is priced by every \
         revocation it has recorded and not yet swept"
    );
}
