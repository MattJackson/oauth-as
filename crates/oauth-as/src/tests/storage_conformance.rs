// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for the private machinery of the storage conformance harness.
//!
//! The harness's own claims are proven end to end in
//! `crates/oauth-as/tests/storage_conformance_selftest.rs`, by running it against deliberately
//! broken stores and watching it report. What is tested HERE is the layer underneath that: the
//! concurrency primitives the harness is built out of, because a rendezvous that does not
//! rendezvous or a join that does not interleave would make the atomicity checks pass vacuously,
//! and a vacuous pass is exactly the failure mode this whole module exists to prevent.

// Everything these tests need (Arc, Mutex, the atomics, Pin, Context, Poll, the fixtures) is
// already imported by the module under test.
use super::*;

/// Yields exactly once, standing in for the suspension point any store that talks to a database
/// has between its read and its delete.
async fn yield_once() {
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
    YieldOnce(false).await
}

#[tokio::test]
async fn join_all_runs_every_future_and_returns_every_result() {
    let futures: Vec<Pin<Box<dyn Future<Output = usize> + Send>>> = (0..5usize)
        .map(|i| {
            Box::pin(async move {
                yield_once().await;
                i
            }) as Pin<Box<dyn Future<Output = usize> + Send>>
        })
        .collect();
    assert_eq!(JoinAll::new(futures).await, vec![0, 1, 2, 3, 4]);
}

/// THE property that makes the cooperative (no spawner) mode worth running: two racers that
/// suspend between their read and their write both perform their read before either writes. A
/// read-then-delete store therefore hands the value to both, which is the violation the harness
/// reports.
#[tokio::test]
async fn join_all_interleaves_at_suspension_points() {
    let log: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
    let futures: Vec<Pin<Box<dyn Future<Output = ()> + Send>>> = ["a", "b"]
        .into_iter()
        .map(|name| {
            let log = Arc::clone(&log);
            Box::pin(async move {
                log.lock()
                    .unwrap()
                    .push(if name == "a" { "a-read" } else { "b-read" });
                yield_once().await;
                log.lock()
                    .unwrap()
                    .push(if name == "a" { "a-delete" } else { "b-delete" });
            }) as Pin<Box<dyn Future<Output = ()> + Send>>
        })
        .collect();
    JoinAll::new(futures).await;

    assert_eq!(
        *log.lock().unwrap(),
        vec!["a-read", "b-read", "a-delete", "b-delete"],
        "both reads must happen before either write, or the cooperative mode cannot catch a \
         read-then-delete store"
    );
}

#[tokio::test]
async fn the_gate_opens_only_once_every_racer_has_arrived() {
    let gate = Gate::new(4);
    let arrived_before_release = Arc::new(AtomicUsize::new(0));

    let futures: Vec<Pin<Box<dyn Future<Output = usize> + Send>>> = (0..4)
        .map(|_| {
            let gate = Arc::clone(&gate);
            let counter = Arc::clone(&arrived_before_release);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                gate.wait().await;
                // Every racer is past the gate only when all four had arrived.
                counter.load(Ordering::SeqCst)
            }) as Pin<Box<dyn Future<Output = usize> + Send>>
        })
        .collect();

    let seen = JoinAll::new(futures).await;
    assert_eq!(seen, vec![4, 4, 4, 4]);
    assert!(
        !gate.unsatisfied(),
        "the gate was satisfiable and was satisfied"
    );
}

/// A racer that is run alone must not hang the host's test suite forever. It gives up after its
/// poll budget and marks the gate unsatisfied, which the harness reports as `harness/race_setup`:
/// a run whose racers never overlapped proves nothing about atomicity and must not read as a pass.
#[tokio::test]
async fn a_lone_racer_gives_up_and_marks_the_race_unsatisfied() {
    let gate = Gate::new(2);
    gate.wait().await;
    assert!(
        gate.unsatisfied(),
        "waiting alone for a partner that never arrives must be recorded, not silently ignored"
    );
}

#[tokio::test]
async fn the_latch_completes_when_every_racer_reports_done() {
    let latch = Latch::new(3);
    for _ in 0..3 {
        let latch = Arc::clone(&latch);
        tokio::spawn(async move {
            yield_once().await;
            latch.done();
        });
    }
    // Hangs rather than fails if the latch is wrong, which the test harness surfaces as a timeout;
    // the assertion below is what makes a spuriously-early wake fail loudly instead.
    latch.wait().await;
    assert_eq!(latch.remaining.load(Ordering::SeqCst), 0);
}

/// The fixtures are the whole basis of the round-trip checks: a field left at a default value
/// would let a store that drops it pass. These are the three that matter most, so they are pinned
/// rather than trusted.
#[test]
fn the_fixtures_carry_the_fields_the_round_trip_checks_exist_for() {
    let token = sample_token("at", "client", Some("fam"));
    assert!(
        token.family_id.is_some(),
        "family_id drives RFC 9700 s4.14.2 revocation"
    );
    assert!(
        !token.resource.is_empty(),
        "resource is the RFC 8707 audience restriction"
    );
    let refresh = sample_refresh("rt", "client", "fam");
    assert_eq!(refresh.state, RefreshTokenState::Spent);
    assert!(!refresh.resource.is_empty());
    let code = sample_authorization_code("code");
    assert!(matches!(
        code.state,
        AuthorizationCodeState::Consumed { .. }
    ));
    assert!(!code.resource.is_empty());
    let grant = sample_device_grant("dc", "WDJB-MJHT");
    assert!(grant.last_poll_at.is_some());
    assert_eq!(normalize_user_code(&grant.user_code), "WDJBMJHT");
}

/// The fields whose fixture value used to BE the default, which is the one way a round-trip check
/// can be present and still see nothing: a store that drops the field reads back exactly what a
/// store that keeps it does. Pinned here rather than trusted, because
/// `sample_authorization_details` parses a literal and a parse failure would silently produce the
/// empty default again.
#[test]
fn the_fixtures_carry_no_default_value_a_dropped_field_could_hide_behind() {
    #[cfg(feature = "rar")]
    {
        assert!(
            !sample_authorization_details().is_empty(),
            "an empty AuthorizationDetails is the default, so the round-trip checks could not \
             tell a store that drops RFC 9396 details from one that keeps them"
        );
        assert!(!sample_token("at", "client", None)
            .authorization_details
            .is_empty());
        assert!(!sample_refresh("rt", "client", "fam")
            .authorization_details
            .is_empty());
        assert!(!sample_authorization_code("code")
            .authorization_details
            .is_empty());
        #[cfg(feature = "par")]
        assert!(sample_pushed_request("urn:x")
            .authorization_details
            .is_some());
    }
    #[cfg(feature = "consent")]
    {
        // Both members, not just the presence of the record: a store that persists `auth_time` and
        // drops `acr` satisfies RFC 9470 `max_age` and silently fails every `acr_values` request.
        let auth = sample_authentication().expect("the fixture reports an authentication");
        assert!(auth.acr.is_some());
        assert!(sample_token("at", "client", None).authentication.is_some());
        assert!(sample_refresh("rt", "client", "fam")
            .authentication
            .is_some());
        assert!(sample_authorization_code("code").authentication.is_some());
        assert!(sample_consent("c", "subject").authentication.is_some());
    }
    #[cfg(feature = "mtls")]
    {
        assert!(sample_token("at", "client", None).x5t_s256.is_some());
        assert!(sample_refresh("rt", "client", "fam").x5t_s256.is_some());
    }
}

/// Two fixtures whose DISTINCTNESS is what makes a check able to fail, in the way a value being
/// non-default is elsewhere in this file. Neither is visible in the check that depends on it, so
/// both are pinned here rather than left to be noticed if they ever collide.
#[test]
fn the_fixtures_that_must_differ_from_each_other_do() {
    // Both handles go into ONE store in the sweep check, one dead and one live. Equal keys would
    // make the second plant overwrite the first, and `sweep_expired/reclaims_pushed_requests`
    // would then be asking about a record that was never there: a vacuous pass, which is the exact
    // failure mode this harness exists to refuse.
    #[cfg(feature = "par")]
    assert_ne!(PUSHED_SWEPT, PUSHED_KEPT);
    #[cfg(feature = "consent")]
    {
        // The per-subject listing check can only see a store filtering on the CLIENT if the two
        // consents share a client and differ in subject. A `sample_consent` that ever derived the
        // client id from the consent id would make that check pass against exactly the defect it
        // was written for.
        let mine = sample_consent("consent-mine", "subject-conformance");
        let theirs = sample_consent("consent-theirs", "subject-other");
        assert_eq!(mine.client_id, theirs.client_id);
        assert_ne!(mine.subject, theirs.subject);
        assert_ne!(mine.consent_id, theirs.consent_id);
    }
}

/// A host is invited to filter or waive by check name, so the names have to be a complete and
/// duplicate-free list or a waiver could silently cover more than the host meant.
#[test]
fn the_published_check_list_has_no_duplicates() {
    let mut sorted = CHECKS.to_vec();
    sorted.sort_unstable();
    let before = sorted.len();
    sorted.dedup();
    assert_eq!(before, sorted.len(), "CHECKS contains a duplicate name");
}
