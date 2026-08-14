// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit gates for [`crate::rate_limit`], driven at EXPLICIT instants.
//!
//! `tests/rate_limit_impl.rs` drives the same limiter through the real server on the real clock,
//! which is the gate that proves the attack is actually stopped. This file exists because that one
//! cannot see inside: it cannot place an attempt one nanosecond either side of a window boundary,
//! and it cannot look at the bounded map. Both are private, so both are tested from in here,
//! through [`FixedWindowRateLimiter::check_at`] and [`FixedWindowRateLimiter::record_at`], which
//! take the instant rather than reading the clock.

use std::time::Duration;

use super::*;

/// The window boundary, in the limiter's own frame of reference.
fn at(limiter: &FixedWindowRateLimiter, offset: Duration) -> Instant {
    limiter.base + offset
}

fn limiter(config: RateLimitConfig) -> FixedWindowRateLimiter {
    FixedWindowRateLimiter::with_config(config)
}

/// The failure half of one `client_id`'s client-authentication budget, read straight out of the
/// private map so that a test can drive the spray until the counter SATURATES rather than assume
/// how many failures that takes. The increment is `failure_cost` (199 at the defaults) and the
/// clamp is the ceiling, so the count is not `ceiling / (1 + failure_cost)`.
fn client_failures(l: &FixedWindowRateLimiter, client_id: &str) -> u64 {
    l.lock().clients.get(client_id).map_or(0, |b| b.failures)
}

/// The failure half of one `client_id`'s authorization-request budget. See [`client_failures`].
fn authorization_failures(l: &FixedWindowRateLimiter, client_id: &str) -> u64 {
    l.lock()
        .authorization
        .get(client_id)
        .map_or(0, |b| b.failures)
}

/// A budget spent by ATTEMPTS: with the failure penalty off, capacity is a plain attempt ceiling.
#[test]
fn a_budget_is_spent_one_unit_per_allowed_attempt() {
    let l = limiter(RateLimitConfig::default().with_device_user_code_budget(3, 0));
    let now = at(&l, Duration::ZERO);
    for i in 0..3 {
        assert_eq!(
            l.check_at(Attempt::DeviceUserCodeEntry, now),
            RateLimitDecision::Allow,
            "attempt {i} is inside the budget"
        );
    }
    assert_eq!(
        l.check_at(Attempt::DeviceUserCodeEntry, now),
        RateLimitDecision::Deny
    );
}

/// The reason this implementation uses `record` and not only `check`: a guessing attack shows up in
/// FAILURES, not in traffic. With the shipped weights a wrong user code costs ten times a right
/// one, so the same budget buys 200 correct entries or 20 wrong ones.
#[test]
fn failures_cost_ten_times_what_successes_cost() {
    let successes = {
        let l = limiter(RateLimitConfig::default());
        let now = at(&l, Duration::ZERO);
        let mut n = 0;
        while l.check_at(Attempt::DeviceUserCodeEntry, now) == RateLimitDecision::Allow {
            l.record_at(Attempt::DeviceUserCodeEntry, AttemptOutcome::Succeeded, now);
            n += 1;
        }
        n
    };
    let failures = {
        let l = limiter(RateLimitConfig::default());
        let now = at(&l, Duration::ZERO);
        let mut n = 0;
        while l.check_at(Attempt::DeviceUserCodeEntry, now) == RateLimitDecision::Allow {
            l.record_at(Attempt::DeviceUserCodeEntry, AttemptOutcome::Failed, now);
            n += 1;
        }
        n
    };
    assert_eq!(
        (successes, failures),
        (DEFAULT_DEVICE_USER_CODE_CAPACITY, 20),
        "the documented default is 200 correct entries a minute or 20 wrong ones"
    );
}

/// RFC 8628 section 5.1 arithmetic, pinned as a number rather than as prose: the shipped default
/// must permit no more than 20 WRONG user codes per window. If somebody moves a constant, this is
/// the test that says which claim in the module docs stopped being true.
#[test]
fn the_shipped_default_permits_twenty_wrong_user_codes_per_window() {
    let cost_of_a_failure = ATTEMPT_COST + DEFAULT_DEVICE_USER_CODE_FAILURE_COST;
    assert_eq!(
        DEFAULT_DEVICE_USER_CODE_CAPACITY / cost_of_a_failure,
        20,
        "the module docs derive the 2^34.6 guessing odds from 20 wrong codes per 60s window"
    );
    let cost_of_a_failed_auth = ATTEMPT_COST + DEFAULT_CLIENT_AUTHENTICATION_FAILURE_COST;
    assert_eq!(
        cost_of_a_failed_auth, 200,
        "the module docs price a failed client authentication at 200 units"
    );
    // The client-authentication number is NOT capacity/200, because the failure penalty is capped
    // at half the capacity so that it can never lock the real client out (see the module docs).
    // What the docs claim is that the first 15 failures in a window are the expensive ones.
    let config = RateLimitConfig::default();
    assert_eq!(
        config.client_authentication_failure_ceiling() / cost_of_a_failed_auth,
        15,
        "the module docs derive the RFC 9700 s4.13 weighting from 15 penalised failures per client"
    );
    // And the number of failures that FILLS the ceiling is one more than that, because `penalise`
    // adds `failure_cost` (199) rather than the 200 a failure costs in total: 15 * 199 = 2985 is
    // short of 3000, so it is the sixteenth that clamps. The two numbers are a unit apart in the
    // divisor and one apart in the answer, which is exactly the drift a test that only divides by
    // 200 cannot see. `the_sixteenth_failure_costs_sixteen_units_and_the_seventeenth_costs_one`
    // drives it rather than deriving it.
    assert_eq!(
        config
            .client_authentication_failure_ceiling()
            .div_ceil(DEFAULT_CLIENT_AUTHENTICATION_FAILURE_COST),
        16,
        "the failure counter climbs by 199 a failure, so 16 of them reach the 3000 ceiling"
    );
    assert_eq!(
        config.client_authentication_failure_ceiling(),
        DEFAULT_CLIENT_AUTHENTICATION_CAPACITY / 2,
        "half of every client's budget is reserved for attempts and cannot be spent by failures"
    );
}

/// A success is charged once, at check time, and never again: `record(Succeeded)` must not
/// double-charge, or a busy verification page would throttle at half the documented ceiling.
#[test]
fn a_successful_outcome_costs_nothing_beyond_the_attempt() {
    let l = limiter(RateLimitConfig::default().with_device_user_code_budget(2, 1_000_000));
    let now = at(&l, Duration::ZERO);
    assert_eq!(
        l.check_at(Attempt::DeviceUserCodeEntry, now),
        RateLimitDecision::Allow
    );
    l.record_at(Attempt::DeviceUserCodeEntry, AttemptOutcome::Succeeded, now);
    assert_eq!(
        l.check_at(Attempt::DeviceUserCodeEntry, now),
        RateLimitDecision::Allow,
        "a success must not consume the failure penalty as well"
    );
}

/// The window boundary, to the nanosecond, on both sides. A limiter whose budget rolls early is a
/// limiter an attacker can pace around.
#[test]
fn the_budget_rolls_exactly_at_the_window_boundary() {
    let window = Duration::from_secs(60);
    let l = limiter(
        RateLimitConfig::default()
            .with_window(window)
            .with_device_user_code_budget(1, 0),
    );

    assert_eq!(
        l.check_at(Attempt::DeviceUserCodeEntry, at(&l, Duration::ZERO)),
        RateLimitDecision::Allow
    );
    assert_eq!(
        l.check_at(
            Attempt::DeviceUserCodeEntry,
            at(&l, window - Duration::from_nanos(1))
        ),
        RateLimitDecision::Deny,
        "one nanosecond before the boundary is still the same budget"
    );
    assert_eq!(
        l.check_at(Attempt::DeviceUserCodeEntry, at(&l, window)),
        RateLimitDecision::Allow,
        "the boundary itself starts a fresh budget"
    );
    // And a jump of many windows lands on a fresh budget too, rather than on a stale counter.
    assert_eq!(
        l.check_at(Attempt::DeviceUserCodeEntry, at(&l, window * 1_000)),
        RateLimitDecision::Allow
    );
}

/// A failure reported after the window has rolled is charged to the NEW window. The alternative,
/// dropping it, would let an attacker aim their guesses at a boundary and pay nothing for them.
#[test]
fn a_penalty_reported_after_the_roll_lands_in_the_new_window() {
    let window = Duration::from_secs(60);
    let l = limiter(
        RateLimitConfig::default()
            .with_window(window)
            .with_device_user_code_budget(10, 10),
    );
    assert_eq!(
        l.check_at(Attempt::DeviceUserCodeEntry, at(&l, Duration::ZERO)),
        RateLimitDecision::Allow
    );
    l.record_at(
        Attempt::DeviceUserCodeEntry,
        AttemptOutcome::Failed,
        at(&l, window),
    );
    assert_eq!(
        l.check_at(Attempt::DeviceUserCodeEntry, at(&l, window)),
        RateLimitDecision::Deny,
        "the penalty was charged to the window it was reported in, not discarded"
    );
}

/// One client being stuffed must not lock every other client out of the token endpoint, so the
/// client-authentication budget is per `client_id` (RFC 6749 section 2.2: not a secret).
#[test]
fn client_budgets_are_independent_of_each_other() {
    let l = limiter(RateLimitConfig::default().with_client_authentication_budget(1, 0));
    let now = at(&l, Duration::ZERO);
    let a = Attempt::ClientAuthentication { client_id: "app-a" };
    let b = Attempt::ClientAuthentication { client_id: "app-b" };

    assert_eq!(l.check_at(a, now), RateLimitDecision::Allow);
    assert_eq!(l.check_at(a, now), RateLimitDecision::Deny);
    assert_eq!(
        l.check_at(b, now),
        RateLimitDecision::Allow,
        "app-b's budget is its own"
    );
}

/// THE LOCKOUT GATE. `check` is asked before the credential is examined and is given nothing but
/// the `client_id`, which RFC 6749 section 2.2 makes public, so the impostor and the real client
/// are indistinguishable at this point. If failures could drive that one counter to its capacity
/// then 30 wrong secrets a minute — one request every two seconds, needing only a public identifier
/// — would take the client's token, introspection, revocation, device-authorization and PAR
/// endpoints away for the rest of the window.
///
/// So the failure penalty saturates at HALF the capacity, and what that buys is a PRICE rather than
/// an immunity: the attacker's failures still cost their [`ATTEMPT_COST`] out of the reserved half,
/// so the reserve's real effect is that the cheapest complete spray leaves nearly all of it. This
/// test drives the spray in the order the SERVER drives it — check, then record — because a spray
/// that only calls `record` charges the attacker nothing for the requests they had to send, and
/// would leave the reserved half looking untouched.
///
/// The companion below pins the other end: what a denial actually costs.
#[test]
fn the_cheapest_complete_failure_spray_leaves_a_client_id_on_the_air() {
    let l = limiter(RateLimitConfig::default());
    let now = at(&l, Duration::ZERO);
    let victim = Attempt::ClientAuthentication {
        client_id: "real-app",
    };
    let ceiling = l.config().client_authentication_failure_ceiling();

    // Sprayed until the failure counter SATURATES, so this is about the clamp and not about the
    // attacker running out of patience. The count is not assumed: 199 units a failure against a
    // 3000-unit ceiling is 15 failures at 2985 and a sixteenth that clamps.
    let mut sprayed = 0;
    while client_failures(&l, "real-app") < ceiling {
        assert_eq!(
            l.check_at(victim, now),
            RateLimitDecision::Allow,
            "spray request {sprayed} is itself inside the budget"
        );
        l.record_at(victim, AttemptOutcome::Failed, now);
        sprayed += 1;
    }
    assert_eq!(
        sprayed, 16,
        "the failure counter climbs by 199 and clamps at 3000, so 16 failures fill it and not 15"
    );

    let mut admitted = 0;
    while l.check_at(victim, now) == RateLimitDecision::Allow {
        admitted += 1;
    }
    assert_eq!(
        admitted,
        DEFAULT_CLIENT_AUTHENTICATION_CAPACITY / 2 - sprayed,
        "the reserved half less the 16 attempt units the spray itself spent is 2984 further \
         authentications, which is 49 a second: a per-client_id budget a cheap failure spray can \
         exhaust IS a lockout an attacker triggers for free"
    );
}

/// The price of the denial the reserve does NOT prevent, pinned so that no document can claim it is
/// dearer than it is. Past the failure ceiling every wrong secret still costs its [`ATTEMPT_COST`]
/// out of the reserved half, so an attacker who is willing to keep sending gets the client off the
/// air after exactly capacity/2 requests — 3000 a minute, or 50 a second, all of them wrong
/// secrets rather than well-formed traffic. That is a hundredfold more than the 30 requests a
/// window it would have cost with no reserve, which is what the reserve is worth: a price, not an
/// impossibility.
#[test]
fn a_within_window_denial_costs_the_whole_reserved_half_in_requests() {
    let l = limiter(RateLimitConfig::default());
    let now = at(&l, Duration::ZERO);
    let victim = Attempt::ClientAuthentication {
        client_id: "real-app",
    };

    let reserved = DEFAULT_CLIENT_AUTHENTICATION_CAPACITY / 2;
    for i in 0..reserved - 1 {
        assert_eq!(
            l.check_at(victim, now),
            RateLimitDecision::Allow,
            "wrong secret {i} of {reserved} is still admitted"
        );
        l.record_at(victim, AttemptOutcome::Failed, now);
    }
    assert_eq!(
        l.check_at(victim, now),
        RateLimitDecision::Allow,
        "request 3000 is the last one the reserved half pays for"
    );
    assert_eq!(
        l.check_at(victim, now),
        RateLimitDecision::Deny,
        "3000 wrong secrets in one window, and not 6000 requests of real volume, is what taking a \
         client_id off the air for the rest of the window costs"
    );
}

/// The same shape at the shared counter: when the map is full, every untracked `client_id` shares
/// the overflow budget, so failures sprayed at untracked identifiers could take that shared budget
/// to its capacity and refuse every untracked client for the rest of the window. The overflow
/// budget carries the same reserve, and it buys the same thing: the cheapest complete spray leaves
/// a legitimate latecomer nearly the whole reserved half.
#[test]
fn the_cheapest_complete_failure_spray_leaves_the_shared_overflow_budget_usable() {
    let l = limiter(RateLimitConfig::default().with_max_tracked_clients(1));
    let now = at(&l, Duration::ZERO);
    let ceiling = l.config().client_authentication_failure_ceiling();
    // The one tracked slot is taken, so everything below shares the overflow budget.
    assert_eq!(
        l.check_at(
            Attempt::ClientAuthentication {
                client_id: "the-tracked-one"
            },
            now
        ),
        RateLimitDecision::Allow
    );

    let mut sprayed = 0u64;
    while l.lock().overflow.failures < ceiling {
        let id = format!("sprayed-{sprayed}");
        let attempt = Attempt::ClientAuthentication { client_id: &id };
        assert_eq!(l.check_at(attempt, now), RateLimitDecision::Allow);
        l.record_at(attempt, AttemptOutcome::Failed, now);
        sprayed += 1;
    }
    assert_eq!(sprayed, 16, "same clamp, same 16 failures to reach it");

    let latecomer = Attempt::ClientAuthentication {
        client_id: "a-legitimate-latecomer",
    };
    let mut admitted = 0;
    while l.check_at(latecomer, now) == RateLimitDecision::Allow {
        admitted += 1;
    }
    assert_eq!(
        admitted,
        DEFAULT_CLIENT_AUTHENTICATION_CAPACITY / 2 - sprayed,
        "a client whose first authentication of the window arrives after the map filled shares the \
         overflow budget, and the cheapest failure spray must leave it nearly whole"
    );
}

/// The reserve removes the lockout; it must not remove the throttle. A client's budget is still
/// finite, and failures still cost 200 units each until the ceiling, so a spray still runs the
/// budget down faster than plain traffic does.
#[test]
fn the_failure_penalty_still_costs_two_hundred_units_up_to_the_ceiling() {
    assert_eq!(
        authentications_after_failures(0),
        DEFAULT_CLIENT_AUTHENTICATION_CAPACITY,
        "with no failures the capacity is a plain attempt ceiling"
    );
    assert_eq!(
        authentications_after_failures(1),
        DEFAULT_CLIENT_AUTHENTICATION_CAPACITY - 200,
        "one failure costs 1 + 199, so it is worth 200 attempts"
    );
    assert_eq!(
        authentications_after_failures(10),
        DEFAULT_CLIENT_AUTHENTICATION_CAPACITY - 2_000,
        "ten failures cost 2000 units, still short of the 3000-unit ceiling"
    );
}

/// How many further authentications one `client_id` gets after `failures` failed ones, driven check
/// THEN record, which is the order the server calls them in: a failed attempt costs `ATTEMPT_COST`
/// at check time and the failure cost on top of it.
fn authentications_after_failures(failures: u64) -> u64 {
    let l = limiter(RateLimitConfig::default());
    let now = at(&l, Duration::ZERO);
    let a = Attempt::ClientAuthentication { client_id: "app" };
    for _ in 0..failures {
        assert_eq!(l.check_at(a, now), RateLimitDecision::Allow);
        l.record_at(a, AttemptOutcome::Failed, now);
    }
    let mut n = 0;
    while l.check_at(a, now) == RateLimitDecision::Allow {
        n += 1;
    }
    n
}

/// Where the expensive failures actually stop, pinned because the module docs have to state it as a
/// number. `penalise` ADDS 199 and clamps at the ceiling, so it is not 200 a failure until 3000 and
/// then 1: fifteen failures leave the counter at 2985, the SIXTEENTH pays only the 15 units still
/// under the ceiling (16 in all, with its attempt unit), and the seventeenth and every one after it
/// pays nothing but [`ATTEMPT_COST`].
///
/// The sibling above pins the ceiling as `capacity / 200 == 15`, which uses a divisor that is not
/// the increment the code applies and so cannot see this at all.
#[test]
fn the_sixteenth_failure_costs_sixteen_units_and_the_seventeenth_costs_one() {
    let fifteen = authentications_after_failures(15);
    let sixteen = authentications_after_failures(16);
    let seventeen = authentications_after_failures(17);
    assert_eq!(
        fifteen,
        DEFAULT_CLIENT_AUTHENTICATION_CAPACITY / 2,
        "15 failures put the failure counter at 15 * 199 = 2985 and cost 15 attempt units, which \
         leaves exactly the reserved half"
    );
    assert_eq!(
        fifteen - sixteen,
        16,
        "the sixteenth failure costs 1 + the 15 units left under the 3000 ceiling, not 200 and not \
         ATTEMPT_COST"
    );
    assert_eq!(
        sixteen - seventeen,
        ATTEMPT_COST,
        "the seventeenth is the first failure that costs nothing beyond its attempt unit"
    );
}

/// The device budget is GLOBAL, and that is a documented property rather than an accident: the
/// library has no caller identity to key it on. Pinned here so nobody "fixes" it by keying on
/// something the library cannot actually see.
#[test]
fn the_device_budget_is_shared_by_every_caller() {
    let l = limiter(RateLimitConfig::default().with_device_user_code_budget(1, 0));
    let now = at(&l, Duration::ZERO);
    assert_eq!(
        l.check_at(Attempt::DeviceUserCodeEntry, now),
        RateLimitDecision::Allow
    );
    assert_eq!(
        l.check_at(Attempt::DeviceUserCodeEntry, now),
        RateLimitDecision::Deny
    );
}

// ------------------------------------------------------ the authorization-endpoint budget
//
// The SECOND per-`client_id` budget, and the one whose caller is UNAUTHENTICATED: the identifier
// `Attempt::AuthorizationRequest` is keyed on is whatever arrived in the query string
// (`server.rs` passes `request.client_id.as_deref().unwrap_or("")`). It has its own map, its own
// overflow counter and its own reserve, so each gate above is MIRRORED here rather than assumed to
// transfer from the client-authentication map to this one.

/// The shipped default's two numbers, driven rather than divided: 3000 arrivals a minute for one
/// `client_id`, or 1500 REFUSED ones.
///
/// It is not `3000 / 10`. Half of this budget is reserved for attempts exactly as client
/// authentication's is, so a refusal costs its 10 units only until the 1500-unit reserve is full
/// and 1 unit each after that, which is what makes the refusal ceiling 1500 and not 300.
#[test]
fn the_shipped_default_permits_three_thousand_authorization_requests_or_fifteen_hundred_refusals() {
    let drive = |outcome: AttemptOutcome| {
        let l = limiter(RateLimitConfig::default());
        let now = at(&l, Duration::ZERO);
        let a = Attempt::AuthorizationRequest { client_id: "app" };
        let mut n = 0;
        while l.check_at(a, now) == RateLimitDecision::Allow {
            l.record_at(a, outcome, now);
            n += 1;
        }
        n
    };
    assert_eq!(
        (
            drive(AttemptOutcome::Succeeded),
            drive(AttemptOutcome::Failed)
        ),
        (DEFAULT_AUTHORIZATION_REQUEST_CAPACITY, 1_500),
        "the documented default is 3000 authorization requests a minute for one client_id or 1500 \
         refused ones"
    );
}

/// The reserve on this budget, which exists for a sharper reason than the token plane's: nobody has
/// authenticated, so a refusal rule keyed on the `client_id` alone would let anyone take a client's
/// LOGIN PAGE off the air by walking its redirect-URI space.
///
/// The count of refusals that fills the reserve is driven off the counter rather than divided out
/// of the 10 units a refusal costs in total, because `record` adds 9 and clamps.
#[test]
fn the_authorization_refusal_penalty_saturates_at_half_the_capacity() {
    let l = limiter(RateLimitConfig::default());
    let now = at(&l, Duration::ZERO);
    let a = Attempt::AuthorizationRequest { client_id: "app" };
    let ceiling = l.config().authorization_request_failure_ceiling();
    assert_eq!(
        ceiling,
        DEFAULT_AUTHORIZATION_REQUEST_CAPACITY / 2,
        "the same divisor governs both budgets"
    );

    let mut refused = 0;
    while authorization_failures(&l, "app") < ceiling {
        assert_eq!(
            l.check_at(a, now),
            RateLimitDecision::Allow,
            "refusal {refused} is itself inside the budget"
        );
        l.record_at(a, AttemptOutcome::Failed, now);
        refused += 1;
    }
    assert_eq!(
        refused, 167,
        "9 units a refusal against a 1500-unit ceiling: 166 reach 1494 and the 167th clamps"
    );

    let mut admitted = 0;
    while l.check_at(a, now) == RateLimitDecision::Allow {
        admitted += 1;
    }
    assert_eq!(
        admitted,
        DEFAULT_AUTHORIZATION_REQUEST_CAPACITY / 2 - refused,
        "the reserved half less the 167 attempt units the walk itself spent is 1333 further \
         arrivals: a client's users can still reach its login page"
    );
}

/// Two separations at once, and the second map exists for the second of them: one client's
/// `/authorize` budget is its own, and spending it does not spend that client's CLIENT
/// AUTHENTICATION budget — so a client being hammered at the login page can still redeem the codes
/// it already issued.
#[test]
fn the_authorization_budget_is_separate_per_client_and_from_client_authentication() {
    // Set through the public fields rather than a builder, because `authorization_request_capacity`
    // has no builder and a host moving it by hand must get the same behaviour.
    let l = limiter(RateLimitConfig {
        authorization_request_capacity: 1,
        authorization_request_failure_cost: 0,
        client_authentication_capacity: 1,
        client_authentication_failure_cost: 0,
        ..RateLimitConfig::default()
    });
    let now = at(&l, Duration::ZERO);
    let authorize_a = Attempt::AuthorizationRequest { client_id: "app-a" };
    let authorize_b = Attempt::AuthorizationRequest { client_id: "app-b" };
    let authenticate_a = Attempt::ClientAuthentication { client_id: "app-a" };

    assert_eq!(l.check_at(authorize_a, now), RateLimitDecision::Allow);
    assert_eq!(l.check_at(authorize_a, now), RateLimitDecision::Deny);
    assert_eq!(
        l.check_at(authorize_b, now),
        RateLimitDecision::Allow,
        "app-b's login page is on its own budget"
    );
    assert_eq!(
        l.check_at(authenticate_a, now),
        RateLimitDecision::Allow,
        "app-a's token traffic is not spent by the traffic at its authorization endpoint"
    );
}

/// Bound 1 for the second map, and the bound an attacker reaches FIRST: this map is keyed on an
/// identifier that arrived in a query string from a caller who has authenticated nothing, so a
/// spray at `/authorize` is the cheapest way to try to grow the limiter. Capped exactly as the
/// other map is — and reported by its own accessor, because a gate watching `tracked_clients` alone
/// cannot see this map at all.
#[test]
fn the_authorization_map_never_exceeds_its_cap() {
    let l = limiter(RateLimitConfig {
        max_tracked_clients: 4,
        authorization_request_capacity: u64::MAX,
        ..RateLimitConfig::default()
    });
    let now = at(&l, Duration::ZERO);
    for i in 0..10_000 {
        let id = format!("sprayed-{i}");
        l.check_at(Attempt::AuthorizationRequest { client_id: &id }, now);
    }
    assert_eq!(l.tracked_authorization_clients(), 4);
    assert_eq!(
        l.tracked_clients(),
        0,
        "and the spray never touched the client-authentication map, which is exactly why a gate \
         that only reads `tracked_clients` proves nothing about this one"
    );
}

/// Bound 2 for the second map: bytes of key, not only entries.
#[test]
fn an_oversized_client_id_never_gets_an_authorization_entry_of_its_own() {
    let l = limiter(RateLimitConfig::default());
    let now = at(&l, Duration::ZERO);
    let huge = "z".repeat(MAX_TRACKED_CLIENT_ID_LEN + 1);
    let ok = "z".repeat(MAX_TRACKED_CLIENT_ID_LEN);

    l.check_at(Attempt::AuthorizationRequest { client_id: &huge }, now);
    assert_eq!(l.tracked_authorization_clients(), 0, "too long to store");

    l.check_at(Attempt::AuthorizationRequest { client_id: &ok }, now);
    assert_eq!(
        l.tracked_authorization_clients(),
        1,
        "exactly at the cap is still stored"
    );
}

/// Bound 3 for the second map: the roll drops its keys AND resets its overflow counter, so nothing
/// an attacker put there outlives one window.
#[test]
fn the_authorization_map_and_its_overflow_are_emptied_when_the_window_rolls() {
    let window = Duration::from_secs(60);
    let l = limiter(RateLimitConfig {
        window,
        max_tracked_clients: 1,
        ..RateLimitConfig::default()
    });
    let now = at(&l, Duration::ZERO);
    let tracked = Attempt::AuthorizationRequest { client_id: "app-a" };
    let untracked = Attempt::AuthorizationRequest {
        client_id: "past-the-cap",
    };
    assert_eq!(l.check_at(tracked, now), RateLimitDecision::Allow);
    assert_eq!(l.check_at(untracked, now), RateLimitDecision::Allow);
    l.record_at(untracked, AttemptOutcome::Failed, now);
    assert_eq!(l.tracked_authorization_clients(), 1);
    assert!(l.lock().authorization_overflow.failures > 0);

    l.check_at(Attempt::DeviceUserCodeEntry, at(&l, window));
    assert_eq!(
        l.tracked_authorization_clients(),
        0,
        "the roll drops every key in this map too"
    );
    assert_eq!(
        l.lock().authorization_overflow.failures,
        0,
        "and resets its shared counter, which is a separate field from the other map's"
    );
}

/// The authorization overflow counter fails closed on the same terms: identifiers past the cap
/// share one budget, so a spray throttles itself harder rather than escaping.
#[test]
fn authorization_identifiers_past_the_cap_share_one_budget() {
    let l = limiter(RateLimitConfig {
        max_tracked_clients: 1,
        authorization_request_capacity: 3,
        authorization_request_failure_cost: 0,
        ..RateLimitConfig::default()
    });
    let now = at(&l, Duration::ZERO);
    assert_eq!(
        l.check_at(Attempt::AuthorizationRequest { client_id: "first" }, now),
        RateLimitDecision::Allow
    );
    for i in 0..3 {
        let id = format!("overflow-{i}");
        assert_eq!(
            l.check_at(Attempt::AuthorizationRequest { client_id: &id }, now),
            RateLimitDecision::Allow,
            "overflow arrival {i}"
        );
    }
    assert_eq!(
        l.check_at(
            Attempt::AuthorizationRequest {
                client_id: "overflow-brand-new"
            },
            now
        ),
        RateLimitDecision::Deny,
        "the shared overflow budget is spent, so the spray throttles itself"
    );
    assert_eq!(
        l.check_at(Attempt::AuthorizationRequest { client_id: "first" }, now),
        RateLimitDecision::Allow,
        "the tracked client is untouched by the spray"
    );
}

// ------------------------------------------------------------------- the bound on the map
//
// `client_id` is attacker-supplied, so an unbounded map keyed on it would make the limiter a
// denial of service in its own right. These pin all three bounds.

/// Bound 1: entry count. A spray of distinct identifiers gets one shared counter past the cap, not
/// a fresh entry each.
#[test]
fn the_tracked_client_map_never_exceeds_its_cap() {
    let l = limiter(
        RateLimitConfig::default()
            .with_max_tracked_clients(4)
            .with_client_authentication_budget(u64::MAX, 0),
    );
    let now = at(&l, Duration::ZERO);
    for i in 0..10_000 {
        let id = format!("sprayed-{i}");
        l.check_at(Attempt::ClientAuthentication { client_id: &id }, now);
    }
    assert_eq!(l.tracked_clients(), 4);
}

/// The BYTES the bounding argument is stated in, pinned against the types rather than left as
/// prose: a tracked entry is a 16-byte `Box<str>` handle plus a 16-byte [`ClientBudget`] in the
/// table, and up to [`MAX_TRACKED_CLIENT_ID_LEN`] bytes of key on the heap. At the default 4096
/// that is `4096 * 128` = 512 KiB of keys plus a table of 8192 slots (a `HashMap` holds its load
/// under 7/8, so 4096 entries take the next power of two up) at 32 bytes a slot = 256 KiB, or about
/// 768 KiB a map — and there are TWO maps, which is the sentence the module docs had to gain.
#[test]
fn a_tracked_entry_costs_the_bytes_the_bounding_argument_says_it_does() {
    assert_eq!(
        std::mem::size_of::<Box<str>>(),
        16,
        "a Box<str> is a pointer and a length; a String would carry a spare capacity word"
    );
    assert_eq!(
        std::mem::size_of::<ClientBudget>(),
        16,
        "two u64 counters, which is what makes a table slot 32 bytes"
    );
    let mut map: HashMap<Box<str>, ClientBudget> = HashMap::new();
    for i in 0..DEFAULT_MAX_TRACKED_CLIENTS {
        map.insert(format!("k{i}").into_boxed_str(), ClientBudget::default());
    }
    assert!(
        map.capacity() >= DEFAULT_MAX_TRACKED_CLIENTS,
        "4096 entries fit without the table having to grow past the next power of two"
    );
}

/// Bound 2: key length. Memory has to be bounded in BYTES and not only in entries, or 4096 keys of
/// a megabyte each would be a "bounded" 4 GB.
#[test]
fn an_oversized_client_id_never_gets_an_entry_of_its_own() {
    let l = limiter(RateLimitConfig::default());
    let now = at(&l, Duration::ZERO);
    let huge = "z".repeat(MAX_TRACKED_CLIENT_ID_LEN + 1);
    let ok = "z".repeat(MAX_TRACKED_CLIENT_ID_LEN);

    l.check_at(Attempt::ClientAuthentication { client_id: &huge }, now);
    assert_eq!(l.tracked_clients(), 0, "too long to store");

    l.check_at(Attempt::ClientAuthentication { client_id: &ok }, now);
    assert_eq!(l.tracked_clients(), 1, "exactly at the cap is still stored");
}

/// Bound 3: lifetime. No key survives a window roll, so there is no eviction policy to get wrong
/// and no slow accumulation of identifiers seen once.
#[test]
fn the_tracked_client_map_is_emptied_when_the_window_rolls() {
    let window = Duration::from_secs(60);
    let l = limiter(RateLimitConfig::default().with_window(window));
    l.check_at(
        Attempt::ClientAuthentication { client_id: "app-a" },
        at(&l, Duration::ZERO),
    );
    assert_eq!(l.tracked_clients(), 1);
    l.check_at(Attempt::DeviceUserCodeEntry, at(&l, window));
    assert_eq!(
        l.tracked_clients(),
        0,
        "the roll drops every key, which costs no information since every counter was being reset"
    );
}

/// The overflow counter FAILS CLOSED: identifiers past the cap share one budget, so a spray
/// throttles itself harder rather than escaping. The alternative (evicting a live counter to make
/// room) would let an attacker RESET a budget on demand.
#[test]
fn identifiers_past_the_cap_share_one_budget_and_are_refused_together() {
    let l = limiter(
        RateLimitConfig::default()
            .with_max_tracked_clients(1)
            .with_client_authentication_budget(3, 0),
    );
    let now = at(&l, Duration::ZERO);
    // The one tracked slot goes to the first identifier seen.
    assert_eq!(
        l.check_at(Attempt::ClientAuthentication { client_id: "first" }, now),
        RateLimitDecision::Allow
    );
    // Three more distinct identifiers share the overflow budget of 3, and the fourth is refused
    // even though it has never been seen before.
    for i in 0..3 {
        let id = format!("overflow-{i}");
        assert_eq!(
            l.check_at(Attempt::ClientAuthentication { client_id: &id }, now),
            RateLimitDecision::Allow,
            "overflow attempt {i}"
        );
    }
    assert_eq!(
        l.check_at(
            Attempt::ClientAuthentication {
                client_id: "overflow-brand-new"
            },
            now
        ),
        RateLimitDecision::Deny,
        "the shared overflow budget is spent, so the spray throttles itself"
    );
    // The tracked client is untouched by the spray: it still has 2 of its own 3 units.
    assert_eq!(
        l.check_at(Attempt::ClientAuthentication { client_id: "first" }, now),
        RateLimitDecision::Allow
    );
}

// ------------------------------------------------------------------------------ arithmetic

/// A denied attempt does not advance the counter, so a sustained flood pins the budget at its
/// capacity instead of overflowing it. `u64` would take longer than the universe to wrap at any
/// real rate, but a limiter whose counter can wrap is a limiter that eventually fails OPEN, which
/// is not a failure mode worth leaving to arithmetic luck.
#[test]
fn a_denied_flood_pins_the_counter_rather_than_overflowing_it() {
    let l = limiter(RateLimitConfig::default().with_device_user_code_budget(1, u64::MAX));
    let now = at(&l, Duration::ZERO);
    assert_eq!(
        l.check_at(Attempt::DeviceUserCodeEntry, now),
        RateLimitDecision::Allow
    );
    for _ in 0..1_000 {
        l.record_at(Attempt::DeviceUserCodeEntry, AttemptOutcome::Failed, now);
        assert_eq!(
            l.check_at(Attempt::DeviceUserCodeEntry, now),
            RateLimitDecision::Deny
        );
    }
    assert_eq!(l.lock().device_user_code, 1, "clamped at the capacity");
}

/// A capacity of zero means "refuse everything", which is a legitimate way to turn an endpoint
/// off. It must not be read as "unlimited", which is the classic off-by-one that turns a throttle
/// into a no-op.
#[test]
fn a_zero_capacity_refuses_rather_than_admitting_everything() {
    let l = limiter(RateLimitConfig::default().with_device_user_code_budget(0, 0));
    assert_eq!(
        l.check_at(Attempt::DeviceUserCodeEntry, at(&l, Duration::ZERO)),
        RateLimitDecision::Deny
    );
}

/// A zero window would divide by zero when computing the window index. Clamped, not rejected, for
/// the same reason `ServerConfig::user_code_length` clamps: a misconfiguration must not become a
/// panic at the moment a user is standing in front of a device.
#[test]
fn a_zero_window_is_clamped_rather_than_dividing_by_zero() {
    let l = limiter(RateLimitConfig::default().with_window(Duration::ZERO));
    assert_eq!(l.config().window, MIN_WINDOW);
    assert_eq!(l.window_index(at(&l, Duration::ZERO)), 0);
    assert_eq!(l.window_index(at(&l, MIN_WINDOW)), 1);

    // And a config that set the field directly (they are all public) rather than going through the
    // builder is clamped at USE, so the divide is safe whichever way the host got here.
    let l = limiter(RateLimitConfig {
        window: Duration::ZERO,
        ..RateLimitConfig::default()
    });
    assert_eq!(l.window_index(at(&l, MIN_WINDOW)), 1);
}

/// An [`Instant`] before the limiter's base cannot happen (they are monotonic) but the arithmetic
/// saturates rather than panicking if one ever does, because a panic inside `check` would take the
/// whole request down.
///
/// What is actually reachable here is the DIRECTION, not a panic: `Instant::duration_since` has
/// saturated rather than panicked since Rust 1.60, so `now - self.base` cannot bring a request
/// down today whatever it is spelled as. What can still go wrong is answering the wrong window.
/// An absolute difference (`if now >= base { now - base } else { base - now }`, which is the
/// plausible way to write this while thinking about the panic that used to exist) puts a pre-base
/// instant in window three, and a limiter that jumps to a window it has no counters for hands out
/// a fresh budget. So the assertion is that it lands in window ZERO, not merely that it returns.
///
/// The instant BEFORE `base` is the whole point, so it is constructed rather than hoped for: the
/// base is moved forward past instants that already exist, which is the only way to hold one that
/// precedes it without depending on how long the machine has been up. `Instant::now() - d` would
/// be the obvious spelling and it is not usable here: it panics on a platform whose clock has not
/// yet run for `d`, which would make this test's own fixture the flake.
#[test]
fn the_window_index_saturates_rather_than_panicking() {
    let mut l = limiter(RateLimitConfig::default());
    assert_eq!(l.window_index(l.base), 0);
    assert_eq!(l.window_index(at(&l, DEFAULT_WINDOW * 3)), 3);

    let before_base = l.base;
    l.base = before_base + DEFAULT_WINDOW * 3;
    assert_eq!(
        l.window_index(before_base),
        0,
        "an instant three windows BEFORE the base must land in window 0, not panic and not wrap \
         to a far-future index that would hand out a fresh budget"
    );
    assert_eq!(
        l.window_index(before_base + DEFAULT_WINDOW),
        0,
        "still before the base, so still window 0"
    );

    // And through the endpoint the host actually calls, since a panic there is the one that takes
    // a request down with it.
    assert_eq!(
        l.check_at(Attempt::DeviceUserCodeEntry, before_base),
        RateLimitDecision::Allow
    );
    l.record_at(
        Attempt::DeviceUserCodeEntry,
        AttemptOutcome::Failed,
        before_base,
    );
}

/// A poisoned mutex must not turn the limiter into a source of panics: a panic elsewhere in the
/// host's process would otherwise take the token endpoint down with it.
#[test]
fn a_poisoned_lock_is_recovered_from_rather_than_propagated() {
    let l = std::sync::Arc::new(limiter(RateLimitConfig::default()));
    let poisoner = std::sync::Arc::clone(&l);
    let _ = std::thread::spawn(move || {
        let _guard = poisoner.lock();
        panic!("poison the limiter's mutex");
    })
    .join();

    assert_eq!(
        l.check_at(Attempt::DeviceUserCodeEntry, at(&l, Duration::ZERO)),
        RateLimitDecision::Allow,
        "the limiter still answers after its mutex was poisoned"
    );
}

// ------------------------------------------------------- per-client_id capacity overrides

/// THE RESOURCE-SERVER GATE. 0.9.2 opened RFC 7662 introspection to a resource server registered
/// in `ServerConfig::resource_servers`, and an introspection is one client authentication charged
/// to that resource server's `client_id`. A resource server introspects ONCE PER PROTECTED API
/// CALL, so the 6000-a-minute default — sized for a client's own token traffic — is now the
/// protected resource's request ceiling.
///
/// The guidance that follows from that is "raise the budget for the resource server", and it is
/// only safe if it can be said about ONE registration: raising
/// `client_authentication_capacity` globally multiplies every OTHER client's wrong-secret volume,
/// and each wrong secret buys the host's argon2id. So the override must lift the named id and
/// leave the rest exactly where they were.
#[test]
fn an_override_raises_one_client_ids_budget_and_nobody_elses() {
    let l = limiter(
        RateLimitConfig::default()
            .with_client_authentication_budget(2, 0)
            .with_client_authentication_capacity_for("resource-server", 5),
    );
    let now = at(&l, Duration::ZERO);
    let rs = Attempt::ClientAuthentication {
        client_id: "resource-server",
    };
    let app = Attempt::ClientAuthentication { client_id: "app" };

    let mut admitted = 0;
    while l.check_at(rs, now) == RateLimitDecision::Allow {
        admitted += 1;
    }
    assert_eq!(
        admitted, 5,
        "the resource server gets the budget it was given"
    );

    let mut admitted = 0;
    while l.check_at(app, now) == RateLimitDecision::Allow {
        admitted += 1;
    }
    assert_eq!(
        admitted, 2,
        "every other client id is still on the configured capacity"
    );
}

/// The reserve moves WITH the override. `client_authentication_failure_ceiling` is derived from
/// the capacity at every use precisely so that a host lowering the capacity gets a reserve that
/// moved with it; an override that raised the capacity but left the reserve frozen at the global
/// half would hand the raised registration a failure penalty that saturates after a fraction of
/// its budget, which is the "IT IS NOT A LOCKOUT" property read the other way round.
#[test]
fn an_override_moves_the_failure_reserve_with_the_capacity() {
    let config = RateLimitConfig::default()
        .with_client_authentication_budget(100, 9)
        .with_client_authentication_capacity_for("resource-server", 1000);
    assert_eq!(
        config.client_authentication_failure_ceiling_for("resource-server"),
        500
    );
    assert_eq!(config.client_authentication_failure_ceiling_for("app"), 50);

    let l = limiter(config);
    let now = at(&l, Duration::ZERO);
    let rs = Attempt::ClientAuthentication {
        client_id: "resource-server",
    };
    while client_failures(&l, "resource-server") < 500 {
        assert_eq!(l.check_at(rs, now), RateLimitDecision::Allow);
        l.record_at(rs, AttemptOutcome::Failed, now);
    }
    assert_eq!(
        client_failures(&l, "resource-server"),
        500,
        "the penalty clamps at half the OVERRIDDEN capacity, not at half the global one"
    );
}

/// An override is a statement about ONE registration, so it must not reach the SHARED overflow
/// counter. An identifier that did not get a counter of its own — because the map is full, or
/// because it is longer than `MAX_TRACKED_CLIENT_ID_LEN` — is charged against a budget every
/// other untracked identifier shares, and applying a raised capacity there would raise it for the
/// spray that filled the map. The overflow counter FAILS CLOSED and stays that way.
#[test]
fn an_override_never_raises_the_shared_overflow_budget() {
    let l = limiter(
        RateLimitConfig::default()
            .with_max_tracked_clients(1)
            .with_client_authentication_budget(2, 0)
            .with_client_authentication_capacity_for("resource-server", 1000),
    );
    let now = at(&l, Duration::ZERO);
    // The one tracked slot goes to the first identifier seen, so the resource server arrives to a
    // full map and shares the overflow counter with everyone else.
    assert_eq!(
        l.check_at(Attempt::ClientAuthentication { client_id: "first" }, now),
        RateLimitDecision::Allow
    );
    let rs = Attempt::ClientAuthentication {
        client_id: "resource-server",
    };
    let mut admitted = 0;
    while l.check_at(rs, now) == RateLimitDecision::Allow {
        admitted += 1;
        assert!(
            admitted <= 8,
            "the overflow budget is not the override's 1000"
        );
    }
    assert_eq!(
        admitted, 2,
        "an untracked identifier is charged the SHARED capacity whatever its override says"
    );
}
