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
        DEFAULT_CLIENT_AUTHENTICATION_CAPACITY / cost_of_a_failed_auth,
        30,
        "the module docs derive the RFC 9700 s4.13 posture from 30 failed auths per client"
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

    // And a config built by field assignment (the struct's fields are public) rather than through
    // the builder is clamped at USE, so the divide is safe whichever way the host got here.
    let mut cfg = RateLimitConfig::default();
    cfg.window = Duration::ZERO;
    let l = limiter(cfg);
    assert_eq!(l.window_index(at(&l, MIN_WINDOW)), 1);
}

/// An [`Instant`] before the limiter's base cannot happen (they are monotonic) but the arithmetic
/// saturates rather than panicking if one ever does, because a panic inside `check` would take the
/// whole request down.
#[test]
fn the_window_index_saturates_rather_than_panicking() {
    let l = limiter(RateLimitConfig::default());
    assert_eq!(l.window_index(l.base), 0);
    assert_eq!(l.window_index(at(&l, DEFAULT_WINDOW * 3)), 3);
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
