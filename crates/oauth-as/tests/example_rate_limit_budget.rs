// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The device user code budget the SHIPPED example installs, gated as a number.
//!
//! `examples/` goes to crates.io and `examples/production_server.rs` says of itself "This file is
//! the one to copy", so its rate limiter configuration carries this crate's authority in exactly
//! the way the library's own defaults do. It shipped for a release configured as
//! `RateLimitConfig::default().with_window(Duration::from_secs(30))` under a comment claiming
//! "the budgets themselves are left at the crate's defaults". They were not: a budget is the PAIR
//! (capacity, window), `with_window` moves only the window, and 200 units per 30 seconds is
//! DOUBLE the wrong-code rate `oauth_as::rate_limit`'s RFC 8628 section 5.1 arithmetic is derived
//! from. Nothing in the tree noticed, because nothing in the tree stated the resulting rate as a
//! number.
//!
//! This file states it. Two halves, and both are needed:
//!
//! 1. THE ARITHMETIC, driven through the real limiter: the crate default admits exactly 20 failed
//!    [`Attempt::DeviceUserCodeEntry`] per window and the window is exactly 60 seconds, so the
//!    ceiling is 20 wrong codes A MINUTE.
//! 2. THE EXAMPLE ACTUALLY INSTALLS IT. An example cannot be linked against, so this reads its
//!    source. Crude, and it is the only thing that connects half 1 to the file a host copies: a
//!    future edit that reintroduces a lone `with_window` on the limiter config fails here.

use std::time::Duration;

use oauth_as::events::{Attempt, AttemptOutcome, RateLimitDecision, RateLimiter};
use oauth_as::rate_limit::{FixedWindowRateLimiter, RateLimitConfig, ATTEMPT_COST};

/// The example a host is told to copy, read as text. `include_str!` is relative to this file.
const PRODUCTION_EXAMPLE: &str = include_str!("../examples/production_server.rs");

/// Every wrong code entry the limiter will admit before it starts refusing, inside one window.
///
/// Charged the way the server charges it: `check` before the code is looked at, `record` with
/// [`AttemptOutcome::Failed`] after it fails to match. A `Deny` ends the count, and the refused
/// attempt is NOT counted because it never reached the store.
fn failures_admitted_in_one_window(limiter: &FixedWindowRateLimiter) -> u64 {
    // Bounded so a limiter that never denies fails this test rather than hanging it.
    for admitted in 0..10_000 {
        if limiter.check(Attempt::DeviceUserCodeEntry) == RateLimitDecision::Deny {
            return admitted;
        }
        limiter.record(Attempt::DeviceUserCodeEntry, AttemptOutcome::Failed);
    }
    panic!("the limiter admitted 10000 failed user code entries in one window");
}

/// RFC 8628 section 5.1: the ceiling the crate's derivation is written against, as a rate.
#[test]
fn crate_default_admits_twenty_wrong_user_codes_a_minute() {
    let config = RateLimitConfig::default();
    let limiter = FixedWindowRateLimiter::with_config(config.clone());

    let per_window = failures_admitted_in_one_window(&limiter);
    assert_eq!(
        per_window,
        config.device_user_code_capacity / (ATTEMPT_COST + config.device_user_code_failure_cost),
        "the admitted count must be the capacity divided by the cost of one failure"
    );

    // The rate, which is the thing the arithmetic in `oauth_as::rate_limit`'s module docs is
    // about. Stated as a division rather than asserted per window so that moving EITHER half of
    // the budget is visible here.
    let windows_per_minute = 60_000 / u64::try_from(config.window.as_millis()).expect("window");
    assert_eq!(
        per_window * windows_per_minute,
        20,
        "the default device budget must admit 20 WRONG user code entries per minute per process \
         (200 units per 60 second window, each failure costing 1 + 9); that is the number the \
         600 second code lifetime and the expected-hit odds in `oauth_as::rate_limit` are \
         derived from"
    );
    assert_eq!(
        config.window,
        Duration::from_secs(60),
        "the default window is 60 seconds, which is what makes the budgets readable as per-minute"
    );
}

/// The shipped example must install THAT budget, not a rate it moved by half a pair.
#[test]
fn production_example_installs_the_derived_device_budget() {
    let squashed: String = PRODUCTION_EXAMPLE
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    assert!(
        squashed.contains("FixedWindowRateLimiter::with_config(RateLimitConfig::default()"),
        "examples/production_server.rs must install the crate's derived budgets unmodified"
    );
    assert!(
        !squashed.contains("RateLimitConfig::default().with_window("),
        "examples/production_server.rs moved the rate limiter's WINDOW without moving its \
         CAPACITIES. A budget is the pair, so this halves the window and doubles every per-minute \
         ceiling in `oauth_as::rate_limit`'s derivation while appearing to leave the defaults \
         alone. Move both halves with `with_device_user_code_budget`, or move neither"
    );
}
