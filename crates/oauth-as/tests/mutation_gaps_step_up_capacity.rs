// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A single allocation gate on [`oauth_as::consent::step_up_challenge`]'s capacity hint.
//!
//! Survivor of the `--all-features` mutation sweep:
//!
//! ```text
//! consent.rs replace + with * in step_up_challenge
//! ```
//!
//! The expression is the `String::with_capacity` hint
//! `acr_values.iter().map(|a| a.len() + 3).sum()`. A capacity hint produces IDENTICAL bytes whether
//! it is right or wrong, so the challenge string is the same under the mutation and no content
//! assertion can tell them apart — which is why the sibling `+ -> -` mutant was killed by a panic
//! (`usize` underflow) rather than by output, and why the crate's own comment on that test guessed
//! this `*` sibling was equivalent.
//!
//! It is NOT equivalent. The hint decides whether the buffer is reserved once or grows, and buffer
//! growth is a `realloc` the counting allocator sees. The real `+ 3` per class reserves enough for
//! the whole header (the `", acr_values=\""` prefix, the inter-class spaces, the closing quote) so
//! that a challenge naming several short classes lands in ONE allocation. The `* 3` mutant
//! under-reserves for short class names — for a one-character class it reserves three bytes where
//! the class plus its separator needs more — so the buffer must grow, adding a second allocation.
//! Ten single-character classes is a value `AuthenticationRequirement::acr_values` can hold (a host
//! builds it and it is not bounded there), and it is the difference between a single reservation and
//! a reservation plus a growth: exactly what the counting allocator is here to catch.
//!
//! # Why this is its own test binary with one `#[test]`
//!
//! The counting allocator is a `#[global_allocator]`, so its counters are process wide. As
//! `tests/allocation.rs` documents at length, the reliable way to measure a one-allocation
//! difference is a binary whose only `#[test]` is the measurement, so the harness has no other
//! thread to schedule allocations onto the same counters mid-measurement.

#![cfg(feature = "consent")]

#[path = "support/alloc.rs"]
mod alloc;

use alloc::{measure, CountingAllocator, TEST_LOCK};
use oauth_as::consent::step_up_challenge;

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator;

#[test]
fn step_up_challenge_reserves_its_buffer_in_a_single_allocation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Ten one-character classes. Built OUTSIDE the measured window so only the challenge buffer's
    // own allocations are counted. Short names are the case the `* 3` hint under-reserves for; ten
    // of them give the real `+ 3` hint comfortable headroom (its reservation exceeds the written
    // length by six bytes) while leaving the mutant several bytes short, so the real code reserves
    // once and the mutant is forced to grow.
    let acr: Vec<Box<str>> = (0..10).map(|_| Box::<str>::from("a")).collect();

    let (challenge, delta) = measure(|| step_up_challenge("Bearer", &acr, None));

    // The output is identical either way; assert it is well formed so a future edit that stops
    // emitting the classes cannot pass this gate by allocating less.
    assert!(
        challenge.contains(r#"acr_values="a a a a a a a a a a""#),
        "all ten classes must reach the challenge: {challenge:?}"
    );
    assert!(
        challenge.contains("insufficient_user_authentication"),
        "RFC 9470 s3: {challenge:?}"
    );

    assert_eq!(
        delta.allocs, 1,
        "step_up_challenge must size its buffer up front and allocate exactly once; the `* 3` \
         capacity hint under-reserves for short class names and forces the buffer to grow, which \
         is a second allocation the counting allocator sees even though the string it produces is \
         byte-for-byte identical (allocs observed: {})",
        delta.allocs
    );
}
