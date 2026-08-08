// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for [`crate::events`], kept out of the implementation file. These reach the private
//! inside of [`Hooks`], which is the whole point: the module's cost promise is a claim about that
//! private representation, and from outside the crate it can only be measured, not inspected.

use super::*;

/// The slot allocates NOTHING until a host installs something. The boxed [`Installed`] struct is
/// the only allocation this module can make, and this pins that it is not made up front: a host
/// that constructs a server and installs no seams carries a null pointer, not an empty struct on
/// the heap.
#[test]
fn nothing_is_allocated_until_something_is_installed() {
    let hooks = Hooks::new();
    assert!(
        hooks.0.is_none(),
        "an empty Hooks must hold no boxed inner struct"
    );
    assert!(!hooks.is_observed());

    let mut hooks = hooks;
    hooks.install_rate_limiter(Box::new(AllowAll));
    assert!(
        hooks.0.is_some(),
        "installing a seam must allocate the inner struct"
    );
    // A rate limiter is not an event sink: `is_observed` gates event-only clones at call sites, so
    // installing an unrelated seam must not switch them on.
    assert!(
        !hooks.is_observed(),
        "is_observed must answer for the EVENT sink specifically"
    );
}

/// Installing twice replaces rather than accumulating, so a host cannot end up with two sinks
/// double-recording, and the slot stays exactly one box wide.
#[test]
fn installing_a_second_sink_replaces_the_first() {
    let mut hooks = Hooks::new();
    hooks.install_event_sink(Box::new(NullSink));
    hooks.install_event_sink(Box::new(NullSink));
    let installed = hooks.0.as_ref().expect("something is installed");
    assert!(installed.events.is_some());
    assert!(installed.rate_limiter.is_none());
    assert!(installed.secret_verifier.is_none());
}

/// [`Hooks::emit`] must not build the event when no sink is installed. A panicking closure is a
/// stronger statement of that than any counter: if the closure runs at all, this test aborts.
#[test]
fn an_absent_sink_never_runs_the_event_closure() {
    let hooks = Hooks::new();
    hooks.emit(|| panic!("the event closure must not run without a sink"));

    // Same again with an unrelated seam installed, so the inner box existing is not mistaken for
    // a sink existing.
    let mut hooks = Hooks::new();
    hooks.install_rate_limiter(Box::new(AllowAll));
    hooks.emit(|| panic!("the event closure must not run without a sink"));
}

/// An absent limiter answers [`RateLimitDecision::Allow`]. Documented here as a test because the
/// alternative (failing closed) would be defensible in isolation and is the wrong call for a
/// library: refusing traffic on behalf of a host that has expressed no policy breaks every
/// existing deployment on upgrade.
#[test]
fn an_absent_limiter_allows() {
    let hooks = Hooks::new();
    assert_eq!(
        hooks.check(Attempt::ClientAuthentication { client_id: "c" }),
        RateLimitDecision::Allow
    );
    hooks.record(
        Attempt::ClientAuthentication { client_id: "c" },
        AttemptOutcome::Succeeded,
    );
}

struct NullSink;

impl EventSink for NullSink {
    fn on_event(&self, _event: Event<'_>) {}
}

struct AllowAll;

impl RateLimiter for AllowAll {
    fn check(&self, _attempt: Attempt<'_>) -> RateLimitDecision {
        RateLimitDecision::Allow
    }
}
