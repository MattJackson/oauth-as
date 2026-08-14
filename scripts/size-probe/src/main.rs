// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The size probe binary.
//!
//! Built twice by `scripts/size-report.sh` for every row of the report: once with the feature set
//! under test and once without `lib`, which is the matched baseline. The difference between the
//! two linked binaries' code and data sections is what oauth-as costs.
//!
//! # Why it EXERCISES rather than merely referencing
//!
//! With `lto = "fat"` the linker deletes everything nothing reaches. A probe that only names a
//! type, or that enables a feature without calling into it, measures the feature at close to
//! zero and reports a lie. That is not hypothetical: an early hand measurement of `http,jwt`
//! read identical to `jwt` alone, because the probe never dispatched an HTTP request.
//!
//! So every plane below CALLS the surface it is measuring and feeds the result into
//! [`std::hint::black_box`], and the process exit code depends on the accumulator, so nothing on
//! the path is dead. What each row of the report means is therefore "what a host pays when it
//! uses this feature", not "what a host pays for enabling it".

// The accumulator is deliberately observable: `std::process::exit` on a value derived from every
// plane is what stops the optimizer from proving the work unnecessary.
fn main() {
    // Seeded from the environment rather than a constant, so no plane can be constant-folded at
    // compile time from a known input. `mut` is unused in the BASELINE build, which links no
    // plane at all, and that build is the whole point of the baseline.
    #[allow(unused_mut)]
    let mut acc: u64 = std::env::args().count() as u64;

    #[cfg(feature = "hostdeps")]
    {
        acc = acc.wrapping_add(hostdeps::exercise());
    }

    #[cfg(feature = "lib")]
    {
        acc = acc.wrapping_add(exercise::run());
    }

    // Never actually taken (the accumulator is at least 1), but the compiler cannot know that,
    // so `acc` and everything that produced it stays alive.
    if std::hint::black_box(acc) == u64::MAX {
        std::process::exit(2);
    }
}

#[cfg(feature = "hostdeps")]
mod hostdeps;

#[cfg(feature = "lib")]
mod blockon;
#[cfg(feature = "lib")]
mod exercise;
#[cfg(any(
    feature = "f-mtls",
    feature = "f-par",
    feature = "f-jar",
    feature = "f-rar",
    feature = "f-dpop",
    feature = "f-client-assertion",
    feature = "f-consent",
    feature = "f-token-exchange",
    feature = "f-resource-metadata",
    feature = "f-cimd",
    feature = "f-test-util",
))]
mod exercise_features;
#[cfg(feature = "f-http")]
mod exercise_http;
#[cfg(feature = "f-jwt")]
mod exercise_jwt;
