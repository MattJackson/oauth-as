// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for the part of the `jwt` module that a caller outside the crate cannot reach.
//!
//! `JwtError` is returned by [`super::JwtConfig::sign_access_token`], which cannot fail for the
//! shapes this crate builds (a struct of strings and numbers always serializes, and ECDSA over a
//! loaded key always signs). The one path that CAN produce one is `unix_seconds`, which is
//! `pub(crate)`, so its refusal and its message are only testable from in here. The rest of the
//! module's surface is driven from `tests/jwt.rs` and `tests/jwt_key_identity.rs`.

use super::*;
use std::time::Duration;

/// RFC 7519 section 2: a `NumericDate` counts seconds SINCE the epoch, so an instant before the
/// epoch has no representation at all. Refusing is the only correct answer; wrapping or saturating
/// would mint a token whose `iat` and `exp` are a fiction, and `exp` in particular is the only
/// thing standing between a leaked token and an unbounded lifetime.
#[test]
fn a_clock_before_the_epoch_is_refused_with_a_message_a_host_can_act_on() {
    let before = UNIX_EPOCH
        .checked_sub(Duration::from_secs(1))
        .expect("SystemTime can represent one second before the epoch");
    let err = unix_seconds(before).expect_err("a pre-epoch instant has no NumericDate");

    // The message is the host's only diagnostic: the wire gets an opaque `server_error`, by
    // design, so a silent or empty message leaves nobody able to find the misconfigured clock.
    let text = err.to_string();
    assert!(text.contains("JWT signing error"), "{text}");
    assert!(text.contains("clock is before the Unix epoch"), "{text}");

    // The epoch itself is representable and is zero, so the refusal is about being BEFORE it.
    assert_eq!(
        unix_seconds(UNIX_EPOCH).expect("the epoch is second zero"),
        0
    );
    assert_eq!(
        unix_seconds(UNIX_EPOCH + Duration::from_secs(1_700_000_000)).expect("a normal instant"),
        1_700_000_000
    );
}
