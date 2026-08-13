// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for the part of the `jwt` module that a caller outside the crate cannot reach.
//!
//! `JwtError` is returned by [`super::JwtConfig::sign_access_token`], which cannot fail for the
//! shapes this crate builds (a struct of strings and numbers always serializes, and ECDSA over a
//! loaded key always signs). The one path that CAN produce one is `unix_seconds`, which is
//! `pub(crate)`, so its refusal and its message are only testable from in here. The rest of the
//! module's surface is driven from `tests/jwt.rs` and `tests/jwt_key_identity.rs`.
//!
//! [`super::CompactJws::reject_unknown_crit`] is also driven directly from here, and for a
//! different reason: its three refusing arms are reached from four verifiers (DPoP proofs, client
//! assertions, RFC 9101 request objects), but only through headers those verifiers will build, so
//! the NON-ARRAY arm — a `crit` that is a string, a number, a null — is not reachable by any route
//! the end-to-end tests take. A check nothing exercises is a check nobody would notice being
//! deleted.

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

/// One JWS with the given protected header, over a fixed payload and an unchecked signature.
///
/// `reject_unknown_crit` reads the header and nothing else, so a real signature would only make the
/// fixture harder to read: these tests are about what the parser refuses BEFORE anybody verifies.
fn jws_with_header(header: &str) -> String {
    compact_jws(header.as_bytes(), br#"{"iss":"someone"}"#, |_| {
        vec![0u8; 64]
    })
}

/// RFC 7515 section 4.1.11 in full, arm by arm, because each arm is a separate refusal and the
/// interesting one is unreachable from any verifier's own tests.
///
/// The member's meaning is that the producer REQUIRES the recipient to understand the named header
/// parameters. This verifier implements no JWS extension, so:
///
/// - a `crit` naming anything is a refusal (RFC 8725 section 3.10 names this as an attack surface:
///   `"crit":["b64"]` with `"b64":false` means the payload was signed unencoded, so a verifier that
///   ignores the member verifies a different message from the one that was signed);
/// - an EMPTY `crit` is refused by 4.1.11 itself, whatever the recipient implements. A verifier that
///   only scanned for unrecognised names would accept it, having found none;
/// - a `crit` that is not an ARRAY is refused too. 4.1.11 fixes the type, and a header that gets it
///   wrong is one this server cannot evaluate the requirement of — which must mean refuse, not
///   ignore. `"crit":"b64"` is exactly what a producer writing the member by hand emits, and a
///   verifier matching only on the array shape would fall through it to a happy accept.
#[test]
fn a_crit_header_is_refused_in_every_shape_rfc_7515_allows_it_to_arrive_in() {
    // No `crit` at all: the ordinary case, and the only accepting arm.
    let ok = jws_with_header(r#"{"alg":"ES256"}"#);
    assert!(CompactJws::parse(&ok)
        .expect("a well formed JWS")
        .reject_unknown_crit()
        .is_ok());

    for (header, expected) in [
        (
            r#"{"alg":"ES256","crit":["b64"],"b64":false}"#,
            "names an extension this server does not implement",
        ),
        (r#"{"alg":"ES256","crit":[]}"#, "empty crit"),
        // The two arms no verifier's own tests reach.
        (r#"{"alg":"ES256","crit":"b64"}"#, "not an array"),
        (r#"{"alg":"ES256","crit":null}"#, "not an array"),
    ] {
        let token = jws_with_header(header);
        let error = CompactJws::parse(&token)
            .expect("the header is well formed JSON, so the refusal is about crit")
            .reject_unknown_crit()
            .expect_err(header);
        assert!(
            error.to_string().contains(expected),
            "{header} was refused as {error}, which does not say {expected}"
        );
    }
}
