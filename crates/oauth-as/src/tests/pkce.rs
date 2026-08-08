// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for [`crate::pkce`], kept out of the implementation file. These reach
//! private items, so they live in the crate rather than in `tests/`.

use super::*;

#[test]
fn verifier_grammar_bounds() {
    let ok = "a".repeat(43);
    assert!(verifier_is_valid(&ok));
    assert!(verifier_is_valid(&"a".repeat(128)));
    assert!(!verifier_is_valid(&"a".repeat(42)), "below 43 chars");
    assert!(!verifier_is_valid(&"a".repeat(129)), "above 128 chars");
    assert!(
        !verifier_is_valid(&format!("{}+", "a".repeat(43))),
        "'+' outside unreserved set"
    );
}

#[test]
fn challenge_shape() {
    let c = code_challenge_s256(&"x".repeat(43));
    assert_eq!(
        c.len(),
        43,
        "SHA-256 is 32 bytes; unpadded base64url of 32 bytes is 43 chars"
    );
    assert!(!c.contains('='), "no padding per RFC 7636 appendix A");
}
