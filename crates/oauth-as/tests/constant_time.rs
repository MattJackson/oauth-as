// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Black-box property tests for [`oauth_as::ClientAuth::verify`]'s secret comparison (C9, C10).
//!
//! `constant_time_eq` itself is private to `client.rs`, so these tests, which live outside the
//! crate like any other host, drive it through the one public entry point that reaches it:
//! `ClientAuth::ConfidentialSecret { .. }.verify(presented)`. The property under test is simple
//! and absolute: `verify` must agree with ordinary `==` on every pair of inputs, for every length
//! and every byte pattern tried, including the padded-length case that used to defeat the
//! accumulator (C9) and the empty-secret edge.

use oauth_as::ClientAuth;

fn verify_agrees_with_eq(secret: &str, presented: &str) {
    let auth = ClientAuth::ConfidentialSecret {
        secret: secret.to_string(),
    };
    let want = secret == presented;
    let got = auth.verify(Some(presented));
    assert_eq!(
        got, want,
        "verify({presented:?}) against registered secret {secret:?}: got {got}, want {want}"
    );
}

#[test]
fn c9_padded_length_wraparound_is_not_treated_as_equal() {
    // The exact case from the audit: a wrong secret padded with 65536 NUL bytes must not verify.
    // 65536 was the smallest padding that defeated the old accumulator, because it only folded in
    // bits 0..=15 of (a.len() ^ b.len()); this checks the fix holds at that boundary and one past
    // it, not only "some large padding".
    let secret = "hunter2";
    for pad in [65536usize, 65536 + 1, 2 * 65536, 65536 * 3] {
        let presented = format!("{secret}{}", "\0".repeat(pad));
        verify_agrees_with_eq(secret, &presented);
    }
}

#[test]
fn empty_secret_and_empty_presented() {
    verify_agrees_with_eq("", "");
    verify_agrees_with_eq("", "x");
    verify_agrees_with_eq("nonempty", "");
}

#[test]
fn property_agrees_with_eq_across_lengths_and_contents() {
    // A small deterministic sweep rather than a proper QuickCheck dependency (the crate's
    // dependency policy is deliberately tiny, see Cargo.toml). Covers: equal inputs at many
    // lengths, one-byte differences at the start/middle/end, differing lengths with a shared
    // prefix, and differing lengths with no relationship at all.
    let lengths = [0usize, 1, 2, 7, 8, 16, 31, 32, 33, 64, 100, 257];
    for &len in &lengths {
        let secret: String = (0..len).map(|i| (b'a' + (i % 26) as u8) as char).collect();

        // Exactly equal.
        verify_agrees_with_eq(&secret, &secret);

        if len > 0 {
            // Flip the first byte.
            let mut mutated = secret.clone().into_bytes();
            mutated[0] ^= 1;
            verify_agrees_with_eq(&secret, &String::from_utf8(mutated).unwrap());

            // Flip the last byte.
            let mut mutated = secret.clone().into_bytes();
            let last = mutated.len() - 1;
            mutated[last] ^= 1;
            verify_agrees_with_eq(&secret, &String::from_utf8(mutated).unwrap());

            // Flip a middle byte.
            let mut mutated = secret.clone().into_bytes();
            mutated[len / 2] ^= 1;
            verify_agrees_with_eq(&secret, &String::from_utf8(mutated).unwrap());
        }

        // Shared prefix, presented shorter by one.
        if len > 0 {
            verify_agrees_with_eq(&secret, &secret[..len - 1]);
        }

        // Shared prefix, presented longer by one arbitrary byte.
        let mut longer = secret.clone();
        longer.push('z');
        verify_agrees_with_eq(&secret, &longer);

        // Totally unrelated content at the same length.
        let unrelated: String = (0..len).map(|_| '_').collect();
        verify_agrees_with_eq(&secret, &unrelated);
    }
}

#[test]
fn public_client_never_verifies_a_presented_secret() {
    // Not the C9/C10 defect, but the same call boundary: a public client has nothing to compare
    // against, so any presented secret, including one that happens to equal some other string, is
    // always rejected.
    let auth = ClientAuth::Public;
    assert!(!auth.verify(Some("")));
    assert!(!auth.verify(Some("anything")));
    assert!(auth.verify(None));
}
