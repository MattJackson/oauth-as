// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for [`crate::client`], kept out of the implementation file. These reach
//! private items, so they live in the crate rather than in `tests/`.

use super::*;

#[test]
fn public_client_rejects_a_presented_secret() {
    let auth = ClientAuth::Public;
    assert!(auth.verify(None));
    assert!(!auth.verify(Some("anything")));
}

#[test]
fn confidential_client_requires_the_exact_secret() {
    let auth = ClientAuth::ConfidentialSecret {
        secret: "s3cret".into(),
    };
    assert!(auth.verify(Some("s3cret")));
    assert!(!auth.verify(Some("s3creT")));
    assert!(!auth.verify(Some("s3cret-and-more")));
    assert!(!auth.verify(Some("")));
    assert!(!auth.verify(None));
}

#[test]
fn c9_length_wraparound_no_longer_compares_unequal_secrets_as_equal() {
    // GREEN, post-fix. Before the fix (see git history / the audit report), this exact case was
    // observed to PASS as `constant_time_eq(&short, &long) == true`: the old accumulator only
    // folded bits 0..=15 of (a.len() ^ b.len()) into the check, and missing bytes were treated as
    // 0 via unwrap_or(0), so padding the shorter input out to a length whose difference is an
    // exact multiple of 65536 defeated both the length check and the byte loop.
    // "hunter2" vs "hunter2" + 65536 NUL bytes must NOT be equal, and now correctly is not: the
    // SHA-256-digest-first comparison has no length-dependent loop bound and no truncated length
    // check for this padding to exploit.
    let short = b"hunter2".to_vec();
    let mut long = short.clone();
    long.extend(vec![0u8; 65536]);
    assert_eq!(
        short.len() ^ long.len(),
        65536,
        "test setup: needs an exact 2^16 length gap"
    );
    assert!(
        !constant_time_eq(&short, &long),
        "unequal secrets must never compare equal, regardless of padding"
    );
}

#[test]
fn c13_confidential_secret_debug_format_is_redacted() {
    let auth = ClientAuth::ConfidentialSecret {
        secret: "top-secret-value".into(),
    };
    let printed = format!("{auth:?}");
    assert!(
        !printed.contains("top-secret-value"),
        "debug format leaked the secret: {printed}"
    );
    assert!(
        printed.contains("[redacted]"),
        "debug format should say the secret was redacted: {printed}"
    );
}

#[test]
fn c13_public_client_debug_format_is_unaffected() {
    // Nothing secret to redact on the Public variant; Debug should still say what it is.
    assert_eq!(format!("{:?}", ClientAuth::Public), "Public");
}

#[test]
fn constant_time_eq_agrees_with_eq() {
    let cases: &[(&[u8], &[u8], bool)] = &[
        (b"", b"", true),
        (b"a", b"", false),
        (b"", b"a", false),
        (b"abc", b"abc", true),
        (b"abc", b"abd", false),
        (b"abc", b"abcd", false),
    ];
    for (a, b, want) in cases {
        assert_eq!(constant_time_eq(a, b), *want, "{:?} vs {:?}", a, b);
    }
}
