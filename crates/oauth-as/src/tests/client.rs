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
