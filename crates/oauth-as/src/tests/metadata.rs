// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for [`crate::metadata`], kept out of the implementation file. These reach
//! private items, so they live in the crate rather than in `tests/`.

use super::*;

#[test]
fn issuer_join_never_doubles_the_slash() {
    assert_eq!(
        under_issuer("https://as.example.com/", "/token"),
        "https://as.example.com/token"
    );
    assert_eq!(
        under_issuer("https://as.example.com", "/token"),
        "https://as.example.com/token"
    );
}
