// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for [`crate::server`], kept out of the implementation file. These reach
//! private items, so they live in the crate rather than in `tests/`.

use super::*;

#[test]
fn user_codes_use_the_alphabet_and_are_unbiased_in_shape() {
    let code = random_user_code(8);
    assert_eq!(code.len(), 8);
    assert!(code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)));
}

#[test]
fn display_form_hyphenates_even_lengths() {
    assert_eq!(display_user_code("WDJBMJHT"), "WDJB-MJHT");
    assert_eq!(display_user_code("ABCDEF"), "ABC-DEF");
    assert_eq!(display_user_code("ABCDE"), "ABCDE");
}

#[test]
fn random_hex_has_the_stated_entropy_width() {
    let h = random_hex(32);
    assert_eq!(h.len(), 64);
    assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(random_hex(32), random_hex(32));
}
