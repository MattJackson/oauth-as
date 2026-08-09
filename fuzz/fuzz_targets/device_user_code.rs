// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! `normalize_user_code`, RFC 8628 section 6.1.
//!
//! RAW BYTES, again correctly: this is a per-character filter and case fold, so its whole
//! behaviour is decided by which characters the input happens to contain and a shaped generator
//! would just be a worse random string.
//!
//! # Why this function is worth fuzzing at all
//!
//! It is the LOOKUP KEY for a device grant. Everything downstream of it, including the
//! brute-force attempt counter that RFC 8628 section 5.4 requires, is namespaced by its output.
//! Two different normalizations of the same typed code are two different grants; a normalization
//! that is not stable under repetition means the code stored at issuance and the code looked up
//! at verification can disagree.
//!
//! # The invariants
//!
//! 1. IDEMPOTENCE. `normalize(normalize(x)) == normalize(x)`. This is the property the storage
//!    key depends on and the only one that is genuinely load bearing: the crate normalizes at
//!    issuance and again at every verification attempt.
//! 2. NON-EXPANSION. The output is never longer, in characters, than the input. The function only
//!    drops and case-folds, so any growth would mean a case fold that changed the character count
//!    and, with it, an unbounded key derived from a bounded input.
//! 3. THE FILTER HOLDS. No output character is whitespace or `-`. Section 6.1 asks for exactly
//!    those to be tolerated on input, which only helps if they are actually gone from the key.
//! 4. NO LOWERCASE ASCII SURVIVES. The whole point of the fold is that `WDJB-MJHT` and
//!    `wdjb-mjht` are the same code.

#![no_main]

use libfuzzer_sys::fuzz_target;
use oauth_as::device::normalize_user_code;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let once = normalize_user_code(input);

    // 1.
    let twice = normalize_user_code(&once);
    assert_eq!(
        once, twice,
        "normalize_user_code is not idempotent on {input:?}: {once:?} -> {twice:?}"
    );

    // 2. Characters, not bytes: the fold is `to_ascii_uppercase`, which is per character.
    assert!(
        once.chars().count() <= input.chars().count(),
        "normalize_user_code grew {input:?} into {once:?}"
    );

    // 3 and 4.
    for c in once.chars() {
        assert!(
            !c.is_whitespace(),
            "whitespace survived normalization of {input:?}: {once:?}"
        );
        assert!(
            c != '-',
            "a hyphen survived normalization of {input:?}: {once:?}"
        );
        assert!(
            !c.is_ascii_lowercase(),
            "lowercase ASCII survived normalization of {input:?}: {once:?}"
        );
    }
});
