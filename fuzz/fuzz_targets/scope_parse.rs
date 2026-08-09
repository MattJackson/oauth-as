// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! `ScopeSet::parse`, RFC 6749 section 3.3.
//!
//! RAW BYTES on purpose, and this is the one place where raw is exactly right: the production
//! under test is a byte-level charset (`%x21 / %x23-5B / %x5D-7E`) split on a single space, so a
//! structure-aware generator would only be re-deriving the grammar the parser is being tested
//! against, and would systematically stop generating the bytes just outside it, which are the
//! only interesting ones.
//!
//! # The invariants, and why they are worth more than "does not panic"
//!
//! 1. ROUND TRIP. `parse(display(parse(s)))` equals `parse(s)`. The `Display` form is what this
//!    server puts in a token response's `scope` member and in the `scope` of a refresh request,
//!    so a set that does not survive its own serialization means a client is granted one thing
//!    and told another. A panic-only target cannot see that at all.
//! 2. CHARSET. Every token of an accepted set is in the section 3.3 charset and non-empty. A
//!    parser that let a space, a quote or a backslash through would produce a `scope` string
//!    whose re-parse splits differently, which is scope smuggling.
//! 3. NO SEPARATOR SURVIVES. No accepted token contains a space, so the set cannot be re-read as
//!    a larger set than was granted.
//! 4. CARDINALITY. The set is deduplicated, so `len()` equals the number of distinct tokens in
//!    the input.

#![no_main]

use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;
use oauth_as::ScopeSet;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        // Not UTF-8 is not an interesting input here: every caller in the crate reaches this
        // through a `&str` that has already been validated, so a `[u8]` that is not UTF-8 is a
        // shape the function can never be handed.
        return;
    };

    let Ok(set) = ScopeSet::parse(input) else {
        return;
    };

    // 2 and 3.
    for token in set.iter() {
        let s = token.as_str();
        assert!(!s.is_empty(), "an empty scope token was accepted");
        assert!(
            !s.contains(' '),
            "an accepted scope token contains the RFC 6749 s3.3 separator: {s:?}"
        );
        assert!(
            s.bytes()
                .all(|b| b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b)),
            "an accepted scope token is outside the RFC 6749 s3.3 charset: {s:?}"
        );
    }

    // 4. `split(' ')` with empties dropped is the RFC's own reading of the production, so the
    // distinct count is derivable from the input without re-implementing the parser.
    let distinct: BTreeSet<&str> = input.split(' ').filter(|t| !t.is_empty()).collect();
    assert_eq!(
        set.len(),
        distinct.len(),
        "the parsed set has a different cardinality from the input's distinct tokens: {input:?}"
    );

    // 1. The round trip, which is the assertion that pays.
    let rendered = set.to_string();
    let reparsed = ScopeSet::parse(&rendered)
        .expect("a rendered ScopeSet must re-parse: it is what this server puts on the wire");
    assert_eq!(
        set, reparsed,
        "a ScopeSet did not survive its own serialization: {input:?} -> {rendered:?}"
    );
});
