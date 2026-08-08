// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 6749 section 3.3 scope rules: the scope-token grammar, set semantics (dedup, ordering,
//! subset), and the space-delimited wire form.
//!
//! Why the grammar matters beyond parsing: RFC 6749 section 5.2 restricts `error_description` to
//! printable ASCII EXCLUDING double quote and backslash. `crate::server` interpolates a rejected
//! scope's text into `error_description` (see the `resolve_scope` comment in `src/server.rs`), so
//! if the scope grammar ever let a double quote or backslash through, a crafted scope value could
//! break out of that description's charset. These tests pin the grammar that guarantees it cannot.

use oauth_as::{Scope, ScopeSet};

/// RFC 6749 section 3.3: `scope-token = 1*( %x21 / %x23-5B / %x5D-7E )`. A space cannot appear in
/// a token because space is the delimiter between tokens, not token content.
#[test]
fn space_is_rejected_because_it_is_the_delimiter_not_content() {
    assert!(Scope::new("has space").is_err());
    assert!(Scope::new(" ").is_err());
    assert!(Scope::new("trailing ").is_err());
    assert!(Scope::new(" leading").is_err());
}

/// RFC 6749 section 3.3 excludes `%x22` (double quote) from scope-token, and section 5.2 excludes
/// it from `error_description` too. A scope grammar that let a quote through would let scope text
/// break out of a description string built by simple interpolation.
#[test]
fn double_quote_is_rejected() {
    assert!(Scope::new("dq\"uote").is_err());
    assert!(Scope::new("\"").is_err());
}

/// RFC 6749 section 3.3 excludes `%x5C` (backslash) from scope-token for the same reason as the
/// double quote: section 5.2's `error_description` charset excludes it too.
#[test]
fn backslash_is_rejected() {
    assert!(Scope::new("back\\slash").is_err());
    assert!(Scope::new("\\").is_err());
}

/// The full legal range, `%x21 / %x23-5B / %x5D-7E`, concatenated into one token (none of these
/// bytes is a space, so this is a single valid token, not several). A plausible wrong
/// implementation that used a narrower "printable ASCII" test, or that mistakenly excluded one of
/// the boundary bytes, would reject part of this and fail here.
#[test]
fn the_full_legal_range_is_accepted() {
    let mut token = String::new();
    for b in 0x21u8..=0x7E {
        if b == 0x22 || b == 0x5C {
            continue; // excluded by the grammar (double quote, backslash)
        }
        token.push(b as char);
    }
    assert!(
        Scope::new(token.clone()).is_ok(),
        "the full RFC 6749 s3.3 legal range must be accepted, got rejected: {token:?}"
    );

    // Boundary bytes individually, so a fencepost error in the range check (`<` vs `<=`) is
    // caught precisely rather than hidden inside the big concatenation above.
    assert!(Scope::new("!").is_ok(), "0x21, the lower bound");
    assert!(Scope::new("[").is_ok(), "0x5B, end of the first sub-range");
    assert!(
        Scope::new("]").is_ok(),
        "0x5D, start of the second sub-range"
    );
    assert!(Scope::new("~").is_ok(), "0x7E, the upper bound");
}

/// Bytes outside `%x21-7E` entirely: a C0 control character and DEL (0x7F), neither of which is
/// printable ASCII at all.
#[test]
fn control_bytes_and_del_are_rejected() {
    assert!(Scope::new("\u{1}").is_err(), "0x01, a C0 control byte");
    assert!(
        Scope::new("\u{7f}").is_err(),
        "0x7F, DEL, just past the upper bound"
    );
}

/// Non-ASCII text is rejected outright: the grammar is a byte range capped at 0x7E, so anything
/// requiring a multi-byte UTF-8 encoding cannot satisfy it token-by-token.
#[test]
fn non_ascii_is_rejected() {
    assert!(Scope::new("caf\u{e9}").is_err());
}

/// RFC 6749 section 3.3: a scope token must be non-empty (`1*(...)`, one or more).
#[test]
fn empty_token_is_rejected() {
    assert!(Scope::new("").is_err());
}

// ---------------------------------------------------------------- set semantics

/// Duplicate tokens collapse into one membership, and the space-delimited output is in a stable,
/// deterministic (lexicographic) order regardless of input order.
#[test]
fn duplicate_tokens_collapse_and_ordering_is_deterministic() {
    let a = ScopeSet::parse("write read read write admin").unwrap();
    assert_eq!(a.len(), 3, "duplicates must collapse to one entry each");
    assert_eq!(a.to_string(), "admin read write");

    // Same tokens, different input order: identical output, because ordering is a property of
    // the set, not of how it was built.
    let b = ScopeSet::parse("admin write read").unwrap();
    assert_eq!(a, b);
    assert_eq!(a.to_string(), b.to_string());
}

/// Repeated internal whitespace between tokens is tolerated by the parser (it is a delimiter, not
/// content), and collapses the same way a single space would.
#[test]
fn repeated_whitespace_between_tokens_is_tolerated() {
    let set = ScopeSet::parse("  read   write  ").unwrap();
    assert_eq!(set.len(), 2);
    assert_eq!(set.to_string(), "read write");
}

/// The empty scope round-trips: `ScopeSet::empty()` serializes to the empty string, and parsing
/// the empty string (or pure whitespace) yields the empty set back.
#[test]
fn empty_scope_round_trips() {
    let empty = ScopeSet::empty();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert_eq!(empty.to_string(), "");

    assert_eq!(ScopeSet::parse("").unwrap(), empty);
    assert_eq!(
        ScopeSet::parse("   ").unwrap(),
        empty,
        "whitespace only is still empty"
    );
}

/// `is_subset` across the cases a permission check actually has to get right: equal sets, a
/// strict subset, a strict superset (which must NOT read as a subset), disjoint sets, and the
/// empty set, which is a subset of everything including itself. The empty-set case is the classic
/// off-by-one: an implementation that requires the two sets to intersect, rather than checking
/// "nothing left uncovered", would wrongly refuse it.
#[test]
fn subset_semantics_cover_equal_strict_disjoint_and_empty() {
    let all = ScopeSet::parse("a b c").unwrap();
    let equal = ScopeSet::parse("c b a").unwrap();
    let strict_subset = ScopeSet::parse("a c").unwrap();
    let strict_superset = ScopeSet::parse("a b c d").unwrap();
    let disjoint = ScopeSet::parse("x y z").unwrap();
    let partially_overlapping = ScopeSet::parse("a x").unwrap();

    assert!(equal.is_subset(&all), "a set is a subset of an equal set");
    assert!(strict_subset.is_subset(&all));
    assert!(
        !strict_superset.is_subset(&all),
        "a strict superset must not read as a subset"
    );
    assert!(!disjoint.is_subset(&all), "disjoint sets share no tokens");
    assert!(
        !partially_overlapping.is_subset(&all),
        "partial overlap is not a subset: EVERY token must be covered"
    );

    // The empty set is a subset of anything, including itself.
    assert!(ScopeSet::empty().is_subset(&all));
    assert!(ScopeSet::empty().is_subset(&ScopeSet::empty()));
    // And nothing (except the empty set) is a subset of the empty set.
    assert!(!all.is_subset(&ScopeSet::empty()));
}

// ---------------------------------------------------------------- wire form

/// The wire form (both directions, per RFC 6749 section 3.3) is the space-delimited token string,
/// and a `ScopeSet` survives a full JSON round trip unchanged.
#[test]
fn serialization_is_space_delimited_and_roundtrips_through_json() {
    let set = ScopeSet::parse("write read admin").unwrap();
    let json = serde_json::to_string(&set).unwrap();
    // Sorted, space-delimited: never comma-delimited, never a JSON array. RFC 6749 section 3.3
    // is explicit that scope is one string of space-delimited tokens.
    assert_eq!(json, "\"admin read write\"");

    let back: ScopeSet = serde_json::from_str(&json).unwrap();
    assert_eq!(back, set);
    assert_eq!(back.to_string(), set.to_string());
}

/// A malformed token inside an otherwise well-formed scope string fails the whole parse: partial
/// acceptance would silently drop the caller's stated intent for that one token.
#[test]
fn one_malformed_token_fails_the_whole_parse() {
    assert!(ScopeSet::parse("read \"write\" admin").is_err());
}
