// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for [`crate::scope`], kept out of the implementation file. These reach
//! private items, so they live in the crate rather than in `tests/`.

use super::*;

#[test]
fn charset_is_rfc6749_3_3() {
    assert!(Scope::new("read").is_ok());
    assert!(Scope::new("urn:example:channel=HBO&level=5").is_ok());
    assert!(Scope::new("!#[]~").is_ok());
    assert!(Scope::new("").is_err(), "empty token");
    assert!(
        Scope::new("has space").is_err(),
        "space is the delimiter, not scope content"
    );
    assert!(Scope::new("dq\"uote").is_err(), "0x22 excluded");
    assert!(Scope::new("back\\slash").is_err(), "0x5C excluded");
    assert!(Scope::new("caf\u{e9}").is_err(), "non-ASCII excluded");
}

#[test]
fn parse_dedupes_orders_and_roundtrips() {
    let set = ScopeSet::parse("write  read read").unwrap();
    assert_eq!(set.len(), 2);
    assert_eq!(set.to_string(), "read write");
    let json = serde_json::to_string(&set).unwrap();
    assert_eq!(json, "\"read write\"");
    let back: ScopeSet = serde_json::from_str(&json).unwrap();
    assert_eq!(back, set);
}

#[test]
fn subset_semantics() {
    let all = ScopeSet::parse("a b c").unwrap();
    let some = ScopeSet::parse("a c").unwrap();
    let other = ScopeSet::parse("a d").unwrap();
    assert!(some.is_subset(&all));
    assert!(!other.is_subset(&all));
    assert!(ScopeSet::empty().is_subset(&all));
}
