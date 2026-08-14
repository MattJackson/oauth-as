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

/// THE WIRE FORM IS A PERSISTED FORMAT, AND IT MUST NOT MOVE WITH THE CONTAINER.
///
/// `ScopeSet` is serialized into the `jsonb` payload of every stored client, token, code, consent
/// and pushed request. 0.9.2 changed the inner container from `BTreeSet<Scope>` to a sorted `Vec`,
/// which is invisible on the wire only because `Serialize` is `serialize_str(&self.to_string())`
/// and the sort-plus-dedup reproduces exactly what the B-tree gave. If either half of that ever
/// stops holding, every record written by an earlier version reads back differently, on a patch
/// bump, with nothing to say so.
///
/// The Postgres suite could not have caught it: `persisted_shape.rs` builds its fixture with
/// `ScopeSet::parse("read")`, a single token, which is identical under any ordering and any
/// deduplication. So this pins the properties a one-token fixture cannot see, with the exact
/// strings rather than a round trip -- a round trip through one implementation agrees with itself
/// even when it has stopped agreeing with what is in the database.
#[test]
fn the_serialized_scope_string_is_sorted_deduplicated_and_space_delimited() {
    // Unsorted in, sorted out.
    let s = ScopeSet::parse("write read admin").unwrap();
    assert_eq!(
        serde_json::to_string(&s).unwrap(),
        r#""admin read write""#,
        "the wire form is sorted, because a BTreeSet was and every stored record was written by one"
    );

    // Duplicates collapse. A `Vec` only deduplicates if something makes it.
    let dup = ScopeSet::parse("read read write read").unwrap();
    assert_eq!(serde_json::to_string(&dup).unwrap(), r#""read write""#);

    // Byte ordering, not locale or length: "10" sorts before "2", and "a" before "aa".
    let numeric = ScopeSet::parse("2 10 1 20 100 0").unwrap();
    assert_eq!(
        serde_json::to_string(&numeric).unwrap(),
        r#""0 1 10 100 2 20""#
    );
    let prefix = ScopeSet::parse("aaa a aa").unwrap();
    assert_eq!(serde_json::to_string(&prefix).unwrap(), r#""a aa aaa""#);

    // Case is significant and uppercase sorts first: RFC 6749 s3.3 scope-tokens are case
    // sensitive, so folding here would merge two distinct scopes into one.
    let mixed = ScopeSet::parse("read Read READ").unwrap();
    assert_eq!(
        serde_json::to_string(&mixed).unwrap(),
        r#""READ Read read""#
    );

    // An empty set is the empty string, not `null` and not `[]`.
    assert_eq!(serde_json::to_string(&ScopeSet::empty()).unwrap(), r#""""#);

    // And what a 0.9.1 node wrote still reads back as the same set.
    let stored: ScopeSet = serde_json::from_str(r#""admin read write""#).unwrap();
    assert_eq!(stored, ScopeSet::parse("write admin read").unwrap());
}
