// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for [`crate::resource_metadata`], kept out of the implementation file. These reach
//! private items, so they live in the crate rather than in `tests/`.

use super::*;

/// RFC 9728 s3.1 states the same insertion rule RFC 8414 s3.1 does: the well-known string goes
/// BETWEEN the host and the rest of the identifier. For `https://rs.example/api` the document is
/// at `/.well-known/oauth-protected-resource/api`, and NOT under the resource's own path (where
/// every resource on one origin would still be distinguishable, but no client would look) and NOT
/// at the bare path (where every resource on one origin would collide).
#[test]
fn the_well_known_path_follows_rfc_9728_section_3_1() {
    assert_eq!(
        well_known_path("https://rs.example"),
        "/.well-known/oauth-protected-resource"
    );
    assert_eq!(
        well_known_path("https://rs.example/"),
        "/.well-known/oauth-protected-resource"
    );
    assert_eq!(
        well_known_path("https://rs.example/api"),
        "/.well-known/oauth-protected-resource/api"
    );
    assert_eq!(
        well_known_path("https://rs.example/api/"),
        "/.well-known/oauth-protected-resource/api"
    );
    assert_eq!(
        well_known_path("https://rs.example/api/v2"),
        "/.well-known/oauth-protected-resource/api/v2"
    );
}

/// RFC 9728 s3.1 says "path and/or query components", which is a shape an RFC 8414 issuer cannot
/// have (s2 forbids a query on the issuer). A resource identifier carrying only a query would lose
/// it entirely if the path rule were applied unchanged, and the client would be told to fetch a
/// different document than the one the resource publishes.
#[test]
fn a_query_component_survives_the_insertion() {
    assert_eq!(
        well_known_path("https://rs.example/api?tenant=1"),
        "/.well-known/oauth-protected-resource/api?tenant=1"
    );
    assert_eq!(
        well_known_path("https://rs.example?tenant=1"),
        "/.well-known/oauth-protected-resource?tenant=1"
    );
    // "any terminating slash following the host component MUST be removed" (s3.1), which is the
    // same slash whether or not a query follows it.
    assert_eq!(
        well_known_path("https://rs.example/?tenant=1"),
        "/.well-known/oauth-protected-resource?tenant=1"
    );
}

/// The path half is delegated to `crate::metadata::issuer_path` on purpose, so the AS document and
/// the resource document cannot come to disagree about where a tenant lives. This pins that they
/// agree rather than merely that each is individually plausible.
#[test]
fn the_path_rule_is_the_same_one_the_as_document_uses() {
    for identifier in [
        "https://x.example",
        "https://x.example/",
        "https://x.example/tenant1",
        "https://x.example/tenant1/",
        "https://x.example/a/b/c",
    ] {
        assert_eq!(
            resource_path(identifier),
            crate::metadata::issuer_path(identifier),
            "the two documents must place {identifier} the same way"
        );
    }
}

/// An undeclared capability is an OMITTED member, not an empty array. The distinction is the whole
/// of RFC 9728 s2's omission rule: `[]` is a claim ("none of these"), absence is silence, and s2
/// gives several members a default that applies only when they are absent.
#[test]
fn an_empty_list_becomes_an_omitted_member_rather_than_an_empty_array() {
    assert_eq!(some_unless_empty(Vec::<String>::new()), None);
    assert_eq!(
        some_unless_empty(vec!["a".to_string()]),
        Some(vec!["a".to_string()])
    );
}
