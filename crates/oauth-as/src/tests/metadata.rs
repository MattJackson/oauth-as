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

/// RFC 8414 s3.1: the well-known string goes BETWEEN the host and the issuer's path, so an
/// issuer with a path publishes at `/.well-known/oauth-authorization-server/tenant1` and not at
/// the bare path (which every tenant would share) nor under the tenant prefix.
#[test]
fn the_well_known_path_follows_rfc_8414_section_3_1() {
    assert_eq!(
        well_known_path("https://as.example"),
        "/.well-known/oauth-authorization-server"
    );
    assert_eq!(
        well_known_path("https://as.example/"),
        "/.well-known/oauth-authorization-server"
    );
    assert_eq!(
        well_known_path("https://as.example/tenant1"),
        "/.well-known/oauth-authorization-server/tenant1"
    );
    assert_eq!(
        well_known_path("https://as.example/tenant1/"),
        "/.well-known/oauth-authorization-server/tenant1"
    );
    assert_eq!(
        well_known_path("https://as.example:8443/a/b"),
        "/.well-known/oauth-authorization-server/a/b"
    );
}

#[test]
fn the_issuer_path_is_only_what_follows_the_authority() {
    // A port, a userinfo-free authority, and an issuer with no path at all: none of these may
    // contribute a path component.
    assert_eq!(issuer_path("https://as.example"), "");
    assert_eq!(issuer_path("https://as.example:8443"), "");
    assert_eq!(issuer_path("https://as.example:8443/tenant1"), "/tenant1");
    // A scheme-less string is not an issuer RFC 8414 s2 admits; it is read as authority plus
    // path rather than rejected here.
    assert_eq!(issuer_path("as.example/tenant1"), "/tenant1");
}
