// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Parsing of the raw authorization request, and construction of the redirect URLs.
//!
//! This file exists because mutation testing found the gap: every match arm in
//! `AuthorizationRequest::from_pairs` could be DELETED, and the whole function replaced with
//! `Default::default()`, without a single test failing. A parameter collector that silently drops
//! `code_challenge` would have disabled PKCE across the entire authorization endpoint, and nothing
//! in the suite would have noticed.

use std::borrow::Cow;

use oauth_as::AuthorizationRequest;

/// Every RFC 6749 section 4.1.1 and RFC 7636 section 4.3 parameter must actually be collected.
/// Pinned one at a time so that dropping any single arm fails a named test rather than a vague one.
#[test]
fn every_defined_parameter_is_collected() {
    let req = AuthorizationRequest::from_pairs([
        ("response_type", "code"),
        ("client_id", "app"),
        ("redirect_uri", "https://app.example/cb"),
        ("scope", "read write"),
        ("state", "xyz"),
        (
            "code_challenge",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        ),
        ("code_challenge_method", "S256"),
    ]);

    assert_eq!(req.response_type.as_deref(), Some("code"));
    assert_eq!(req.client_id.as_deref(), Some("app"));
    assert_eq!(req.redirect_uri.as_deref(), Some("https://app.example/cb"));
    assert_eq!(req.scope.as_deref(), Some("read write"));
    assert_eq!(req.state.as_deref(), Some("xyz"));
    assert_eq!(
        req.code_challenge.as_deref(),
        Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
        "dropping this arm would silently disable PKCE at the authorization endpoint"
    );
    assert_eq!(req.code_challenge_method.as_deref(), Some("S256"));
}

/// RFC 6749 section 3.1 requires the server to ignore parameters it does not understand, so an
/// unknown parameter must not upset collection of the ones it does.
#[test]
fn unknown_parameters_are_ignored() {
    let req = AuthorizationRequest::from_pairs([
        ("nonce", "not-ours"),
        ("client_id", "app"),
        ("prompt", "consent"),
        ("response_type", "code"),
    ]);
    assert_eq!(req.client_id.as_deref(), Some("app"));
    assert_eq!(req.response_type.as_deref(), Some("code"));
}

/// RFC 6749 section 3.1: a parameter MUST NOT be included more than once. When one is anyway, the
/// FIRST occurrence wins. Last-wins is the smuggling-friendly choice: if a proxy and the server
/// disagree about which copy counts, an attacker can show one value to the thing that authorizes
/// and another to the thing that logs.
#[test]
fn a_repeated_parameter_keeps_the_first_occurrence() {
    let req = AuthorizationRequest::from_pairs([
        ("redirect_uri", "https://app.example/cb"),
        ("redirect_uri", "https://attacker.example/steal"),
        ("client_id", "app"),
        ("client_id", "other-app"),
    ]);
    assert_eq!(
        req.redirect_uri.as_deref(),
        Some("https://app.example/cb"),
        "first wins, or a duplicate parameter becomes a redirect-target smuggling vector"
    );
    assert_eq!(req.client_id.as_deref(), Some("app"));
}

/// An empty parameter list produces a request with nothing set, which the validator must then
/// refuse. This is the shape of the bare GET the conformance harness performs.
#[test]
fn no_parameters_produces_an_entirely_empty_request() {
    let req = AuthorizationRequest::from_pairs(Vec::<(&str, &str)>::new());
    assert!(req.response_type.is_none());
    assert!(req.client_id.is_none());
    assert!(req.redirect_uri.is_none());
    assert!(req.scope.is_none());
    assert!(req.state.is_none());
    assert!(req.code_challenge.is_none());
    assert!(req.code_challenge_method.is_none());
}

/// An empty VALUE is not the same as an absent parameter, and the distinction matters: the
/// validator treats an empty client_id as missing, but it must be the validator making that
/// choice, not the collector losing the information.
#[test]
fn an_empty_value_is_preserved_as_present_and_empty() {
    let req = AuthorizationRequest::from_pairs([("client_id", "")]);
    assert_eq!(req.client_id.as_deref(), Some(""));
}

/// The `Cow` fields exist so a host parsing a query string that needs no percent-decoding borrows
/// it instead of allocating. If these ever became owned, the crate's allocation claims would be
/// quietly false, so the borrow is asserted structurally rather than trusted.
#[test]
fn borrowed_input_stays_borrowed() {
    let req = AuthorizationRequest::from_pairs([("client_id", "app"), ("state", "xyz")]);
    assert!(
        matches!(req.client_id, Some(Cow::Borrowed(_))),
        "from_pairs must not copy a value that was already a borrowed str"
    );
    assert!(matches!(req.state, Some(Cow::Borrowed(_))));
}

/// An owned input must survive too, since a host that DID have to percent-decode passes owned
/// strings and would otherwise silently lose them.
#[test]
fn owned_input_is_accepted() {
    let decoded = String::from("https://app.example/cb?a=1");
    let req = AuthorizationRequest::from_pairs([("redirect_uri", decoded)]);
    assert_eq!(
        req.redirect_uri.as_deref(),
        Some("https://app.example/cb?a=1")
    );
}
