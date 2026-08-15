// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for [`crate::authorization`], kept out of the implementation file. These reach
//! private items, so they live in the crate rather than in `tests/`.

use super::*;

#[test]
fn wire_spellings() {
    assert_eq!(
        serde_json::to_value(ResponseType::Code).unwrap(),
        serde_json::json!("code")
    );
    assert_eq!(
        serde_json::to_value(CodeChallengeMethod::S256).unwrap(),
        serde_json::json!("S256")
    );
}

#[test]
fn implicit_grant_is_not_representable() {
    assert!(serde_json::from_value::<ResponseType>(serde_json::json!("token")).is_err());
    assert!(serde_json::from_value::<CodeChallengeMethod>(serde_json::json!("plain")).is_err());
}

// C11, GREEN. Before this fix, the following compiled and ran (observed against the pre-fix
// checkout as part of this fix's red-before-green step, not left in the tree):
//
//     let forged = ValidatedAuthorizationRequest {
//         client_id: crate::client::ClientId::new("victim-client"),
//         redirect_uri: "https://attacker.example/".to_string(),
//         scope: crate::scope::ScopeSet::parse("read").unwrap(),
//         state: None,
//         code_challenge: "forged-challenge".to_string(),
//         code_challenge_method: CodeChallengeMethod::S256,
//     };
//
// It no longer compiles: `ValidatedAuthorizationRequest` now carries a private `_sealed: Sealed`
// field, and `Sealed` is a private type of this module, so a struct-literal expression cannot
// name it (E0451, "field `_sealed` of struct `ValidatedAuthorizationRequest` is private") even
// from this file, which is a `#[path]`-included submodule of `authorization` and could otherwise
// see private items via `use super::*`. That is deliberate: this test module can call the sealed
// constructor below (a normal function call, not a struct literal), but it cannot forge the
// struct by naming every field, which is exactly the gap C11 found. Uncomment the block above in
// isolation to see the compile error again; it is left as a comment rather than a
// `#[test]`-under-`#[should_panic]` because this is a compile-time property, not a runtime one.

#[test]
fn c13_authorization_code_record_debug_format_redacts_code_and_tokens() {
    let record = AuthorizationCodeRecord {
        issued_at: std::time::UNIX_EPOCH,
        code: "the-secret-code-value".to_string(),
        client_id: crate::client::ClientId::new("some-client"),
        redirect_uri: "https://registered.example/callback".to_string(),
        redirect_uri_was_explicit: true,
        scope: crate::scope::ScopeSet::parse("read").unwrap(),
        subject: "user-1".to_string(),
        code_challenge: "some-challenge".to_string(),
        code_challenge_method: CodeChallengeMethod::S256,
        resource: vec!["https://rs.example/api".to_string()],
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        expires_at: std::time::SystemTime::UNIX_EPOCH,
        state: AuthorizationCodeState::Consumed {
            access_token: Some("the-secret-access-token".to_string()),
            refresh_token: Some("the-secret-refresh-token".to_string()),
        },
        #[cfg(feature = "consent")]
        authentication: None,
    };
    let printed = format!("{record:?}");
    assert!(!printed.contains("the-secret-code-value"), "{printed}");
    assert!(!printed.contains("the-secret-access-token"), "{printed}");
    assert!(!printed.contains("the-secret-refresh-token"), "{printed}");
    // Non-secret fields stay visible: this is a redaction, not a black box.
    assert!(printed.contains("some-client"), "{printed}");
    assert!(printed.contains("registered.example"), "{printed}");
    assert!(printed.contains("user-1"), "{printed}");
}

#[test]
fn c13_issued_state_debug_format_has_nothing_to_redact() {
    assert_eq!(format!("{:?}", AuthorizationCodeState::Issued), "Issued");
}

#[test]
fn c13_consumed_state_without_refresh_token_shows_none_not_a_value() {
    let state = AuthorizationCodeState::Consumed {
        access_token: Some("at".to_string()),
        refresh_token: None,
    };
    let printed = format!("{state:?}");
    assert!(!printed.contains("\"at\""), "{printed}");
    assert!(printed.contains("None"), "{printed}");
}

#[test]
fn c11_only_the_sealed_constructor_produces_a_validated_request() {
    // GREEN: the sealed constructor is reachable from within the crate (this test module), and
    // it is the only way left to obtain a ValidatedAuthorizationRequest without going through
    // AuthorizationServer::validate_authorization_request in server.rs.
    let validated = ValidatedAuthorizationRequest::new(
        crate::client::ClientId::new("victim-client"),
        "https://registered.example/callback".to_string(),
        true,
        crate::scope::ScopeSet::parse("read").unwrap(),
        None,
        "some-challenge".to_string(),
        CodeChallengeMethod::S256,
        "https://as.example".to_string(),
        Vec::new(),
    );
    assert_eq!(
        validated.redirect_uri,
        "https://registered.example/callback"
    );
}

/// RFC 8707 s2 states three rules about a `resource` value and this function is where all three
/// live, so it is checked exhaustively over the interesting shapes rather than only through the
/// endpoint that calls it. The rules: an absolute URI (RFC 3986 s4.3, so a scheme and a `:`), a
/// query component is PERMITTED, and a fragment is FORBIDDEN.
#[test]
fn rfc8707_resource_indicators_must_be_absolute_uris_without_a_fragment() {
    for ok in [
        "https://rs.example",
        "https://rs.example/api",
        "https://rs.example/api?tenant=1",
        // Not every resource server is an https URL: RFC 8707 s2 says absolute URI, and a URN is
        // one. Refusing it would exclude a shape the RFC explicitly admits.
        "urn:example:resource",
        "coap+tcp://rs.example/x",
    ] {
        assert!(
            is_valid_resource_indicator(ok),
            "RFC 8707 s2 admits {ok} as a resource indicator"
        );
    }

    for bad in [
        // No scheme at all: a relative reference names nothing the AS can restrict a token to.
        "",
        "/api",
        "rs.example/api",
        "//rs.example/api",
        // A scheme must start with a letter (RFC 3986 s3.1) and must not be empty.
        ":no-scheme",
        "1http://rs.example",
        "ht_tp://rs.example",
        // Fragments are forbidden outright, wherever they appear.
        "https://rs.example/#",
        "https://rs.example/api#section",
        "https://rs.example/api?q=1#f",
        // Not URI characters at all: RFC 3986 s2 requires these to be percent-encoded, and a value
        // that cannot survive a query string must not reach a token's audience.
        "https://rs.example/a b",
        "https://rs.example/\u{e9}",
    ] {
        assert!(
            !is_valid_resource_indicator(bad),
            "RFC 8707 s2 must refuse {bad:?} as a resource indicator"
        );
    }
}

/// RFC 8707 s2 permits `resource` to be repeated, so parsing keeps EVERY occurrence, in order.
/// This is the one parameter exempt from the first-wins rule RFC 6749 s3.1 motivates for the rest:
/// there, a duplicate is a smuggling attempt; here, it is the client naming a second audience.
#[test]
fn rfc8707_resource_is_the_one_repeatable_authorization_parameter() {
    let req = AuthorizationRequest::from_pairs([
        ("client_id", "app"),
        ("resource", "https://a.example"),
        ("client_id", "attacker"),
        ("resource", "https://b.example"),
    ]);
    assert_eq!(
        req.resource,
        vec!["https://a.example", "https://b.example"],
        "every resource occurrence is part of the request (RFC 8707 s2)"
    );
    assert_eq!(
        req.client_id.as_deref(),
        Some("app"),
        "every OTHER parameter still keeps the first occurrence (RFC 6749 s3.1)"
    );
}

/// The success-redirect response Debug prints its shape and redacts the one-time `code`.
///
/// Kills `396 <impl Debug for AuthorizationResponse>::fmt -> Ok(Default::default())`. RFC 6749
/// section 4.1.2 makes the code a credential in its own right; a host that logs the response it is
/// about to redirect with would write a live, unredeemed code to disk. Emptied, the hand-written
/// redaction prints nothing at all, so the derived form this type shipped with until 0.9.2 is
/// effectively back.
#[test]
fn authorization_response_debug_format_redacts_the_code() {
    let response = AuthorizationResponse {
        code: "the-secret-authorization-code".to_string(),
        state: Some("client-state-xyz".to_string()),
        iss: "https://as.example".to_string(),
    };
    let printed = format!("{response:?}");
    assert!(
        printed.contains("AuthorizationResponse"),
        "an emptied Debug names nothing: {printed}"
    );
    assert!(printed.contains("[redacted]"), "{printed}");
    assert!(
        !printed.contains("the-secret-authorization-code"),
        "the code is a bearer credential and must not print: {printed}"
    );
    // state is the client's own echoed value and iss is this server's public identifier.
    assert!(printed.contains("client-state-xyz"), "{printed}");
    assert!(printed.contains("as.example"), "{printed}");
}

/// A persisted code record with no `redirect_uri_was_explicit` member deserializes to the
/// fail-closed `true`.
///
/// Kills `653 redirect_uri_was_explicit_default -> false`. The member arrived after 0.9.0, and
/// `#[serde(default = "redirect_uri_was_explicit_default")]` is what lets a record minted before
/// it still deserialize. TRUE is the fail-closed reading: it keeps RFC 6749 section 4.1.3's
/// required-parameter check for a code with no stated decision, rather than silently waiving it for
/// every grant that survived the upgrade. Under the mutant that default is `false`, which waives it.
#[test]
fn a_code_record_missing_redirect_uri_was_explicit_defaults_to_fail_closed_true() {
    let record = AuthorizationCodeRecord {
        issued_at: std::time::UNIX_EPOCH,
        code: "code-value".to_string(),
        client_id: crate::client::ClientId::new("some-client"),
        redirect_uri: "https://registered.example/callback".to_string(),
        redirect_uri_was_explicit: true,
        scope: crate::scope::ScopeSet::parse("read").unwrap(),
        subject: "user-1".to_string(),
        code_challenge: "some-challenge".to_string(),
        code_challenge_method: CodeChallengeMethod::S256,
        resource: vec!["https://rs.example/api".to_string()],
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        expires_at: std::time::SystemTime::UNIX_EPOCH,
        state: AuthorizationCodeState::Consumed {
            access_token: Some("at".to_string()),
            refresh_token: None,
        },
        #[cfg(feature = "consent")]
        authentication: None,
    };
    let mut value = serde_json::to_value(&record).expect("the record serializes");
    let removed = value
        .as_object_mut()
        .expect("a record serializes to a JSON object")
        .remove("redirect_uri_was_explicit");
    assert!(
        removed.is_some(),
        "the field must be present to model a record written before it existed"
    );
    let restored: AuthorizationCodeRecord =
        serde_json::from_value(value).expect("a pre-field record still deserializes");
    assert!(
        restored.redirect_uri_was_explicit,
        "a record with no stated decision must default to the fail-closed TRUE that keeps \
         RFC 6749 s4.1.3's required-parameter check"
    );
}
