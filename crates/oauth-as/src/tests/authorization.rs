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
        code: "the-secret-code-value".to_string(),
        client_id: crate::client::ClientId::new("some-client"),
        redirect_uri: "https://registered.example/callback".to_string(),
        scope: crate::scope::ScopeSet::parse("read").unwrap(),
        subject: "user-1".to_string(),
        code_challenge: "some-challenge".to_string(),
        code_challenge_method: CodeChallengeMethod::S256,
        expires_at: std::time::SystemTime::UNIX_EPOCH,
        state: AuthorizationCodeState::Consumed {
            access_token: "the-secret-access-token".to_string(),
            refresh_token: Some("the-secret-refresh-token".to_string()),
        },
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
        access_token: "at".to_string(),
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
        crate::scope::ScopeSet::parse("read").unwrap(),
        None,
        "some-challenge".to_string(),
        CodeChallengeMethod::S256,
    );
    assert_eq!(
        validated.redirect_uri,
        "https://registered.example/callback"
    );
}
