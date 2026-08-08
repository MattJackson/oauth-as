// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for [`crate::token`], kept out of the implementation file. These reach
//! private items, so they live in the crate rather than in `tests/`.

use super::*;

use std::time::{Duration, UNIX_EPOCH};

/// C13: an issued access token is a bearer credential (RFC 6750 section 1: holding the string IS
/// the authorization), so `{:?}` on the persisted record must not print it. The metadata around it
/// is not a credential and must stay visible, or the record becomes undebuggable.
#[test]
fn c13_issued_token_debug_redacts_the_access_token() {
    let record = IssuedToken {
        access_token: "at-secret-value".into(),
        client_id: ClientId::new("app"),
        subject: Some("alice".into()),
        scope: ScopeSet::parse("read write").unwrap(),
        resource: vec!["https://rs.example/api".to_string()],
        issued_at: UNIX_EPOCH + Duration::from_secs(1_000),
        expires_at: UNIX_EPOCH + Duration::from_secs(4_600),
        family_id: Some("fam-1".into()),
    };
    let printed = format!("{record:?}");
    assert!(
        !printed.contains("at-secret-value"),
        "debug format leaked the access token: {printed}"
    );
    assert!(printed.contains("[redacted]"), "{printed}");
    for visible in ["app", "alice", "read", "write", "fam-1"] {
        assert!(
            printed.contains(visible),
            "non-secret field {visible} must stay visible: {printed}"
        );
    }
}

/// C13: a refresh token is the credential whose leak RFC 9700 section 4.14.2 exists to contain, so
/// it must never print. `family_id` and `state` are what an operator reads to understand a family
/// revocation and are not credentials, so they must remain visible.
#[test]
fn c13_refresh_token_record_debug_redacts_the_refresh_token() {
    let record = RefreshTokenRecord {
        refresh_token: "rt-secret-value".into(),
        client_id: ClientId::new("app"),
        subject: Some("alice".into()),
        scope: ScopeSet::parse("read").unwrap(),
        resource: vec!["https://rs.example/api".to_string()],
        expires_at: Some(UNIX_EPOCH + Duration::from_secs(9_000)),
        family_id: "fam-1".into(),
        state: RefreshTokenState::Spent,
    };
    let printed = format!("{record:?}");
    assert!(
        !printed.contains("rt-secret-value"),
        "debug format leaked the refresh token: {printed}"
    );
    assert!(printed.contains("[redacted]"), "{printed}");
    for visible in ["app", "alice", "read", "fam-1", "Spent"] {
        assert!(
            printed.contains(visible),
            "non-secret field {visible} must stay visible: {printed}"
        );
    }
}

/// C13: the success response carries the access token, and optionally a refresh token, both
/// bearer credentials (RFC 6750 section 1; RFC 9700 section 4.14.2). `{:?}` must not print either
/// value, but must keep the `Some`/`None` shape of `refresh_token` visible: whether the grant
/// minted a refresh token is diagnostic, and a presented one must not debug-print the same as an
/// absent one.
#[test]
fn c13_token_response_debug_redacts_both_tokens_and_keeps_option_shape_visible() {
    let with_refresh = TokenResponse {
        access_token: "at-secret-value".into(),
        token_type: TokenType::Bearer,
        expires_in: 3600,
        refresh_token: Some("rt-secret-value".into()),
        scope: Some("read write".into()),
    };
    let printed = format!("{with_refresh:?}");
    assert!(
        !printed.contains("at-secret-value"),
        "debug format leaked the access token: {printed}"
    );
    assert!(
        !printed.contains("rt-secret-value"),
        "debug format leaked the refresh token: {printed}"
    );
    assert!(printed.contains("[redacted]"), "{printed}");
    for visible in ["3600", "read", "write"] {
        assert!(
            printed.contains(visible),
            "non-secret field {visible} must stay visible: {printed}"
        );
    }

    let without_refresh = TokenResponse {
        refresh_token: None,
        ..with_refresh
    };
    let printed_without = format!("{without_refresh:?}");
    assert_ne!(
        printed, printed_without,
        "a Some(refresh_token) and a None must not debug-print identically"
    );
    assert!(
        printed_without.contains("None"),
        "absent refresh_token must render as None, not as a redacted value: {printed_without}"
    );
}

#[test]
fn success_response_shape_is_rfc6749_5_1() {
    let full = TokenResponse {
        access_token: "at".into(),
        token_type: TokenType::Bearer,
        expires_in: 3600,
        refresh_token: Some("rt".into()),
        scope: Some("read write".into()),
    };
    assert_eq!(
        serde_json::to_value(&full).unwrap(),
        serde_json::json!({
            "access_token": "at",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "rt",
            "scope": "read write",
        })
    );
    let minimal = TokenResponse {
        access_token: "at".into(),
        token_type: TokenType::Bearer,
        expires_in: 60,
        refresh_token: None,
        scope: None,
    };
    assert_eq!(
        serde_json::to_value(&minimal).unwrap(),
        serde_json::json!({ "access_token": "at", "token_type": "Bearer", "expires_in": 60 }),
        "absent optionals must be omitted, not null"
    );
}
