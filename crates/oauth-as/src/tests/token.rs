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
