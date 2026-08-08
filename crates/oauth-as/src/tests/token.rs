// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for [`crate::token`], kept out of the implementation file. These reach
//! private items, so they live in the crate rather than in `tests/`.

use super::*;

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
