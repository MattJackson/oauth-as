// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for [`crate::error`], kept out of the implementation file. These reach
//! private items, so they live in the crate rather than in `tests/`.

use super::*;

#[test]
fn wire_spellings_are_the_registered_tokens() {
    for (code, wire) in [
        (ErrorCode::InvalidRequest, "invalid_request"),
        (ErrorCode::InvalidClient, "invalid_client"),
        (ErrorCode::InvalidGrant, "invalid_grant"),
        (ErrorCode::UnauthorizedClient, "unauthorized_client"),
        (ErrorCode::UnsupportedGrantType, "unsupported_grant_type"),
        (ErrorCode::InvalidScope, "invalid_scope"),
        (ErrorCode::AccessDenied, "access_denied"),
        (
            ErrorCode::UnsupportedResponseType,
            "unsupported_response_type",
        ),
        (ErrorCode::ServerError, "server_error"),
        (ErrorCode::TemporarilyUnavailable, "temporarily_unavailable"),
        (ErrorCode::AuthorizationPending, "authorization_pending"),
        (ErrorCode::SlowDown, "slow_down"),
        (ErrorCode::ExpiredToken, "expired_token"),
    ] {
        assert_eq!(serde_json::to_value(code).unwrap(), serde_json::json!(wire));
        assert_eq!(code.as_str(), wire);
    }
}

#[test]
fn absent_optional_fields_are_omitted_not_null() {
    let body = serde_json::to_value(ErrorResponse::new(ErrorCode::AuthorizationPending)).unwrap();
    assert_eq!(
        body,
        serde_json::json!({ "error": "authorization_pending" })
    );
}

#[test]
fn http_status_mapping_follows_rfc6749_5_2() {
    assert_eq!(
        ErrorResponse::new(ErrorCode::InvalidClient).http_status(),
        401
    );
    assert_eq!(
        ErrorResponse::new(ErrorCode::InvalidGrant).http_status(),
        400
    );
    assert_eq!(ErrorResponse::new(ErrorCode::SlowDown).http_status(), 400);
    assert_eq!(
        ErrorResponse::new(ErrorCode::ServerError).http_status(),
        500
    );
    assert_eq!(
        ErrorResponse::new(ErrorCode::TemporarilyUnavailable).http_status(),
        503
    );
}
