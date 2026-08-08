// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for [`crate::device`], kept out of the implementation file. These reach
//! private items, so they live in the crate rather than in `tests/`.

use super::*;

#[test]
fn device_authorization_response_shape_is_rfc8628_3_2() {
    let r = DeviceAuthorizationResponse {
        device_code: "dc".into(),
        user_code: "WDJB-MJHT".into(),
        verification_uri: "https://example.com/device".into(),
        verification_uri_complete: None,
        expires_in: 600,
        interval: 5,
    };
    assert_eq!(
        serde_json::to_value(&r).unwrap(),
        serde_json::json!({
            "device_code": "dc",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://example.com/device",
            "expires_in": 600,
            "interval": 5,
        }),
        "absent verification_uri_complete must be omitted, not null"
    );
}

#[test]
fn user_code_normalization_is_case_hyphen_and_space_insensitive() {
    for entry in [
        "WDJB-MJHT",
        "wdjb-mjht",
        "wdjbmjht",
        " wdjb mjht ",
        "WdJb-MjHt",
    ] {
        assert_eq!(normalize_user_code(entry), "WDJBMJHT", "entry {:?}", entry);
    }
}
