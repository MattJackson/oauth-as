// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for [`crate::grant`], kept out of the implementation file. These reach
//! private items, so they live in the crate rather than in `tests/`.

use super::*;

#[test]
fn device_grant_wire_spelling_is_the_full_urn() {
    assert_eq!(
        serde_json::to_value(GrantType::DeviceCode).unwrap(),
        serde_json::json!("urn:ietf:params:oauth:grant-type:device_code")
    );
    assert_eq!(
        "urn:ietf:params:oauth:grant-type:device_code"
            .parse::<GrantType>()
            .unwrap(),
        GrantType::DeviceCode
    );
}

#[test]
fn unknown_grant_type_is_rejected() {
    assert!(
        "password".parse::<GrantType>().is_err(),
        "the ROPC grant is removed in OAuth 2.1"
    );
    assert!(
        "implicit".parse::<GrantType>().is_err(),
        "the implicit grant is removed in OAuth 2.1"
    );
}
