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
