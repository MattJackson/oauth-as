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

/// C13: `device_code` and `user_code` are both credentials (RFC 8628 section 5.1 for the user
/// code; the device code is what the device polls with), and `verification_uri_complete` embeds
/// the user code by construction, so redacting `user_code` while leaving the complete URI intact
/// would just leak it back out through a different field.
#[test]
fn c13_device_authorization_response_debug_redacts_both_codes_and_the_complete_uri() {
    let with_complete = DeviceAuthorizationResponse {
        device_code: "device-secret-value".into(),
        user_code: "WDJB-MJHT".into(),
        verification_uri: "https://example.com/device".into(),
        verification_uri_complete: Some("https://example.com/device?user_code=WDJB-MJHT".into()),
        expires_in: 600,
        interval: 5,
    };
    let printed = format!("{with_complete:?}");
    assert!(
        !printed.contains("device-secret-value"),
        "debug format leaked the device code: {printed}"
    );
    assert!(
        !printed.contains("WDJB-MJHT"),
        "debug format leaked the user code, directly or via the complete URI: {printed}"
    );
    assert!(printed.contains("[redacted]"), "{printed}");
    for visible in ["example.com/device", "600", "5"] {
        assert!(
            printed.contains(visible),
            "non-secret field {visible} must stay visible: {printed}"
        );
    }

    let without_complete = DeviceAuthorizationResponse {
        verification_uri_complete: None,
        ..with_complete
    };
    let printed_without = format!("{without_complete:?}");
    assert_ne!(
        printed, printed_without,
        "a Some(verification_uri_complete) and a None must not debug-print identically"
    );
    assert!(
        printed_without.contains("None"),
        "absent verification_uri_complete must render as None: {printed_without}"
    );
}

/// C13: the persisted grant carries the same two codes as the wire response, plus lifecycle
/// metadata that must stay visible for the record to remain debuggable.
#[test]
fn c13_device_grant_debug_redacts_both_codes_and_keeps_metadata_visible() {
    let grant = DeviceGrant {
        device_code: "device-secret-value".into(),
        user_code: "WDJB-MJHT".into(),
        client_id: crate::client::ClientId::new("some-client"),
        scope: crate::scope::ScopeSet::parse("read").unwrap(),
        state: DeviceGrantState::Approved {
            subject: "user-1".into(),
        },
        created_at: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(600),
        interval: Duration::from_secs(5),
        last_poll_at: None,
    };
    let printed = format!("{grant:?}");
    assert!(
        !printed.contains("device-secret-value"),
        "debug format leaked the device code: {printed}"
    );
    assert!(
        !printed.contains("WDJB-MJHT"),
        "debug format leaked the user code: {printed}"
    );
    assert!(printed.contains("[redacted]"), "{printed}");
    for visible in ["some-client", "read", "user-1", "Approved"] {
        assert!(
            printed.contains(visible),
            "non-secret field {visible} must stay visible: {printed}"
        );
    }
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
