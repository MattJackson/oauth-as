// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for [`crate::server`], kept out of the implementation file. These reach
//! private items, so they live in the crate rather than in `tests/`.

use super::*;

#[test]
fn user_codes_use_the_alphabet_and_are_unbiased_in_shape() {
    let code = random_user_code(8);
    assert_eq!(code.len(), 8);
    assert!(code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)));
}

#[test]
fn display_form_hyphenates_even_lengths() {
    assert_eq!(display_user_code("WDJBMJHT"), "WDJB-MJHT");
    assert_eq!(display_user_code("ABCDEF"), "ABC-DEF");
    assert_eq!(display_user_code("ABCDE"), "ABCDE");
}

#[test]
fn random_hex_has_the_stated_entropy_width() {
    let h = random_hex(32);
    assert_eq!(h.len(), 64);
    assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(random_hex(32), random_hex(32));
}

/// C13: every credential a token request carries is a credential in the RFC's own terms
/// (`client_secret` is a password per RFC 6749 section 2.3.1; `code`, `refresh_token` and
/// `device_code` are bearer artifacts per sections 4.1.2 and 6 and RFC 8628 section 3.4), so none
/// of them may appear in a debug format. Pins that `{:?}` cannot become a credential leak for a
/// host that debug-prints the request it just parsed.
#[test]
fn c13_token_request_debug_redacts_every_credential() {
    let cases = vec![
        TokenRequest::AuthorizationCode {
            client_id: ClientId::new("app"),
            client_secret: Some("secret-value".into()),
            code: "code-value".into(),
            redirect_uri: Some("https://app.example/cb".into()),
            code_verifier: Some("verifier-value".into()),
        },
        TokenRequest::ClientCredentials {
            client_id: ClientId::new("app"),
            client_secret: Some("secret-value".into()),
            scope: None,
        },
        TokenRequest::DeviceCode {
            client_id: ClientId::new("app"),
            client_secret: Some("secret-value".into()),
            device_code: "device-value".into(),
        },
        TokenRequest::RefreshToken {
            client_id: ClientId::new("app"),
            client_secret: Some("secret-value".into()),
            refresh_token: "refresh-value".into(),
            scope: None,
        },
    ];
    for request in &cases {
        let printed = format!("{request:?}");
        for leaked in [
            "secret-value",
            "code-value",
            "verifier-value",
            "device-value",
            "refresh-value",
        ] {
            assert!(
                !printed.contains(leaked),
                "debug format leaked {leaked}: {printed}"
            );
        }
        assert!(
            printed.contains("[redacted]"),
            "debug format should say what was redacted: {printed}"
        );
        // client_id is explicitly NOT a secret (RFC 6749 section 2.2), so it must stay visible or
        // the redaction has made the type useless to debug.
        assert!(
            printed.contains("app"),
            "client_id must stay visible: {printed}"
        );
    }
}

/// C13: redaction must not erase the SHAPE of the request. Whether a secret or a PKCE verifier was
/// presented at all is the difference between an `invalid_client` and a missing-credential
/// rejection (RFC 6749 section 5.2), and it is not itself a secret, so `Some` and `None` must stay
/// distinguishable.
#[test]
fn c13_token_request_debug_keeps_the_some_none_distinction() {
    let with_secret = TokenRequest::AuthorizationCode {
        client_id: ClientId::new("app"),
        client_secret: Some("secret-value".into()),
        code: "code-value".into(),
        redirect_uri: None,
        code_verifier: Some("verifier-value".into()),
    };
    let without_secret = TokenRequest::AuthorizationCode {
        client_id: ClientId::new("app"),
        client_secret: None,
        code: "code-value".into(),
        redirect_uri: None,
        code_verifier: None,
    };
    let with = format!("{with_secret:?}");
    let without = format!("{without_secret:?}");
    assert_ne!(
        with, without,
        "a presented secret and an absent one must not debug-print identically"
    );
    assert!(with.contains("Some(\"[redacted]\")"), "{with}");
    assert!(without.contains("client_secret: None"), "{without}");
    assert!(without.contains("code_verifier: None"), "{without}");
}

/// C13: the variant name says which grant is being redeemed and is not a secret, so redaction must
/// leave it readable.
#[test]
fn c13_token_request_debug_still_names_the_grant() {
    let request = TokenRequest::RefreshToken {
        client_id: ClientId::new("app"),
        client_secret: None,
        refresh_token: "refresh-value".into(),
        scope: Some(ScopeSet::parse("read").unwrap()),
    };
    let printed = format!("{request:?}");
    assert!(printed.starts_with("RefreshToken"), "{printed}");
    // The requested scope is a permission boundary the operator must be able to read.
    assert!(printed.contains("read"), "{printed}");
}
