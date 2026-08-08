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

/// RFC 8628 section 5.1: the user code is short because a human types it, and its entropy is only
/// sufficient in combination with host rate limiting. That makes every bit of it worth defending,
/// so the byte-to-symbol mapping must be exactly uniform rather than approximately so.
///
/// Checked EXHAUSTIVELY over all 256 byte values, which is why `user_code_symbol` exists as a
/// separate function: uniformity is not observable in any single generated code, and a test that
/// could only look at sampled output would have to be a statistical argument instead of a proof.
/// The three facts below are what "unbiased rejection sampling" actually means:
///
/// 1. exactly 240 of the 256 byte values are accepted (240 is the largest multiple of the 20
///    symbol alphabet that fits in a byte),
/// 2. every accepted value maps into the alphabet, and
/// 3. every symbol has exactly the same number of preimages, so no symbol is more likely.
///
/// Widening the accepted range by even one value (`<` becoming `<=`) breaks fact 3 by giving the
/// first symbol a thirteenth preimage; narrowing or inverting it breaks facts 1 and 3; replacing
/// the modulo with a division breaks fact 3 by making the last eight symbols unreachable.
#[test]
fn the_user_code_symbol_draw_is_exactly_uniform_over_the_alphabet() {
    let mut counts = std::collections::BTreeMap::new();
    let mut accepted = 0usize;
    for byte in 0u8..=255 {
        match user_code_symbol(byte) {
            Some(symbol) => {
                accepted += 1;
                assert!(
                    USER_CODE_ALPHABET.contains(&symbol),
                    "byte {byte} produced {symbol}, which is outside the RFC 8628 s6.1 alphabet"
                );
                *counts.entry(symbol).or_insert(0usize) += 1;
            }
            None => assert!(
                byte >= USER_CODE_REJECT_AT,
                "byte {byte} is below the rejection bound and must have been accepted"
            ),
        }
    }

    assert_eq!(
        accepted, 240,
        "exactly the 240 values below the rejection bound may be folded into the alphabet"
    );
    assert_eq!(
        counts.len(),
        USER_CODE_ALPHABET.len(),
        "every symbol in the alphabet must be reachable"
    );
    for (symbol, count) in &counts {
        assert_eq!(
            *count, 12,
            "symbol {} has {count} preimages, not the uniform 12: the draw is biased",
            *symbol as char
        );
    }
}

/// The generator itself, on top of the mapping above: it must keep drawing until it has exactly
/// `len` symbols (a rejected byte costs a redraw, never a short code), and never emit anything
/// outside the RFC 8628 section 6.1 alphabet.
#[test]
fn random_user_code_redraws_rejections_rather_than_shortening_the_code() {
    for len in [MIN_USER_CODE_LENGTH, 9, 16] {
        let code = random_user_code(len);
        assert_eq!(code.len(), len, "a rejected byte must cost a redraw");
        assert!(code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)));
    }
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
