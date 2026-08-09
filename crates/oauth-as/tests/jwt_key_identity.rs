// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! What a signing key IS, as opposed to what it signs: its `kid`, its equality, what it says when
//! it refuses to load, and what it reveals when a host logs the configuration it lives in.
//!
//! `tests/jwt.rs` proves the tokens and the JWKS are RFC-shaped. None of it constrains this
//! surface, and a mutation run said so: the `Debug` redaction, the `PartialEq` implementation, the
//! `kid` accessor and both error `Display` implementations could all be replaced with something
//! degenerate and every existing test still passed. Each of those is a real property. The
//! redaction is the one that matters most: `ServerConfig` derives `Debug`, so a host that logs its
//! config at startup logs whatever this type chooses to print.

#![cfg(feature = "jwt-p256")]
// Requires `jwt-p256`, the built-in ES256 backend, because every test below has to PRODUCE a
// signature. `jwt` alone carries the `Es256Signer`/`Es256Verifier` seam and no curve arithmetic at
// all, so in that build there is nothing here that could run.

use oauth_as::jwt::{AccessTokenFormat, EcdsaP256Key, JwtConfig};
use oauth_as::server::ServerConfig;

/// A fixed scalar, so every assertion below is about the code and not about randomness.
const SCALAR_A: [u8; 32] = [0x2a; 32];
/// A different, also valid, scalar.
const SCALAR_B: [u8; 32] = [0x3b; 32];

const AUDIENCE: &str = "https://rs.example";

fn key(kid: &str, scalar: &[u8; 32]) -> EcdsaP256Key {
    EcdsaP256Key::from_scalar_bytes(kid, scalar).expect("a valid P-256 scalar")
}

/// The scalar as a host would most plausibly find it in a log: lowercase hex.
fn hex(scalar: &[u8; 32]) -> String {
    scalar.iter().map(|b| format!("{b:02x}")).collect()
}

/// RFC 7517 section 4.5 and RFC 7515 section 4.1.4: the `kid` is what makes rotation possible, so
/// the name the host chose has to be the name that comes back, and the same name has to appear in
/// the published key set. A `kid` that is not the configured one is a verifier picking the wrong
/// key out of a rotation set, which fails closed but fails.
#[test]
fn the_configured_kid_is_the_one_reported_and_the_one_published() {
    let config = JwtConfig::new(key("kid-under-test", &SCALAR_A), AUDIENCE);
    assert_eq!(config.kid(), "kid-under-test");
    let jwks = config.jwks();
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(
        jwks.keys[0].kid, "kid-under-test",
        "the JWKS entry must name the key tokens are signed under"
    );
}

/// A key that will not load has to say WHY. The host is the only party who can fix it, the message
/// is the only diagnostic it gets, and the crate's own doc comment promises the message never
/// contains key material. Both halves are asserted, because a message that leaks the scalar is
/// worse than no message.
#[test]
fn key_errors_name_the_problem_and_never_carry_key_material() {
    // SEC 1: a P-256 private scalar is exactly 32 bytes. `SecretKey::from_slice` would left-pad a
    // short input into a different, much weaker key, so the length is checked first.
    let short = EcdsaP256Key::from_scalar_bytes("k", &[0x11u8; 31]).expect_err("31 bytes");
    let text = short.to_string();
    assert!(text.contains("signing key error"), "{text}");
    assert!(text.contains("32 bytes"), "{text}");

    // SEC 1 again: valid scalars are 1 <= d <= n-1, so all zeroes is out of range. Reducing it
    // instead of refusing would silently hand the host a key it did not choose.
    let zero = EcdsaP256Key::from_scalar_bytes("k", &[0u8; 32]).expect_err("zero scalar");
    let text = zero.to_string();
    assert!(text.contains("not a valid P-256 private scalar"), "{text}");

    // The PKCS#8 loader is behind `jwt-pkcs8`, which is a feature of the p256 BACKEND rather than
    // of `jwt` (see Cargo.toml): a build with the DER decoder off has no such refusal to display.
    #[cfg(feature = "jwt-pkcs8")]
    {
        let der = EcdsaP256Key::from_pkcs8_der("k", b"not der").expect_err("not PKCS#8");
        let text = der.to_string();
        assert!(text.contains("PKCS#8"), "{text}");
    }

    // The rejected bytes must not come back out in the diagnostic.
    let secret = [0x11u8; 31];
    let leaked = EcdsaP256Key::from_scalar_bytes("k", &secret).expect_err("31 bytes");
    let text = leaked.to_string();
    let spelling: String = secret.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        !text.contains(&spelling),
        "the error leaked the scalar: {text}"
    );
}

/// Equality is over the PUBLIC identity only: the `kid` plus the public point, never the secret
/// scalar. Both halves have to count, and both have to be REQUIRED, or the type answers "same key"
/// for two keys a verifier would treat as different.
///
/// The three cases below are chosen so that no degenerate implementation survives all of them:
/// always-true fails the second, always-false fails the first, `||` instead of `&&` fails the
/// second, and inverting either comparison fails the first.
#[test]
fn key_equality_is_over_the_public_identity_and_needs_both_halves() {
    let a1 = key("kid-1", &SCALAR_A);
    let a2 = key("kid-1", &SCALAR_A);
    let same_key_other_kid = key("kid-2", &SCALAR_A);
    let same_kid_other_key = key("kid-1", &SCALAR_B);

    // Two handles to the same key, loaded independently.
    assert_eq!(a1, a2);
    // A rotation set holds the same public point under two names only by mistake, but if it did,
    // they are still two entries and a verifier selects between them by `kid`.
    assert_ne!(a1, same_key_other_kid);
    // The dangerous direction: a matching `kid` must never be enough on its own, or a rotated key
    // reusing a name compares equal to the key it replaced.
    assert_ne!(a1, same_kid_other_key);
}

/// `ServerConfig` derives `Debug`, so a host that logs its configuration at startup logs this
/// type. The `Debug` implementation is hand-written precisely so that what it logs is the `kid`
/// and the word `<redacted>`, and never the signing key.
#[test]
fn a_signing_key_is_redacted_in_debug_output_including_through_the_server_config() {
    let scalar_hex = hex(&SCALAR_A);
    let signing = key("kid-1", &SCALAR_A);

    let text = format!("{signing:?}");
    assert!(text.contains("EcdsaP256Key"), "{text}");
    assert!(
        text.contains("kid-1"),
        "the kid is the one thing that IS safe to log: {text}"
    );
    assert!(text.contains("<redacted>"), "{text}");
    assert!(
        !text.contains(&scalar_hex),
        "the signing key was printed: {text}"
    );

    // The path a real host actually takes: `{:?}` on the whole config.
    let mut config = ServerConfig::new("https://as.example", "https://as.example/device");
    config.access_token_format =
        AccessTokenFormat::Jwt(Box::new(JwtConfig::new(signing, AUDIENCE)));
    let text = format!("{config:?}");
    assert!(
        text.contains("<redacted>"),
        "a logged ServerConfig must still redact the signing key: {text}"
    );
    assert!(
        !text.contains(&scalar_hex),
        "logging the config printed the signing key: {text}"
    );
}
