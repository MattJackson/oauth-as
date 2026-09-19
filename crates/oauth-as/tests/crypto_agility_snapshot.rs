// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! THE WIRE-IDENTICAL PROOF for Phase A of crypto agility.
//!
//! Phase A generalises the ES256-hardcoded JWT seam onto an algorithm-tagged one (`JwsAlg`,
//! `JwsSigner`/`JwsVerifier`, the `Jwk` enum) WITHOUT adding any algorithm: ES256 stays the only
//! wired one, and every byte a client or resource server sees must be unchanged. A fixed signing
//! key is deterministic, so its published JWKS document and the JOSE header of a token it signs are
//! fixed strings; this test pins both. If a future edit to the seam changes the serialization —
//! drops `use`/`alg` from the JWKS, reorders members, or alters the header — this snapshot is what
//! goes red before any consumer notices.

#![cfg(feature = "jwt-p256")]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use oauth_as::jwt::{AccessTokenClaims, Audience, EcdsaP256Key, JwtConfig};

/// A fixed, in-range P-256 private scalar. Deterministic input means deterministic public key, and
/// therefore a byte-for-byte reproducible JWKS.
const SCALAR: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

const KID: &str = "snapshot-key";

fn config() -> JwtConfig {
    let key = EcdsaP256Key::from_scalar_bytes(KID, &SCALAR).expect("a valid 32-byte P-256 scalar");
    JwtConfig::new(key, "https://rs.example").with_jwks_uri("https://as.example/jwks")
}

/// The RFC 7517 JWKS document is byte-identical to what 0.9.x served: `kty`, `crv`, `x`, `y`, `kid`,
/// then the `use`/`alg` hints, in that order, with no whitespace.
#[test]
fn the_jwks_document_is_byte_identical() {
    let jwks = serde_json::to_string(&config().jwks()).expect("the JWKS serializes");
    assert_eq!(
        jwks,
        r#"{"keys":[{"kty":"EC","crv":"P-256","x":"UVw9brnjlrkE0_7Kf1T9zQzB6Ze_N13KUVrQpsO0A18","y":"RTa-OlDzGPv5pUdZAqIhUCvvDVfgjFOyzApW8X2fk1Q","kid":"snapshot-key","use":"sig","alg":"ES256"}]}"#,
        "the served JWKS must not change byte-for-byte across the Phase A refactor"
    );
}

/// The RFC 9068 access token's JOSE protected header is byte-identical: `alg`, `typ`, `kid`, in that
/// order, with `alg` sourced from the signer's own algorithm rather than a literal.
#[tokio::test]
async fn the_token_jose_header_is_byte_identical() {
    let claims = AccessTokenClaims::new(
        "https://as.example",
        4_000_000_000,
        Audience::One("https://rs.example".to_string()),
        "client-42",
        "client-42",
        1_700_000_000,
        "jti-snapshot",
    );
    let token = config()
        .sign_access_token(&claims)
        .await
        .expect("the fixed key signs");
    let header_b64 = token.split('.').next().expect("a compact JWS has a header");
    let header = URL_SAFE_NO_PAD
        .decode(header_b64)
        .expect("the header segment is base64url");
    assert_eq!(
        String::from_utf8(header).expect("the header is UTF-8"),
        r#"{"alg":"ES256","typ":"at+jwt","kid":"snapshot-key"}"#,
        "the token JOSE header must not change byte-for-byte across the Phase A refactor"
    );
}
