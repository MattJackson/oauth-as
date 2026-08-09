// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The `jwt` plane: key handling, RFC 9068 signing, the RFC 7517 JWKS, and verification.
//!
//! The core plane already signs, because `exercise::config` sets `AccessTokenFormat::Jwt` when
//! this feature is on, so every token issued there goes through ES256. What this adds is the rest
//! of the surface a host touches: key import and export, the published key set, and the
//! VERIFICATION half that `jar`, `dpop` and `client_assertion` all rest on.

use oauth_as::jwt::{EcdsaP256Key, PublicJwk};

pub fn plane() -> u64 {
    let mut acc: u64 = 0;

    let key = EcdsaP256Key::generate("probe-es256-2");
    acc = acc.wrapping_add(key.kid().len() as u64);

    // PKCS#8 export and re-import. This is the ONLY thing p256's `pkcs8` sub-feature buys, and it
    // is behind this crate's own `jwt-pkcs8` feature, so the report can show BOTH what it costs a
    // host that uses it and what it costs a host that merely has it compiled in.
    #[cfg(feature = "f-jwt-pkcs8")]
    if let Ok(der) = key.to_pkcs8_der() {
        acc = acc.wrapping_add(der.len() as u64);
        if let Ok(reloaded) = EcdsaP256Key::from_pkcs8_der("probe-es256-3", &der) {
            acc = acc.wrapping_add(reloaded.kid().len() as u64);
        }
    }
    // The raw-scalar constructor, which is what a host with a KMS-held key uses.
    let scalar = [7u8; 32];
    if let Ok(from_scalar) = EcdsaP256Key::from_scalar_bytes("probe-es256-4", &scalar) {
        acc = acc.wrapping_add(from_scalar.kid().len() as u64);
    }

    // RFC 7517: the JWK and the key set a resource server fetches.
    let jwk = key.public_jwk();
    acc = acc.wrapping_add(
        serde_json::to_string(&jwk)
            .map(|s| s.len() as u64)
            .unwrap_or(0),
    );

    // The VERIFY side: parse a published JWK back and compute its RFC 7638 thumbprint. One copy
    // of this code serves `jar`, `dpop` and `client_assertion` (see the VERIFICATION banner in
    // src/jwt.rs), so it is charged to `jwt` here rather than three times over.
    if let Ok(value) = serde_json::to_value(&jwk) {
        if let Ok(parsed) = PublicJwk::from_json(&value) {
            acc = acc.wrapping_add(parsed.thumbprint().len() as u64);
            acc = acc.wrapping_add(parsed.kty().len() as u64);
        }
    }

    std::hint::black_box(acc)
}
