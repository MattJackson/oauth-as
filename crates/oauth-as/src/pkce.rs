// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! PKCE (RFC 7636), `S256` only per OAuth 2.1. The derivation is
//! `code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))` with no padding
//! (section 4.2), and `tests/rfc_vectors.rs` locks it against the appendix B vector.

use crate::crypto::CryptoProvider;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

/// Compute the `S256` challenge for a verifier (RFC 7636 section 4.2).
#[cfg(any(feature = "rustcrypto", feature = "aws-lc", feature = "fips"))]
pub fn code_challenge_s256(verifier: &str) -> String {
    code_challenge_s256_with_crypto(&crate::crypto::builtin(), verifier)
}

/// Perform this operation with the explicitly selected crypto provider.
pub fn code_challenge_s256_with_crypto(crypto: &dyn CryptoProvider, verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(crypto.sha256(verifier.as_bytes()))
}

/// Verify a presented verifier against a stored challenge (RFC 7636 section 4.6): recompute and
/// compare. The comparison is constant time in the challenge length; an S256 challenge is a fixed
/// 43 characters so length itself leaks nothing.
#[cfg(any(feature = "rustcrypto", feature = "aws-lc", feature = "fips"))]
pub fn verify_s256(verifier: &str, challenge: &str) -> bool {
    verify_s256_with_crypto(&crate::crypto::builtin(), verifier, challenge)
}

/// Perform this operation with the explicitly selected crypto provider.
pub fn verify_s256_with_crypto(
    crypto: &dyn CryptoProvider,
    verifier: &str,
    challenge: &str,
) -> bool {
    let computed = code_challenge_s256_with_crypto(crypto, verifier);
    crypto.ct_eq(computed.as_bytes(), challenge.as_bytes())
}

/// Whether a string is a well-formed `code_verifier` (RFC 7636 section 4.1): 43 to 128 characters
/// of `ALPHA / DIGIT / "-" / "." / "_" / "~"`.
pub fn verifier_is_valid(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

#[cfg(test)]
#[path = "tests/pkce.rs"]
mod tests;
