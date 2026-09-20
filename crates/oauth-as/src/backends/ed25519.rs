// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! THE BUILT-IN EdDSA (Ed25519) BACKEND, behind `jwt-ed25519`. Phase C of the crypto-agility
//! work, the EdDSA sibling of the `jwt-p256` ES256 backend in `crate::jwt`.
//!
//! # The Ed25519 backend module
//!
//! This module is WIRED and LIVE: `lib.rs` pulls it in with `mod backends;` behind the
//! `jwt-ed25519` feature, and it builds on the crypto-agile vocabulary of the JWS seam in
//! `src/jwt.rs` — [`JwsAlg`], [`JwsSignature`], the `Jwk::Okp` variant, [`OkpCurve`], the
//! [`JwsSigner`]/[`JwsVerifier`] traits, and the `KeyError`/`SignerError` error types (gated on
//! `jwt`, so an EdDSA-only build has them too). The feature-INDEPENDENT proof of the RFC 8037 A.4
//! crypto (`ed25519-dalek` driven directly, no seam) lives in `tests/ed25519_rfc8037_vector.rs`;
//! the `#[cfg(test)] mod tests` at the bottom of this file drives the same vector THROUGH the seam.
//!
//! # Ed25519 ONLY
//!
//! [`JwsAlg::EdDsa`] means Ed25519 (RFC 8037 `OKP`/`Ed25519`) and nothing else. Ed448 shares the
//! `EdDSA` JOSE algorithm name (RFC 8037 §3.1) but is a different curve with a different key and
//! signature size; this crate does not implement it, so [`Ed25519Verifier::verify`] rejects any
//! OKP key whose curve is not `Ed25519`, and the `classify_alg("EdDSA")` arm resolves to Ed25519
//! only. That the JOSE name is shared is the one place "EdDSA" is ambiguous on the wire.

#![cfg(feature = "jwt-ed25519")]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
#[cfg(feature = "jwt-ed25519-pkcs8")]
use ed25519_dalek::pkcs8::DecodePrivateKey as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use std::fmt;
use std::future::Future;

use crate::jwt::{
    Jwk, JwsAlg, JwsSignature, JwsSigner, JwsVerifier, KeyError, OkpCurve, SignerError,
};

/// An Ed25519 public key, private seed, and signature are each a fixed width (RFC 8032 §5.1): the
/// public key `x` and the seed `d` are 32 bytes, the signature is 64. A width that is off by any
/// amount is a different value, never a paddable one, so every decode below checks it exactly.
const ED25519_KEY_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;

/// An Ed25519 signing key plus the `kid` that names it, mirroring `crate::jwt::EcdsaP256Key`.
///
/// THE BUILT-IN EdDSA BACKEND. The private seed lives in this process, which is the right answer
/// for most deployments and the wrong one for a deployment whose policy forbids it — for that, the
/// [`JwsSigner`] seam takes a host implementation (e.g. a KMS) instead, exactly as it does for
/// ES256. `sign` is deterministic (RFC 8032), so unlike a randomised scheme it consumes no
/// entropy at sign time and needs no `rand` feature.
#[derive(Clone)]
pub struct Ed25519Signer {
    kid: String,
    signing: SigningKey,
}

impl Ed25519Signer {
    /// Load from the raw 32-byte Ed25519 private seed (RFC 8032 §5.1.5; the `d` member of an OKP
    /// JWK, RFC 8037 §2).
    ///
    /// The seed is exactly 32 bytes. Anything else is a caller mistake failed loudly on, the same
    /// way `EcdsaP256Key::from_scalar_bytes` refuses a short P-256 scalar rather than left-padding
    /// it into a valid-but-different key.
    pub fn from_seed_bytes(kid: impl Into<String>, seed: &[u8]) -> Result<Self, KeyError> {
        let seed: [u8; ED25519_KEY_LEN] = seed
            .try_into()
            .map_err(|_| KeyError::new("an Ed25519 private seed is exactly 32 bytes"))?;
        Ok(Ed25519Signer {
            kid: kid.into(),
            // `SigningKey::from_bytes` is infallible in ed25519-dalek 2.x: every 32-byte string is
            // a valid seed (the scalar is derived by hashing it, so there is no out-of-range seed
            // to reject the way there is for a P-256 scalar).
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// Load from a PKCS#8 (RFC 5208 / RFC 8410 `OneAsymmetricKey`) DER document, the format most
    /// KMS exports and `openssl pkcs8` emit for an Ed25519 key. This is the EdDSA sibling of
    /// `EcdsaP256Key::from_pkcs8_der`, for a host whose key material arrives as the DER its KMS or
    /// `openssl` already produced rather than as the raw 32-byte seed `from_seed_bytes` takes.
    ///
    /// DER, not PEM: `ed25519-dalek`'s `pem` feature is deliberately left off (see `Cargo.toml`), so
    /// this accepts the binary `PrivateKeyInfo`, never a `-----BEGIN PRIVATE KEY-----` text wrapper.
    /// Any input that is not a well-formed PKCS#8 Ed25519 private key is an `Err`, never a panic.
    #[cfg(feature = "jwt-ed25519-pkcs8")]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwt-ed25519-pkcs8")))]
    pub fn from_pkcs8_der(kid: impl Into<String>, der: &[u8]) -> Result<Self, KeyError> {
        let signing = SigningKey::from_pkcs8_der(der)
            .map_err(|_| KeyError::new("not a valid PKCS#8 Ed25519 private key"))?;
        Ok(Ed25519Signer {
            kid: kid.into(),
            signing,
        })
    }

    /// The key identifier published in the JWKS and in every token header.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The base64url (unpadded) 32-byte public key `x`, exactly as it appears in an OKP JWK.
    fn public_x(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing.verifying_key().to_bytes())
    }

    /// The PUBLIC half as an OKP JWK. There is no method that produces a JWK containing `d`.
    pub fn public_jwk(&self) -> Jwk {
        Jwk::Okp {
            crv: OkpCurve::Ed25519,
            x: self.public_x(),
            kid: Some(self.kid.clone()),
        }
    }

    /// The 64-byte Ed25519 signature over `signing_input` (RFC 8032 detached form, which is the
    /// `EdDSA` JWS signature of RFC 8037 §3.1 — no separate encoding step, unlike ES256's DER→r||s
    /// conversion).
    fn sign_ed25519(&self, signing_input: &[u8]) -> [u8; ED25519_SIG_LEN] {
        // Deterministic and total: signing cannot fail for in-process key material, so there is no
        // error arm to turn into a `server_error`. The seam still returns `Result` because a host
        // signer (a KMS) can fail; this backend simply never takes that arm.
        self.signing.sign(signing_input).to_bytes()
    }
}

impl fmt::Debug for Ed25519Signer {
    /// Redacted: a host that logs its `ServerConfig` must not thereby log its signing seed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Signer")
            .field("kid", &self.kid)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl PartialEq for Ed25519Signer {
    /// Equality over the PUBLIC identity only (kid plus public key), never touching the seed.
    fn eq(&self, other: &Self) -> bool {
        self.kid == other.kid
            && self.signing.verifying_key().to_bytes() == other.signing.verifying_key().to_bytes()
    }
}

impl Eq for Ed25519Signer {}

impl JwsSigner for Ed25519Signer {
    fn alg(&self) -> JwsAlg {
        JwsAlg::EdDsa
    }

    fn sign(
        &self,
        signing_input: &[u8],
    ) -> impl Future<Output = Result<JwsSignature, SignerError>> + Send {
        // Computed BEFORE the async block so nothing borrows `signing_input` across a suspension
        // point that does not exist: the seed is in-process, so the future is ready on first poll.
        let signature = JwsSignature::EdDsa(self.sign_ed25519(signing_input));
        async move { Ok(signature) }
    }

    fn public_jwk(&self) -> Jwk {
        Ed25519Signer::public_jwk(self)
    }
}

/// The built-in backend's verifying half: EdDSA/Ed25519 over `ed25519-dalek`, using
/// `VerifyingKey::verify_strict`.
///
/// A unit struct so it can be INSTALLED, the same way [`crate::jwt::P256Verifier`] is: a host's own
/// EdDSA verifier replaces it, and `AuthorizationServer` falls back to this one when the host
/// installs none and `jwt-ed25519` is compiled in.
///
/// # `verify_strict`, not `verify`, and it is load bearing
///
/// `VerifyingKey::verify` implements the RFC 8032 §5.1.7 COFACTORED equation, which accepts
/// small-order public keys and non-canonically encoded points. That is the historical Ed25519
/// malleability footgun: one message has more than one accepting `(A, signature)`, so a value a
/// deployment recorded as unique stops being unique. `VerifyingKey::verify_strict` uses the
/// cofactorLESS equation and additionally rejects small-order `A` and non-canonical `R` — the
/// ZIP215 hardening. This crate treats signature verification as the one place an
/// algorithm-confusion or malleability bug is catastrophic (see the VERIFICATION banner in
/// `src/jwt.rs`), so this backend uses `verify_strict` exclusively. The rejection is proven in
/// `tests/ed25519_rfc8037_vector.rs`: an all-zeros key with an all-zeros signature is ACCEPTED by
/// `verify` and REFUSED by `verify_strict`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ed25519Verifier;

impl JwsVerifier for Ed25519Verifier {
    fn alg(&self) -> JwsAlg {
        JwsAlg::EdDsa
    }

    /// `true` iff `signature` is a valid Ed25519 signature (per `verify_strict`) over exactly
    /// `signing_input` under exactly `key`, where `key` is an OKP/Ed25519 public JWK.
    ///
    /// Every failure returns `false` and NOTHING panics, for any input: a non-OKP key, an OKP key
    /// on a curve other than Ed25519, an `x` that is not 32 base64url bytes, a signature that is
    /// not exactly 64 bytes (INCLUDING a zero-length one — the third JWS segment is
    /// attacker-controlled bytes of any length), and a signature that simply does not verify all
    /// have the one safe answer.
    fn verify(&self, key: &Jwk, signing_input: &[u8], signature: &[u8]) -> bool {
        // Reject any non-OKP key (an EC/P-256 key must never verify under the EdDSA backend — that
        // is exactly the algorithm confusion the seam exists to prevent) and any OKP curve other
        // than Ed25519 (Ed448 shares the JOSE `EdDSA` name but is not this curve).
        let Jwk::Okp { crv, x, .. } = key else {
            return false;
        };
        if !matches!(crv, OkpCurve::Ed25519) {
            return false;
        }
        verify_ed25519(x, signing_input, signature)
    }
}

/// Verify an Ed25519 signature (RFC 8037 §3.1) over `signing_input` given the base64url public key
/// `x`, using `verify_strict`. `false` for every failure; never panics. This is the crate's ONE
/// implementation of EdDSA verification, mirroring `crate::jwt::verify_es256`.
pub fn verify_ed25519(x_b64: &str, signing_input: &[u8], signature: &[u8]) -> bool {
    // The third JWS segment is attacker-controlled and of ANY length; match into the fixed array
    // rather than slicing, so a 0-, 63-, or 65-byte signature is a `false`, never a panic.
    let Ok(sig_bytes): Result<[u8; ED25519_SIG_LEN], _> = signature.try_into() else {
        return false;
    };
    let Ok(x_bytes) = URL_SAFE_NO_PAD.decode(x_b64) else {
        return false;
    };
    let Ok(x_arr): Result<[u8; ED25519_KEY_LEN], _> = x_bytes.try_into() else {
        return false;
    };
    // `from_bytes` decompresses the point but does NOT reject small-order keys; `verify_strict`
    // below is what closes that. A point that does not decompress at all is rejected here.
    let Ok(verifying_key) = VerifyingKey::from_bytes(&x_arr) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify_strict(signing_input, &signature)
        .is_ok()
}

// NOTE: OKP JWK parsing and the RFC 7638 OKP thumbprint are NOT duplicated here. The canonical,
// production implementations are `crate::jwt::Jwk::from_json` (routed through `serde` too) and
// `crate::jwt::Jwk::thumbprint`; the tests below exercise those directly so this backend cannot
// drift a second, unreviewed copy of either.

// TRAIT-LEVEL TESTS.
//
// These exercise `Ed25519Signer`/`Ed25519Verifier` THROUGH the `JwsSigner`/`JwsVerifier` seam and
// the `Jwk::Okp` variant. The raw crypto they rest on is proven feature-independently, without the
// seam, in `tests/ed25519_rfc8037_vector.rs`.
#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8037 A.4 fixtures (see tests/CRYPTO_VECTORS.md §2).
    const SEED_B64: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
    const X_B64: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    const SIGNING_INPUT: &[u8] = b"eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
    const EXPECTED_SIG_B64: &str =
        "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

    fn seed() -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(SEED_B64).unwrap()
    }

    #[tokio::test]
    async fn signer_reports_eddsa_and_matches_rfc_vector() {
        let signer = Ed25519Signer::from_seed_bytes("k1", &seed()).unwrap();
        assert!(matches!(signer.alg(), JwsAlg::EdDsa));
        let JwsSignature::EdDsa(sig) = JwsSigner::sign(&signer, SIGNING_INPUT).await.unwrap()
        else {
            panic!("Ed25519Signer must produce a JwsSignature::EdDsa");
        };
        assert_eq!(
            sig.to_vec(),
            URL_SAFE_NO_PAD.decode(EXPECTED_SIG_B64).unwrap()
        );
    }

    #[test]
    fn public_jwk_is_okp_ed25519() {
        let signer = Ed25519Signer::from_seed_bytes("k1", &seed()).unwrap();
        let Jwk::Okp { crv, x, kid } = signer.public_jwk() else {
            panic!("public_jwk must be Jwk::Okp");
        };
        assert!(matches!(crv, OkpCurve::Ed25519));
        assert_eq!(x, X_B64);
        assert_eq!(kid.as_deref(), Some("k1"));
    }

    #[test]
    fn verifier_accepts_the_vector_and_reports_eddsa() {
        let verifier = Ed25519Verifier;
        assert!(matches!(verifier.alg(), JwsAlg::EdDsa));
        let key = Jwk::Okp {
            crv: OkpCurve::Ed25519,
            x: X_B64.to_string(),
            kid: None,
        };
        let sig = URL_SAFE_NO_PAD.decode(EXPECTED_SIG_B64).unwrap();
        assert!(verifier.verify(&key, SIGNING_INPUT, &sig));
    }

    #[test]
    fn verifier_rejects_wrong_length_signature_without_panicking() {
        let verifier = Ed25519Verifier;
        let key = Jwk::Okp {
            crv: OkpCurve::Ed25519,
            x: X_B64.to_string(),
            kid: None,
        };
        // Zero-length, 63-byte, 65-byte: every non-64 length is a `false`, never a panic.
        assert!(!verifier.verify(&key, SIGNING_INPUT, &[]));
        assert!(!verifier.verify(&key, SIGNING_INPUT, &[0u8; 63]));
        assert!(!verifier.verify(&key, SIGNING_INPUT, &[0u8; 65]));
    }

    #[test]
    fn verifier_rejects_tampered_input() {
        let verifier = Ed25519Verifier;
        let key = Jwk::Okp {
            crv: OkpCurve::Ed25519,
            x: X_B64.to_string(),
            kid: None,
        };
        let sig = URL_SAFE_NO_PAD.decode(EXPECTED_SIG_B64).unwrap();
        assert!(!verifier.verify(&key, b"not the signed input", &sig));
    }

    #[test]
    fn verifier_rejects_non_okp_key() {
        // An EC key must never verify under the EdDSA backend: this is the algorithm-confusion
        // guard.
        let verifier = Ed25519Verifier;
        let ec_key = crate::jwt::sample_ec_jwk_for_tests();
        let sig = URL_SAFE_NO_PAD.decode(EXPECTED_SIG_B64).unwrap();
        assert!(!verifier.verify(&ec_key, SIGNING_INPUT, &sig));
    }

    #[test]
    fn small_order_public_key_is_rejected() {
        // The all-zeros OKP public key is a small-order point; `verify_strict` must refuse it (the
        // ZIP215 hardening), so `verify` returns false even for the all-zeros signature that the
        // lenient cofactored check would accept. Proven at the raw layer in
        // tests/ed25519_rfc8037_vector.rs.
        let key = Jwk::Okp {
            crv: OkpCurve::Ed25519,
            x: URL_SAFE_NO_PAD.encode([0u8; 32]),
            kid: None,
        };
        assert!(!Ed25519Verifier.verify(&key, b"msg", &[0u8; 64]));
    }

    #[test]
    fn thumbprint_member_order_is_crv_kty_x() {
        use sha2::{Digest as _, Sha256};
        // Exercises the CANONICAL `Jwk::thumbprint` (the production path), not a backend-local
        // copy. Regenerated from the canonical RFC 7638 §3.2 JSON (`{crv, kty, x}`, lexicographic,
        // no whitespace) so a reorder of the members in `Jwk::thumbprint` goes red here.
        let expected = {
            let json = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{X_B64}"}}"#);
            URL_SAFE_NO_PAD.encode(Sha256::digest(json.as_bytes()))
        };
        let jwk = Jwk::Okp {
            crv: OkpCurve::Ed25519,
            x: X_B64.to_string(),
            kid: None,
        };
        assert_eq!(jwk.thumbprint(), expected);
    }

    #[test]
    fn parse_rejects_private_and_foreign_curve() {
        // Exercises the CANONICAL `Jwk::from_json` (the production parse, routed through `serde`
        // too), not a backend-local copy.
        // `d` present -> refused.
        let with_d = serde_json::json!({"kty":"OKP","crv":"Ed25519","x":X_B64,"d":SEED_B64});
        assert!(Jwk::from_json(&with_d).is_err());
        // Ed448 shares the EdDSA name but is a foreign curve here.
        let ed448 = serde_json::json!({"kty":"OKP","crv":"Ed448","x":X_B64});
        assert!(Jwk::from_json(&ed448).is_err());
        // Well-formed public key -> accepted as Jwk::Okp.
        let ok = serde_json::json!({"kty":"OKP","crv":"Ed25519","x":X_B64});
        assert!(matches!(Jwk::from_json(&ok), Ok(Jwk::Okp { .. })));
    }

    /// `from_pkcs8_der` round-trips: encode the RFC 8037 A.4 seed to PKCS#8 DER, load it back, and
    /// the signer publishes the vector's `x`, signs the vector input, and the verifier accepts the
    /// signature under the JWK the signer published. DER is produced in-test via `EncodePrivateKey`,
    /// so no fixture bytes are pinned and the encode/decode pair is exercised end to end.
    #[cfg(feature = "jwt-ed25519-pkcs8")]
    #[test]
    fn from_pkcs8_der_roundtrips_and_matches_public_jwk() {
        use ed25519_dalek::pkcs8::EncodePrivateKey as _;

        let seed_bytes: [u8; ED25519_KEY_LEN] = seed().try_into().unwrap();
        let der = SigningKey::from_bytes(&seed_bytes)
            .to_pkcs8_der()
            .expect("an Ed25519 signing key encodes to PKCS#8 DER");

        let signer = Ed25519Signer::from_pkcs8_der("k1", der.as_bytes())
            .expect("a valid PKCS#8 Ed25519 key loads");

        let Jwk::Okp { crv, x, kid } = signer.public_jwk() else {
            panic!("public_jwk must be Jwk::Okp");
        };
        assert!(matches!(crv, OkpCurve::Ed25519));
        assert_eq!(
            x, X_B64,
            "the PKCS#8-loaded key publishes the A.4 vector's x"
        );
        assert_eq!(kid.as_deref(), Some("k1"));

        let sig = signer.sign_ed25519(SIGNING_INPUT);
        assert!(
            Ed25519Verifier.verify(&signer.public_jwk(), SIGNING_INPUT, &sig),
            "a signature from the PKCS#8-loaded signer verifies under its own JWK"
        );
    }

    /// Malformed DER is an `Err`, never a panic.
    #[cfg(feature = "jwt-ed25519-pkcs8")]
    #[test]
    fn from_pkcs8_der_rejects_malformed_der() {
        assert!(Ed25519Signer::from_pkcs8_der("k", b"not pkcs8 der").is_err());
        assert!(Ed25519Signer::from_pkcs8_der("k", &[]).is_err());
    }
}
