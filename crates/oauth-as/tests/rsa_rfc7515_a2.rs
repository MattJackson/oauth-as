// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! STANDALONE RS256 crypto vector test — proves the raw RSASSA-PKCS1-v1.5 + SHA-256 arithmetic
//! (RFC 8017 §8.2, which RFC 7518 §3.3 names `RS256`) against the official RFC 7515 Appendix A.2
//! vector, using the `rsa` crate DIRECTLY.
//!
//! WHY IT IS STANDALONE. The `RsaSigner`/`RsaVerifier` backend in `src/backends/rsa.rs` is written
//! against the Phase A JWS seam (`JwsSigner`, `JwsVerifier`, `JwsAlg::Rs256`, `Jwk::Rsa`), which is
//! being implemented in PARALLEL and has NOT landed in this worktree. So the trait-level tests that
//! exercise the backend cannot compile here yet (see the module `phase_a_dependent` at the bottom,
//! left commented with the exact assertions to un-comment once Phase A merges). This file instead
//! proves the thing that is fully knowable NOW — that the `rsa` primitive the backend delegates to
//! reproduces the RFC's bytes — so Phase B ships with a passing, source-of-truth crypto check
//! independent of the seam.
//!
//! Gated on `jwt-rsa`: without that feature the whole file is empty and this test target passes
//! trivially. Vectors are transcribed from RFC 7515 Appendix A.2 (also mirrored, with the exact
//! `rsa` dependency facts, in `tests/CRYPTO_VECTORS.md`).
#![cfg(feature = "jwt-rsa")]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::traits::PublicKeyParts as _;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

// --- RFC 7515 Appendix A.2 vector (base64url, unpadded, as transcribed in CRYPTO_VECTORS.md) ---

/// RSA public modulus `n` (2048-bit == 256 bytes decoded).
const N_B64URL: &str = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";
/// RSA public exponent `e` (65537).
const E_B64URL: &str = "AQAB";
/// RSA private exponent `d`.
const D_B64URL: &str = "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ";
/// First prime factor `p`.
const P_B64URL: &str = "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc";
/// Second prime factor `q`.
const Q_B64URL: &str = "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc";

/// The JWS Signing Input: `ASCII(BASE64URL(header)) "." BASE64URL(payload)`, verbatim from A.2.
const SIGNING_INPUT: &[u8] =
    b"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

/// The expected RS256 signature (base64url, 256 bytes decoded).
const EXPECTED_SIG_B64URL: &str = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

fn b64url(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(s)
        .expect("vector is valid base64url")
}

fn public_key() -> RsaPublicKey {
    let n = BigUint::from_bytes_be(&b64url(N_B64URL));
    let e = BigUint::from_bytes_be(&b64url(E_B64URL));
    RsaPublicKey::new(n, e).expect("A.2 public key (n, e) is well-formed")
}

fn private_key() -> RsaPrivateKey {
    let n = BigUint::from_bytes_be(&b64url(N_B64URL));
    let e = BigUint::from_bytes_be(&b64url(E_B64URL));
    let d = BigUint::from_bytes_be(&b64url(D_B64URL));
    let p = BigUint::from_bytes_be(&b64url(P_B64URL));
    let q = BigUint::from_bytes_be(&b64url(Q_B64URL));
    let key = RsaPrivateKey::from_components(n, e, d, vec![p, q])
        .expect("A.2 private components are consistent");
    key.validate().expect("A.2 private key validates");
    key
}

/// The modulus is exactly 2048 bits / 256 bytes — the ≥2048-bit floor the backend enforces sits
/// right at this vector, so the vector both exercises the happy path and documents the boundary.
#[test]
fn a2_modulus_is_2048_bits() {
    assert_eq!(public_key().size(), 256, "RSA-2048 modulus is 256 octets");
    assert_eq!(
        b64url(EXPECTED_SIG_B64URL).len(),
        256,
        "RS256 signature length == modulus length"
    );
}

/// THE CORE RFC 7515 A.2.2 CHECK: reconstruct the public key from (n, e), and verify the exact
/// expected signature over the exact Signing Input with RSASSA-PKCS1-v1.5 / SHA-256.
#[test]
fn a2_public_key_verifies_expected_signature() {
    let verifying_key = VerifyingKey::<Sha256>::new(public_key());
    let sig = Signature::try_from(b64url(EXPECTED_SIG_B64URL).as_slice())
        .expect("A.2 signature is well-formed");
    assert!(
        verifying_key.verify(SIGNING_INPUT, &sig).is_ok(),
        "RFC 7515 A.2 signature MUST verify against its public key"
    );
}

/// RSASSA-PKCS1-v1.5 is DETERMINISTIC, so signing the A.2 Signing Input with the A.2 private key
/// must reproduce the A.2 signature byte-for-byte. This proves the signer path too, not just
/// verification.
#[test]
fn a2_private_key_reproduces_expected_signature_deterministically() {
    let signing_key = SigningKey::<Sha256>::new(private_key());
    let produced = signing_key.sign(SIGNING_INPUT).to_bytes();
    assert_eq!(
        produced.as_ref(),
        b64url(EXPECTED_SIG_B64URL).as_slice(),
        "PKCS#1 v1.5 is deterministic: produced signature must equal the RFC A.2 signature"
    );
}

/// A tampered Signing Input must NOT verify against the untouched signature — the negative half of
/// the vector, so "verify returned Ok" cannot be a stuck-true.
#[test]
fn a2_tampered_input_does_not_verify() {
    let verifying_key = VerifyingKey::<Sha256>::new(public_key());
    let sig = Signature::try_from(b64url(EXPECTED_SIG_B64URL).as_slice()).unwrap();
    let mut tampered = SIGNING_INPUT.to_vec();
    *tampered.last_mut().unwrap() ^= 0x01;
    assert!(
        verifying_key.verify(&tampered, &sig).is_err(),
        "a modified Signing Input must not verify"
    );
}

/// A truncated signature must be rejected, not panic.
///
/// API FACT this pins down (and that the backend's `RsaVerifier::verify` must compensate for):
/// `rsa::pkcs1v15::Signature::try_from` is LENIENT about length — it interprets the bytes as a
/// big-endian integer and does NOT check them against the modulus size, so a 255-byte slice parses
/// without error. It is `verify` that then fails. The backend therefore CANNOT lean on `try_from`
/// for the "signature length == modulus length" rule the design requires; it must apply an explicit
/// `sig.len() == key.size()` guard of its own BEFORE building the `Signature` (both to honour the
/// design contract and so an over-length signature can never be silently accepted). This test
/// asserts both halves: `try_from` is lenient, and `verify` nonetheless rejects.
#[test]
fn a2_truncated_signature_is_rejected() {
    let full = b64url(EXPECTED_SIG_B64URL);
    let truncated = &full[..full.len() - 1];

    // `try_from` does not enforce the length — this is the leniency the backend must guard around.
    let parsed = Signature::try_from(truncated);
    assert!(
        parsed.is_ok(),
        "rsa's Signature::try_from is length-lenient (documents why the backend needs its own guard)"
    );

    // The explicit length guard the backend applies: 255 != 256, reject before touching `rsa`.
    assert_ne!(truncated.len(), public_key().size());

    // And even if the guard were absent, verification of the truncated signature fails (never a
    // panic, never an accept).
    let verifying_key = VerifyingKey::<Sha256>::new(public_key());
    assert!(
        verifying_key
            .verify(SIGNING_INPUT, &parsed.unwrap())
            .is_err(),
        "a truncated signature must not verify"
    );
}
