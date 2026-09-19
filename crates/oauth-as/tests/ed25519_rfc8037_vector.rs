//! STANDALONE Ed25519 crypto proof for the Phase C (`jwt-ed25519`) backend, driving
//! `ed25519-dalek` DIRECTLY against the official RFC 8037 Appendix A.4 vector.
//!
//! # Why this test does not touch the crate's own backend
//!
//! `src/backends/ed25519.rs` is written against the Phase A JWS seam (`JwsAlg`, `JwsSignature`,
//! `Jwk::Okp`, `JwsSigner`/`JwsVerifier`), which has NOT landed in this worktree, so it does not
//! compile into the crate yet. This file therefore proves the RAW crypto the backend rests on,
//! with no dependency on Phase A: the same seed, signing input, and expected signature the backend
//! will produce, verified here through `ed25519-dalek` exactly as the backend calls it
//! (`SigningKey::from_bytes` -> `sign` -> `verify_strict`). The trait-level tests that exercise the
//! backend THROUGH the seam live in `src/backends/ed25519.rs`'s own `#[cfg(test)] mod tests` and
//! come online with Phase A.
//!
//! Vector source: RFC 8037 Appendix A.4 ("Ed25519 Signing Example"); transcribed in
//! `tests/CRYPTO_VECTORS.md` §2.
//!
//! Feature-gated on `jwt-ed25519` (run: `cargo test -p oauth-as --features jwt-ed25519`). Without
//! the feature this file is empty and the crate's normal test run is unaffected.
#![cfg(feature = "jwt-ed25519")]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

/// RFC 8037 A.4 §2.1: the 32-byte private seed `d`, base64url unpadded.
const SEED_B64: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
/// RFC 8037 A.4 §2.2: the 32-byte public key `x`, base64url unpadded.
const PUBLIC_X_B64: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
/// RFC 8037 A.4 §2.4: the JWS Signing Input `BASE64URL(header) "." BASE64URL(payload)`.
const SIGNING_INPUT: &[u8] = b"eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
/// RFC 8037 A.4 §2.5: the expected 64-byte signature, base64url unpadded.
const EXPECTED_SIG_B64: &str =
    "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

fn b64(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(s)
        .expect("valid base64url in RFC vector")
}

fn seed_key() -> SigningKey {
    let seed: [u8; 32] = b64(SEED_B64).try_into().expect("Ed25519 seed is 32 bytes");
    SigningKey::from_bytes(&seed)
}

/// The public key derived from the RFC seed equals the RFC's published `x`. If the backend's
/// `public_jwk()` ever disagrees with the key it signs under, this is the layer that catches it.
#[test]
fn derived_public_key_matches_rfc_x() {
    let vk = seed_key().verifying_key();
    assert_eq!(
        vk.to_bytes().as_slice(),
        b64(PUBLIC_X_B64).as_slice(),
        "public key derived from RFC 8037 A.4 seed must equal the RFC's x",
    );
}

/// END-TO-END: signing the RFC signing input with the RFC seed reproduces the RFC signature BYTE
/// FOR BYTE (Ed25519 is deterministic, so this is an exact equality, not merely "verifies"), and
/// `verify_strict` then accepts it under the RFC public key.
#[test]
fn rfc8037_a4_sign_reproduces_vector_and_verify_strict_accepts() {
    let sk = seed_key();

    let signature: Signature = sk.sign(SIGNING_INPUT);
    assert_eq!(
        signature.to_bytes().as_slice(),
        b64(EXPECTED_SIG_B64).as_slice(),
        "Ed25519 signature over the RFC 8037 A.4 input must equal the RFC's signature exactly",
    );

    let x: [u8; 32] = b64(PUBLIC_X_B64).try_into().unwrap();
    let vk = VerifyingKey::from_bytes(&x).expect("RFC public key decompresses");
    let vector_sig = Signature::from_bytes(&b64(EXPECTED_SIG_B64).try_into().unwrap());
    assert!(
        vk.verify_strict(SIGNING_INPUT, &vector_sig).is_ok(),
        "verify_strict must ACCEPT the genuine RFC 8037 A.4 signature",
    );
}

/// A single flipped bit in the signing input must break verification — the property that makes the
/// signature mean anything.
#[test]
fn tampered_input_is_rejected() {
    let x: [u8; 32] = b64(PUBLIC_X_B64).try_into().unwrap();
    let vk = VerifyingKey::from_bytes(&x).unwrap();
    let sig = Signature::from_bytes(&b64(EXPECTED_SIG_B64).try_into().unwrap());

    let mut tampered = SIGNING_INPUT.to_vec();
    tampered[0] ^= 0x01;
    assert!(
        vk.verify_strict(&tampered, &sig).is_err(),
        "a modified signing input must not verify",
    );
}

/// THE FOOTGUN, PROVEN. The all-zeros Ed25519 public key is a SMALL-ORDER point. With the all-zeros
/// signature (`R` = the same small-order point, `s` = 0), the lenient verification equation
/// `[s]B = R + [H(R‖A‖M)]A` collapses to `identity = R + [k]A`, which holds whenever
/// `H(R‖A‖M) ≡ 3 (mod 4)` — i.e. for roughly a quarter of all messages, `VerifyingKey::verify`
/// ACCEPTS a signature nobody holding a private key produced. That is a genuine forgery hazard.
/// `VerifyingKey::verify_strict` (the ZIP215 hardening the Phase C backend uses EXCLUSIVELY)
/// REFUSES the small-order key outright, for EVERY message. This test searches for a message the
/// lenient path accepts (proving the hazard is real and not hypothetical) and then asserts strict
/// verification rejects that exact case — the precise reason the backend must never call `verify`.
#[test]
fn verify_strict_rejects_small_order_key_that_lenient_verify_accepts() {
    // The all-zeros 32-byte encoding is a small-order point (it decompresses fine).
    let small_order = VerifyingKey::from_bytes(&[0u8; 32])
        .expect("all-zeros encoding is a valid (small-order) point");
    let zero_sig = Signature::from_bytes(&[0u8; 64]);

    // Whether the lenient (cofactorless) check accepts the zero signature depends on the message
    // hash mod 4, so find one it accepts. ~1/4 of messages qualify, so this terminates at once.
    let accepted_by_lenient = (0u32..1000)
        .map(|n| format!("small-order forgery probe {n}").into_bytes())
        .find(|msg| small_order.verify(msg, &zero_sig).is_ok())
        .expect("some message must make lenient verify accept the small-order forgery");

    // Lenient verify ACCEPTS this forgery (the hazard) ...
    assert!(small_order.verify(&accepted_by_lenient, &zero_sig).is_ok());
    // ... while strict verify REFUSES it (the mitigation the backend relies on).
    assert!(
        small_order
            .verify_strict(&accepted_by_lenient, &zero_sig)
            .is_err(),
        "verify_strict MUST reject a small-order public key that lenient verify accepted",
    );
}

/// Several other known small-order encodings (RFC 8032's 8-element cofactor group) are all refused
/// by `verify_strict`, regardless of the signature offered.
#[test]
fn verify_strict_rejects_all_known_small_order_keys() {
    // The identity (y=1), y=0 (two encodings), and y=-1 (order 2) — canonical small-order points.
    let encodings: [[u8; 32]; 4] = [
        {
            let mut e = [0u8; 32];
            e[0] = 1;
            e
        },
        [0u8; 32],
        {
            let mut e = [0u8; 32];
            e[31] = 0x80;
            e
        },
        {
            let mut e = [0xffu8; 32];
            e[0] = 0xec;
            e[31] = 0x7f;
            e
        },
    ];
    let sig = Signature::from_bytes(&[0u8; 64]);
    for (i, enc) in encodings.iter().enumerate() {
        let vk = VerifyingKey::from_bytes(enc)
            .unwrap_or_else(|_| panic!("small-order encoding {i} should decompress"));
        assert!(
            vk.verify_strict(b"msg", &sig).is_err(),
            "verify_strict must reject small-order key #{i}",
        );
    }
}
