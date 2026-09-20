// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Proves the exported signer conformance harness is CRYPTO-AGILE: it validates RS256, EdDSA and
//! PS256 backends, not only the ES256 one it was born for.
//!
//! `tests/signer_conformance_selftest.rs` drives the ES256 path red and green. This file is the
//! other three algorithms. Before the harness was generalised it dispatched nothing on the signer's
//! algorithm: it demanded a 64-byte `[u8; 64]` signature (RS256/PS256 are 256 bytes) and checked the
//! published key against the ES256 P-256 vector, so a CONFORMANT RS256, EdDSA or PS256 signer failed
//! it SPURIOUSLY. The green tests here are what make that impossible to regress to; the broken ones
//! prove the harness still bites once it is looking at the right algorithm.

#![cfg(all(feature = "test-util", feature = "jwt-rsa", feature = "jwt-ed25519"))]

use std::future::Future;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use oauth_as::jwt::{Jwk, JwsAlg, JwsSignature, JwsSigner, SignerError};
use oauth_as::signer_conformance::{SignerConformance, Violation};
use oauth_as::{
    Ed25519Signer, Ed25519Verifier, Ps256Signer, Ps256Verifier, RsaSigner, RsaVerifier,
};

const SIGNER_VERIFIES_UNDER_ITS_OWN_JWK: &str = "signer/verifies_under_its_own_public_jwk";

/// A distinct RSA-2048 private key in PKCS#8 DER (base64), generated offline. Distinct from the RFC
/// 7515 A.2 key on purpose: a signer that IS the A.2 example key would (correctly) be flagged by the
/// harness's example-key check, and these green tests need a key with no such footgun.
const RSA_PKCS8_DER_B64: &str = concat!(
    "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC74HzAqWG6gfO8WtOXAFRrzTc/3eK7whRsnR1/su5N6MVNEhRd",
    "QeyBpH2UFnIXlmG35HDa++626zsrQJv51qtDxIU2oov/WwCPqXKpapJMPQ04drn6yyI7zeCTkNC8o3P90cT4kLVHc3lHjuTJh7Lx",
    "LdITD4WJN15Cr3rKgTruCvNWl/7159hxc0lzZBHbyWnsF/0y6HWATnYpkTTZmTkDHU3tOYq7h8yYPzk/2LSJQl2tXc59+9tAxDxy",
    "qEobqBwa8eN+tpqqlKUsfxYBC0vu16nVvCckg0EQF8nOjsGCD/mO6Yej5812sa747nUxyxydxaCtPqHRcYfg3a1ycAk9AgMBAAEC",
    "ggEAD5D8BSKDnGZkAXktCtfWJtBsAXiq7o+YDZ++7/OtVvswTcBvu4JYzC0K0phBf77P/eKJjztMfg9jaaQCyGKG8ih4ORyiqNer",
    "ZjvN6keQM4zjaYg8xJDMF1RphRB8mwSX+bHFtiqXOoJQzCMExcXeh6kaPMYOdF4IC1JqxBiM/2f4eAdR+2sEw98ms5irlICPZgj5",
    "VjTJX0DEpC/7LgltJu84GHEJqpvQjJu+s1mLXKonfzHOnKRLX1gjjqhzmPUs1kbiReTBsyJHGsW8tNQk0TSLHkCgycqem+kA6byj",
    "9zzle1wPq5lyyOFB2aP+jqzNoil40mRd/Fsyvrk/8+YaQQKBgQDnpJkTYvpXmD9/nCCGuAVA0MZ1sRjHnj2qSy/5nei8JstlW6B2",
    "caJ6cAjFVG1HKjTG8biF02pUMRiXlM9jt3tnMxHYZOMs1718x+bzSjG4R/pkmlIzkwOESe5NLwo2RSMJXMmgkqzM/ukxynHQ/KMD",
    "jAh9rhkfC0IBycX7ygzQhQKBgQDPocmlMrQqb5mwoUPFWzPmajjy8XIpl0lIGWBpn5v4dYZ5amntvYVfVn7mnr/g3i4ckAWQZoq8",
    "6xvOydtvC/nkvLP7ygHW3nB2swEzSGUk4/66fhbtIwSTEo5W3y9pxTrJ5s7DiR2owwZ/fxztQGhLqHU9l9eDrtcG5TZ+x+DPWQKB",
    "gCsz4LTj7eruY1FqjgpyQdCP36PNruB0G+4p7b2xfNmyppa12xycHwCU6p3bHDJ8pbFBHfgfsSIYsgx7XZ6sduCNftOMJW6Uoium",
    "oOVZPiKvkfy3Z4Nk9O/0VfShRFdQ17MEUjqXgJEPLfDyX/3pUIH12ROPp/HJSLtKpZlLWs59AoGABD7OnK4YuPVnMxFZDWP7/64U",
    "VANTzj3lpa+/JOm6iq38fecLG21QmM5v8c81JSfl0XewZW9zTsGP4/6EmhSom2CwXWmX+Ai8S/EFCUNlrgdrYezKEzcwFMHAX05Y",
    "7dS2iwJJH/5huN2j+F9k/AThHQrousWsBmlAxEdTgewcUKECgYAPo+fh9oAgSmlI2LfVD8pz8QLk8EUxrHDkr+Cm8Lc3cT8tGTV9",
    "fZu/GAvq+Z8NPgNnt6DoprUkkS5P2WV4MlPBi5DdBKbFXi9hGrlIMZ6WFa5j6p6PSGGU8IUeH4IMM3hIU+R5/lMAPurPe76lhCpz",
    "Yy3UrhfhOX+SSZweUvDNng==",
);

/// A second, well-formed 2048-bit RSA public modulus (base64urlUInt). Used as the WRONG key a
/// broken signer publishes: a valid RSA key that is not the signing key, so the harness's
/// "verifies under its own public_jwk" check must fire without any other check masking it.
const OTHER_RSA_N: &str = "4-QFArXj8EHf7YtUPQelHj3thYoTF0_9V1onh-E-UeHXjJoFS1Mfw_LKNhJD_lwHdefGCSdVuMGtFeXUNtN0XTA9_Z4Q2YSS0mVo_HM25e_phlKkk6Nxy7JfmSnto0O-enYCSIJx4MJ2NOqvpZrv0C8HRSilH5PJ9b82jnxV4n2153xQsTNBIVc5N9McB3TIF1zYh3O3h1fGfP3JsR6qLQerehoJc8FQ9bD_0y2CEpHLaeYn6qgv279-dQo-wuw3Xsj8loaqZW0WPyhjE9TZsaMM9SR3J7RBUf2fKvqki7tgIuiZQ7J0XeJ3rdsPsmF1hP7Muvre1MtPmeC_7VDlKQ";

fn rsa_signer() -> RsaSigner {
    let der = STANDARD
        .decode(RSA_PKCS8_DER_B64)
        .expect("the embedded PKCS#8 is base64");
    RsaSigner::from_pkcs8_der("rs256-test", &der).expect("a valid 2048-bit RSA key")
}

/// The SAME distinct RSA key as `rsa_signer`, wrapped as a PS256 (RSASSA-PSS) signer. Distinct from
/// the RFC 7515 A.2 key so the harness's example-key check does not (correctly) fire.
fn ps256_signer() -> Ps256Signer {
    let der = STANDARD
        .decode(RSA_PKCS8_DER_B64)
        .expect("the embedded PKCS#8 is base64");
    Ps256Signer::from_pkcs8_der("ps256-test", &der).expect("a valid 2048-bit RSA key")
}

/// A one-line executor, so this file needs no async-runtime feature of its own. Every future the
/// harness builds resolves on its first poll (the built-in backends hold their key in-process).
fn block_on<F: Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn noop(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    let waker = unsafe { Waker::from_raw(clone(std::ptr::null())) };
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => return value,
            Poll::Pending => continue,
        }
    }
}

// ------------------------------------------------------------------------------------ the green

/// A CONFORMANT RS256 backend (a distinct-key `RsaSigner` + `RsaVerifier`) passes every check.
///
/// This is finding (a): before the harness dispatched on `JwsSigner::alg`, it demanded a 64-byte
/// signature and an ES256/P-256 published key, so this correct RSA pair failed spuriously.
#[test]
fn a_conformant_rs256_backend_passes_every_check() {
    let violations = block_on(SignerConformance::new(rsa_signer(), RsaVerifier).run());
    assert!(violations.is_empty(), "{violations:#?}");
}

/// A CONFORMANT EdDSA backend (`Ed25519Signer` + `Ed25519Verifier`) passes every check. Finding (b).
#[test]
fn a_conformant_eddsa_backend_passes_every_check() {
    let signer = Ed25519Signer::from_seed_bytes("eddsa-test", &[3u8; 32])
        .expect("a fixed 32-byte seed keeps this test deterministic");
    let violations = block_on(SignerConformance::new(signer, Ed25519Verifier).run());
    assert!(violations.is_empty(), "{violations:#?}");
}

/// A CONFORMANT PS256 (RSASSA-PSS) backend (`Ps256Signer` + `Ps256Verifier`) passes every check.
/// This is the one test that exercises the harness's `JwsAlg::Ps256` arm end to end — its pinned
/// salt-32 known-answer vector and the shared RS256/EdDSA/PS256 generic verifier routine — so the
/// harness cannot silently stop covering the algorithm FAPI 2.0 actually asks for.
#[test]
fn a_conformant_ps256_backend_passes_every_check() {
    let violations = block_on(SignerConformance::new(ps256_signer(), Ps256Verifier).run());
    assert!(violations.is_empty(), "{violations:#?}");
}

// ------------------------------------------------------------------------------------- the red

/// How a wrapped RSA signer is made wrong. All roads lead to the harness's
/// `signer/verifies_under_its_own_public_jwk` check, which is exactly the one that could not be
/// reached at all while the harness insisted on a 64-byte ES256 signature.
enum Break {
    /// Publish a valid RSA key that is NOT the signing key.
    WrongKey(Jwk),
    /// Return a signature one byte short of the modulus width.
    TruncateSignature,
}

/// A real `RsaSigner` wrapped to misbehave in exactly one way.
struct BrokenRsa {
    inner: RsaSigner,
    how: Break,
}

impl JwsSigner for BrokenRsa {
    fn alg(&self) -> JwsAlg {
        self.inner.alg()
    }

    fn sign(
        &self,
        signing_input: &[u8],
    ) -> impl Future<Output = Result<JwsSignature, SignerError>> + Send {
        // `RsaSigner::sign` computes its result synchronously and moves it into the returned future,
        // so `fut` borrows nothing and this stays `Send`.
        let fut = JwsSigner::sign(&self.inner, signing_input);
        let truncate = matches!(self.how, Break::TruncateSignature);
        async move {
            let signature = fut.await?;
            if truncate {
                if let JwsSignature::Rs256(bytes) = signature {
                    let mut bytes = bytes.into_vec();
                    bytes.pop();
                    return Ok(JwsSignature::Rs256(bytes.into_boxed_slice()));
                }
            }
            Ok(signature)
        }
    }

    fn public_jwk(&self) -> Jwk {
        match &self.how {
            Break::WrongKey(jwk) => jwk.clone(),
            Break::TruncateSignature => JwsSigner::public_jwk(&self.inner),
        }
    }
}

fn reports(violations: &[Violation], check: &str) -> bool {
    violations.iter().any(|v| v.check == check)
}

/// A RS256 signer whose `public_jwk()` is a DIFFERENT (valid) RSA key is caught: its signatures do
/// not verify under its own published JWK. Finding (c), part one.
#[test]
fn a_broken_rs256_signer_that_publishes_the_wrong_key_is_flagged() {
    let wrong_key = Jwk::Rsa {
        n: OTHER_RSA_N.to_string(),
        e: "AQAB".to_string(),
        kid: Some("not-the-signing-key".to_string()),
    };
    let broken = BrokenRsa {
        inner: rsa_signer(),
        how: Break::WrongKey(wrong_key),
    };
    let violations = block_on(SignerConformance::new(broken, RsaVerifier).run());
    assert!(
        reports(&violations, SIGNER_VERIFIES_UNDER_ITS_OWN_JWK),
        "a signer publishing a key it does not sign with must be flagged: {violations:#?}"
    );
}

/// A RS256 signer that returns a truncated signature is caught: a signature that is not the modulus
/// width does not verify. Finding (c), part two.
#[test]
fn a_broken_rs256_signer_that_truncates_its_signature_is_flagged() {
    let broken = BrokenRsa {
        inner: rsa_signer(),
        how: Break::TruncateSignature,
    };
    let violations = block_on(SignerConformance::new(broken, RsaVerifier).run());
    assert!(
        reports(&violations, SIGNER_VERIFIES_UNDER_ITS_OWN_JWK),
        "a signer returning a wrong-length signature must be flagged: {violations:#?}"
    );
}
