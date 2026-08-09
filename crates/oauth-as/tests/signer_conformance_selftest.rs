// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Proves the exported ES256 signer conformance harness can go RED.
//!
//! A conformance harness nobody has watched fail is exactly the thing this project refuses to
//! trust: it is indistinguishable, from the outside, from a harness that returns an empty vector
//! whatever it is handed. This repository has already been bitten by that once, in the `Storage`
//! harness, where nine checks had no planted fault and one had no caller at all. So every check in
//! [`oauth_as::signer_conformance::CHECKS`] is driven red here by a backend that is WRONG in one
//! specific way, in a way an implementor actually gets it wrong.
//!
//! The green side is here too, and is not a formality: the harness must report NOTHING against the
//! crate's own `jwt-p256` backend, and nothing against `FaultySigner`/`FaultyVerifier` with every
//! fault switched off. A correct implementation and the reference implementation both passing is
//! what stops the checks from being a description of `p256`'s incidental behaviour.
//!
//! Each planted fault asserts that the check it targets is AMONG the reported violations, not that
//! it is the only one. That is deliberate: a signer whose `public_jwk()` is not its signing key
//! genuinely fails more than one thing, and an exclusivity assertion would only be satisfiable by
//! faults too artificial to be the ones a host writes.

#![cfg(all(feature = "test-util", feature = "jwt-p256"))]

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use oauth_as::jwt::{
    EcdsaP256Key, Es256Signer, Es256Verifier, Jwk, P256Verifier, PublicJwk, SignerError,
};
use oauth_as::signer_conformance::{SignerConformance, Violation, CHECKS};

/// The RFC 7515 appendix A.3 key, all three parameters. Quoted from the RFC.
const A3_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
const A3_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
const A3_D: &str = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";
const A3_SIGNING_INPUT: &str = concat!(
    "eyJhbGciOiJFUzI1NiJ9",
    ".",
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
);
const A3_SIGNATURE: &str =
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

fn b64(value: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(value)
        .expect("a vector is base64url")
}

// ------------------------------------------------------------------------ the broken backend

/// Which defect this backend carries. All false is a CORRECT backend, which the green tests below
/// depend on: every fault is one edit away from the right implementation, which is the point. A
/// host does not write a signer that is wrong everywhere; it writes one that is wrong in the one
/// place that still compiles, still returns 64 bytes, and still looks like a signature.
#[derive(Clone, Copy, Default)]
struct Faults {
    /// The signer refuses. What an unreachable KMS, or one whose IAM policy was tightened under
    /// the deployment, actually looks like.
    signer_refuses: bool,
    /// The signer returns the ASN.1 DER encoding, truncated into the 64 bytes the trait demands.
    /// This is the single most likely defect in a KMS-backed signer: RFC 7518 s3.4 wants
    /// fixed-width `R || S` and almost every provider returns DER.
    signer_returns_der: bool,
    /// The signer signs correctly, with a key that is NOT the one `public_jwk()` publishes. The
    /// shape a host gets by copying a JWK out of one environment's config into another's.
    signer_uses_a_foreign_key: bool,
    /// The signer ignores the bytes it was handed and signs a fixed message: a buffer captured
    /// once, or a digest computed from something other than the argument.
    signer_ignores_its_argument: bool,
    /// `public_jwk()` fetches (or regenerates) per call instead of returning a value cached at
    /// construction, so the `kid` drifts. The trait requires caching precisely because it is sync.
    public_jwk_drifts: bool,
    /// `public_jwk()` publishes a `y` coordinate with its leading zero trimmed, which is the
    /// classic JWK interoperability bug: right for 255 keys out of 256.
    public_jwk_trims_a_coordinate: bool,
    /// `public_jwk()` publishes no `kid`, so rotation has nothing to select on.
    public_jwk_has_no_kid: bool,
    /// The host is signing with the key printed, private half and all, in RFC 7515 appendix A.3.1.
    /// It happens: the appendix is the first ES256 key most implementors ever see.
    signs_with_the_published_example_key: bool,
    /// The verifier says no to everything, which is what a verifier configured for the wrong curve
    /// or the wrong digest does.
    verifier_always_false: bool,
    /// The verifier says yes to everything: the failure with no symptom until someone forges.
    verifier_always_true: bool,
    /// The verifier ignores the key it was given and uses one it was built with. Every signature
    /// then verifies under every key, so no token is bound to any issuer.
    verifier_ignores_the_key: bool,
    /// The verifier ignores the signing input and verifies over a fixed message, so a token's
    /// claims can be edited without invalidating it.
    verifier_ignores_the_input: bool,
    /// The verifier ignores the signature it was given and checks one it already holds.
    verifier_ignores_the_signature: bool,
    /// The verifier ALSO accepts the DER encoding, by converting it back before checking. Every
    /// signature then has two spellings, so a value recorded as unique is not.
    verifier_accepts_der: bool,
}

struct FaultySigner {
    faults: Faults,
    /// The key that actually signs.
    key: EcdsaP256Key,
    /// A second key, used only by `signer_uses_a_foreign_key` as the one that gets PUBLISHED.
    other: EcdsaP256Key,
    reads: AtomicUsize,
}

impl FaultySigner {
    fn new(faults: Faults) -> Self {
        let key = if faults.signs_with_the_published_example_key {
            EcdsaP256Key::from_scalar_bytes("example", &b64(A3_D))
                .expect("the RFC 7515 A.3 private scalar is a valid P-256 scalar")
        } else {
            EcdsaP256Key::from_scalar_bytes("selftest-1", &[7u8; 32])
                .expect("a fixed scalar keeps this test deterministic")
        };
        FaultySigner {
            faults,
            key,
            other: EcdsaP256Key::from_scalar_bytes("selftest-2", &[9u8; 32])
                .expect("a fixed scalar keeps this test deterministic"),
            reads: AtomicUsize::new(0),
        }
    }
}

impl Es256Signer for FaultySigner {
    fn sign(
        &self,
        signing_input: &[u8],
    ) -> impl Future<Output = Result<[u8; 64], SignerError>> + Send {
        let faults = self.faults;
        let message: Vec<u8> = if faults.signer_ignores_its_argument {
            b"a buffer this signer captured once".to_vec()
        } else {
            signing_input.to_vec()
        };
        let signed = self
            .key
            .sign_signing_input(&String::from_utf8_lossy(&message))
            .map(|s| {
                let mut out = [0u8; 64];
                out.copy_from_slice(&s);
                out
            });
        async move {
            if faults.signer_refuses {
                return Err(SignerError::new("the key service refused"));
            }
            let mut signature =
                signed.map_err(|_| SignerError::new("the selftest key failed to sign"))?;
            if faults.signer_returns_der {
                // The DER encoding, cut to the 64 bytes the trait's type demands. That truncation
                // is exactly what an implementor does when the compiler tells them their KMS
                // response is the wrong length.
                let der = to_der(&signature);
                signature = [0u8; 64];
                let n = der.len().min(64);
                signature[..n].copy_from_slice(&der[..n]);
            }
            Ok(signature)
        }
    }

    fn public_jwk(&self) -> Jwk {
        let source = if self.faults.signer_uses_a_foreign_key {
            &self.other
        } else {
            &self.key
        };
        let mut jwk = source.public_jwk();
        if self.faults.public_jwk_drifts {
            jwk.kid = format!("drift-{}", self.reads.fetch_add(1, Ordering::SeqCst));
        }
        if self.faults.public_jwk_trims_a_coordinate {
            // One byte short, the way a big-integer library that strips leading zeros emits it.
            let mut y = URL_SAFE_NO_PAD
                .decode(&jwk.y)
                .expect("this crate emits base64url");
            y.remove(0);
            jwk.y = URL_SAFE_NO_PAD.encode(y);
        }
        if self.faults.public_jwk_has_no_kid {
            jwk.kid = String::new();
        }
        jwk
    }
}

struct FaultyVerifier {
    faults: Faults,
}

impl Es256Verifier for FaultyVerifier {
    fn verify(&self, key: &PublicJwk, signing_input: &[u8], signature: &[u8]) -> bool {
        let real = P256Verifier;
        if self.faults.verifier_always_false {
            return false;
        }
        if self.faults.verifier_always_true {
            return true;
        }
        if self.faults.verifier_ignores_the_key {
            let baked = PublicJwk::from_coordinates(A3_X, A3_Y).expect("the RFC's key parses");
            return real.verify(&baked, signing_input, signature);
        }
        if self.faults.verifier_ignores_the_input {
            return real.verify(key, A3_SIGNING_INPUT.as_bytes(), signature);
        }
        if self.faults.verifier_ignores_the_signature {
            return real.verify(key, signing_input, &b64(A3_SIGNATURE));
        }
        if self.faults.verifier_accepts_der {
            if let Some(fixed) = from_der(signature) {
                return real.verify(key, signing_input, &fixed);
            }
        }
        real.verify(key, signing_input, signature)
    }
}

// ------------------------------------------------------------------------------- DER helpers

/// `R || S` to the ASN.1 DER `SEQUENCE { r INTEGER, s INTEGER }`.
fn to_der(fixed_width: &[u8]) -> Vec<u8> {
    fn integer(value: &[u8], out: &mut Vec<u8>) {
        let start = value
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(value.len() - 1);
        let body = &value[start..];
        let pad = usize::from(body[0] & 0x80 != 0);
        out.push(0x02);
        out.push((body.len() + pad) as u8);
        if pad == 1 {
            out.push(0x00);
        }
        out.extend_from_slice(body);
    }
    let mut body = Vec::new();
    integer(&fixed_width[..32], &mut body);
    integer(&fixed_width[32..], &mut body);
    let mut out = vec![0x30, body.len() as u8];
    out.extend_from_slice(&body);
    out
}

/// The inverse, deliberately lenient, because a verifier that accepts DER is lenient: that is the
/// defect.
fn from_der(der: &[u8]) -> Option<[u8; 64]> {
    if der.len() < 8 || der[0] != 0x30 || usize::from(der[1]) + 2 != der.len() {
        return None;
    }
    let mut out = [0u8; 64];
    let mut at = 2;
    for half in 0..2 {
        if der.get(at) != Some(&0x02) {
            return None;
        }
        let len = usize::from(*der.get(at + 1)?);
        let body = der.get(at + 2..at + 2 + len)?;
        let body = if body.len() == 33 && body[0] == 0 {
            &body[1..]
        } else {
            body
        };
        if body.len() > 32 {
            return None;
        }
        let start = half * 32 + (32 - body.len());
        out[start..half * 32 + 32].copy_from_slice(body);
        at += 2 + len;
    }
    Some(out)
}

// ----------------------------------------------------------------------------- the runner

fn run(faults: Faults) -> Vec<Violation> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime");
    rt.block_on(SignerConformance::new(FaultySigner::new(faults), FaultyVerifier { faults }).run())
}

/// Assert that the named check is among what the harness reported. See the module docs on why this
/// is containment rather than exclusivity.
fn assert_reports(faults: Faults, check: &str) {
    assert!(
        CHECKS.contains(&check),
        "{check} is not in CHECKS, so a host filtering on it would be waiving nothing"
    );
    let violations = run(faults);
    assert!(
        violations.iter().any(|v| v.check == check),
        "the planted fault must make {check} go red; the harness reported {violations:#?}"
    );
}

// --------------------------------------------------------------------------------- the green

/// The crate's own `jwt-p256` backend, which is what every consumer had before the seam existed,
/// must pass every check. If it did not, the harness would be describing something other than the
/// contract.
#[test]
fn the_built_in_p256_backend_passes_every_check() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let violations =
        rt.block_on(SignerConformance::new(EcdsaP256Key::generate("built-in"), P256Verifier).run());
    assert!(violations.is_empty(), "{violations:#?}");
}

/// A SECOND correct implementation, so the checks are not a description of one backend's
/// incidental behaviour.
#[test]
fn the_selftest_backend_with_no_faults_passes_every_check() {
    let violations = run(Faults::default());
    assert!(violations.is_empty(), "{violations:#?}");
}

// ------------------------------------------------------------------- one red per check name

#[test]
fn every_check_has_a_planted_fault() {
    // The list below is the whole of `CHECKS`, paired with the fault that drives it red. Its job
    // is to fail the day a check is added without one, which is the exact defect the `Storage`
    // harness shipped with.
    let planted: Vec<&str> = vec![
        "verifier/rfc7515_appendix_a3_vector",
        "verifier/rejects_a_foreign_key",
        "verifier/rejects_a_tampered_signing_input",
        "verifier/rejects_a_tampered_signature",
        "verifier/rejects_the_der_encoding",
        "signer/signs",
        "signer/output_is_not_der",
        "signer/verifies_under_its_own_public_jwk",
        "signer/does_not_verify_under_another_key",
        "signer/binds_the_signing_input",
        "signer/public_jwk_is_stable",
        "signer/public_jwk_is_an_es256_p256_key",
        "signer/public_jwk_has_a_kid",
        "signer/is_not_the_published_example_key",
    ];
    let mut missing: Vec<&&str> = CHECKS.iter().filter(|c| !planted.contains(c)).collect();
    missing.sort_unstable();
    assert!(
        missing.is_empty(),
        "these checks have no planted fault in this file, so nobody has watched them fail: \
         {missing:?}"
    );
    for name in &planted {
        assert!(
            CHECKS.contains(name),
            "{name} is not a check the harness reports"
        );
    }
}

#[test]
fn a_verifier_that_says_no_fails_the_rfc_vector() {
    assert_reports(
        Faults {
            verifier_always_false: true,
            ..Default::default()
        },
        "verifier/rfc7515_appendix_a3_vector",
    );
}

#[test]
fn a_verifier_that_ignores_its_key_is_caught() {
    assert_reports(
        Faults {
            verifier_ignores_the_key: true,
            ..Default::default()
        },
        "verifier/rejects_a_foreign_key",
    );
}

#[test]
fn a_verifier_that_ignores_its_input_is_caught() {
    assert_reports(
        Faults {
            verifier_ignores_the_input: true,
            ..Default::default()
        },
        "verifier/rejects_a_tampered_signing_input",
    );
}

#[test]
fn a_verifier_that_ignores_its_signature_is_caught() {
    assert_reports(
        Faults {
            verifier_ignores_the_signature: true,
            ..Default::default()
        },
        "verifier/rejects_a_tampered_signature",
    );
}

#[test]
fn a_verifier_that_also_accepts_der_is_caught() {
    assert_reports(
        Faults {
            verifier_accepts_der: true,
            ..Default::default()
        },
        "verifier/rejects_the_der_encoding",
    );
}

#[test]
fn a_verifier_that_says_yes_to_everything_is_caught_by_the_foreign_key_check() {
    // This is the ONLY way `signer/does_not_verify_under_another_key` can go red, and saying so
    // is the point: no signer can produce a signature that verifies under a key whose private half
    // it does not hold, so a red here always means the verifier.
    assert_reports(
        Faults {
            verifier_always_true: true,
            ..Default::default()
        },
        "signer/does_not_verify_under_another_key",
    );
}

#[test]
fn a_signer_that_refuses_is_caught() {
    assert_reports(
        Faults {
            signer_refuses: true,
            ..Default::default()
        },
        "signer/signs",
    );
}

#[test]
fn a_signer_that_returns_der_is_caught_by_name() {
    assert_reports(
        Faults {
            signer_returns_der: true,
            ..Default::default()
        },
        "signer/output_is_not_der",
    );
}

#[test]
fn a_signer_that_publishes_a_key_it_does_not_sign_with_is_caught() {
    assert_reports(
        Faults {
            signer_uses_a_foreign_key: true,
            ..Default::default()
        },
        "signer/verifies_under_its_own_public_jwk",
    );
}

#[test]
fn a_signer_that_ignores_the_bytes_it_was_handed_is_caught() {
    assert_reports(
        Faults {
            signer_ignores_its_argument: true,
            ..Default::default()
        },
        "signer/binds_the_signing_input",
    );
}

#[test]
fn a_public_jwk_that_is_not_cached_is_caught() {
    assert_reports(
        Faults {
            public_jwk_drifts: true,
            ..Default::default()
        },
        "signer/public_jwk_is_stable",
    );
}

#[test]
fn a_trimmed_coordinate_is_caught() {
    assert_reports(
        Faults {
            public_jwk_trims_a_coordinate: true,
            ..Default::default()
        },
        "signer/public_jwk_is_an_es256_p256_key",
    );
}

#[test]
fn a_public_jwk_with_no_kid_is_caught() {
    assert_reports(
        Faults {
            public_jwk_has_no_kid: true,
            ..Default::default()
        },
        "signer/public_jwk_has_a_kid",
    );
}

#[test]
fn signing_with_the_rfcs_own_example_key_is_caught() {
    assert_reports(
        Faults {
            signs_with_the_published_example_key: true,
            ..Default::default()
        },
        "signer/is_not_the_published_example_key",
    );
}
