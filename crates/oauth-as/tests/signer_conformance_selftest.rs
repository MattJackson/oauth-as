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
//!
//! # The coverage guard guards a fault, not a name
//!
//! [`planted_faults`] is the single place a check name and the fault that drives it are written
//! down together, and `every_check_has_a_planted_fault` RUNS all of it. The earlier shape compared
//! `CHECKS` against a hand-maintained literal list of NAMES and stopped there, so it proved a name
//! had been typed and nothing more: an entry whose fault had rotted, or whose `#[test]` had been
//! deleted, passed it in silence. That is the same overclaim as the `Storage` harness's, in the
//! file written to make the `Storage` harness's overclaim impossible.

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
    /// The signer PANICS in the synchronous half of `sign`, where a KMS wrapper marshals its
    /// request: `self.client.get().unwrap()`, a `kid` parsed with `expect`, a config read that was
    /// `None` in this environment. `Es256Signer::sign` says MUST NOT PANIC for any input ever, and
    /// this half panics before the future is even polled.
    signer_panics_while_building_the_request: bool,
    /// The signer PANICS while the future is polled, which is where the KMS RESPONSE is read: the
    /// `copy_from_slice` that assumes 64 bytes, the `unwrap` on a field the API left absent. The
    /// two are separate faults because the harness has to catch in two places to see both, and a
    /// harness that caught only one would report green for half of this defect.
    signer_panics_while_awaiting_the_response: bool,
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
    /// The verifier takes the first 64 bytes and PANICS on anything shorter. This is what an
    /// implementor writes after reading "the signature MUST be the 64-byte fixed-width R || S":
    /// the sentence sounds like a guarantee about the argument and is a requirement on the answer.
    /// The signature is the third JWS segment base64url-decoded, so a proof ending in a bare `.`
    /// makes it a zero-length slice and the panic unwinds into the host's token endpoint.
    verifier_indexes_the_first_64_bytes: bool,
    /// The verifier left-pads a short signature up to 64 bytes and verifies THAT. It does not
    /// panic, so it is the quieter half of the same defect: it never says no on length, and gives
    /// values the signer never produced a chance to be accepted.
    ///
    /// It rejects anything LONGER than 64 bytes, and that is deliberate rather than incidental. A
    /// backend that pads short inputs and truncates long ones is caught by the harness's 65-byte
    /// case, whose padded reconstruction is the A.3 signature itself, and being caught there meant
    /// `verifier/rejects_a_wrong_length_signature` went red without the LEADING_ZERO vector ever
    /// being consulted: the one case in the harness that only a padding verifier can fail was
    /// satisfied by a different case, so a typo in `LEADING_ZERO_SIGNATURE` would have been
    /// invisible and the check vacuous. Rejecting the long ones leaves the leading-zero case as
    /// the ONLY way this fault can be seen, which is what makes those constants load bearing. The
    /// truncating half is still driven, by `verifier_indexes_the_first_64_bytes`.
    verifier_pads_a_short_signature: bool,
    /// The verifier decodes the key's coordinates into a point and UNWRAPS, the way a KMS-shaped
    /// verifier does after reading that `key` is a P-256 public key. `PublicJwk` guarantees the
    /// coordinate WIDTH and deliberately not the curve equation, and RFC 9449 s4.3 hands the `jwk`
    /// straight out of a DPoP proof header, so this panics on bytes an unauthenticated client
    /// chose.
    verifier_unwraps_an_off_curve_key: bool,
    /// The verifier reads the first byte of the signing input before doing any arithmetic, which
    /// panics on the empty one the contract says it may be handed.
    verifier_reads_the_first_input_byte: bool,
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
        if faults.signer_panics_while_building_the_request {
            // Before the future exists at all: this is the half a `catch_unwind` around the
            // AWAITED call alone would miss.
            panic!("the KMS request builder unwrapped a None");
        }
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
            if faults.signer_panics_while_awaiting_the_response {
                // Inside the poll, where the KMS response is read: the half a `catch_unwind`
                // around only the SYNCHRONOUS call would miss.
                panic!("the KMS response was the wrong length and copy_from_slice said so");
            }
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
        if self.faults.verifier_unwraps_an_off_curve_key {
            // Written as an implementor writes it after reading that `key` is a P-256 public key.
            // `from_sec1_bytes` is what checks the curve equation, and `expect` is what turns a
            // client-supplied DPoP `jwk` into a panic in the host's token endpoint.
            let mut sec1 = [0u8; 65];
            sec1[0] = 0x04;
            sec1[1..33].copy_from_slice(&b64(key.x()));
            sec1[33..].copy_from_slice(&b64(key.y()));
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .expect("this verifier assumes the coordinates are a point, which is the defect");
        }
        if self.faults.verifier_reads_the_first_input_byte {
            // A peek at the JWS header before any arithmetic. Every signing input this crate
            // builds has a first byte; the contract says one arriving from the wire need not.
            let _first = signing_input[0];
        }
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
        if self.faults.verifier_indexes_the_first_64_bytes {
            // Written exactly as an implementor writes it after reading "the signature MUST be the
            // 64-byte fixed-width R || S". It PANICS on anything shorter, and the shortest input
            // is free: a JWS whose third segment is empty.
            return real.verify(key, signing_input, &signature[..64]);
        }
        if self.faults.verifier_pads_a_short_signature {
            if signature.len() > 64 {
                // This backend gets the LONG ones right. See the fault's doc: catching it on a
                // 65-byte input would let the leading-zero case, which is the only one that can
                // catch a padding verifier, go unconsulted.
                return false;
            }
            let mut fixed = [0u8; 64];
            fixed[64 - signature.len()..].copy_from_slice(signature);
            return real.verify(key, signing_input, &fixed);
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

/// THE ONE LIST: every check the harness reports, paired with the fault that drives it red.
///
/// This is the only place a check name and a `Faults` value are written down together. The
/// per-fault `#[test]`s below do not carry their own `Faults`; they look themselves up here, so a
/// name and its fault cannot drift apart, and `every_check_has_a_planted_fault` RUNS every entry,
/// so an entry is a claim this file makes good on rather than a name somebody typed.
///
/// The previous shape of this file compared `CHECKS` against a hand-maintained literal list and
/// nothing else. That guarded only that a name had been WRITTEN DOWN: an entry whose fault had
/// been deleted, or whose `#[test]` had been renamed away, or that had never had a fault at all,
/// passed it silently. That is exactly the defect the `Storage` harness shipped with (nine checks
/// with no planted fault, one with no caller), which is the failure this file exists to make
/// impossible, so the guard was weaker than its own name.
fn planted_faults() -> Vec<(&'static str, Faults)> {
    vec![
        (
            "verifier/rfc7515_appendix_a3_vector",
            Faults {
                verifier_always_false: true,
                ..Default::default()
            },
        ),
        (
            "verifier/rejects_a_foreign_key",
            Faults {
                verifier_ignores_the_key: true,
                ..Default::default()
            },
        ),
        (
            "verifier/rejects_a_tampered_signing_input",
            Faults {
                verifier_ignores_the_input: true,
                ..Default::default()
            },
        ),
        (
            "verifier/rejects_a_tampered_signature",
            Faults {
                verifier_ignores_the_signature: true,
                ..Default::default()
            },
        ),
        (
            "verifier/rejects_the_der_encoding",
            Faults {
                verifier_accepts_der: true,
                ..Default::default()
            },
        ),
        // TWO entries for the wrong-length obligation, because it has two natural wrong answers and
        // catching one says nothing about the other. `assert_planted` drives EVERY entry with a
        // matching name, so both are exercised by name and by the coverage guard.
        (
            "verifier/rejects_a_wrong_length_signature",
            Faults {
                verifier_pads_a_short_signature: true,
                ..Default::default()
            },
        ),
        (
            "verifier/rejects_a_wrong_length_signature",
            Faults {
                // The 65-byte case: this verifier reads a 64-byte PREFIX and ignores the rest.
                verifier_indexes_the_first_64_bytes: true,
                ..Default::default()
            },
        ),
        // THREE entries, one per input the MUST NOT PANIC clause names that a natural
        // implementation actually dies on: the short SIGNATURE, the off-curve KEY, and the empty
        // SIGNING INPUT. Each is a different `unwrap` in a different line of a host's verifier, and
        // a fault for one says nothing about the other two: for two rounds the harness presented
        // only the lengths, so a verifier that unwrapped the key passed every published check while
        // panicking on a DPoP proof anyone could send.
        (
            "verifier/does_not_panic",
            Faults {
                verifier_indexes_the_first_64_bytes: true,
                ..Default::default()
            },
        ),
        (
            "verifier/does_not_panic",
            Faults {
                verifier_unwraps_an_off_curve_key: true,
                ..Default::default()
            },
        ),
        (
            "verifier/does_not_panic",
            Faults {
                verifier_reads_the_first_input_byte: true,
                ..Default::default()
            },
        ),
        (
            "signer/signs",
            Faults {
                signer_refuses: true,
                ..Default::default()
            },
        ),
        // TWO entries, because `sign` returns a future and so has two places to panic: the
        // synchronous half that builds it and the poll that drives it. A harness that caught only
        // one of them would report green for the other.
        (
            "signer/does_not_panic",
            Faults {
                signer_panics_while_building_the_request: true,
                ..Default::default()
            },
        ),
        (
            "signer/does_not_panic",
            Faults {
                signer_panics_while_awaiting_the_response: true,
                ..Default::default()
            },
        ),
        (
            "signer/output_is_not_der",
            Faults {
                signer_returns_der: true,
                ..Default::default()
            },
        ),
        (
            "signer/verifies_under_its_own_public_jwk",
            Faults {
                signer_uses_a_foreign_key: true,
                ..Default::default()
            },
        ),
        // The ONLY way this one can go red, and saying so is the point: no signer can produce a
        // signature that verifies under a key whose private half it does not hold, so a red here
        // always means the verifier.
        (
            "signer/does_not_verify_under_another_key",
            Faults {
                verifier_always_true: true,
                ..Default::default()
            },
        ),
        (
            "signer/binds_the_signing_input",
            Faults {
                signer_ignores_its_argument: true,
                ..Default::default()
            },
        ),
        (
            "signer/public_jwk_is_stable",
            Faults {
                public_jwk_drifts: true,
                ..Default::default()
            },
        ),
        (
            "signer/public_jwk_is_an_es256_p256_key",
            Faults {
                public_jwk_trims_a_coordinate: true,
                ..Default::default()
            },
        ),
        (
            "signer/public_jwk_has_a_kid",
            Faults {
                public_jwk_has_no_kid: true,
                ..Default::default()
            },
        ),
        (
            "signer/is_not_the_published_example_key",
            Faults {
                signs_with_the_published_example_key: true,
                ..Default::default()
            },
        ),
    ]
}

/// Look the named check's planted faults up and drive EVERY one of them.
///
/// Every, not the first: a check whose obligation has two distinct wrong answers gets an entry per
/// answer (see the wrong-length pair), and finding only the first would leave the other planted and
/// never driven, which is the exact shape of rot this file exists to prevent.
fn assert_planted(check: &str) {
    let table = planted_faults();
    let matching: Vec<Faults> = table
        .iter()
        .filter(|(name, _)| *name == check)
        .map(|(_, faults)| *faults)
        .collect();
    assert!(
        !matching.is_empty(),
        "{check} has no entry in planted_faults()"
    );
    for faults in matching {
        assert_reports(faults, check);
    }
}

/// The guard, and it now means what it is called: for every check the harness reports, a fault is
/// planted AND driven, here, in this test, and observed to make that check go red.
///
/// Both directions are asserted. A check with no entry is a check nobody has watched fail. An
/// entry naming a check `CHECKS` does not contain is a fault aimed at nothing, which is how a
/// table stays green while the thing it guards has been renamed out from under it.
#[test]
fn every_check_has_a_planted_fault() {
    let planted = planted_faults();

    let mut missing: Vec<&&str> = CHECKS
        .iter()
        .filter(|c| !planted.iter().any(|(name, _)| name == *c))
        .collect();
    missing.sort_unstable();
    assert!(
        missing.is_empty(),
        "these checks have no planted fault in this file, so nobody has watched them fail: \
         {missing:?}"
    );

    let mut aimed_at_nothing: Vec<&str> = planted
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| !CHECKS.contains(name))
        .collect();
    aimed_at_nothing.sort_unstable();
    assert!(
        aimed_at_nothing.is_empty(),
        "these entries name a check the harness does not report, so the fault proves nothing: \
         {aimed_at_nothing:?}"
    );

    // And RUN every one. This is the half the old guard did not have: without it, "has a planted
    // fault" meant "has a name in a list", and a fault that no longer worked would never say so.
    for (name, faults) in &planted {
        assert_reports(*faults, name);
    }
}

#[test]
fn a_verifier_that_says_no_fails_the_rfc_vector() {
    assert_planted("verifier/rfc7515_appendix_a3_vector");
}

#[test]
fn a_verifier_that_ignores_its_key_is_caught() {
    assert_planted("verifier/rejects_a_foreign_key");
}

#[test]
fn a_verifier_that_ignores_its_input_is_caught() {
    assert_planted("verifier/rejects_a_tampered_signing_input");
}

#[test]
fn a_verifier_that_ignores_its_signature_is_caught() {
    assert_planted("verifier/rejects_a_tampered_signature");
}

#[test]
fn a_verifier_that_also_accepts_der_is_caught() {
    assert_planted("verifier/rejects_the_der_encoding");
}

#[test]
fn a_verifier_that_says_yes_to_everything_is_caught_by_the_foreign_key_check() {
    // This is the ONLY way `signer/does_not_verify_under_another_key` can go red, and saying so
    // is the point: no signer can produce a signature that verifies under a key whose private half
    // it does not hold, so a red here always means the verifier.
    assert_planted("signer/does_not_verify_under_another_key");
}

/// The finding this check was added for. Both natural wrong answers to "the signature MUST be 64
/// bytes" are driven here: the one that PANICS on a short slice and the one that pads it up to 64
/// and accepts. Before the wrong-length cases existed, the harness handed the verifier nothing
/// shorter than 64 bytes and BOTH of these passed every published check.
#[test]
fn a_verifier_that_does_not_reject_a_wrong_length_signature_is_caught() {
    assert_planted("verifier/rejects_a_wrong_length_signature");

    // And the PADDING verifier is caught by the LEADING-ZERO case specifically, which is the only
    // case in the harness that can catch it and the reason those four constants exist. Asserted on
    // the detail, not just the name: the previous shape of this fault also truncated long inputs,
    // so the 65-byte case reported first and the check went red without the leading-zero vector
    // being consulted at all. A typo in `LEADING_ZERO_SIGNATURE` was then invisible, which is
    // exactly the "green run that proves nothing" this file exists to prevent.
    let violations = run(Faults {
        verifier_pads_a_short_signature: true,
        ..Default::default()
    });
    let padding: Vec<&Violation> = violations
        .iter()
        .filter(|v| v.check == "verifier/rejects_a_wrong_length_signature")
        .collect();
    assert!(
        padding
            .iter()
            .any(|v| v.detail.contains("LEADING ZERO byte removed")),
        "a padding verifier must be caught by the case built for it: {violations:#?}"
    );
}

/// A verifier that panics is reported as a Violation rather than ending the host's test run, which
/// is the only reason the check above can be observed at all against `signature[..64]`.
#[test]
fn a_verifier_that_panics_is_reported_rather_than_aborting_the_run() {
    assert_planted("verifier/does_not_panic");

    // And it is reported ONCE, naming the first input that panicked, rather than once per call the
    // harness makes. Six identical violations would bury the length that mattered.
    let violations = run(Faults {
        verifier_indexes_the_first_64_bytes: true,
        ..Default::default()
    });
    assert_eq!(
        violations
            .iter()
            .filter(|v| v.check == "verifier/does_not_panic")
            .count(),
        1,
        "{violations:#?}"
    );

    // The other two inputs the MUST NOT PANIC clause names, each asserted on the DETAIL rather
    // than on the check name: the name only says that SOMETHING panicked, and what these two
    // faults are here to prove is that the harness PRESENTS an off-curve key and an empty signing
    // input at all. Before it did, a verifier that unwrapped its key panicked on a DPoP proof
    // anyone could send and collected a green run from this harness.
    for (faults, expected) in [
        (
            Faults {
                verifier_unwraps_an_off_curve_key: true,
                ..Default::default()
            },
            "an OFF-CURVE key",
        ),
        (
            Faults {
                verifier_reads_the_first_input_byte: true,
                ..Default::default()
            },
            "an EMPTY signing input",
        ),
    ] {
        let violations = run(faults);
        assert!(
            violations
                .iter()
                .any(|v| v.check == "verifier/does_not_panic" && v.detail.contains(expected)),
            "the panic must be reported against {expected}: {violations:#?}"
        );
    }
}

/// A signer that panics is reported too, and both halves of `sign` are covered.
///
/// `Es256Signer::sign` carries the same MUST NOT PANIC clause as the verifier and, until this
/// existed, nothing checked it: the harness wrapped every verifier call and called the signer bare.
/// The blast radius is the larger of the two, since a panic there unwinds out of
/// `JwtConfig::sign_access_token` and into the host's token endpoint.
#[test]
fn a_signer_that_panics_is_reported_rather_than_aborting_the_run() {
    assert_planted("signer/does_not_panic");

    // A panic is ALSO an `Err` for `signer/signs`: nothing below a missing signature can be
    // checked, so the run has to stop where it stops for a signer that refused.
    for faults in [
        Faults {
            signer_panics_while_building_the_request: true,
            ..Default::default()
        },
        Faults {
            signer_panics_while_awaiting_the_response: true,
            ..Default::default()
        },
    ] {
        let violations = run(faults);
        assert!(
            violations.iter().any(|v| v.check == "signer/signs"),
            "a signer that panicked did not sign: {violations:#?}"
        );
    }
}

#[test]
fn a_signer_that_refuses_is_caught() {
    assert_planted("signer/signs");
}

#[test]
fn a_signer_that_returns_der_is_caught_by_name() {
    assert_planted("signer/output_is_not_der");
}

#[test]
fn a_signer_that_publishes_a_key_it_does_not_sign_with_is_caught() {
    assert_planted("signer/verifies_under_its_own_public_jwk");
}

#[test]
fn a_signer_that_ignores_the_bytes_it_was_handed_is_caught() {
    assert_planted("signer/binds_the_signing_input");
}

#[test]
fn a_public_jwk_that_is_not_cached_is_caught() {
    assert_planted("signer/public_jwk_is_stable");
}

#[test]
fn a_trimmed_coordinate_is_caught() {
    assert_planted("signer/public_jwk_is_an_es256_p256_key");
}

#[test]
fn a_public_jwk_with_no_kid_is_caught() {
    assert_planted("signer/public_jwk_has_a_kid");
}

#[test]
fn signing_with_the_rfcs_own_example_key_is_caught() {
    assert_planted("signer/is_not_the_published_example_key");
}
