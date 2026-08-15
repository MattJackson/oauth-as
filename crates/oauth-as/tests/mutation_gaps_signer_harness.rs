// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! FAULTS THE EXPORTED `signer_conformance` HARNESS COULD NOT SEE, FOUND BY MUTATING IT.
//!
//! # Why these matter more than an ordinary coverage gap
//!
//! This module is a PUBLISHED surface. A host enables `test-util`, points
//! [`oauth_as::signer_conformance::SignerConformance`] at the KMS or HSM backend it is about to
//! deploy, and takes an empty violation list as evidence that its signing is correct. A hole here
//! does not weaken this crate's confidence in itself; it weakens a STRANGER'S confidence in THEIR
//! backend, and it does so by reporting green.
//!
//! `tests/signer_conformance_selftest.rs` plants one deliberate fault per check and proves each is
//! caught. What the `--all-features` mutation sweep at commit `42fa851` adds is the other half of
//! the question: which parts of the harness could be WEAKENED with the selftest still green? Nine
//! such sites turned up, and this file closes them:
//!
//! ```text
//! signer_conformance.rs replace <impl fmt::Display for Violation>::fmt -> fmt::Result with Ok(Default::default())
//! signer_conformance.rs replace && with || in check_signer   (the example-key check)
//! signer_conformance.rs replace && with || in check_signer   (the DER heuristic)
//! signer_conformance.rs replace && with || in check_signer   (the DER heuristic)
//! signer_conformance.rs replace || with && in check_signer   (the binding cross-check)
//! signer_conformance.rs replace & with | in der::integer
//! signer_conformance.rs replace & with ^ in der::integer
//! signer_conformance.rs replace != with == in der::integer
//! ```
//!
//! Two of them can make the harness report GREEN for a backend that is broken, which is the bar
//! that makes a survivor worth almost any cost. The `418` one lets a signer that ignores the bytes
//! it was handed past `signer/binds_the_signing_input`; the three in `der::integer` make the DER
//! the harness presents NON-CANONICAL, so a verifier that accepts canonical DER (which is what
//! OpenSSL and every KMS emits, and therefore the only DER a real deployment would ever be handed)
//! is no longer caught by `verifier/rejects_the_der_encoding`.
//!
//! The other direction, a harness that reports a violation against a CORRECT backend, is not
//! harmless either: a false accusation against a KMS is a deployment that does not ship.

#![cfg(all(feature = "test-util", feature = "jwt-p256"))]

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use oauth_as::jwt::{
    verify_es256, EcdsaP256Key, Es256Signer, Es256Verifier, Jwk, P256Verifier, PublicJwk,
    SignerError,
};
use oauth_as::signer_conformance::{SignerConformance, Violation, CHECKS};

// ------------------------------------------------------------------ check names
//
// Literals rather than imports, because the harness keeps the constants private and publishes them
// only through `CHECKS`. Pinned against that list below, so a rename fails here rather than
// quietly making every assertion in this file match nothing.

const VERIFIER_REJECTS_DER: &str = "verifier/rejects_the_der_encoding";
const SIGNER_IS_NOT_DER: &str = "signer/output_is_not_der";
const SIGNER_BINDS_THE_SIGNING_INPUT: &str = "signer/binds_the_signing_input";
const SIGNER_IS_NOT_THE_PUBLISHED_EXAMPLE_KEY: &str = "signer/is_not_the_published_example_key";

#[test]
fn every_name_this_file_asserts_on_is_a_published_check() {
    for name in [
        VERIFIER_REJECTS_DER,
        SIGNER_IS_NOT_DER,
        SIGNER_BINDS_THE_SIGNING_INPUT,
        SIGNER_IS_NOT_THE_PUBLISHED_EXAMPLE_KEY,
    ] {
        assert!(
            CHECKS.contains(&name),
            "{name} is not in the published CHECKS list, so every assertion in this file that \
             names it has silently stopped matching anything"
        );
    }
}

// ------------------------------------------------------------------ the RFC 7515 A.3 vector
//
// Restated here from RFC 7515 appendix A.3 rather than imported: the harness keeps its copy
// private, and a vector this file took from the code under test would prove only that the code
// agrees with itself.

const A3_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
const A3_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
const A3_SIGNATURE: &str =
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
/// RFC 7517 appendix A.1's example EC public key, which the harness uses as the key a signature
/// must NOT verify under.
const OTHER_Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";

/// The two signing inputs the harness asks a signer for, duplicated from
/// `src/signer_conformance.rs`.
///
/// DUPLICATED ON PURPOSE and pinned by `the_harness_asks_for_exactly_these_two_signing_inputs`
/// below. `a_signer_that_covers_the_second_input_and_crosses_into_it_is_caught` has to produce a
/// signature over the SECOND input while being asked for the first, which cannot be expressed
/// without knowing what the second one is. Without the pinning test a rename would leave that
/// fixture signing a stale string, the test would still pass for an unrelated reason, and the
/// mutant it exists to kill would come back to life unnoticed.
const INPUT_A: &str = "oauth-as.signer-conformance.a";
const INPUT_B: &str = "oauth-as.signer-conformance.b";

fn decode(b64: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(b64).expect("a base64url constant")
}

fn run(signer: impl Es256Signer, verifier: impl Es256Verifier) -> Vec<Violation> {
    futures_lite_block_on(SignerConformance::new(signer, verifier).run())
}

/// A one-line executor, so this file needs no runtime feature of its own.
///
/// Every future here resolves on its first poll: the built-in signer holds its key in this
/// process, and the fixtures below are all synchronous. A future that suspended would spin, which
/// is exactly the failure a test would want to see rather than hide.
fn futures_lite_block_on<F: Future>(future: F) -> F::Output {
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

fn reports(violations: &[Violation], check: &str) -> bool {
    violations.iter().any(|v| v.check == check)
}

// ------------------------------------------------------------------ a correct backend

/// The built-in backend, which must produce no violations at all. Every "this fixture is reported"
/// assertion below is only meaningful against this baseline.
#[test]
fn the_built_in_backend_is_the_baseline_and_reports_nothing() {
    let violations = run(EcdsaP256Key::generate("baseline"), P256Verifier);
    assert!(violations.is_empty(), "{violations:#?}");
}

// ------------------------------------------------------------------ Violation's Display

/// A violation prints BOTH halves: the check that failed and what was observed.
///
/// Kills `<impl fmt::Display for Violation>::fmt -> Ok(Default::default())`. The harness returns
/// violations rather than panicking precisely so a host can report them the way it likes, and
/// `Display` is the way most hosts will. Emptied, a failing conformance run prints a list of blank
/// lines and the deployment learns nothing.
#[test]
fn a_violation_prints_its_check_and_its_detail() {
    let v = Violation {
        check: SIGNER_IS_NOT_DER,
        detail: "the signature looks like an ASN.1 DER SEQUENCE".to_string(),
    };
    let printed = v.to_string();
    assert!(
        printed.contains(SIGNER_IS_NOT_DER),
        "the check name is how a host groups, filters or waives: {printed:?}"
    );
    assert!(
        printed.contains("ASN.1 DER SEQUENCE"),
        "and the detail is the part that says what to fix: {printed:?}"
    );
}

// ------------------------------------------------------------------ fixtures

/// Signs with a real key, but publishes whatever JWK it was built with and returns whatever
/// signature bytes it was built to return.
struct Fixture {
    key: EcdsaP256Key,
    published: Jwk,
    /// Sixty-four fixed bytes to return instead of a real signature.
    fixed_signature: Option<[u8; 64]>,
    /// Sign THIS message instead of the one asked for, on the FIRST call only.
    first_call_signs_instead: Option<Vec<u8>>,
    calls: AtomicUsize,
    /// Every signing input the harness asked for, in order.
    asked: Mutex<Vec<Vec<u8>>>,
}

impl Fixture {
    fn correct() -> Self {
        let key = EcdsaP256Key::from_scalar_bytes("fixture", &[7u8; 32])
            .expect("a fixed scalar keeps this file deterministic");
        let published = key.public_jwk();
        Fixture {
            key,
            published,
            fixed_signature: None,
            first_call_signs_instead: None,
            calls: AtomicUsize::new(0),
            asked: Mutex::new(Vec::new()),
        }
    }
}

impl Es256Signer for Fixture {
    fn sign(
        &self,
        signing_input: &[u8],
    ) -> impl Future<Output = Result<[u8; 64], SignerError>> + Send {
        self.asked
            .lock()
            .expect("no test here panics while holding this")
            .push(signing_input.to_vec());
        let first = self.calls.fetch_add(1, Ordering::SeqCst) == 0;
        let out = if let Some(fixed) = self.fixed_signature {
            fixed
        } else {
            let message: &[u8] = match (first, &self.first_call_signs_instead) {
                (true, Some(other)) => other,
                _ => signing_input,
            };
            let mut buf = [0u8; 64];
            buf.copy_from_slice(
                &self
                    .key
                    .sign_signing_input(&String::from_utf8_lossy(message))
                    .expect("the fixture key signs"),
            );
            buf
        };
        async move { Ok(out) }
    }

    fn public_jwk(&self) -> Jwk {
        self.published.clone()
    }
}

// ------------------------------------------------------------------ the example-key check

/// A key that shares ONLY its `x` with the RFC 7515 appendix A.3 example key is not accused of
/// BEING that key.
///
/// Kills `332:32: replace && with ||`. The accusation this check makes is that the deployment is
/// signing with a key whose private half is printed in an RFC, which is the strongest sentence in
/// the whole harness; under `||` it is made against any key that collides on one coordinate. A
/// harness that cries wolf about a key that is fine is a harness a deployment learns to ignore.
#[test]
fn a_key_sharing_one_coordinate_with_the_rfc_example_is_not_accused_of_being_it() {
    let mut fixture = Fixture::correct();
    fixture.published = Jwk {
        kty: "EC",
        crv: "P-256",
        x: A3_X.to_string(),
        y: OTHER_Y.to_string(),
        kid: "half-a-collision".to_string(),
        use_: "sig",
        alg: "ES256",
    };
    let violations = run(fixture, P256Verifier);
    assert!(
        !reports(&violations, SIGNER_IS_NOT_THE_PUBLISHED_EXAMPLE_KEY),
        "only BOTH coordinates matching means the signer is the example key: {violations:#?}"
    );
}

// ------------------------------------------------------------------ the DER heuristic

/// Sixty-four bytes that merely BEGIN with `0x30`, over a plausible length byte, are not accused
/// of being DER.
///
/// Kills `366:33: replace && with ||`, the FIRST of the two conjunctions, and the choice of bytes
/// is the whole test. The condition is `(A && B) && C` for `A = [0] == 0x30`, `B = [2] == 0x02`,
/// `C = [1] in 0x40..=0x48`, so a witness has to make `A && B` differ from `A || B` AND let the
/// difference reach the answer: A true, B false, C TRUE gives `(T && F) && T = false` against
/// `(T || F) && T = true`. The earlier fixture set C false as well, so both spellings answered
/// false, the assertion below held either way, and the mutant it names survived it untouched —
/// a test that could not fail for its stated reason, in the file whose subject is exactly that.
///
/// The heuristic is deliberately three conditions wide, because two fixed bytes plus a plausible
/// length is about one chance in two million of a false accusation against a random `R || S`; one
/// condition alone is one in 256, which every deployment would eventually hit and none would be
/// able to explain.
#[test]
fn a_signature_that_merely_starts_with_thirty_is_not_accused_of_being_der() {
    let mut fixture = Fixture::correct();
    let mut signature = [0x11u8; 64];
    signature[0] = 0x30;
    signature[1] = 0x44; // inside 0x40..=0x48, so the third condition cannot mask the mutant
    signature[2] = 0x11; // not the 0x02 that starts a DER INTEGER
    fixture.fixed_signature = Some(signature);
    let violations = run(fixture, P256Verifier);
    assert!(
        !reports(&violations, SIGNER_IS_NOT_DER),
        "one byte in three is not the DER shape: {violations:#?}"
    );
}

/// Sixty-four bytes whose SECOND byte merely falls in the DER length range are not accused either.
///
/// Kills `366:57: replace && with ||`, which is the other of the two conjunctions and needs a
/// different witness: the first two conditions are false here and only the length range matches.
#[test]
fn a_signature_whose_second_byte_looks_like_a_der_length_is_not_accused() {
    let mut fixture = Fixture::correct();
    let mut signature = [0x11u8; 64];
    signature[0] = 0x11; // not 0x30
    signature[1] = 0x44; // inside 0x40..=0x48
    signature[2] = 0x11; // not 0x02
    fixture.fixed_signature = Some(signature);
    let violations = run(fixture, P256Verifier);
    assert!(
        !reports(&violations, SIGNER_IS_NOT_DER),
        "a length byte alone is not the DER shape: {violations:#?}"
    );
}

// ------------------------------------------------------------------ the binding cross-check

/// The harness asks for exactly the two inputs this file names.
///
/// Pins the duplication of `INPUT_A` and `INPUT_B`. Without it the fixture below could be signing
/// a string the harness no longer uses, and the test would keep passing for the wrong reason.
#[test]
fn the_harness_asks_for_exactly_these_two_signing_inputs() {
    let fixture = std::sync::Arc::new(Fixture::correct());
    let violations = run(std::sync::Arc::clone(&fixture), P256Verifier);
    assert!(violations.is_empty(), "{violations:#?}");
    let asked = fixture.asked.lock().expect("no panic while held");
    assert_eq!(
        asked.as_slice(),
        &[INPUT_A.as_bytes().to_vec(), INPUT_B.as_bytes().to_vec()],
        "the fixture below depends on the SECOND input being exactly this"
    );
}

/// A signer whose first signature is over the harness's SECOND input is caught by the binding
/// check.
///
/// Kills `418:21: replace || with &&`, and this is the one that can make the harness report a
/// backend fine when it is not. The two facts the check reports as one are that the second
/// signature covers the second input, and that NEITHER signature verifies over the other's input.
/// This fixture satisfies the first and fails the second in exactly one direction, which is
/// precisely what `&&` stops seeing.
///
/// A real backend lands here by signing a buffer it captured rather than the argument it was
/// handed, which is what a KMS wrapper does when it reuses a request struct across calls.
#[test]
fn a_signer_that_crosses_into_the_other_input_in_one_direction_is_caught() {
    let mut fixture = Fixture::correct();
    fixture.first_call_signs_instead = Some(INPUT_B.as_bytes().to_vec());
    let violations = run(fixture, P256Verifier);
    assert!(
        reports(&violations, SIGNER_BINDS_THE_SIGNING_INPUT),
        "one signature verified over the other's input, which is the whole of this check: \
         {violations:#?}"
    );
}

// ------------------------------------------------------------------ the DER the harness presents

/// The canonical ASN.1 DER `SEQUENCE { r INTEGER, s INTEGER }` for a 64-byte `R || S`.
///
/// Written here independently of the harness's own encoder, which is the point: it is the encoding
/// OpenSSL and every KMS emits, with MINIMAL length octets and a leading `0x00` if and only if the
/// top bit of the first content octet is set (X.690 section 8.3).
fn canonical_der(fixed_width: &[u8]) -> Vec<u8> {
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

/// A verifier that accepts the CANONICAL DER encoding of the RFC 7515 A.3 signature, and nothing
/// else that is not a proper fixed-width signature.
///
/// This is the malleable verifier `verifier/rejects_the_der_encoding` exists to catch, written to
/// accept ONLY the encoding a real KMS would hand it.
struct AcceptsCanonicalDer {
    canonical: Vec<u8>,
}

impl Es256Verifier for AcceptsCanonicalDer {
    fn verify(&self, key: &PublicJwk, signing_input: &[u8], signature: &[u8]) -> bool {
        if signature == self.canonical.as_slice() {
            return true;
        }
        verify_es256(key, signing_input, signature)
    }
}

/// The DER the harness presents is the CANONICAL encoding, so a verifier that accepts canonical
/// DER is caught.
///
/// Kills the three `der::integer` mutants at `512`. Each of them changes when the leading `0x00`
/// is emitted: `&` to `|` or `^` pads both integers unconditionally, and `!=` to `==` inverts the
/// rule, which drops the pad from an integer whose top bit IS set and so encodes a NEGATIVE
/// value. All three produce something still DER-shaped, which is why every existing check stayed
/// green, and all three stop being the encoding a real deployment would ever be handed. A verifier
/// that accepts canonical DER, which is the only kind worth catching, then passes.
#[test]
fn the_der_the_harness_presents_is_the_canonical_encoding() {
    let signature = decode(A3_SIGNATURE);
    let verifier = AcceptsCanonicalDer {
        canonical: canonical_der(&signature),
    };
    let violations = run(EcdsaP256Key::generate("canonical"), verifier);
    assert!(
        reports(&violations, VERIFIER_REJECTS_DER),
        "a verifier that accepts the canonical DER of a valid signature is malleable and must be \
         reported: {violations:#?}"
    );
}

/// The harness's A.3 constants are the RFC's, checked against this file's independent copy.
///
/// Cheap, and it is what stops the test above from passing because both sides happen to agree on
/// the wrong vector: the key here is the RFC's, and the signature verifies under it.
#[test]
fn the_rfc_7515_a3_vector_restated_here_is_self_consistent() {
    let key = PublicJwk::from_coordinates(A3_X, A3_Y).expect("the RFC's coordinates are 32 bytes");
    let signing_input = concat!(
        "eyJhbGciOiJFUzI1NiJ9",
        ".",
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    );
    assert!(
        verify_es256(&key, signing_input.as_bytes(), &decode(A3_SIGNATURE)),
        "the appendix A.3 vector must verify under the appendix A.3 key"
    );
}

// ------------------------------------------------------------------ the two tamperings the harness makes
//
// `check_verifier` builds a signature that MUST be rejected by flipping the low bit of the first
// signature byte (`bad_signature[0] ^= 0x01`) and a signing input that MUST be rejected by flipping
// the low bit of the last input byte (`tampered[last] ^= 0x01`). The `^= 0x01` matters: it is what
// guarantees the byte actually CHANGES. A mutant that masks the byte (`&= 0x01`) instead produces a
// DIFFERENT wrong value, so a correct verifier still rejects it and the baseline stays green -- but
// a verifier that is malleable at exactly the bit the harness flips is no longer caught, because the
// harness is now flipping a different bit than the one the verifier tolerates.

/// The A.3 signing input, restated (see `INPUT_A`/`INPUT_B` above on why this file duplicates rather
/// than imports the harness's private constants). Pinned by
/// `the_rfc_7515_a3_vector_restated_here_is_self_consistent`, which verifies the A.3 signature over
/// exactly these bytes.
const A3_SIGNING_INPUT: &str = concat!(
    "eyJhbGciOiJFUzI1NiJ9",
    ".",
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
);

const VERIFIER_REJECTS_A_TAMPERED_SIGNATURE: &str = "verifier/rejects_a_tampered_signature";
const VERIFIER_REJECTS_A_TAMPERED_INPUT: &str = "verifier/rejects_a_tampered_signing_input";

/// Accepts ONE exact signature and otherwise verifies for real: a verifier malleable at precisely
/// the byte value the harness's `^= 0x01` produces.
struct AcceptsExactSignature {
    accept: Vec<u8>,
}

impl Es256Verifier for AcceptsExactSignature {
    fn verify(&self, key: &PublicJwk, signing_input: &[u8], signature: &[u8]) -> bool {
        signature == self.accept.as_slice() || verify_es256(key, signing_input, signature)
    }
}

/// Accepts ONE exact signing input and otherwise verifies for real: malleable at precisely the input
/// byte the harness's `^= 0x01` produces.
struct AcceptsExactInput {
    accept_input: Vec<u8>,
}

impl Es256Verifier for AcceptsExactInput {
    fn verify(&self, key: &PublicJwk, signing_input: &[u8], signature: &[u8]) -> bool {
        signing_input == self.accept_input.as_slice() || verify_es256(key, signing_input, signature)
    }
}

/// The tampered-signature check XOR-flips the byte rather than masking it.
///
/// Kills `signer_conformance.rs:402 replace ^= with &= in check_verifier`. The harness presents the
/// A.3 signature with its first byte `^= 0x01`; this verifier accepts exactly that value. Under the
/// real `^=` the presented signature IS that value, so the malleable verifier is caught. Under `&=`
/// the harness zeroes the byte instead (`0x0e & 0x01 == 0x00`), presents a signature this verifier
/// does not recognise and that does not verify, and the check never fires. (The `|= 0x01` mutant is
/// equivalent here: the real byte `0x0e` is even, so `^` and `|` with `0x01` both yield `0x0f`.)
#[test]
fn the_tampered_signature_check_flips_the_bit_rather_than_masking_the_byte() {
    assert!(CHECKS.contains(&VERIFIER_REJECTS_A_TAMPERED_SIGNATURE));
    let mut accept = decode(A3_SIGNATURE);
    accept[0] ^= 0x01;
    let violations = run(
        EcdsaP256Key::generate("tamper-signature"),
        AcceptsExactSignature { accept },
    );
    assert!(
        reports(&violations, VERIFIER_REJECTS_A_TAMPERED_SIGNATURE),
        "a verifier that accepts the exact bit-flipped signature the harness presents must be \
         caught; a harness that masked the byte instead would present something else and miss it: \
         {violations:#?}"
    );
}

/// The tampered-input check XOR-flips the byte rather than masking it.
///
/// Kills `signer_conformance.rs:390 replace ^= with &= in check_verifier`. The harness presents the
/// A.3 signing input with its LAST byte `^= 0x01`; this verifier accepts exactly that input. Under
/// the real `^=` the presented input IS that value and the malleable verifier is caught. Under `&=`
/// the harness produces `0x51 & 0x01 == 0x01` instead, a different input this verifier does not
/// recognise, and the check never fires. (The `|= 0x01` mutant is not a survivor: the real byte
/// `0x51` is odd, so `| 0x01` leaves it unchanged, the "tampered" input equals the real one, and a
/// correct verifier accepting it makes the baseline green run go red.)
#[test]
fn the_tampered_input_check_flips_the_bit_rather_than_masking_the_byte() {
    assert!(CHECKS.contains(&VERIFIER_REJECTS_A_TAMPERED_INPUT));
    let mut accept_input = A3_SIGNING_INPUT.as_bytes().to_vec();
    let last = accept_input.len() - 1;
    accept_input[last] ^= 0x01;
    let violations = run(
        EcdsaP256Key::generate("tamper-input"),
        AcceptsExactInput { accept_input },
    );
    assert!(
        reports(&violations, VERIFIER_REJECTS_A_TAMPERED_INPUT),
        "a verifier that accepts the exact bit-flipped input the harness presents must be caught; \
         a harness that masked the byte instead would present something else and miss it: \
         {violations:#?}"
    );
}
