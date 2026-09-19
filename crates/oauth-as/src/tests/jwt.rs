// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for the part of the `jwt` module that a caller outside the crate cannot reach.
//!
//! `JwtError` is returned by [`super::JwtConfig::sign_access_token`], which cannot fail for the
//! shapes this crate builds (a struct of strings and numbers always serializes, and ECDSA over a
//! loaded key always signs). The one path that CAN produce one is `unix_seconds`, which is
//! `pub(crate)`, so its refusal and its message are only testable from in here. The rest of the
//! module's surface is driven from `tests/jwt.rs` and `tests/jwt_key_identity.rs`.
//!
//! [`super::CompactJws::reject_unknown_crit`] is also driven directly from here, and for a
//! different reason: its three refusing arms are reached from four verifiers (DPoP proofs, client
//! assertions, RFC 9101 request objects), but only through headers those verifiers will build, so
//! the NON-ARRAY arm — a `crit` that is a string, a number, a null — is not reachable by any route
//! the end-to-end tests take. A check nothing exercises is a check nobody would notice being
//! deleted.

use super::*;
use std::time::Duration;

/// RFC 7519 section 2: a `NumericDate` counts seconds SINCE the epoch, so an instant before the
/// epoch has no representation at all. Refusing is the only correct answer; wrapping or saturating
/// would mint a token whose `iat` and `exp` are a fiction, and `exp` in particular is the only
/// thing standing between a leaked token and an unbounded lifetime.
#[test]
fn a_clock_before_the_epoch_is_refused_with_a_message_a_host_can_act_on() {
    let before = UNIX_EPOCH
        .checked_sub(Duration::from_secs(1))
        .expect("SystemTime can represent one second before the epoch");
    let err = unix_seconds(before).expect_err("a pre-epoch instant has no NumericDate");

    // The message is the host's only diagnostic: the wire gets an opaque `server_error`, by
    // design, so a silent or empty message leaves nobody able to find the misconfigured clock.
    let text = err.to_string();
    assert!(text.contains("JWT signing error"), "{text}");
    assert!(text.contains("clock is before the Unix epoch"), "{text}");

    // The epoch itself is representable and is zero, so the refusal is about being BEFORE it.
    assert_eq!(
        unix_seconds(UNIX_EPOCH).expect("the epoch is second zero"),
        0
    );
    assert_eq!(
        unix_seconds(UNIX_EPOCH + Duration::from_secs(1_700_000_000)).expect("a normal instant"),
        1_700_000_000
    );
}

/// One JWS with the given protected header, over a fixed payload and an unchecked signature.
///
/// `reject_unknown_crit` reads the header and nothing else, so a real signature would only make the
/// fixture harder to read: these tests are about what the parser refuses BEFORE anybody verifies.
fn jws_with_header(header: &str) -> String {
    compact_jws(header.as_bytes(), br#"{"iss":"someone"}"#, |_| {
        vec![0u8; 64]
    })
}

/// RFC 7515 section 4.1.11 in full, arm by arm, because each arm is a separate refusal and the
/// interesting one is unreachable from any verifier's own tests.
///
/// The member's meaning is that the producer REQUIRES the recipient to understand the named header
/// parameters. This verifier implements no JWS extension, so:
///
/// - a `crit` naming anything is a refusal (RFC 8725 section 3.10 names this as an attack surface:
///   `"crit":["b64"]` with `"b64":false` means the payload was signed unencoded, so a verifier that
///   ignores the member verifies a different message from the one that was signed);
/// - an EMPTY `crit` is refused by 4.1.11 itself, whatever the recipient implements. A verifier that
///   only scanned for unrecognised names would accept it, having found none;
/// - a `crit` that is not an ARRAY is refused too. 4.1.11 fixes the type, and a header that gets it
///   wrong is one this server cannot evaluate the requirement of — which must mean refuse, not
///   ignore. `"crit":"b64"` is exactly what a producer writing the member by hand emits, and a
///   verifier matching only on the array shape would fall through it to a happy accept.
#[test]
fn a_crit_header_is_refused_in_every_shape_rfc_7515_allows_it_to_arrive_in() {
    // No `crit` at all: the ordinary case, and the only accepting arm.
    let ok = jws_with_header(r#"{"alg":"ES256"}"#);
    assert!(CompactJws::parse(&ok)
        .expect("a well formed JWS")
        .reject_unknown_crit()
        .is_ok());

    for (header, expected) in [
        (
            r#"{"alg":"ES256","crit":["b64"],"b64":false}"#,
            "names an extension this server does not implement",
        ),
        (r#"{"alg":"ES256","crit":[]}"#, "empty crit"),
        // The two arms no verifier's own tests reach.
        (r#"{"alg":"ES256","crit":"b64"}"#, "not an array"),
        (r#"{"alg":"ES256","crit":null}"#, "not an array"),
    ] {
        let token = jws_with_header(header);
        let error = CompactJws::parse(&token)
            .expect("the header is well formed JSON, so the refusal is about crit")
            .reject_unknown_crit()
            .expect_err(header);
        assert!(
            error.to_string().contains(expected),
            "{header} was refused as {error}, which does not say {expected}"
        );
    }
}

/// [`super::consistent`] is the algorithm-confusion guard: it must REFUSE a key whose kind is not
/// the kind the chosen algorithm signs with, and ACCEPT the matching kind. The verifiers each carry
/// their own key-kind guard as well (defense in depth), so a `consistent` that always returned
/// `true` would still be caught end-to-end — but the invariant lives here, and this pins it
/// directly: a mutant that made `consistent` unconditionally `true` fails every cross-kind
/// assertion below.
#[test]
fn consistent_refuses_a_key_of_the_wrong_kind_for_the_algorithm() {
    // Coordinates/parameters are irrelevant to `consistent`; only the KIND is read. Empty strings
    // are fine because the function inspects the variant, not the bytes.
    let ec = Jwk::Ec {
        crv: EcCurve::P256,
        x: String::new(),
        y: String::new(),
        kid: None,
    };
    let rsa = Jwk::Rsa {
        n: String::new(),
        e: String::new(),
        kid: None,
    };
    let okp = Jwk::Okp {
        crv: OkpCurve::Ed25519,
        x: String::new(),
        kid: None,
    };

    // Matching kind: accepted.
    assert!(consistent(JwsAlg::Es256, &ec));
    assert!(consistent(JwsAlg::Rs256, &rsa));
    assert!(consistent(JwsAlg::EdDsa, &okp));

    // Cross-kind: refused. Each of these is a case a mutant returning `true` gets wrong.
    assert!(!consistent(JwsAlg::Rs256, &ec));
    assert!(!consistent(JwsAlg::EdDsa, &ec));
    assert!(!consistent(JwsAlg::Es256, &rsa));
    assert!(!consistent(JwsAlg::EdDsa, &rsa));
    assert!(!consistent(JwsAlg::Es256, &okp));
    assert!(!consistent(JwsAlg::Rs256, &okp));
}

/// Invariant #1: the algorithm is chosen by the REGISTRATION, and the token header only gets to
/// agree with it. [`super::expect_alg`] under [`super::AlgPolicy::Registered`] must accept a header
/// whose `alg` matches and refuse one that does not. The comparison is `alg != expected`; a mutant
/// flipping it to `==` accepts the mismatch and refuses the match, so both assertions here go red.
#[test]
fn expect_alg_pins_the_registered_algorithm_against_the_header() {
    // The `installed` set is not consulted on the `Registered` path, so an empty one is enough.
    let installed = JwsVerifiers::new();
    let sign = |_: &str| vec![0u8; 64];

    // Header agrees with the registration: accepted, and yields the registered algorithm.
    let matching = compact_jws(br#"{"alg":"ES256"}"#, br#"{"iss":"someone"}"#, sign);
    let jws = CompactJws::parse(&matching).expect("a well formed JWS");
    assert_eq!(
        expect_alg(&jws, AlgPolicy::Registered(JwsAlg::Es256), &installed),
        Ok(JwsAlg::Es256),
    );

    // Header names a different (but wired) algorithm: refused as a mismatch, NEVER honoured.
    let mismatch = compact_jws(br#"{"alg":"RS256"}"#, br#"{"iss":"someone"}"#, sign);
    let jws = CompactJws::parse(&mismatch).expect("a well formed JWS");
    assert_eq!(
        expect_alg(&jws, AlgPolicy::Registered(JwsAlg::Es256), &installed),
        Err(AlgRefusal::Mismatch),
    );
}

/// [`super::JwsSignature::from_wire`] is the width check the fixed-size arrays make impossible to
/// skip: the fixed-width curves require EXACTLY 64 bytes, RS256 takes the decoded octets as-is. A
/// mutant returning `None` for every input fails the `Some` round-trips below.
#[test]
fn from_wire_accepts_the_right_width_and_round_trips() {
    // ES256: exactly 64 bytes, round-tripped by value.
    let es = JwsSignature::from_wire(JwsAlg::Es256, &[7u8; 64]).expect("64 bytes is a valid ES256");
    assert_eq!(es.alg(), JwsAlg::Es256);
    assert_eq!(es.as_bytes(), &[7u8; 64]);
    assert!(JwsSignature::from_wire(JwsAlg::Es256, &[0u8; 63]).is_none());
    assert!(JwsSignature::from_wire(JwsAlg::Es256, &[0u8; 65]).is_none());

    // EdDSA: same fixed 64-byte width.
    let ed = JwsSignature::from_wire(JwsAlg::EdDsa, &[9u8; 64]).expect("64 bytes is a valid EdDSA");
    assert_eq!(ed.alg(), JwsAlg::EdDsa);
    assert_eq!(ed.as_bytes(), &[9u8; 64]);
    assert!(JwsSignature::from_wire(JwsAlg::EdDsa, &[0u8; 32]).is_none());

    // RS256: octets as-is, so a 256-byte (RSA-2048) modulus width is taken verbatim.
    let rs = JwsSignature::from_wire(JwsAlg::Rs256, &[1u8; 256]).expect("RS256 takes octets as-is");
    assert_eq!(rs.alg(), JwsAlg::Rs256);
    assert_eq!(rs.as_bytes(), &[1u8; 256]);
}

/// The ES256 PKCS#8 round-trip, pinned BY VALUE: [`super::EcdsaP256Key::to_pkcs8_der`] must emit
/// non-empty DER (a `PrivateKeyInfo` SEQUENCE) that [`super::EcdsaP256Key::from_pkcs8_der`] reads
/// back into the SAME public key. A mutant returning `Ok(vec![])` or `Ok(vec![0])` fails the
/// non-empty / DER-tag assertions; a mutant returning `Ok(Default::default())` from the loader
/// fails the public-JWK equality.
#[cfg(feature = "jwt-pkcs8")]
#[test]
fn ecdsa_p256_pkcs8_der_round_trips_by_value() {
    // A deterministic key (fixed scalar) so the round-trip is a known answer, not a coin flip.
    let scalar = [0x42u8; 32];
    let key = EcdsaP256Key::from_scalar_bytes("pkcs8-kid", &scalar)
        .expect("0x42-repeated is a valid P-256 scalar");

    let der = key
        .to_pkcs8_der()
        .expect("PKCS#8 export succeeds for a loaded key");
    assert!(!der.is_empty(), "PKCS#8 export must not be empty");
    assert_eq!(
        der[0], 0x30,
        "a PKCS#8 PrivateKeyInfo is a DER SEQUENCE (tag 0x30)"
    );

    let reloaded =
        EcdsaP256Key::from_pkcs8_der("pkcs8-kid", &der).expect("the DER we just wrote round-trips");
    assert_eq!(
        reloaded.public_jwk(),
        key.public_jwk(),
        "the reloaded key must be the same key by its public half",
    );
}
