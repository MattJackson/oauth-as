// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! What an UNAUTHENTICATED DPoP proof may cost this server before it is refused.
//!
//! Every test here is an attack sent by somebody who holds no credential at all: the `DPoP` header
//! is read and parsed before the client is authenticated, so whatever this validator does with a
//! hostile string, it does for anyone on the internet.
//!
//! Two properties, both about REFUSING rather than about accepting:
//!
//! - an `iat` so large that `UNIX_EPOCH + Duration::from_secs(iat)` cannot be represented must be
//!   REFUSED, not panicked on. This crate is a library: a panic here unwinds into the host's
//!   request handler, and the request that triggers it is one line of attacker JSON.
//! - a proof larger than [`oauth_as::dpop::MAX_PROOF_BYTES`] must be refused BEFORE it is parsed.
//!   The proof arrives in a header, so the crate's `MAX_BODY_BYTES` never applies to it.
#![cfg(feature = "dpop")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::dpop::{verify_proof, DpopFailure, MAX_PROOF_BYTES};
use oauth_as::jwt::{compact_jws, EcdsaP256Key};

const TOKEN_ENDPOINT: &str = "https://as.example/token";

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

/// A correctly signed RFC 9449 section 4.2 proof carrying exactly the claims given, so every test
/// below reaches the check it is aimed at rather than failing earlier on the signature.
fn signed_proof(key: &EcdsaP256Key, claims: &serde_json::Value) -> String {
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": serde_json::to_value(key.to_public_jwk()).unwrap(),
    });
    compact_jws(
        &serde_json::to_vec(&header).unwrap(),
        &serde_json::to_vec(claims).unwrap(),
        |input| key.sign_signing_input(input).unwrap(),
    )
}

// ------------------------------------------------------------------- the time claim that overflows

/// THE ATTACK: one unauthenticated request carrying `{"iat": 18446744073709551615}`.
///
/// `UNIX_EPOCH + Duration::from_secs(u64::MAX)` is not representable as a `SystemTime` and std
/// PANICS on the overflow, so before this test the proof never reached the window check at all: the
/// addition happened first. The assertion is the REFUSAL, deliberately not `should_panic`, because
/// the property being bought is that no panic occurs.
///
/// Refusing is also right on the merits and not merely defensive: RFC 9449 section 4.3 (10) wants
/// `iat` within an acceptable window, and a value 584 billion years hence is outside every window a
/// server could pick.
#[test]
fn an_iat_of_u64_max_is_refused_rather_than_panicking() {
    let key = EcdsaP256Key::generate("attacker");
    let proof = signed_proof(
        &key,
        &serde_json::json!({
            "jti": "overflow-1",
            "htm": "POST",
            "htu": TOKEN_ENDPOINT,
            "iat": u64::MAX,
        }),
    );

    assert_eq!(
        verify_proof(&proof, "POST", TOKEN_ENDPOINT, now()),
        Err(DpopFailure::StaleProof),
        "an iat that cannot be represented is outside every acceptance window"
    );
}

/// The same overflow one step below the top, so the fix cannot be a special case for `u64::MAX`.
#[test]
fn an_iat_near_u64_max_is_refused_rather_than_panicking() {
    let key = EcdsaP256Key::generate("attacker");
    for iat in [u64::MAX - 1, u64::MAX / 2, i64::MAX as u64] {
        let proof = signed_proof(
            &key,
            &serde_json::json!({
                "jti": "overflow-2",
                "htm": "POST",
                "htu": TOKEN_ENDPOINT,
                "iat": iat,
            }),
        );
        assert_eq!(
            verify_proof(&proof, "POST", TOKEN_ENDPOINT, now()),
            Err(DpopFailure::StaleProof),
            "iat {iat} is in the future and must be refused"
        );
    }
}

// ------------------------------------------------------------------------ the unbounded proof

/// THE ATTACK: a megabyte of `DPoP` header from a client that has authenticated as nobody.
///
/// The proof is a HEADER, so the crate's body cap never applied to it, and `CompactJws::parse`
/// base64-decodes the whole thing and runs two `serde_json::from_slice` calls over the result
/// before any claim is looked at. The refusal must come BEFORE that work.
#[test]
fn a_proof_larger_than_the_cap_is_refused_before_it_is_parsed() {
    let key = EcdsaP256Key::generate("attacker");
    let proof = signed_proof(
        &key,
        &serde_json::json!({
            "jti": "x".repeat(MAX_PROOF_BYTES),
            "htm": "POST",
            "htu": TOKEN_ENDPOINT,
            "iat": 1_700_000_000u64,
        }),
    );
    assert!(proof.len() > MAX_PROOF_BYTES);

    assert_eq!(
        verify_proof(&proof, "POST", TOKEN_ENDPOINT, now()),
        Err(DpopFailure::Malformed),
        "a proof past the cap is refused on size, whatever it would have parsed as"
    );
}

/// The cap must not be so tight that a real proof cannot fit: this is the shape RFC 9449 section
/// 4.3 actually describes, with a P-256 JWK, `htm`, `htu`, `iat`, `jti` and an ES256 signature.
#[test]
fn an_ordinary_proof_is_far_inside_the_cap() {
    let key = EcdsaP256Key::generate("device");
    let proof = signed_proof(
        &key,
        &serde_json::json!({
            "jti": "e1j3V_bKic8-LAEB",
            "htm": "POST",
            "htu": TOKEN_ENDPOINT,
            "iat": 1_700_000_000u64,
        }),
    );

    assert!(
        proof.len() * 4 < MAX_PROOF_BYTES,
        "a conforming proof is {} bytes; a cap of {MAX_PROOF_BYTES} must leave room to spare",
        proof.len()
    );
    assert!(verify_proof(&proof, "POST", TOKEN_ENDPOINT, now()).is_ok());
}
