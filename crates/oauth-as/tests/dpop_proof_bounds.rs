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
//! - a `jti` larger than [`oauth_as::dpop::MAX_JTI_BYTES`] must be refused, which is a DIFFERENT
//!   bound from the one above: the proof cap bounds the work, and the `jti` is the one value the
//!   caller goes on to WRITE DOWN. Under the proof cap alone a single 4 KiB request buys nearly 3
//!   KiB of replay-store row, held for minutes, from a caller holding no credential at all.
//! - a proof whose header carries RFC 7515 section 4.1.11 `crit` must be refused, because this
//!   verifier implements no JWS extension and the member says the producer requires one.
#![cfg(all(feature = "dpop", feature = "jwt-p256"))]
// Requires `jwt-p256`, the built-in ES256 backend, because every test below has to PRODUCE a
// signature. `jwt` alone carries the `Es256Signer`/`Es256Verifier` seam and no curve arithmetic at
// all, so in that build there is nothing here that could run.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::dpop::{verify_proof, DpopFailure, MAX_JTI_BYTES, MAX_PROOF_BYTES};
use oauth_as::jwt::{compact_jws, EcdsaP256Key};

/// The crate's built-in ES256 backend. Verification now goes through the [`oauth_as::jwt::Es256Verifier`] seam,
/// so a verifier is a per-call argument; this is the one a consumer who enables `jwt-p256` gets by
/// default, which is what keeps these tests measuring the behaviour they always measured.
#[cfg(feature = "jwt-p256")]
const VERIFIER: &oauth_as::jwt::P256Verifier = &oauth_as::jwt::P256Verifier;

const TOKEN_ENDPOINT: &str = "https://as.example/token";

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

/// A correctly signed RFC 9449 section 4.2 proof carrying exactly the claims given, so every test
/// below reaches the check it is aimed at rather than failing earlier on the signature.
fn signed_proof(key: &EcdsaP256Key, claims: &serde_json::Value) -> String {
    signed_proof_with_header(key, &proof_header(key), claims)
}

/// The RFC 9449 section 4.2 header, as a value a test can add a member to.
fn proof_header(key: &EcdsaP256Key) -> serde_json::Value {
    serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": serde_json::to_value(key.to_public_jwk()).unwrap(),
    })
}

/// A correctly signed proof over a header the caller chose, so a test can put a `crit` in it. The
/// signature is over the bytes that arrive, so the spoiled header is the one that is signed: these
/// are proofs a client really could mint, not corrupted ones that would fail on the signature.
fn signed_proof_with_header(
    key: &EcdsaP256Key,
    header: &serde_json::Value,
    claims: &serde_json::Value,
) -> String {
    compact_jws(
        &serde_json::to_vec(header).unwrap(),
        &serde_json::to_vec(claims).unwrap(),
        |input| key.sign_signing_input(input).unwrap(),
    )
}

/// The claim set section 4.3 asks for, with a `jti` the caller chooses.
fn claims_with_jti(jti: &str) -> serde_json::Value {
    serde_json::json!({
        "jti": jti,
        "htm": "POST",
        "htu": TOKEN_ENDPOINT,
        "iat": 1_700_000_000u64,
    })
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
        verify_proof(VERIFIER, &proof, "POST", TOKEN_ENDPOINT, now()),
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
            verify_proof(VERIFIER, &proof, "POST", TOKEN_ENDPOINT, now()),
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
///
/// THE BULK IS AN UNREGISTERED CLAIM, and must not be the `jti`. `tests/cap_boundaries.rs` names
/// this hazard for the accepting side and it bites just as hard here: a `jti` big enough to push
/// the proof past the size cap is also past `MAX_JTI_BYTES`, and that check answers with the SAME
/// `DpopFailure::Malformed`. A fixture padded that way therefore stays green with the size gate
/// deleted — it just travels further to reach the identical error, having done exactly the base64
/// decode and the two JSON parses the gate exists to prevent. Padding with a claim no check reads
/// leaves the size gate as the only thing that can refuse this proof.
#[test]
fn a_proof_larger_than_the_cap_is_refused_before_it_is_parsed() {
    let key = EcdsaP256Key::generate("attacker");
    let jti = "e1j3V_bKic8-LAEB";
    let proof = signed_proof(
        &key,
        &serde_json::json!({
            "jti": jti,
            "htm": "POST",
            "htu": TOKEN_ENDPOINT,
            "iat": 1_700_000_000u64,
            "client_padding": "x".repeat(MAX_PROOF_BYTES),
        }),
    );
    assert!(proof.len() > MAX_PROOF_BYTES);
    assert!(
        jti.len() <= MAX_JTI_BYTES,
        "the jti must be inside its own cap, or the refusal below could come from that check \
         instead and the size gate could be deleted with this test still green"
    );

    assert_eq!(
        verify_proof(VERIFIER, &proof, "POST", TOKEN_ENDPOINT, now()),
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
    assert!(verify_proof(VERIFIER, &proof, "POST", TOKEN_ENDPOINT, now()).is_ok());
}

// ---------------------------------------------------------------------------- the retained jti

/// THE ATTACK: valid proofs, one per request, each carrying a `jti` of nearly three kilobytes.
///
/// This is the crate's only path on which somebody who has authenticated as NOBODY causes a durable
/// store write: `AuthorizationServer` claims the returned `jti` through `Storage::claim_replay_id`,
/// with a deadline up to `MAX_PROOF_AGE` past an `iat` the caller may put a minute ahead. The
/// attacker mints one P-256 key and loops, so every proof VERIFIES and every claim succeeds, and it
/// does not matter that the token request then fails `invalid_client`: the row is already written.
///
/// The 4096-byte proof cap does not reach this. It bounds the WORK, which is over when the function
/// returns; the `jti` is the part that outlives the request, and under that cap alone a 4 KiB
/// request buys 2.9 KiB of storage held three hundred times longer than the request took to refuse.
#[test]
fn a_jti_past_the_cap_is_refused_even_though_the_proof_is_well_inside_the_proof_cap() {
    let key = EcdsaP256Key::generate("attacker");
    let proof = signed_proof(&key, &claims_with_jti(&"j".repeat(MAX_JTI_BYTES + 1)));

    // The point of the test: this proof is one the proof-size cap is happy with, and is refused
    // anyway. Without the separate bound it verifies, and its jti goes into the host's store.
    assert!(
        proof.len() < MAX_PROOF_BYTES,
        "the proof is {} bytes, inside the {MAX_PROOF_BYTES} cap, so the refusal must come from \
         the jti bound and not from the proof bound",
        proof.len()
    );
    assert_eq!(
        verify_proof(VERIFIER, &proof, "POST", TOKEN_ENDPOINT, now()),
        Err(DpopFailure::Malformed),
        "a jti this server would have to remember must be refused on length"
    );
}

/// The other side of the boundary, so the bound is `> MAX_JTI_BYTES` and not `>=`, and so a cap that
/// was quietly tightened later would be caught here rather than by a client that stopped working.
///
/// A `jti` of exactly the cap is accepted AND IS RETURNED, which is the thing that matters: the
/// caller is about to write this value down, so the test asserts what it receives rather than that
/// the call was `Ok`.
#[test]
fn a_jti_of_exactly_the_cap_is_accepted() {
    let key = EcdsaP256Key::generate("device");
    let jti = "j".repeat(MAX_JTI_BYTES);
    let proof = signed_proof(&key, &claims_with_jti(&jti));

    let verified = verify_proof(VERIFIER, &proof, "POST", TOKEN_ENDPOINT, now())
        .expect("a jti of exactly the cap is inside it");
    assert_eq!(verified.jti, jti);
}

/// The cap must not be so tight that a real client cannot mint a unique value: RFC 9449 section 4.2
/// asks only for uniqueness, and the two things a conforming client reaches for are a UUID (36
/// characters) and a base64url random (22 for 128 bits).
#[test]
fn the_jti_cap_leaves_room_for_the_values_conforming_clients_use() {
    let key = EcdsaP256Key::generate("device");
    for jti in ["e1j3V_bKic8-LAEB", "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"] {
        assert!(jti.len() <= MAX_JTI_BYTES);
        let proof = signed_proof(&key, &claims_with_jti(jti));
        assert_eq!(
            verify_proof(VERIFIER, &proof, "POST", TOKEN_ENDPOINT, now())
                .expect("a UUID or a 128-bit random is a conforming jti")
                .jti,
            jti
        );
    }
}

// ------------------------------------------------------------------------------------- crit

/// RFC 7515 section 4.1.11 with RFC 8725 section 3.10, on the DPoP path.
///
/// `crit` is the producer stating that understanding the named header parameters is REQUIRED to
/// process the JWS correctly. `b64` (RFC 7797) is the one that shows why ignoring it is not a
/// lenient reading: with `"b64": false` the payload is signed unencoded, so a verifier that ignores
/// the member verifies a DIFFERENT MESSAGE from the one the producer signed. This server implements
/// no JWS extension at all, so any `crit` is a refusal.
///
/// The same rule was tested for client assertions and for RFC 9101 request objects and NOT here,
/// which is the "one hardened reader, unhardened siblings" shape `reject_unknown_crit` was moved
/// onto `CompactJws` to end — reproduced in the test suite instead of in the code.
#[test]
fn a_proof_whose_header_names_an_unknown_crit_extension_is_refused() {
    let key = EcdsaP256Key::generate("device");
    let mut header = proof_header(&key);
    header["crit"] = serde_json::json!(["b64"]);
    header["b64"] = serde_json::json!(false);
    let proof = signed_proof_with_header(&key, &header, &claims_with_jti("crit-1"));

    assert_eq!(
        verify_proof(VERIFIER, &proof, "POST", TOKEN_ENDPOINT, now()),
        Err(DpopFailure::Malformed),
        "a crit naming an extension this server does not implement makes the JWS invalid"
    );
}

/// The other half of section 4.1.11: an EMPTY `crit` is forbidden by the RFC itself, whatever the
/// recipient implements. A verifier that only looked for names it did not recognise would accept
/// this one, having found none.
#[test]
fn a_proof_whose_header_has_an_empty_crit_is_refused() {
    let key = EcdsaP256Key::generate("device");
    let mut header = proof_header(&key);
    header["crit"] = serde_json::json!([]);
    let proof = signed_proof_with_header(&key, &header, &claims_with_jti("crit-2"));

    assert_eq!(
        verify_proof(VERIFIER, &proof, "POST", TOKEN_ENDPOINT, now()),
        Err(DpopFailure::Malformed),
        "RFC 7515 s4.1.11 forbids an empty crit outright"
    );
}
