// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9449 section 4.3 proof validation, tested as ATTACKS.
//!
//! A DPoP proof is not a secret: it travels in a header on every request, so a network position, a
//! logging proxy or a compromised resource server sees them constantly. The whole security of DPoP
//! is therefore in what a captured proof CANNOT be used for, and that is what these tests are about:
//! a proof captured at a resource server and replayed at the token endpoint (`htu`), a proof
//! captured from a GET and replayed on a POST (`htm`), a proof captured yesterday (`iat`), a proof
//! captured a second ago and sent twice (`jti`), and a proof carrying an attacker's own key.
//!
//! Each was watched failing against an implementation that verified only the signature, before the
//! check that refuses it was written.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::json;

use super::*;
use crate::jwt::{compact_jws, hmac_sha256, EcdsaP256Key};

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

const HTM: &str = "POST";
const HTU: &str = "https://as.example/token";

/// The claim set RFC 9449 section 4.2 asks for, before a test spoils one member of it.
fn claims() -> serde_json::Value {
    json!({ "jti": "proof-0001", "htm": HTM, "htu": HTU, "iat": secs(now()) })
}

fn header(key: &EcdsaP256Key) -> serde_json::Value {
    json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": serde_json::to_value(key.to_public_jwk()).unwrap(),
    })
}

fn proof_with(
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

fn verify(proof: &str) -> Result<VerifiedProof, DpopFailure> {
    verify_proof(proof, HTM, HTU, now())
}

// -------------------------------------------------------------------------------- happy paths

#[test]
fn a_conforming_proof_verifies_and_yields_the_key_thumbprint() {
    let key = EcdsaP256Key::generate("device-key");
    let proof = proof_with(&key, &header(&key), &claims());
    let verified = verify(&proof).expect("a conforming proof verifies");
    assert_eq!(verified.jti, "proof-0001");
    assert_eq!(verified.jkt, key.to_public_jwk().thumbprint());
}

#[test]
fn the_request_uri_is_compared_without_its_query_or_fragment() {
    // RFC 9449 s4.3 (7): `htu` is compared "ignoring any query and fragment parts". A client that
    // included them, or a request that carried them, must still match.
    let key = EcdsaP256Key::generate("k");
    let proof = proof_with(&key, &header(&key), &claims());
    assert!(verify_proof(&proof, HTM, "https://as.example/token?x=1#f", now()).is_ok());

    let mut c = claims();
    c["htu"] = json!("https://as.example/token?x=1");
    let proof = proof_with(&key, &header(&key), &c);
    assert!(verify(&proof).is_ok());
}

#[test]
fn a_proof_within_the_acceptance_window_verifies() {
    let key = EcdsaP256Key::generate("k");
    let mut c = claims();
    c["iat"] = json!(secs(now() - MAX_PROOF_AGE) + 1);
    let proof = proof_with(&key, &header(&key), &c);
    assert!(verify(&proof).is_ok());
}

// --------------------------------------------------------------------------- cross-protocol typ

#[test]
fn a_jwt_that_is_not_typed_as_a_proof_is_refused() {
    // RFC 9449 s4.3 (3): `typ` MUST be `dpop+jwt`. Without this check, a client assertion (or any
    // other JWT the client signs with the same key) would be accepted as a proof, and the two are
    // sent on the SAME request to the SAME endpoint.
    let key = EcdsaP256Key::generate("k");
    for typ in [json!("JWT"), json!("at+jwt"), json!("DPOP+JWT")] {
        let mut h = header(&key);
        h["typ"] = typ.clone();
        let proof = proof_with(&key, &h, &claims());
        assert_eq!(verify(&proof), Err(DpopFailure::NotAProof), "typ {typ}");
    }
}

#[test]
fn a_proof_with_no_typ_at_all_is_refused() {
    let key = EcdsaP256Key::generate("k");
    let mut h = header(&key);
    h.as_object_mut().unwrap().remove("typ");
    let proof = proof_with(&key, &h, &claims());
    assert_eq!(verify(&proof), Err(DpopFailure::NotAProof));
}

// ----------------------------------------------------------------------------- algorithm attacks

#[test]
fn alg_none_is_refused() {
    let key = EcdsaP256Key::generate("k");
    let mut h = header(&key);
    h["alg"] = json!("none");
    let header_bytes = serde_json::to_vec(&h).unwrap();
    let payload = serde_json::to_vec(&claims()).unwrap();
    let proof = compact_jws(&header_bytes, &payload, |_| Vec::new());
    assert_eq!(verify(&proof), Err(DpopFailure::UnsupportedAlgorithm));
}

#[test]
fn a_symmetric_alg_is_refused() {
    // RFC 9449 s4.2: the proof is signed with an ASYMMETRIC algorithm. A MAC would be verified with
    // a key both parties hold, which proves possession of nothing the server does not already have,
    // so accepting HS256 here would turn proof-of-possession back into a bearer scheme. The key the
    // attacker MACs with here is the `jwk` in the proof's own header, which is public by design.
    let key = EcdsaP256Key::generate("k");
    let mut h = header(&key);
    h["alg"] = json!("HS256");
    let secret = serde_json::to_string(&key.to_public_jwk()).unwrap();
    let proof = compact_jws(
        &serde_json::to_vec(&h).unwrap(),
        &serde_json::to_vec(&claims()).unwrap(),
        |input| hmac_sha256(secret.as_bytes(), input.as_bytes()).to_vec(),
    );
    assert_eq!(verify(&proof), Err(DpopFailure::UnsupportedAlgorithm));
}

// -------------------------------------------------------------------------------- proof key rules

#[test]
fn a_proof_whose_jwk_carries_the_private_key_is_refused() {
    // RFC 9449 s4.3 (4): the `jwk` MUST NOT contain a private key. A client that sent one has just
    // leaked its key to us; continuing as if nothing happened would mint a token bound to a key
    // that is no longer only the client's.
    let key = EcdsaP256Key::generate("k");
    let mut h = header(&key);
    h["jwk"]["d"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let proof = proof_with(&key, &h, &claims());
    assert_eq!(verify(&proof), Err(DpopFailure::BadProofKey));
}

#[test]
fn a_proof_with_no_jwk_is_refused() {
    let key = EcdsaP256Key::generate("k");
    let mut h = header(&key);
    h.as_object_mut().unwrap().remove("jwk");
    let proof = proof_with(&key, &h, &claims());
    assert_eq!(verify(&proof), Err(DpopFailure::BadProofKey));
}

#[test]
fn a_proof_signed_by_a_key_other_than_the_one_it_advertises_is_refused() {
    // KEY SUBSTITUTION. An attacker who captures a proof cannot make it bind to a key they hold:
    // swapping the `jwk` header for their own invalidates the signature, and signing it afresh
    // requires the private half they do not have. RFC 9449 s4.3 (6) is what forces that, by
    // requiring the signature to verify under the proof's OWN embedded key.
    let key = EcdsaP256Key::generate("k");
    let attacker = EcdsaP256Key::generate("attacker");
    let proof = proof_with(&key, &header(&attacker), &claims());
    assert_eq!(verify(&proof), Err(DpopFailure::BadSignature));
}

#[test]
fn a_tampered_proof_payload_is_refused() {
    let key = EcdsaP256Key::generate("k");
    let proof = proof_with(&key, &header(&key), &claims());
    let mut parts: Vec<String> = proof.split('.').map(str::to_string).collect();
    let mut c = claims();
    c["htu"] = json!("https://as.example/other");
    parts[1] = {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&c).unwrap())
    };
    assert_eq!(verify(&parts.join(".")), Err(DpopFailure::BadSignature));
}

// ------------------------------------------------------------------------------- binding attacks

#[test]
fn a_proof_made_for_another_uri_is_refused() {
    // THE CAPTURED-PROOF REPLAY. Proofs travel in the clear on every request, so a resource server
    // (or anything sitting in front of one) sees the client's proofs constantly. Without the `htu`
    // check, any of them could be taken to the AUTHORIZATION SERVER's token endpoint and spent
    // there. RFC 9449 s4.3 (7).
    let key = EcdsaP256Key::generate("k");
    let mut c = claims();
    c["htu"] = json!("https://rs.example/resource");
    let proof = proof_with(&key, &header(&key), &c);
    assert_eq!(verify(&proof), Err(DpopFailure::WrongUri));
}

#[test]
fn a_proof_made_for_another_method_is_refused() {
    // The same replay, narrowed: a proof made for a GET must not be spendable on a POST. RFC 9449
    // s4.3 (7) binds the method for exactly this reason.
    let key = EcdsaP256Key::generate("k");
    let mut c = claims();
    c["htm"] = json!("GET");
    let proof = proof_with(&key, &header(&key), &c);
    assert_eq!(verify(&proof), Err(DpopFailure::WrongMethod));
}

#[test]
fn htm_is_compared_case_sensitively() {
    // RFC 9110 s9.1 makes the method case sensitive, and `post` is not `POST`. Accepting either
    // would be inventing a normalisation the RFC does not have.
    let key = EcdsaP256Key::generate("k");
    let mut c = claims();
    c["htm"] = json!("post");
    let proof = proof_with(&key, &header(&key), &c);
    assert_eq!(verify(&proof), Err(DpopFailure::WrongMethod));
}

#[test]
fn a_proof_missing_htm_or_htu_is_refused() {
    let key = EcdsaP256Key::generate("k");
    for missing in ["htm", "htu"] {
        let mut c = claims();
        c.as_object_mut().unwrap().remove(missing);
        let proof = proof_with(&key, &header(&key), &c);
        assert!(verify(&proof).is_err(), "a proof with no {missing}");
    }
}

// ---------------------------------------------------------------------------------- time attacks

#[test]
fn a_stale_proof_is_refused() {
    // RFC 9449 s4.3 (10): `iat` within an acceptable window. The window is what bounds how long a
    // captured proof is worth anything, and it is also what bounds the replay cache: a proof older
    // than the window is refused by time, so its `jti` no longer has to be remembered.
    let key = EcdsaP256Key::generate("k");
    let mut c = claims();
    c["iat"] = json!(secs(now() - MAX_PROOF_AGE) - 1);
    let proof = proof_with(&key, &header(&key), &c);
    assert_eq!(verify(&proof), Err(DpopFailure::StaleProof));
}

#[test]
fn a_proof_from_the_future_is_refused() {
    let key = EcdsaP256Key::generate("k");
    let mut c = claims();
    c["iat"] = json!(secs(now() + CLOCK_SKEW_LEEWAY) + 1);
    let proof = proof_with(&key, &header(&key), &c);
    assert_eq!(verify(&proof), Err(DpopFailure::StaleProof));
}

#[test]
fn a_proof_with_no_iat_is_refused() {
    let key = EcdsaP256Key::generate("k");
    let mut c = claims();
    c.as_object_mut().unwrap().remove("iat");
    let proof = proof_with(&key, &header(&key), &c);
    assert_eq!(verify(&proof), Err(DpopFailure::StaleProof));
}

#[test]
fn a_proof_with_no_jti_is_refused() {
    // RFC 9449 s4.3 (2). Same argument as the client assertion's: a proof with no `jti` cannot be
    // remembered, so accepting it is accepting an indefinitely replayable one.
    let key = EcdsaP256Key::generate("k");
    for jti in [json!(""), json!(null)] {
        let mut c = claims();
        c["jti"] = jti.clone();
        let proof = proof_with(&key, &header(&key), &c);
        assert_eq!(verify(&proof), Err(DpopFailure::MissingJti), "jti {jti}");
    }
}

#[test]
fn the_replay_deadline_is_exactly_the_window_this_proof_stays_acceptable_in() {
    // The `jti` must be remembered for as long as THIS proof would still pass the `iat` check, and
    // no longer. Shorter leaves a hole exactly where a replay would be aimed: the cache forgets the
    // proof while the clock still accepts it. Longer is not a security problem but is storage an
    // attacker chooses, which is the same mistake `MAX_ASSERTION_LIFETIME` exists to avoid.
    let key = EcdsaP256Key::generate("k");
    for age in [0u64, 60, 299] {
        let mut c = claims();
        let iat = secs(now()) - age;
        c["iat"] = json!(iat);
        let proof = proof_with(&key, &header(&key), &c);
        let verified = verify(&proof).unwrap();
        assert_eq!(
            verified.replay_until,
            UNIX_EPOCH + Duration::from_secs(iat) + MAX_PROOF_AGE,
            "a proof issued {age}s ago is remembered until its own iat plus the window"
        );
    }
}

// ------------------------------------------------------------------------------- the thumbprint

#[test]
fn the_thumbprint_is_the_rfc_7638_construction_and_nothing_else() {
    // Computed here from the RFC's own recipe (s3.1 to s3.3), independently of the implementation:
    // the required members ONLY, lexicographically ordered, no whitespace, SHA-256, base64url
    // without padding. If `thumbprint` ever grows a member or reorders one, this fails.
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};

    let key = EcdsaP256Key::generate("some-kid");
    let jwk = key.to_public_jwk();
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        jwk.crv, jwk.kty, jwk.x, jwk.y
    );
    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
    assert_eq!(jwk.thumbprint(), expected);
}

#[test]
fn the_thumbprint_ignores_kid_and_any_other_optional_member() {
    // RFC 7638 s3.2 excludes everything but the required members, which is what makes the
    // thumbprint a property of the KEY. If `kid` fed in, one key relabelled would bind to a
    // different `cnf.jkt` and a resource server would reject a token that is genuinely the
    // client's.
    let key = EcdsaP256Key::generate("kid-one");
    let mut relabelled = key.to_public_jwk();
    let original = relabelled.thumbprint();
    relabelled.kid = Some("kid-two".into());
    assert_eq!(relabelled.thumbprint(), original);
    relabelled.kid = None;
    assert_eq!(relabelled.thumbprint(), original);
}

#[test]
fn garbage_is_refused_rather_than_panicking() {
    for input in ["", ".", "..", "a.b", "a.b.c.d", "not base64.at all.here"] {
        assert!(verify(input).is_err(), "{input:?} must be refused");
    }
}

#[test]
fn htu_of_strips_the_query_and_the_fragment() {
    assert_eq!(
        htu_of("https://as.example/token"),
        "https://as.example/token"
    );
    assert_eq!(
        htu_of("https://as.example/token?a=b"),
        "https://as.example/token"
    );
    assert_eq!(
        htu_of("https://as.example/token#f"),
        "https://as.example/token"
    );
    assert_eq!(
        htu_of("https://as.example/token#f?a=b"),
        "https://as.example/token"
    );
}
