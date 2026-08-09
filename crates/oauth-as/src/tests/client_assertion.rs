// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 7523 section 3 assertion validation, tested as ATTACKS rather than as coverage.
//!
//! Every test here except the happy paths is a request an attacker would actually send: an
//! assertion minted for a different server, an assertion belonging to a different client, a
//! signature made with a key the registration never named, an `alg` the registration does not use,
//! a DPoP proof passed off as a credential, and a validity window the client chose for itself. The
//! claim being made is that each one is REFUSED, and each was watched failing against an
//! implementation that verified only the signature before the check that refuses it was written.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::json;

use super::*;
use crate::jwt::{compact_jws, hmac_sha256, EcdsaP256Key, PublicJwk};

/// A fixed instant, so every window in this file is arithmetic rather than a race.
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

const CLIENT: &str = "assertion-client";
const TOKEN_ENDPOINT: &str = "https://as.example/token";
const ISSUER: &str = "https://as.example";
const SECRET: &str = "a-high-entropy-registered-client-secret";

fn audiences() -> Vec<&'static str> {
    vec![TOKEN_ENDPOINT, ISSUER]
}

/// The claim set RFC 7523 section 3 asks for, before a test spoils one member of it.
fn claims() -> serde_json::Value {
    json!({
        "iss": CLIENT,
        "sub": CLIENT,
        "aud": TOKEN_ENDPOINT,
        "exp": secs(now()) + 120,
        "iat": secs(now()),
        "jti": "assertion-0001",
    })
}

fn hs256(secret: &str, header: &serde_json::Value, claims: &serde_json::Value) -> String {
    compact_jws(
        &serde_json::to_vec(header).unwrap(),
        &serde_json::to_vec(claims).unwrap(),
        |input| hmac_sha256(secret.as_bytes(), input.as_bytes()).to_vec(),
    )
}

fn es256(key: &EcdsaP256Key, header: &serde_json::Value, claims: &serde_json::Value) -> String {
    compact_jws(
        &serde_json::to_vec(header).unwrap(),
        &serde_json::to_vec(claims).unwrap(),
        |input| key.sign_signing_input(input).unwrap(),
    )
}

fn secret_keys() -> AssertionKeys {
    AssertionKeys::ClientSecret {
        secret: SECRET.to_string(),
    }
}

fn key_pair() -> (EcdsaP256Key, AssertionKeys) {
    let key = EcdsaP256Key::generate("client-key-1");
    let keys = AssertionKeys::PublicKeys {
        keys: vec![key.to_public_jwk()],
    };
    (key, keys)
}

fn verify(keys: &AssertionKeys, assertion: &str) -> Result<VerifiedAssertion, AssertionFailure> {
    verify_assertion(keys, assertion, CLIENT, &audiences(), now())
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.encode(bytes)
}

// ------------------------------------------------------------------------------- happy paths

#[test]
fn a_client_secret_jwt_assertion_verifies() {
    let assertion = hs256(SECRET, &json!({"alg": "HS256", "typ": "JWT"}), &claims());
    let verified = verify(&secret_keys(), &assertion).expect("a conforming assertion verifies");
    assert_eq!(verified.jti, "assertion-0001");
    assert_eq!(verified.expires_at, now() + Duration::from_secs(120));
}

#[test]
fn a_private_key_jwt_assertion_verifies() {
    let (key, keys) = key_pair();
    let assertion = es256(&key, &json!({"alg": "ES256", "typ": "JWT"}), &claims());
    let verified = verify(&keys, &assertion).expect("a conforming assertion verifies");
    assert_eq!(verified.jti, "assertion-0001");
}

#[test]
fn a_header_with_no_typ_at_all_is_accepted() {
    // RFC 7523 does not require `typ`, and a great deal of deployed client software omits it.
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &claims());
    assert!(verify(&secret_keys(), &assertion).is_ok());
}

#[test]
fn the_issuer_is_an_acceptable_audience_as_well_as_the_token_endpoint() {
    // RFC 7523 s3 (3) requires the assertion to identify the AS as an intended audience and offers
    // the token endpoint URL as an acceptable value; OpenID Connect Core s9 and much deployed
    // client software use the ISSUER instead. Refusing the issuer would refuse most real clients
    // over a distinction the RFC does not make.
    let mut c = claims();
    c["aud"] = json!(ISSUER);
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
    assert!(verify(&secret_keys(), &assertion).is_ok());
}

#[test]
fn an_array_valued_audience_is_accepted_when_one_element_matches() {
    // RFC 7519 s4.1.3 admits the array form, and a client talking to several servers sends one.
    let mut c = claims();
    c["aud"] = json!(["https://other.example/token", TOKEN_ENDPOINT]);
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
    assert!(verify(&secret_keys(), &assertion).is_ok());
}

// ---------------------------------------------------------------------------- algorithm attacks

#[test]
fn an_hmac_assertion_from_a_public_key_client_is_refused() {
    // THE JWS ALGORITHM CONFUSION ATTACK. The registration is `private_key_jwt`, so the key this
    // server holds for the client is PUBLIC: anyone who can read the client's JWKS has it. The
    // attacker signs an otherwise perfect assertion with HS256, using that public key's own
    // serialization as the HMAC secret, and a verifier that takes `alg` from the token header
    // dutifully MACs with a "secret" the whole world knows. Here the registration decides the
    // algorithm, so there is no header value that can reach the HMAC path at all.
    let (key, keys) = key_pair();
    let public = serde_json::to_string(&key.to_public_jwk()).unwrap();
    let assertion = hs256(&public, &json!({"alg": "HS256", "typ": "JWT"}), &claims());
    assert_eq!(
        verify(&keys, &assertion),
        Err(AssertionFailure::AlgorithmMismatch)
    );
}

#[test]
fn an_ecdsa_assertion_from_a_client_secret_client_is_refused() {
    // The mirror image, refused for the same reason: the registration says HS256, so a key the
    // client chose for itself is not a key this server will verify anything against.
    let (key, _) = key_pair();
    let assertion = es256(&key, &json!({"alg": "ES256", "typ": "JWT"}), &claims());
    assert_eq!(
        verify(&secret_keys(), &assertion),
        Err(AssertionFailure::AlgorithmMismatch)
    );
}

#[test]
fn alg_none_is_refused() {
    // RFC 7515 appendix A.5's unsecured JWS. `alg: none` with an empty signature is the oldest JWT
    // vulnerability there is, and the only safe implementation of it is not having one.
    let header = serde_json::to_vec(&json!({"alg": "none", "typ": "JWT"})).unwrap();
    let payload = serde_json::to_vec(&claims()).unwrap();
    let assertion = compact_jws(&header, &payload, |_| Vec::new());
    assert_eq!(
        verify(&secret_keys(), &assertion),
        Err(AssertionFailure::AlgorithmMismatch)
    );
}

#[test]
fn a_header_with_no_alg_at_all_is_refused() {
    let assertion = hs256(SECRET, &json!({"typ": "JWT"}), &claims());
    assert_eq!(
        verify(&secret_keys(), &assertion),
        Err(AssertionFailure::AlgorithmMismatch)
    );
}

#[test]
fn a_dpop_proof_is_not_a_client_assertion() {
    // CROSS PROTOCOL REUSE. A DPoP proof (RFC 9449 s4.2) and a client assertion are both JWTs a
    // client signs and hands to this same endpoint on the same request. Without the `typ` check
    // they are interchangeable to a verifier, so a proof observed on one request could be presented
    // as the client's authentication credential on the next. RFC 9449 s4.2 fixes the proof's `typ`
    // at `dpop+jwt` precisely so the two cannot be confused; this is the other half of that.
    let assertion = hs256(
        SECRET,
        &json!({"alg": "HS256", "typ": "dpop+jwt"}),
        &claims(),
    );
    assert_eq!(
        verify(&secret_keys(), &assertion),
        Err(AssertionFailure::Malformed)
    );
}

#[test]
fn an_access_token_is_not_a_client_assertion() {
    // The same argument for RFC 9068 s2.1's `at+jwt`: this server SIGNS those, and a token it
    // signed must never be presentable back to it as a client's credential.
    let assertion = hs256(SECRET, &json!({"alg": "HS256", "typ": "at+jwt"}), &claims());
    assert_eq!(
        verify(&secret_keys(), &assertion),
        Err(AssertionFailure::Malformed)
    );
}

// ---------------------------------------------------------------------------- signature attacks

#[test]
fn an_assertion_signed_by_a_key_the_registration_does_not_name_is_refused() {
    let (_, keys) = key_pair();
    let attacker = EcdsaP256Key::generate("attacker-key");
    let assertion = es256(&attacker, &json!({"alg": "ES256"}), &claims());
    assert_eq!(
        verify(&keys, &assertion),
        Err(AssertionFailure::BadSignature)
    );
}

#[test]
fn a_payload_edited_after_signing_is_refused() {
    // The signature covers the RECEIVED bytes of `header.payload`, so re-encoding the payload with
    // one claim changed invalidates it however faithfully the rest is reproduced.
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &claims());
    let mut parts: Vec<&str> = assertion.split('.').collect();
    let forged = base64_url(
        &serde_json::to_vec(&json!({
            "iss": CLIENT, "sub": CLIENT, "aud": TOKEN_ENDPOINT,
            "exp": secs(now()) + 120, "iat": secs(now()), "jti": "forged-0001",
        }))
        .unwrap(),
    );
    parts[1] = &forged;
    let assertion = parts.join(".");
    assert_eq!(
        verify(&secret_keys(), &assertion),
        Err(AssertionFailure::BadSignature)
    );
}

#[test]
fn a_wrong_client_secret_is_refused() {
    let assertion = hs256("not-the-secret", &json!({"alg": "HS256"}), &claims());
    assert_eq!(
        verify(&secret_keys(), &assertion),
        Err(AssertionFailure::BadSignature)
    );
}

#[test]
fn one_of_several_registered_keys_is_enough() {
    // Rotation: a client that has published a new key while the old one is still live.
    let old = EcdsaP256Key::generate("old");
    let new = EcdsaP256Key::generate("new");
    let keys = AssertionKeys::PublicKeys {
        keys: vec![old.to_public_jwk(), new.to_public_jwk()],
    };
    let assertion = es256(&new, &json!({"alg": "ES256"}), &claims());
    assert!(verify(&keys, &assertion).is_ok());
}

// -------------------------------------------------------------------------------- claim attacks

#[test]
fn an_assertion_naming_another_client_as_issuer_is_refused() {
    // RFC 7523 s3 (1): `iss` is the client. An attacker holding one client's credential must not be
    // able to authenticate as another, which is exactly what an unchecked `iss` allows the moment
    // two registrations share a secret.
    let mut c = claims();
    c["iss"] = json!("some-other-client");
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
    assert_eq!(
        verify(&secret_keys(), &assertion),
        Err(AssertionFailure::WrongPrincipal)
    );
}

#[test]
fn an_assertion_naming_another_client_as_subject_is_refused() {
    // RFC 7523 s3 (2): for client authentication `sub` is the client too, so a `sub` naming another
    // principal is a request to authenticate as somebody else.
    let mut c = claims();
    c["sub"] = json!("some-other-client");
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
    assert_eq!(
        verify(&secret_keys(), &assertion),
        Err(AssertionFailure::WrongPrincipal)
    );
}

#[test]
fn an_assertion_missing_iss_or_sub_is_refused() {
    for missing in ["iss", "sub"] {
        let mut c = claims();
        c.as_object_mut().unwrap().remove(missing);
        let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
        assert_eq!(
            verify(&secret_keys(), &assertion),
            Err(AssertionFailure::WrongPrincipal),
            "an assertion with no {missing} must be refused"
        );
    }
}

#[test]
fn an_assertion_addressed_to_another_server_is_refused() {
    // THE CROSS SERVER REPLAY. A client that authenticates to several authorization servers with
    // the same credential hands each of them a signed assertion. Without the `aud` check, ANY of
    // those servers can take the assertion it was given and present it to the others as that
    // client. RFC 7523 s3 (3) exists for this and for nothing else.
    let mut c = claims();
    c["aud"] = json!("https://evil.example/token");
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
    assert_eq!(
        verify(&secret_keys(), &assertion),
        Err(AssertionFailure::WrongAudience)
    );
}

#[test]
fn an_assertion_with_no_audience_is_refused() {
    let mut c = claims();
    c.as_object_mut().unwrap().remove("aud");
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
    assert_eq!(
        verify(&secret_keys(), &assertion),
        Err(AssertionFailure::WrongAudience)
    );
}

#[test]
fn an_expired_assertion_is_refused() {
    let mut c = claims();
    c["exp"] = json!(secs(now()) - 1);
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
    assert_eq!(
        verify(&secret_keys(), &assertion),
        Err(AssertionFailure::Expired)
    );
}

#[test]
fn an_assertion_with_no_exp_is_refused() {
    // RFC 7523 s3 (4) makes `exp` REQUIRED, and it is what bounds how long a captured assertion is
    // worth replaying. An assertion with no expiry is a bearer credential with no expiry.
    let mut c = claims();
    c.as_object_mut().unwrap().remove("exp");
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
    assert_eq!(
        verify(&secret_keys(), &assertion),
        Err(AssertionFailure::Expired)
    );
}

#[test]
fn an_assertion_valid_for_longer_than_this_server_will_track_is_refused() {
    // The replay defence remembers a `jti` until the assertion's own `exp`, so an `exp` the CLIENT
    // chooses is a storage commitment the client chooses. An assertion valid for a year is either a
    // broken client or an attacker filling the store, and honouring it would mean either unbounded
    // memory or a silently shortened replay window; the second is worse, because it would make a
    // year-long credential replayable after ten minutes without anybody being told.
    let mut c = claims();
    c["exp"] = json!(secs(now() + MAX_ASSERTION_LIFETIME) + 1);
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
    assert_eq!(
        verify(&secret_keys(), &assertion),
        Err(AssertionFailure::Expired)
    );
}

#[test]
fn an_assertion_that_is_not_yet_valid_is_refused() {
    let mut c = claims();
    c["nbf"] = json!(secs(now() + CLOCK_SKEW_LEEWAY) + 1);
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
    assert_eq!(
        verify(&secret_keys(), &assertion),
        Err(AssertionFailure::NotYetValid)
    );
}

#[test]
fn an_assertion_issued_in_the_future_is_refused() {
    let mut c = claims();
    c["iat"] = json!(secs(now() + CLOCK_SKEW_LEEWAY) + 1);
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
    assert_eq!(
        verify(&secret_keys(), &assertion),
        Err(AssertionFailure::NotYetValid)
    );
}

#[test]
fn small_clock_skew_is_tolerated_in_the_one_safe_direction() {
    // Two servers whose clocks differ by seconds is the normal state of the internet, and refusing
    // an assertion over it would be an outage rather than a defence. The leeway is granted only to
    // `iat`/`nbf`; `an_expired_assertion_is_refused` above pins that `exp` gets none.
    let mut c = claims();
    c["iat"] = json!(secs(now()) + 5);
    c["nbf"] = json!(secs(now()) + 5);
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
    assert!(verify(&secret_keys(), &assertion).is_ok());
}

#[test]
fn an_assertion_with_no_jti_is_refused() {
    // RFC 7523 s3 (7) requires a `jti`, and section 3 requires the server to reject a repeat of one
    // within the assertion's validity. An assertion with no `jti` cannot be tracked, so accepting
    // it would be accepting an infinitely replayable credential; the only honest answer is to
    // refuse it rather than skip the check.
    let mut c = claims();
    c.as_object_mut().unwrap().remove("jti");
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
    assert_eq!(
        verify(&secret_keys(), &assertion),
        Err(AssertionFailure::MissingJti)
    );
}

#[test]
fn an_assertion_with_an_empty_jti_is_refused() {
    let mut c = claims();
    c["jti"] = json!("");
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
    assert_eq!(
        verify(&secret_keys(), &assertion),
        Err(AssertionFailure::MissingJti)
    );
}

#[test]
fn a_non_string_claim_where_a_string_is_required_is_refused_not_coerced() {
    // `"iss": 7` must not read as the client id "7", and must not panic.
    let mut c = claims();
    c["iss"] = json!(7);
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
    assert_eq!(
        verify(&secret_keys(), &assertion),
        Err(AssertionFailure::WrongPrincipal)
    );
}

#[test]
fn a_fractional_or_negative_exp_reads_as_absent_rather_than_as_the_epoch() {
    // Truncating `-1` towards zero would read as 1970, which is expired, so this happens to fail
    // safe; pinning it anyway, because the same truncation on `nbf` would fail OPEN.
    for bad in [json!(-1), json!(1.5), json!("soon")] {
        let mut c = claims();
        c["exp"] = bad.clone();
        let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
        assert_eq!(
            verify(&secret_keys(), &assertion),
            Err(AssertionFailure::Expired),
            "exp {bad} must not be coerced"
        );
    }
}

#[test]
fn garbage_is_refused_rather_than_panicking() {
    for input in [
        "",
        ".",
        "..",
        "a.b",
        "a.b.c.d",
        "not base64.at all.here",
        "eyJhbGciOiJIUzI1NiJ9",
        "e30.e30.e30.e30.e30",
    ] {
        assert!(
            verify(&secret_keys(), input).is_err(),
            "{input:?} must be refused"
        );
    }
}

// ------------------------------------------------------------------------------ the primitives

#[test]
fn hmac_sha256_matches_the_rfc_4231_test_case_2_vector() {
    // RFC 4231 s4.3: key "Jefe", data "what do ya want for nothing?". Quoted because a hand rolled
    // HMAC that is never checked against a published vector is a hand rolled HMAC nobody has
    // checked. This is the case that catches an ipad/opad swap.
    let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    let actual: String = tag.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        actual,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

#[test]
fn hmac_sha256_matches_the_rfc_4231_test_case_6_vector() {
    // RFC 4231 s4.7: a 131 byte key, which is the branch where the key is hashed first. Worth its
    // own case because short keys keep working when that branch is wrong.
    let tag = hmac_sha256(
        &[0xaau8; 131],
        b"Test Using Larger Than Block-Size Key - Hash Key First",
    );
    let actual: String = tag.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        actual,
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

#[test]
fn a_jwk_carrying_a_private_parameter_is_refused() {
    // RFC 9449 s4.3 requires this of a DPoP proof key, and the same rule is applied everywhere this
    // crate parses a JWK: see `PRIVATE_JWK_MEMBERS` in src/jwt.rs. A registration that silently
    // absorbed a `d` would be a client's private key sitting in the authorization server's store.
    let key = EcdsaP256Key::generate("k");
    for member in ["d", "k", "p", "q"] {
        let mut value = serde_json::to_value(key.to_public_jwk()).unwrap();
        value[member] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert!(
            PublicJwk::from_json(&value).is_err(),
            "a JWK carrying {member} must be refused"
        );
    }
}

#[test]
fn a_jwk_with_a_trimmed_coordinate_is_refused() {
    // RFC 7518 s6.2.1.2 fixes the coordinate at the field size with leading zeros KEPT. A trimmed
    // coordinate names a different point, so accepting it would make one key have two spellings and
    // therefore two RFC 7638 thumbprints.
    let key = EcdsaP256Key::generate("k");
    let mut value = serde_json::to_value(key.to_public_jwk()).unwrap();
    value["x"] = json!("AAAA");
    assert!(PublicJwk::from_json(&value).is_err());
}

// -------------------------------------------------------------- the exact edges of each window
//
// Each of the three tests below sits ON a boundary that a comparison operator decides. A `>` that
// becomes a `>=` (or the reverse) moves the boundary by one second in a direction no test above
// notices, because every test above is at least a second clear of it. These are the tests that
// notice.

#[test]
fn an_assertion_expiring_exactly_at_the_tracking_horizon_is_accepted() {
    // The refusal above is for an `exp` FURTHER OUT than this server will remember a `jti` for.
    // Exactly at the horizon is not further out: the whole lifetime is trackable, so refusing it
    // would reject a client that had done precisely what the limit asks.
    let mut c = claims();
    c["exp"] = json!(secs(now() + MAX_ASSERTION_LIFETIME));
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
    let verified = verify(&secret_keys(), &assertion).expect("exp at the horizon is trackable");
    assert_eq!(verified.expires_at, now() + MAX_ASSERTION_LIFETIME);
}

#[test]
fn an_assertion_issued_exactly_at_the_skew_horizon_is_accepted() {
    // RFC 7523 s3 (5) and (6): `nbf` and `iat` are checked with leeway, and the leeway is a
    // tolerance rather than a strict inequality. A client whose clock is ahead by EXACTLY the
    // leeway is inside what the deployment said it would tolerate.
    for claim in ["iat", "nbf"] {
        let mut c = claims();
        c[claim] = json!(secs(now() + CLOCK_SKEW_LEEWAY));
        let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
        assert!(
            verify(&secret_keys(), &assertion).is_ok(),
            "{claim} exactly at the skew horizon must be inside the tolerance"
        );
    }
}

// -------------------------------------------------------- the unverified lookup key, and its bar
//
// RFC 7521 section 4.2 makes `client_id` optional on a request carrying an assertion, so something
// has to read `sub` BEFORE any signature has been checked in order to find the registration that
// holds the key. `unverified_subject` is that something, and the whole safety argument for it is
// that it returns the assertion's own `sub` verbatim and nothing else: a caller that received a
// constant, or an empty string, would be looking up the wrong registration (or always the same
// one) for every request, and the re-check in `verify_assertion` would then refuse every honest
// client while an attacker's own registration is the one that gets found.

#[test]
fn the_unverified_subject_is_the_assertions_own_sub_verbatim() {
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &claims());
    assert_eq!(unverified_subject(&assertion).as_deref(), Some(CLIENT));

    // A DIFFERENT subject must read back differently, or the lookup is a constant wearing a
    // parameter.
    let mut other = claims();
    other["sub"] = json!("some-other-client");
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &other);
    assert_eq!(
        unverified_subject(&assertion).as_deref(),
        Some("some-other-client")
    );
}

#[test]
fn an_assertion_with_no_readable_subject_yields_no_lookup_key() {
    // Nothing to look up is NOT the same as looking up the empty client id: a host that received
    // `Some("")` here would go on to query its store for a client whose id is the empty string.
    let mut c = claims();
    c.as_object_mut().unwrap().remove("sub");
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
    assert_eq!(unverified_subject(&assertion), None);

    // And a string that is not a JWS at all yields nothing rather than a guess.
    assert_eq!(unverified_subject("not-a-jws"), None);
    assert_eq!(unverified_subject(""), None);

    // A non-string `sub` is not a subject either.
    let mut c = claims();
    c["sub"] = json!(7);
    let assertion = hs256(SECRET, &json!({"alg": "HS256"}), &c);
    assert_eq!(unverified_subject(&assertion), None);
}
