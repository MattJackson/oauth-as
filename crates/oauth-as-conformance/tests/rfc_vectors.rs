// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Hermetic RFC test-vector suite. No network, no AS required: this half proves the harness's
//! own checkers against the PUBLISHED vectors, so a green from the black-box half means
//! something. Every expected value comes from `vectors/rfc_vectors.json`, vendored verbatim
//! from the RFC Editor text and citing its appendix.
//!
//! # RED-proof knob, and why it is now PER TEST
//!
//! `OAUTH_CONFORMANCE_SELFTEST_BREAK=<name>` plants a deliberate fault so that exactly one test
//! here MUST fail. `scripts/oauth-conformance.sh --selftest` uses it to prove the gate can go red
//! before anyone trusts a green.
//!
//! It used to accept ONE name, `pkce`, honoured in ONE test. Nine tests live in this file, so
//! eight of them had never been observed failing, and that is precisely what concealed a live
//! defect: `rfc9068_validator_accepts_conforming_and_rejects_each_missing_claim` asserted
//! `violations.iter().any(|m| m.contains(missing))` against messages that name all seven required
//! claims in every message, so it passed for a validator that misattributed every one of them.
//! A gate nobody has watched fail is a gate nobody has tested.
//!
//! Every test below therefore has a fault name, and each fault corrupts an EXPECTATION rather
//! than the code under test, so the only way to be green under one is for the assertion it
//! targets to be doing nothing. The names, which is the list a caller loops over:
//!
//! `pkce`, `jws-hs256`, `jws-rs256`, `jws-es256`, `rfc9068`, `rfc8414`, `error-shape`,
//! `token-response`, `device-auth`. [`SELFTEST_FAULTS`] is the same list, in code.

use hmac::{Hmac, Mac as _};
use oauth_as_conformance as conf;
use serde_json::{json, Value};
use sha2::Sha256;

/// Every fault name this file honours, one per test. A caller that wants to prove the whole
/// hermetic suite can go red runs it once per entry and requires a failure each time.
///
/// Kept as a constant, and gated by the test below, so that adding a test without adding a fault
/// name is a failure rather than a silent return to one-watched-test-in-nine.
pub const SELFTEST_FAULTS: [&str; 9] = [
    "pkce",
    "jws-hs256",
    "jws-rs256",
    "jws-es256",
    "rfc9068",
    "rfc8414",
    "error-shape",
    "token-response",
    "device-auth",
];

/// Whether the caller asked for THIS test's deliberate fault.
fn selftest_break(name: &str) -> bool {
    std::env::var("OAUTH_CONFORMANCE_SELFTEST_BREAK").as_deref() == Ok(name)
}

/// Every fault name must be honoured by exactly one `selftest_break` call site, and every call
/// site must use a name from the list. Checked against this file's own source because there is
/// nothing else that can check it: a name nobody honours is a `--selftest` run that passes while
/// proving nothing, which is the failure this whole knob exists to prevent.
#[test]
fn every_selftest_fault_name_is_honoured_exactly_once() {
    let source = include_str!("rfc_vectors.rs");
    for name in SELFTEST_FAULTS {
        let needle = format!("selftest_break(\"{name}\")");
        assert_eq!(
            source.matches(&needle).count(),
            1,
            "fault name \"{name}\" must be honoured by exactly one test"
        );
    }
    // And no call site names something the list does not carry. The two occurrences above are
    // not counted: both are escaped in the source (`\"`), so neither matches this needle.
    assert_eq!(
        source.matches("selftest_break(\"").count(),
        SELFTEST_FAULTS.len(),
        "a selftest_break call site names a fault that SELFTEST_FAULTS does not list"
    );
}

fn octets(v: &Value) -> Vec<u8> {
    v.as_array()
        .expect("vector octet field must be an array")
        .iter()
        .map(|n| u8::try_from(n.as_u64().expect("octet")).expect("octet fits u8"))
        .collect()
}

/// RFC 7636 Appendix B: verifier octets -> code_verifier -> S256 -> code_challenge.
#[test]
fn pkce_s256_rfc7636_appendix_b() {
    let vecs = conf::rfc_vectors();
    let v = &vecs["pkce_s256"];
    let verifier_octets = octets(&v["verifier_octets"]);
    let verifier = v["code_verifier"].as_str().unwrap();
    let mut challenge = v["code_challenge"].as_str().unwrap().to_string();
    if selftest_break("pkce") {
        // Deliberate corruption used by --selftest to prove this suite can fail.
        challenge = format!("BROKEN{challenge}");
    }
    assert_eq!(
        conf::b64url(&verifier_octets),
        verifier,
        "RFC 7636 App B: base64url(verifier octets) must equal the published code_verifier"
    );
    assert_eq!(
        conf::pkce_s256_challenge(verifier),
        challenge,
        "RFC 7636 App B: BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) must equal the \
         published code_challenge"
    );
    let challenge_octets = octets(&v["challenge_octets"]);
    assert_eq!(
        conf::b64url(&challenge_octets),
        v["code_challenge"].as_str().unwrap(),
        "RFC 7636 App B: the published SHA-256 octets must base64url-encode to the challenge"
    );
}

/// RFC 7515 Appendix A.1: HMAC-SHA256 JWS, byte-exact recompute and verify.
#[test]
fn jws_rfc7515_a1_hs256() {
    let vecs = conf::rfc_vectors();
    let v = &vecs["jws_a1_hs256"];
    let header_octets = octets(&v["header_octets"]);
    let payload_octets = octets(&v["payload_octets"]);
    let header_b64 = v["header_b64"].as_str().unwrap();
    let payload_b64 = v["payload_b64"].as_str().unwrap();
    assert_eq!(
        conf::b64url(&header_octets),
        header_b64,
        "RFC 7515 A.1 header encoding"
    );
    assert_eq!(
        conf::b64url(&payload_octets),
        payload_b64,
        "RFC 7515 A.1 payload encoding"
    );

    let mut key = conf::b64url_decode(v["jwk_k"].as_str().unwrap()).unwrap();
    if selftest_break("jws-hs256") {
        // Corrupt the KEY, so the recomputed MAC cannot equal the published signature.
        key[0] ^= 0xff;
    }
    let signing_input = format!("{header_b64}.{payload_b64}");
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(signing_input.as_bytes());
    let sig = mac.finalize().into_bytes();
    assert_eq!(
        conf::b64url(&sig),
        v["signature_b64"].as_str().unwrap(),
        "RFC 7515 A.1: HMAC-SHA256(signing input) must equal the published JWS signature"
    );
    assert_eq!(sig.as_slice(), octets(&v["signature_octets"]).as_slice());
}

/// RFC 7515 Appendix A.2: RS256 JWS verified with the published RSA public key (n, e).
#[test]
fn jws_rfc7515_a2_rs256_verifies() {
    let vecs = conf::rfc_vectors();
    let v = &vecs["jws_a2_rs256"];
    let mut token = format!(
        "{}.{}.{}",
        v["header_b64"].as_str().unwrap(),
        v["payload_b64"].as_str().unwrap(),
        v["signature_b64"].as_str().unwrap()
    );
    if selftest_break("jws-rs256") {
        // Corrupt the payload so the published signature cannot cover it.
        token = token.replacen('.', ".BROKEN", 1);
    }
    let jwks = json!({ "keys": [{ "kty": "RSA", "n": v["jwk_n"], "e": v["jwk_e"] }] });
    conf::verify_jwt_against_jwks(&token, &jwks)
        .expect("RFC 7515 A.2: published RS256 signature must verify with the published key");

    // Negative control: flipping the last signature character must fail verification.
    let mut broken = token.clone();
    let last = broken.pop().unwrap();
    broken.push(if last == 'w' { 'x' } else { 'w' });
    assert!(
        conf::verify_jwt_against_jwks(&broken, &jwks).is_err(),
        "a corrupted RS256 signature must NOT verify; if it does the verifier is broken"
    );
}

/// RFC 7515 Appendix A.3: ES256 JWS verified with the published EC public key (x, y).
#[test]
fn jws_rfc7515_a3_es256_verifies() {
    let vecs = conf::rfc_vectors();
    let v = &vecs["jws_a3_es256"];
    let token = format!(
        "{}.{}.{}",
        v["header_b64"].as_str().unwrap(),
        v["payload_b64"].as_str().unwrap(),
        v["signature_b64"].as_str().unwrap()
    );
    let jwks = json!({
        "keys": [{ "kty": "EC", "crv": "P-256", "x": v["jwk_x"], "y": v["jwk_y"] }]
    });
    conf::verify_jwt_against_jwks(&token, &jwks)
        .expect("RFC 7515 A.3: published ES256 signature must verify with the published key");

    // Negative control, the sibling of the RS256 one above. Without it this test proves only
    // that the verifier says yes to something, which a verifier that says yes to EVERYTHING also
    // does; ECDSA is the algorithm this crate actually signs with, so it is the one that most
    // needs the other half. Flipping the last signature character must fail.
    let mut broken = token.clone();
    let last = broken.pop().unwrap();
    broken.push(if last == 'w' { 'x' } else { 'w' });
    assert!(
        conf::verify_jwt_against_jwks(&broken, &jwks).is_err(),
        "a corrupted ES256 signature must NOT verify; if it does the verifier is broken"
    );
    if selftest_break("jws-es256") {
        // Corrupt the KEY, so the published signature cannot verify under it.
        let bad =
            json!({ "keys": [{ "kty": "EC", "crv": "P-256", "x": v["jwk_y"], "y": v["jwk_x"] }] });
        conf::verify_jwt_against_jwks(&token, &bad)
            .expect("selftest fault: the published ES256 signature must not verify here");
    }
}

/// RFC 9068 s2.1/s2.2: the validator must accept a conforming token and must name every
/// missing required claim. An AS validator that never rejects anything is worthless.
#[test]
fn rfc9068_validator_accepts_conforming_and_rejects_each_missing_claim() {
    let vecs = conf::rfc_vectors();
    let required: Vec<String> = vecs["rfc9068"]["required_claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();

    let header = json!({ "typ": "at+jwt", "alg": "RS256", "kid": "k1" });
    let claims = json!({
        "iss": "https://as.example",
        "exp": 1_900_000_000u64,
        "aud": "https://rs.example",
        "sub": "user-1",
        "client_id": "client-1",
        "iat": 1_800_000_000u64,
        "jti": "id-1"
    });
    let tok = |h: &Value, c: &Value| {
        format!(
            "{}.{}.{}",
            conf::b64url(h.to_string().as_bytes()),
            conf::b64url(c.to_string().as_bytes()),
            conf::b64url(b"sig")
        )
    };
    assert!(
        conf::validate_rfc9068_access_token(&tok(&header, &claims)).is_empty(),
        "validator must accept a token carrying every RFC 9068 s2.2 required claim"
    );

    for missing in &required {
        let mut c = claims.clone();
        if !selftest_break("rfc9068") {
            c.as_object_mut().unwrap().remove(missing);
        }
        let violations = conf::validate_rfc9068_access_token(&tok(&header, &c));
        // NOT `violations.iter().any(|m| m.contains(missing))`, which is what stood here and
        // which asserted nothing. Every message this validator builds ENDS with the fixed list
        // "RFC 9068 s2.2 REQUIRES iss, exp, aud, sub, client_id, iat, jti", so it contains all
        // seven names whatever claim it is about: `contains("jti")` is true for a violation about
        // `iss`, and the assertion degenerated to "at least one violation exists". A validator
        // that misattributed EVERY missing claim to `jti` passed it.
        //
        // So: EXACTLY one violation, and it must NAME the claim that was dropped, matched
        // against the quoted subject at the front of the message rather than anywhere in it.
        assert_eq!(
            violations.len(),
            1,
            "dropping required claim \"{missing}\" must produce exactly one violation; \
             got {violations:?}"
        );
        assert!(
            violations[0].starts_with(&format!("claim \"{missing}\" ")),
            "the violation for a dropped \"{missing}\" must be ABOUT \"{missing}\"; \
             got {violations:?}"
        );
    }

    // typ header wrong (RFC 9068 s2.1) and alg none must both be rejected.
    let bad_typ = json!({ "typ": "JWT", "alg": "RS256" });
    assert!(!conf::validate_rfc9068_access_token(&tok(&bad_typ, &claims)).is_empty());
    let alg_none = json!({ "typ": "at+jwt", "alg": "none" });
    assert!(!conf::validate_rfc9068_access_token(&tok(&alg_none, &claims)).is_empty());
}

/// RFC 8414 s2: metadata validator accepts a conforming document, rejects a broken one, and
/// enforces issuer match (s3.3).
#[test]
fn rfc8414_metadata_validator() {
    let good = json!({
        "issuer": "http://127.0.0.1:8914",
        "authorization_endpoint": "http://127.0.0.1:8914/authorize",
        "token_endpoint": "http://127.0.0.1:8914/token",
        "device_authorization_endpoint": "http://127.0.0.1:8914/device_authorization",
        "jwks_uri": "http://127.0.0.1:8914/jwks",
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code"
        ],
        "code_challenge_methods_supported": ["S256"]
    });
    assert!(
        conf::validate_as_metadata(&good, "http://127.0.0.1:8914").is_empty(),
        "validator must accept a document with every RFC 8414 required field"
    );

    for field in [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "device_authorization_endpoint",
        "response_types_supported",
        "code_challenge_methods_supported",
    ] {
        let mut broken = good.clone();
        if !selftest_break("rfc8414") {
            broken.as_object_mut().unwrap().remove(field);
        }
        assert!(
            !conf::validate_as_metadata(&broken, "http://127.0.0.1:8914").is_empty(),
            "removing \"{field}\" must be reported (RFC 8414 s2 / RFC 8628 s4)"
        );
    }
    assert!(
        !conf::validate_as_metadata(&good, "http://other.example").is_empty(),
        "issuer mismatch with the retrieval URL must be reported (RFC 8414 s3.3)"
    );

    // RFC 8414 s2: the issuer "MUST NOT include a query or fragment component". Driven with the
    // SAME string as the retrieval URL, so the s3.3 mismatch check cannot be what fires and this
    // is the only violation left: without a case like this the branch is deletable and green.
    for suffix in ["?x=1", "#f"] {
        let mut with_suffix = good.clone();
        let iss = format!("http://127.0.0.1:8914{suffix}");
        with_suffix.as_object_mut().unwrap()["issuer"] = json!(iss);
        let violations = conf::validate_as_metadata(&with_suffix, &iss);
        assert_eq!(
            violations,
            vec!["issuer must have no query or fragment (RFC 8414 s2)".to_string()],
            "an issuer carrying \"{suffix}\" must be reported, and reported for that reason"
        );
    }

    // RFC 8414 s2 / RFC 8628: `grant_types_supported`, when present, has to name the grants this
    // AS is being judged as supporting. The block was written but never driven: the fixture above
    // lists both, so only the ACCEPTING path ran and every refusal in it was deletable.
    let mut no_device = good.clone();
    no_device.as_object_mut().unwrap()["grant_types_supported"] =
        json!(["authorization_code", "refresh_token"]);
    assert!(
        conf::validate_as_metadata(&no_device, "http://127.0.0.1:8914")
            .iter()
            .any(|m| m.contains("urn:ietf:params:oauth:grant-type:device_code")),
        "grant_types_supported without the device grant must be reported by NAME (RFC 8628)"
    );
    let mut no_code = good.clone();
    no_code.as_object_mut().unwrap()["grant_types_supported"] = json!(["refresh_token"]);
    assert!(
        conf::validate_as_metadata(&no_code, "http://127.0.0.1:8914")
            .iter()
            .any(|m| m.contains("authorization_code")),
        "grant_types_supported without authorization_code must be reported by name"
    );
    let mut not_array = good.clone();
    not_array.as_object_mut().unwrap()["grant_types_supported"] = json!("authorization_code");
    assert!(
        conf::validate_as_metadata(&not_array, "http://127.0.0.1:8914")
            .iter()
            .any(|m| m.contains("must be a JSON array")),
        "a non-array grant_types_supported must be reported as a type error, not ignored"
    );

    // RFC 8414 s2: every endpoint the document advertises has to be a URL. The fixture's are all
    // valid, so the parseability loop had never rejected anything.
    for key in [
        "authorization_endpoint",
        "token_endpoint",
        "device_authorization_endpoint",
        "jwks_uri",
    ] {
        let mut unparseable = good.clone();
        unparseable.as_object_mut().unwrap()[key] = json!("not a url");
        assert!(
            conf::validate_as_metadata(&unparseable, "http://127.0.0.1:8914")
                .iter()
                .any(|m| m.contains(key) && m.contains("is not a valid URL")),
            "a \"{key}\" that is a string but not a URL must be reported (RFC 8414 s2)"
        );
    }
}

/// RFC 6749 s5.2 / RFC 8628 s3.5: error-shape validator accepts each legal device error and
/// rejects wrong shapes.
#[test]
fn error_shape_validator() {
    for code in [
        "authorization_pending",
        "slow_down",
        "expired_token",
        "access_denied",
    ] {
        assert!(
            conf::validate_error_body(&json!({ "error": code })).is_empty(),
            "RFC 8628 s3.5 error code \"{code}\" must be accepted"
        );
    }
    let unregistered = if selftest_break("error-shape") {
        // A code that IS registered, so the assertion below can only pass if it checks nothing.
        "invalid_request"
    } else {
        "not_a_registered_code"
    };
    assert!(!conf::validate_error_body(&json!({ "error": unregistered })).is_empty());
    assert!(!conf::validate_error_body(&json!({ "message": "nope" })).is_empty());
    assert!(!conf::validate_error_body(&json!({ "error": 42 })).is_empty());
    assert!(!conf::validate_error_body(&json!("just a string")).is_empty());

    // RFC 6749 s5.2 fixes `error_description` to %x20-21 / %x23-5B / %x5D-7E: printable ASCII
    // MINUS the double quote (%x22) and the backslash (%x5C), which are excluded because the
    // value lands inside a JSON string and both are what escapes one. The only case here used to
    // be the non-ASCII one below, which the printable-range arm alone catches, so the two
    // excluded characters, the whole reason the range is split into two pieces, were untested.
    for (description, why) in [
        (
            "he said \"no\"",
            "a double quote (%x22) is outside the s5.2 charset",
        ),
        (
            "a back\\slash",
            "a backslash (%x5C) is outside the s5.2 charset",
        ),
        (
            "smart \u{201c}quotes\u{201d}",
            "non-ASCII is outside the s5.2 charset",
        ),
        (
            "tab\there",
            "a control character is outside the s5.2 charset",
        ),
    ] {
        assert!(
            !conf::validate_error_body(
                &json!({ "error": "invalid_request", "error_description": description })
            )
            .is_empty(),
            "{why}: {description:?} must be reported"
        );
    }
    // And the positive half, so the check cannot pass by rejecting everything: every other
    // printable ASCII character IS legal, including the two that bracket each excluded one.
    let legal: String = (0x20u8..=0x7e)
        .filter(|c| *c != b'"' && *c != b'\\')
        .map(char::from)
        .collect();
    assert!(
        conf::validate_error_body(
            &json!({ "error": "invalid_request", "error_description": legal })
        )
        .is_empty(),
        "every character in %x20-21 / %x23-5B / %x5D-7E must be accepted (RFC 6749 s5.2)"
    );
}

/// RFC 6749 s5.1: token-response validator accepts the RFC shape and rejects broken ones.
#[test]
fn token_response_shape_validator() {
    let good = json!({
        "access_token": "abc",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "def",
        "scope": "read"
    });
    assert!(conf::validate_token_response(&good).is_empty());
    if selftest_break("token-response") {
        // A CONFORMING body where a broken one is expected.
        assert!(!conf::validate_token_response(&good).is_empty());
    }
    assert!(!conf::validate_token_response(&json!({ "token_type": "Bearer" })).is_empty());
    assert!(!conf::validate_token_response(&json!({ "access_token": "x" })).is_empty());
    assert!(!conf::validate_token_response(
        &json!({ "access_token": "x", "token_type": "Bearer", "expires_in": "3600" })
    )
    .is_empty());
    assert!(
        !conf::validate_token_response(&json!({ "access_token": "x", "token_type": "mac" }))
            .is_empty()
    );
}

/// RFC 8628 s3.2: device-authorization-response validator.
#[test]
fn device_authorization_response_shape_validator() {
    let good = json!({
        "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
        "user_code": "WDJB-MJHT",
        "verification_uri": "https://example.com/device",
        "verification_uri_complete": "https://example.com/device?user_code=WDJB-MJHT",
        "expires_in": 1800,
        "interval": 5
    });
    assert!(conf::validate_device_authorization_response(&good).is_empty());
    for field in ["device_code", "user_code", "verification_uri", "expires_in"] {
        let mut broken = good.clone();
        if !selftest_break("device-auth") {
            broken.as_object_mut().unwrap().remove(field);
        }
        assert!(
            !conf::validate_device_authorization_response(&broken).is_empty(),
            "removing \"{field}\" must be reported (RFC 8628 s3.2)"
        );
    }

    // RFC 8628 s3.2: `verification_uri` is the URI the user is told to visit, so a string that is
    // not a URI is not a usable response. The loop above only REMOVES the field, which trips the
    // required-member check first, so the parseability arm had never rejected anything.
    let mut unparseable = good.clone();
    unparseable.as_object_mut().unwrap()["verification_uri"] = json!("not a uri");
    assert!(
        conf::validate_device_authorization_response(&unparseable)
            .iter()
            .any(|m| m.contains("is not a valid URI")),
        "a verification_uri that is present but not a URI must be reported (RFC 8628 s3.2)"
    );
}
