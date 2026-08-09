// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 7523 section 3 time claims that cannot be represented as a `SystemTime`.
//!
//! `exp`, `nbf` and `iat` come out of the assertion's own JSON, which is written by whoever sent
//! the request: an assertion is checked BEFORE the client is authenticated (it IS the
//! authentication), so these values are unauthenticated attacker input. A value large enough that
//! `UNIX_EPOCH + Duration::from_secs(value)` cannot be represented made std panic, and this crate
//! is a library, so that panic unwinds into the host's request handler.
//!
//! Each test asserts the REFUSAL rather than `should_panic`: the property is that no panic happens,
//! and that the refusal is the one the module already had for a time claim it will not accept.
#![cfg(all(feature = "client_assertion", feature = "jwt-p256"))]
// Requires `jwt-p256`, the built-in ES256 backend, because every test below has to PRODUCE a
// signature. `jwt` alone carries the `Es256Signer`/`Es256Verifier` seam and no curve arithmetic at
// all, so in that build there is nothing here that could run.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::client_assertion::{verify_assertion, AssertionFailure, AssertionKeys};
use oauth_as::jwt::{compact_jws, EcdsaP256Key};

/// The crate's built-in ES256 backend. Verification now goes through the [`oauth_as::jwt::Es256Verifier`] seam,
/// so a verifier is a per-call argument; this is the one a consumer who enables `jwt-p256` gets by
/// default, which is what keeps these tests measuring the behaviour they always measured.
#[cfg(feature = "jwt-p256")]
const VERIFIER: &oauth_as::jwt::P256Verifier = &oauth_as::jwt::P256Verifier;

const TOKEN_ENDPOINT: &str = "https://as.example/token";
const CLIENT_ID: &str = "pkjwt";

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn keys(key: &EcdsaP256Key) -> AssertionKeys {
    AssertionKeys::PublicKeys {
        keys: vec![key.to_public_jwk()],
    }
}

fn sign(key: &EcdsaP256Key, claims: &serde_json::Value) -> String {
    compact_jws(
        br#"{"alg":"ES256","typ":"JWT"}"#,
        &serde_json::to_vec(claims).unwrap(),
        |input| key.sign_signing_input(input).unwrap(),
    )
}

/// THE ATTACK: `{"exp": 18446744073709551615}` on an otherwise well-formed assertion.
///
/// `exp` is read and converted to an instant BEFORE either bound is compared, so the panic happened
/// on a request that a correct server refuses outright: RFC 7523 section 3 (4) plus this module's
/// `MAX_ASSERTION_LIFETIME` cap mean an `exp` that far out was never acceptable.
#[test]
fn an_exp_of_u64_max_is_refused_rather_than_panicking() {
    let key = EcdsaP256Key::generate("client-key");
    let assertion = sign(
        &key,
        &serde_json::json!({
            "iss": CLIENT_ID,
            "sub": CLIENT_ID,
            "aud": TOKEN_ENDPOINT,
            "exp": u64::MAX,
            "jti": "a-1",
        }),
    );

    assert_eq!(
        verify_assertion(
            Some(VERIFIER),
            &keys(&key),
            &assertion,
            CLIENT_ID,
            &[TOKEN_ENDPOINT],
            now()
        ),
        Err(AssertionFailure::Expired),
        "an exp past MAX_ASSERTION_LIFETIME is refused, and one that cannot be represented is too"
    );
}

/// The same for `nbf` and for `iat`, which are optional and are checked only when present. Both are
/// compared against a horizon of `now + CLOCK_SKEW_LEEWAY`, and a value that cannot be represented
/// is beyond every horizon.
#[test]
fn an_nbf_or_iat_of_u64_max_is_refused_rather_than_panicking() {
    let key = EcdsaP256Key::generate("client-key");
    for claim in ["nbf", "iat"] {
        let mut claims = serde_json::json!({
            "iss": CLIENT_ID,
            "sub": CLIENT_ID,
            "aud": TOKEN_ENDPOINT,
            "exp": 1_700_000_120u64,
            "jti": "a-2",
        });
        claims[claim] = serde_json::json!(u64::MAX);
        let assertion = sign(&key, &claims);

        assert_eq!(
            verify_assertion(
                Some(VERIFIER),
                &keys(&key),
                &assertion,
                CLIENT_ID,
                &[TOKEN_ENDPOINT],
                now()
            ),
            Err(AssertionFailure::NotYetValid),
            "{claim} of u64::MAX is in the future by more than any leeway"
        );
    }
}
