// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9101 request objects: the `aud` check and the `nbf` boundary, which a mutation sweep found
//! nothing constraining.
//!
//! `tests/jar.rs` covers what an attacker can do WITHOUT the client's key. Everything here needs
//! the key, so the key is generated in the test and the request object is signed here, which is
//! the only way to reach the claim checks at all: a request object that does not verify never gets
//! as far as `aud`, `nbf` or `exp`.
//!
//! The clock is FROZEN. Two of the mutants below differ from the original only at the exact
//! instant `now == nbf`, and a test that reads the wall clock cannot reliably produce that instant.

#![cfg(all(feature = "jar", feature = "par", feature = "jwt-p256"))]
// Requires `jwt-p256`, the built-in ES256 backend, because every test below has to PRODUCE a
// signature. `jwt` alone carries the `Es256Signer`/`Es256Verifier` seam and no curve arithmetic at
// all, so in that build there is nothing here that could run.

use std::time::{Duration, SystemTime};

use oauth_as::jwt::{compact_jws, EcdsaP256Key};
use oauth_as::{
    AuthorizationError, AuthorizationServer, Client, ClientAuth, ClientId, Clock, ErrorCode,
    GrantType, JarConfig, MemoryStorage, RegisteredRequestObjectKey, RequestObjectKeys, ScopeSet,
    ServerConfig,
};

/// RFC 7636 appendix B's verifier, so the challenge below is a real S256 challenge.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const ISSUER: &str = "https://as.example";
/// The frozen instant every claim set below is written against.
const NOW: u64 = 1_700_000_000;

#[derive(Clone)]
struct FrozenClock;

impl Clock for FrozenClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(NOW)
    }
}

struct Keys(RegisteredRequestObjectKey);

impl RequestObjectKeys for Keys {
    fn registered_key(&self, client_id: &ClientId) -> Option<RegisteredRequestObjectKey> {
        (client_id.as_str() == "app").then(|| self.0.clone())
    }
}

async fn server(key: &EcdsaP256Key) -> AuthorizationServer<MemoryStorage, FrozenClock> {
    let mut cfg = ServerConfig::new(ISSUER, "https://as.example/device");
    cfg.jar = Some(Box::new(JarConfig::new()));
    let jwk = key.public_jwk();
    let registered = RegisteredRequestObjectKey::es256_from_jwk_coordinates(
        Some(jwk.kid.clone()),
        &jwk.x,
        &jwk.y,
    )
    .expect("a JWK this crate emitted registers");
    let server = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), FrozenClock)
        .with_request_object_keys(Box::new(Keys(registered)));
    server
        .register_client(Client {
            client_id: ClientId::new("app"),
            auth: ClientAuth::Public,
            grant_types: vec![GrantType::AuthorizationCode],
            redirect_uris: vec!["https://app.example/cb".to_string()],
            allowed_scopes: ScopeSet::parse("read write").unwrap(),
            default_scopes: ScopeSet::parse("read").unwrap(),
            name: None,
            registration: None,
        })
        .await
        .unwrap();
    server
}

/// A conforming RFC 9101 section 4 claim set, plus whatever `extra` the caller wants to add or
/// override. Everything the authorization request itself needs is fixed and valid, so any refusal
/// below is about the claim under test and nothing else.
fn request_object(key: &EcdsaP256Key, extra: serde_json::Value) -> String {
    // `exp` is in the BASE claims, not spliced in per test, because 0.9.1 refuses a request object
    // without one and every test in this file is about something else: an aud array, an nbf, a
    // crit. A fixture missing it would make all of them fail for a reason none of them names. A
    // test that IS about the lifetime overrides it through `extra`, which is applied after.
    // Sixty seconds past `NOW`, the FROZEN clock this suite runs on, NOT past the wall clock. A
    // real-time `exp` here is years beyond a clock frozen in 2023, which trips
    // `JarConfig::max_request_object_lifetime` and reds every test in the file for a reason none of
    // them is about. Worth stating because the ceiling catching that is the ceiling working.
    let exp = NOW + 60;
    let mut claims = serde_json::json!({
        "client_id": "app",
        "response_type": "code",
        "redirect_uri": "https://app.example/cb",
        "scope": "read",
        "code_challenge": oauth_as::pkce::code_challenge_s256(VERIFIER),
        "code_challenge_method": "S256",
        "exp": exp,
    });
    let object = claims.as_object_mut().expect("an object");
    for (k, v) in extra.as_object().expect("extra must be an object") {
        object.insert(k.clone(), v.clone());
    }
    let header = format!(r#"{{"alg":"ES256","kid":"{}"}}"#, key.kid());
    compact_jws(
        header.as_bytes(),
        &serde_json::to_vec(&claims).unwrap(),
        |input| key.sign_signing_input(input).unwrap(),
    )
}

/// The refusal a request object earned, or `None` if it was accepted.
async fn refusal(extra: serde_json::Value) -> Option<ErrorCode> {
    let key = EcdsaP256Key::generate("client-key");
    let server = server(&key).await;
    let object = request_object(&key, extra);
    match server
        .validate_signed_authorization_request("app", &object)
        .await
    {
        Ok(_) => None,
        Err(AuthorizationError::Direct(e)) => Some(e.error),
        Err(AuthorizationError::Redirect(r)) => Some(r.error.error),
    }
}

/// KILLS: `par.rs delete match arm serde_json::Value::Array(many) in verified_request_object`, and
/// `par.rs replace == with != in verified_request_object` (the `aud` comparison).
///
/// RFC 7519 section 4.1.3 makes `aud` "either an array of case-sensitive strings or, in the
/// special case when there is one audience, a single case-sensitive string". The array is the
/// GENERAL form and the string is the special case, so a client that writes the general form is
/// the conforming one. Deleting the array arm sends every such object to the `_ => false` fallback
/// and refuses it: a JAR deployment whose clients use a standard JWT library (most of which emit
/// an array) stops working entirely, and the error blames the audience.
///
/// Inverting the comparison is worse than that. It ACCEPTS an object addressed to some other
/// authorization server and REFUSES the one addressed here, which is precisely the mix-up that
/// `aud` exists to stop: a request object captured at another AS becomes a valid request here.
#[tokio::test]
async fn an_aud_array_naming_this_server_is_accepted_and_one_naming_another_is_not() {
    assert_eq!(
        refusal(serde_json::json!({"aud": [ISSUER]})).await,
        None,
        "RFC 7519 s4.1.3: an aud array naming this issuer addresses this server"
    );
    assert_eq!(
        refusal(serde_json::json!({"aud": ["https://other.example", ISSUER]})).await,
        None,
        "an aud array is satisfied when ANY entry names this server"
    );
    assert_eq!(
        refusal(serde_json::json!({"aud": ["https://other.example"]})).await,
        Some(ErrorCode::InvalidRequestObject),
        "an object addressed only to another AS, replayed here, is the mix-up aud exists to stop"
    );
}

/// KILLS: `par.rs replace <= with < in verified_request_object` (the `nbf` bound).
///
/// THE OPERATOR IS `<=`, AND IT HAS THE CLOCK-SKEW LEEWAY ON THE LEFT OF IT: the refusal is
/// `now + CLOCK_SKEW_LEEWAY <= nbf`, with the leeway `skew.rs` defines once for the whole crate at
/// sixty seconds. So the object is refused from `nbf = NOW + 60` upwards and accepted below it,
/// and the naive reading — "the instant `now == nbf` is the first acceptable one" — is off by the
/// whole leeway. Naming the operator that is actually there matters here more than usual, because
/// these headers are what tells the next person which mutants a case can and cannot kill: a header
/// naming mutants of `<` describes mutants cargo-mutants will never generate.
///
/// RFC 7519 section 4.1.5 makes `nbf` "the time before which the JWT MUST NOT be accepted", and
/// the leeway is granted in the one direction that can only ever admit a request that was going to
/// be fine a moment later (see `skew::CLOCK_SKEW_LEEWAY`). A client that stamps `nbf` with the same
/// second as `iat` — the default of every JWT library this crate's clients are likely to use — is
/// comfortably inside it, and must not spend the second it was minted in earning an intermittent,
/// unreproducible `invalid_request_object`.
#[tokio::test]
async fn a_request_object_valid_from_this_instant_is_accepted() {
    assert_eq!(
        refusal(serde_json::json!({"nbf": NOW})).await,
        None,
        "RFC 7519 s4.1.5: at nbf the object has become valid, it has not stopped being valid"
    );
    // The LAST accepted instant, one second below the leeway. Tightening the comparison to `<`
    // would still accept this, which is why the refusal a second later is the case that kills it.
    assert_eq!(
        refusal(serde_json::json!({"nbf": NOW + 59})).await,
        None,
        "one second inside the sixty-second skew leeway is still accepted"
    );
}

/// KILLS: `par.rs replace <= with < in verified_request_object`, `replace <= with ==`, and
/// `replace <= with >`.
///
/// The other half of the same bound, and the half with an attacker in it. An object stamped for
/// the future is one whose validity window has not opened; accepting it lets a client (or whoever
/// captured the object) pre-mint authorization requests and hold them, which is exactly the replay
/// window `nbf` narrows.
///
/// TWO FIXTURES, AND THE FAR ONE IS NOT REDUNDANT. `NOW + 60` sits EXACTLY on
/// `now + CLOCK_SKEW_LEEWAY`, which is what makes it the first refused instant and what kills the
/// `<` mutant — but it is also the one value at which `==` agrees with `<=`, so a suite that
/// tested only the boundary let `<= -> ==` survive: a comparison that refuses objects stamped
/// precisely sixty seconds out and accepts every object stamped further ahead than that, which is
/// every object an attacker would pre-mint. `NOW + 3600` is clear of the leeway and separates them.
#[tokio::test]
async fn a_request_object_not_yet_valid_is_refused() {
    assert_eq!(
        refusal(serde_json::json!({"nbf": NOW + 60})).await,
        Some(ErrorCode::InvalidRequestObject),
        "nbf exactly one leeway ahead is the FIRST instant the bound refuses"
    );
    assert_eq!(
        refusal(serde_json::json!({"nbf": NOW + 3600})).await,
        Some(ErrorCode::InvalidRequestObject),
        "an object stamped an hour into the future is pre-minted, and is what a bound that only \
         refused the exact boundary would hand back"
    );
}

/// KILLS: `par.rs replace <= with > in verified_request_object`.
///
/// The ordinary case, and the one a reversed comparison destroys: a request object minted a moment
/// ago, with `nbf` in the past, is the shape of every real request. Reversing the bound refuses
/// all of them and accepts only the ones from the future.
#[tokio::test]
async fn a_request_object_valid_since_the_past_is_accepted() {
    assert_eq!(
        refusal(serde_json::json!({"nbf": NOW - 300, "iat": NOW - 300})).await,
        None,
        "an object whose validity window opened five minutes ago is inside it"
    );
}

/// KILLS: `par.rs replace RequestObjectKeyError::detail -> &str with "xyzzy"`.
///
/// `RegisteredRequestObjectKey` is built by the HOST, out of whatever its client registration
/// table holds, and this error is the only thing it gets back when that fails. The four ways it
/// can fail are four different operator problems: a mangled base64url field, a coordinate stored
/// at the wrong width (a trimmed leading zero is the common one), a SEC 1 blob of the wrong
/// length, and a SEC 1 blob of the right length that is not the uncompressed form. A constant
/// detail collapses all four into one unactionable message at the exact moment a deployment is
/// trying to work out why its clients cannot use JAR.
///
/// "not a point on P-256" is NO LONGER one of them, and that is the seam rather than a regression:
/// `--features jar` carries no elliptic curve of its own after 0.9.0, so the curve equation is
/// checked by the installed `Es256Verifier` per request instead, still failing closed. See
/// `src/tests/par.rs`'s `an_off_curve_key_registers_but_verifies_nothing`.
#[test]
fn the_reason_a_registered_key_was_refused_is_the_actual_reason() {
    // A valid P-256 point, so that only the field under test is wrong in each case.
    const X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
    const Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";

    let bad_x = RegisteredRequestObjectKey::es256_from_jwk_coordinates(None, "not base64url!!", Y)
        .expect_err("a mangled x is not a key");
    let bad_y = RegisteredRequestObjectKey::es256_from_jwk_coordinates(None, X, "not base64url!!")
        .expect_err("a mangled y is not a key");
    // 31 bytes: the trimmed-leading-zero mistake RFC 7518 s6.2.1.2 forbids.
    let short = base64_url(&[1u8; 31]);
    let narrow = RegisteredRequestObjectKey::es256_from_jwk_coordinates(None, &short, Y)
        .expect_err("a 31 byte coordinate is not a key");
    let wrong_form = RegisteredRequestObjectKey::es256_from_sec1(None, &[0x00; 65])
        .expect_err("65 bytes that do not begin 0x04 are not an uncompressed point");

    assert!(
        bad_x.detail().contains('x'),
        "the detail must name WHICH coordinate failed to decode, got {:?}",
        bad_x.detail()
    );
    assert!(
        bad_y.detail().contains('y'),
        "the detail must name WHICH coordinate failed to decode, got {:?}",
        bad_y.detail()
    );
    assert!(
        narrow.detail().contains("32 bytes"),
        "the detail must say what width was expected, got {:?}",
        narrow.detail()
    );
    assert!(
        wrong_form.detail().contains("0x04"),
        "the detail must say which SEC 1 encoding was expected, got {:?}",
        wrong_form.detail()
    );
    // And, the property that makes the four assertions above worth making: they are four
    // DIFFERENT sentences. A single constant would satisfy any one of them written loosely.
    let details = [
        bad_x.detail(),
        bad_y.detail(),
        narrow.detail(),
        wrong_form.detail(),
    ];
    for (i, a) in details.iter().enumerate() {
        for b in details.iter().skip(i + 1) {
            assert_ne!(a, b, "each refusal must be distinguishable from the others");
        }
    }
}

/// Base64url, unpadded, without reaching for the `base64` crate's engine import in a file that
/// needs it exactly once.
fn base64_url(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.encode(bytes)
}
