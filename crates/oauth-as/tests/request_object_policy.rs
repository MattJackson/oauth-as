// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! WHAT A SIGNED REQUEST OBJECT DOES NOT EXCUSE, AND WHAT ITS HEADER AND TIME CLAIMS MEAN.
//!
//! Every test here is GREEN as of 0.9.1. Nine of them were red when they were written and spent a
//! short while `#[ignore]`d, because the first of the defects below was reported in an audit round
//! BEFORE 0.9.0 was published, was never fixed, and shipped anyway. That is the clearest evidence
//! in this repository that a confirmed finding can fall out of a queue between rounds, and it is
//! why they were kept and annotated rather than deleted.
//!
//! Defects found by reading the RFC 9101 verification body end to end, all of them in the same
//! shape: a check that was SKIPPED rather than failed, so the wire behaviour of a refusal and the
//! wire behaviour of a pass were the same.
//!
//! 1. `require_pushed_authorization_requests` was bypassed by anyone holding a signed request
//!    object, because the query-borne JAR entry point reached the validation that has no policy
//!    gate in front of it. RFC 9126 s4 and RFC 9101 s10.5 answer DIFFERENT questions (where the
//!    data travelled, versus whether it was authenticated), so neither satisfies the other, and a
//!    request object travels in the browser URL by design.
//! 2. A request object had no REQUIRED lifetime and no ceiling on the lifetime it could name, and
//!    there is no single-use claim on it either, so one captured object authorized the same
//!    request for as long as the client's key stayed registered. That is what makes the bypass in
//!    (1) an attack rather than an untidiness: see
//!    [`a_request_object_with_no_expiry_is_refused_rather_than_replayable_forever`].
//! 3. RFC 7515 s4.1.11 `crit` was ignored. A JWS naming an extension the recipient does not
//!    understand is INVALID, unconditionally, and this verifier understands none.
//! 4. `exp` and `nbf` were read with `as_u64`, which answers `None` for the non-integer
//!    NumericDate spellings RFC 7519 s2 explicitly permits. The `None` was paired with the clock in
//!    one tuple destructure, so those spellings SKIPPED the check instead of failing it: an expired
//!    object with a fractional `exp` was accepted.
//! 5. No clock-skew leeway, in the one module that had drifted from `skew.rs`, on a refusal that
//!    reaches the USER as an error page rather than the client as a redirect.

#![cfg(all(feature = "jar", feature = "jwt-p256", feature = "par"))]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use oauth_as::jwt::{compact_jws, EcdsaP256Key};
use oauth_as::{
    AuthorizationError, AuthorizationServer, Client, ClientAuth, ClientId, Clock, ErrorCode,
    GrantType, JarConfig, MemoryStorage, ParConfig, RegisteredRequestObjectKey, RequestObjectKeys,
    ScopeSet, ServerConfig,
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// The instant every fixture below calls "now". A hand-cranked clock rather than the wall clock,
/// because the whole subject of this file is what a request object is worth at a LATER instant
/// than the one it was minted at, and a test that has to sleep to ask that question does not get
/// asked.
const BASE: u64 = 1_700_000_000;

#[derive(Clone)]
struct ManualClock(Arc<Mutex<SystemTime>>);

impl ManualClock {
    fn at_base() -> Self {
        ManualClock(Arc::new(Mutex::new(UNIX_EPOCH + Duration::from_secs(BASE))))
    }

    fn advance(&self, d: Duration) {
        *self.0.lock().expect("no test panics while holding this") += d;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().expect("no test panics while holding this")
    }
}

struct Keys(RegisteredRequestObjectKey);

impl RequestObjectKeys for Keys {
    fn registered_key(&self, client_id: &ClientId) -> Option<RegisteredRequestObjectKey> {
        (client_id.as_str() == "app").then(|| self.0.clone())
    }
}

fn client() -> Client {
    Client {
        client_id: ClientId::new("app"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::AuthorizationCode],
        redirect_uris: vec!["https://app.example/cb".to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

async fn server_at(
    key: &EcdsaP256Key,
    jar: Option<JarConfig>,
    par: Option<ParConfig>,
    clock: ManualClock,
) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.jar = jar.map(Box::new);
    cfg.par = par.map(Box::new);
    let jwk = key.public_jwk();
    let registered = RegisteredRequestObjectKey::es256_from_jwk_coordinates(
        Some(jwk.kid.clone()),
        &jwk.x,
        &jwk.y,
    )
    .expect("a JWK this crate emitted registers");
    let server = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), clock)
        .with_request_object_keys(Box::new(Keys(registered)));
    server.register_client(client()).await.unwrap();
    server
}

async fn server(
    key: &EcdsaP256Key,
    jar: Option<JarConfig>,
    par: Option<ParConfig>,
) -> AuthorizationServer<MemoryStorage, ManualClock> {
    server_at(key, jar, par, ManualClock::at_base()).await
}

/// A genuinely signed request object carrying whatever extra claims the caller names, with the
/// header the caller names.
fn signed(key: &EcdsaP256Key, header: &str, extra: &str) -> String {
    let challenge = oauth_as::pkce::code_challenge_s256(VERIFIER);
    let payload = format!(
        r#"{{"client_id":"app","response_type":"code","redirect_uri":"https://app.example/cb","scope":"read","code_challenge":"{challenge}","code_challenge_method":"S256"{extra}}}"#
    );
    compact_jws(header.as_bytes(), payload.as_bytes(), |input| {
        key.sign_signing_input(input)
            .expect("the fixture key signs")
    })
}

fn plain_header(key: &EcdsaP256Key) -> String {
    format!(r#"{{"alg":"ES256","kid":"{}"}}"#, key.public_jwk().kid)
}

/// The `exp` an ordinary conforming client sends: comfortably inside the default ceiling, so
/// every fixture that is not ABOUT the lifetime carries one and none of them are testing the
/// lifetime by accident.
fn live_exp() -> String {
    format!(r#","exp":{}"#, BASE + 30)
}

/// ATTACK, RFC 9126 s4. The deployment declared, and advertised in its RFC 8414 document, that
/// authorization request data arrives only through PAR. A signed request object in the query
/// walked past that: it reached the validation with no policy gate in front of it.
///
/// The reason this matters more than "one more way to send a request": a request object travels in
/// the browser's URL, so it lands in Referer headers, proxy logs and history. The whole point of
/// requiring PAR is that request data never goes there, and never goes there UNAUTHENTICATED and
/// REUSABLE, which is what the next test is about.
#[tokio::test]
async fn a_signed_request_object_does_not_satisfy_a_par_only_policy() {
    let key = EcdsaP256Key::generate("client-key");
    let mut par = ParConfig::new();
    par.require_pushed_authorization_requests = true;
    let server = server(&key, Some(JarConfig::new()), Some(par)).await;
    let object = signed(&key, &plain_header(&key), &live_exp());

    match server
        .validate_signed_authorization_request("app", &object)
        .await
    {
        Err(AuthorizationError::Direct(error)) => assert_eq!(
            error.error,
            ErrorCode::InvalidRequest,
            "RFC 9126 s4 is about where the data travelled, which a signature does not answer"
        ),
        other => panic!(
            "with require_pushed_authorization_requests set, a query-borne request object must \
             be refused, got {other:?}"
        ),
    }
}

/// ATTACK, replay, and this is the half that makes the gate above worth having.
///
/// RFC 9101 does not require `exp` on a request object, this server honoured one only when it was
/// present, and there is no `jti` and no single-use store for request objects anywhere in the
/// crate. So an object with no time claims authorized ITS EXACT REQUEST for as long as the client
/// kept its key registered, and one is trivially captured: it rides in the browser's URL bar.
///
/// The flow, spelled out because "replayable" understates it. The attacker starts an ordinary
/// authorization at client C in their own browser, so the signed object in their URL bar carries
/// C's `code_challenge` and C's `state` for the ATTACKER's session at C. They copy it. Later they
/// induce a victim who holds a live session at this server to fetch the same URL. This server
/// validates the object, the host mints a code for the VICTIM, and it is delivered to C's
/// REGISTERED redirect URI, which is the one place the attacker did not have to control. C
/// redeems it with the `code_verifier` it stored for the ATTACKER's session, and the attacker's
/// session at C is now authenticated as the victim. Nothing in the sequence needs the attacker to
/// forge anything: the object is genuinely signed, and one signature is enough for every replay.
///
/// So an unbounded request object is a bearer credential. The refusal below is what stops it
/// being one, and the ten years is only there to make the "forever" literal.
#[tokio::test]
async fn a_request_object_with_no_expiry_is_refused_rather_than_replayable_forever() {
    let key = EcdsaP256Key::generate("client-key");
    let clock = ManualClock::at_base();
    let server = server_at(&key, Some(JarConfig::new()), None, clock.clone()).await;
    let object = signed(&key, &plain_header(&key), "");

    match server
        .validate_signed_authorization_request("app", &object)
        .await
    {
        Err(AuthorizationError::Direct(error)) => assert_eq!(
            error.error,
            ErrorCode::InvalidRequestObject,
            "a request object with no lifetime is a bearer credential, not a request"
        ),
        other => panic!("a request object with no exp must be refused, got {other:?}"),
    }

    // The same object, ten years on, and the point of asking twice: before this change BOTH of
    // these calls succeeded, which is the whole defect stated as one assertion.
    clock.advance(Duration::from_secs(10 * 365 * 24 * 3600));
    assert!(
        server
            .validate_signed_authorization_request("app", &object)
            .await
            .is_err(),
        "and it is still refused ten years later, which is how long it used to work for"
    );
}

/// The ceiling, which is the other half of the same defence: a client cannot buy back the
/// unbounded object by NAMING an unbounded `exp`. Requiring the claim and then honouring any value
/// it carries would have moved the decision from this server to the holder of the key.
///
/// The bound is on the life REMAINING at presentation (`exp` minus now), not on `exp` minus `iat`,
/// because `iat` is optional too and because the remaining life is exactly the replay window.
#[tokio::test]
async fn a_request_object_whose_remaining_life_exceeds_the_ceiling_is_refused() {
    let key = EcdsaP256Key::generate("client-key");
    let server = server(&key, Some(JarConfig::new()), None).await;
    let object = signed(
        &key,
        &plain_header(&key),
        &format!(r#","exp":{}"#, BASE + 365 * 24 * 3600),
    );

    match server
        .validate_signed_authorization_request("app", &object)
        .await
    {
        Err(AuthorizationError::Direct(error)) => assert_eq!(
            error.error,
            ErrorCode::InvalidRequestObject,
            "an exp a year out is an unbounded object with a lifetime claim stapled to it"
        ),
        other => panic!("a request object may not name its own replay window, got {other:?}"),
    }
}

/// The bound is a WINDOW and not a prohibition, and this is the test that says what the window
/// buys: the object works, and then it stops working. Both halves matter, because a change that
/// refused everything would satisfy the two tests above and break every client.
#[tokio::test]
async fn a_short_lived_request_object_works_and_then_stops_working() {
    let key = EcdsaP256Key::generate("client-key");
    let clock = ManualClock::at_base();
    let server = server_at(&key, Some(JarConfig::new()), None, clock.clone()).await;
    let object = signed(&key, &plain_header(&key), &live_exp());

    server
        .validate_signed_authorization_request("app", &object)
        .await
        .expect("an object with a 30 second lifetime is inside the ceiling");

    clock.advance(Duration::from_secs(31));
    match server
        .validate_signed_authorization_request("app", &object)
        .await
    {
        Err(AuthorizationError::Direct(error)) => {
            assert_eq!(error.error, ErrorCode::InvalidRequestObject)
        }
        other => panic!("past its exp the same object is refused, got {other:?}"),
    }
}

/// The converse substitution, refused in the same pass so the pair cannot go back to being
/// asymmetric: a PUSH is not a signature, so `require_signed_request_object` still applies to a
/// pushed request that carried plain parameters.
#[tokio::test]
async fn a_pushed_plain_request_does_not_satisfy_a_signed_request_object_policy() {
    let key = EcdsaP256Key::generate("client-key");
    let mut jar = JarConfig::new();
    jar.require_signed_request_object = true;
    let server = server(&key, Some(jar), Some(ParConfig::new())).await;
    let challenge = oauth_as::pkce::code_challenge_s256(VERIFIER);

    let refused = server
        .pushed_authorization_request(
            &ClientId::new("app"),
            None,
            &[
                ("response_type", "code"),
                ("client_id", "app"),
                ("redirect_uri", "https://app.example/cb"),
                ("scope", "read"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
            ],
        )
        .await
        .expect_err("RFC 9101 s10.5 applies to a pushed request that carried no object");
    assert_eq!(refused.error, ErrorCode::InvalidRequest);
}

/// RFC 7515 s4.1.11 with RFC 8725 s3.10: a `crit` naming anything is invalid here, because this
/// verifier implements no extension header parameters at all.
///
/// The object below is otherwise perfect and its signature verifies under the registered key. That
/// is the point: before this, the server accepted it and verified it as an ordinary JWS, which is
/// the server telling the signer it honoured `b64: false` when it never read the member.
#[tokio::test]
async fn a_crit_header_naming_an_unimplemented_extension_is_refused() {
    let key = EcdsaP256Key::generate("client-key");
    let server = server(&key, Some(JarConfig::new()), None).await;
    let header = format!(
        r#"{{"alg":"ES256","kid":"{}","crit":["b64"],"b64":false}}"#,
        key.public_jwk().kid
    );
    let object = signed(&key, &header, &live_exp());

    match server
        .validate_signed_authorization_request("app", &object)
        .await
    {
        Err(AuthorizationError::Direct(error)) => {
            assert_eq!(error.error, ErrorCode::InvalidRequestObject)
        }
        other => {
            panic!("RFC 7515 s4.1.11: an unsupported crit makes the JWS invalid, got {other:?}")
        }
    }
}

/// RFC 7519 s2: NumericDate is a JSON number and "non-integer values can be used". An `exp` an hour
/// in the PAST, written as `...0.5`, is an expired object however it is spelled.
///
/// `as_u64` answered `None` for it, and the `None` was paired with the clock in a single tuple
/// destructure, so the whole expiry check was skipped in silence. A captured object with a
/// fractional `exp` was replayable for as long as the client's key stayed registered.
#[tokio::test]
async fn a_fractional_exp_in_the_past_is_still_expired() {
    let key = EcdsaP256Key::generate("client-key");
    let server = server(&key, Some(JarConfig::new()), None).await;
    let object = signed(
        &key,
        &plain_header(&key),
        &format!(r#","exp":{}.5"#, BASE - 3600),
    );

    match server
        .validate_signed_authorization_request("app", &object)
        .await
    {
        Err(AuthorizationError::Direct(error)) => {
            assert_eq!(error.error, ErrorCode::InvalidRequestObject);
            // THE CODE ALONE CANNOT SEE THE BUG COME BACK. `exp` is REQUIRED now, so an `as_u64`
            // that answered `None` for `...0.5` would refuse this object too — for having NO exp,
            // with the same `invalid_request_object`. The description is what says the claim was
            // READ and found to be in the past, rather than not read at all.
            assert!(
                error
                    .error_description
                    .unwrap_or_default()
                    .contains("has expired"),
                "a fractional exp must be READ and found expired, not treated as absent"
            );
        }
        other => panic!(
            "an expired request object must be refused however exp is spelled, got {other:?}"
        ),
    }
}

/// The same skip in the other direction, and the one an attacker chooses: an exponent-notation
/// `exp` is a conforming NumericDate that `as_u64` also could not read.
#[tokio::test]
async fn an_exponent_notation_exp_in_the_past_is_still_expired() {
    let key = EcdsaP256Key::generate("client-key");
    let server = server(&key, Some(JarConfig::new()), None).await;
    // 1.0e9 seconds is September 2001, comfortably expired, and is exactly the JSON number RFC
    // 7519 s2 permits and `as_u64` refuses to read.
    let object = signed(&key, &plain_header(&key), r#","exp":1.0e9"#);

    match server
        .validate_signed_authorization_request("app", &object)
        .await
    {
        Err(AuthorizationError::Direct(error)) => {
            assert_eq!(error.error, ErrorCode::InvalidRequestObject);
            // Same reason as the fractional case above: with `exp` required, "could not read it"
            // and "read it and it is stale" are the same error CODE, and only the description
            // tells them apart.
            assert!(
                error
                    .error_description
                    .unwrap_or_default()
                    .contains("has expired"),
                "an exponent-notation exp must be READ and found expired, not treated as absent"
            );
        }
        other => panic!(
            "an expired request object must be refused however exp is spelled, got {other:?}"
        ),
    }
}

/// `skew.rs` exists because `client-assertion` and `dpop` had drifted on this number. This module
/// was the one still applying none: a client whose clock is one second fast was refused, and
/// because the refusal is an `AuthorizationError::Direct` the USER sees an error page while the
/// client learns nothing. The same client's `private_key_jwt`, minted from the same clock, is
/// accepted at the token endpoint.
#[tokio::test]
async fn an_nbf_inside_the_clock_skew_leeway_is_accepted() {
    let key = EcdsaP256Key::generate("client-key");
    let server = server(&key, Some(JarConfig::new()), None).await;
    let object = signed(
        &key,
        &plain_header(&key),
        &format!(r#","nbf":{}{}"#, BASE + 5, live_exp()),
    );

    server
        .validate_signed_authorization_request("app", &object)
        .await
        .expect("a client five seconds fast is inside the crate-wide 60s leeway");
}

/// The leeway is a WINDOW and not a waiver: an `nbf` well past it is still refused, so a change
/// that widened the allowance without bound would fail here rather than pass quietly.
#[tokio::test]
async fn an_nbf_far_beyond_the_leeway_is_still_refused() {
    let key = EcdsaP256Key::generate("client-key");
    let server = server(&key, Some(JarConfig::new()), None).await;
    let object = signed(
        &key,
        &plain_header(&key),
        &format!(r#","nbf":{}{}"#, BASE + 86_400, live_exp()),
    );

    match server
        .validate_signed_authorization_request("app", &object)
        .await
    {
        Err(AuthorizationError::Direct(error)) => {
            assert_eq!(error.error, ErrorCode::InvalidRequestObject)
        }
        other => panic!("an nbf a day out is not clock skew, got {other:?}"),
    }
}

/// A present time claim that is not a NumericDate at all is MALFORMED, not absent. The rest of
/// this crate treats a present-but-unreadable claim that way, and treating it as absent is what
/// made every check above skippable.
///
/// THE NAME OF THIS TEST IS THE ASSERTION, so the assertion has to be able to tell malformed from
/// ignored. It cannot do that from the error code: `exp` is required, so an `as_u64` that read
/// `"soon"` as absent would refuse this object as well, with the same `invalid_request_object`,
/// and the 0.9.0 defect could be restored wholesale under a green suite. The description names
/// which of the two happened.
#[tokio::test]
async fn a_non_numeric_exp_is_malformed_rather_than_ignored() {
    let key = EcdsaP256Key::generate("client-key");
    let server = server(&key, Some(JarConfig::new()), None).await;
    let object = signed(&key, &plain_header(&key), r#","exp":"soon""#);

    match server
        .validate_signed_authorization_request("app", &object)
        .await
    {
        Err(AuthorizationError::Direct(error)) => {
            assert_eq!(error.error, ErrorCode::InvalidRequestObject);
            assert!(
                error
                    .error_description
                    .unwrap_or_default()
                    .contains("is not a NumericDate"),
                "a string exp must be refused as MALFORMED, not reported as a missing exp"
            );
        }
        other => panic!("a string exp is not a NumericDate, got {other:?}"),
    }
}

/// The control: with no policy set and a conforming lifetime, the same object validates. Without
/// this, every assertion above could be passing because the fixture never worked.
#[tokio::test]
async fn the_same_object_validates_when_no_policy_forbids_it() {
    let key = EcdsaP256Key::generate("client-key");
    let server = server(&key, Some(JarConfig::new()), None).await;
    let object = signed(&key, &plain_header(&key), &live_exp());

    server
        .validate_signed_authorization_request("app", &object)
        .await
        .expect("the fixture object must validate when nothing refuses it");
}

/// Not a policy test: this pins that the base64url encoding the fixtures rely on is the unpadded
/// one RFC 7515 s2 requires, so a malformed fixture cannot make a refusal look like a pass.
///
/// TWO THINGS THIS HAD TO FIX TO SAY ANYTHING. It asserted on `URL_SAFE_NO_PAD`, which is not what
/// builds the fixtures — [`signed`] goes through `oauth_as::jwt::compact_jws` — and it fed it three
/// bytes, the one length in three at which base64 emits no padding character under ANY engine. So
/// it could not have caught a padded encoder, and it was not looking at the encoder in use anyway.
/// One byte and two bytes are the lengths that pad (`=` and `==` respectively), and the encoder is
/// the fixtures' own.
#[test]
fn the_fixture_encoding_is_unpadded_base64url() {
    for len in 1..=3 {
        let bytes = vec![b'a'; len];
        assert!(
            !URL_SAFE_NO_PAD.encode(&bytes).contains('='),
            "{len} byte(s) must encode without padding"
        );
        let jws = compact_jws(&bytes, &bytes, |_| vec![0u8; len]);
        assert!(
            !jws.contains('='),
            "the fixtures' own encoder padded a {len}-byte segment: {jws}"
        );
    }
}

/// THE BOUNDARY ITSELF, which the two tests above step over rather than land on.
///
/// KILLS the 0.9.1 mutation survivor `replace > with >= in verified_request_object`. One test
/// presents an object a YEAR out and one presents thirty seconds, so both sit far from the edge
/// and neither can tell `>` from `>=`. The mutation makes an object whose remaining life is
/// EXACTLY `max_request_object_lifetime` refused instead of accepted.
///
/// Which way the boundary falls is a real decision and not a detail. `>` means the configured
/// ceiling is an ALLOWED lifetime, so a client that sets `exp` to exactly the documented maximum
/// works; `>=` means the documented maximum is the first value that fails, and every client that
/// reads the number and uses it is refused for doing what the configuration told them to. The
/// second is the kind of off-by-one that gets diagnosed as "the server is flaky" for a week.
#[tokio::test]
async fn a_request_object_at_exactly_the_ceiling_is_accepted() {
    let key = EcdsaP256Key::generate("client-key");
    let clock = ManualClock::at_base();
    let server = server_at(&key, Some(JarConfig::new()), None, clock.clone()).await;

    // `JarConfig::default()`'s ceiling is 300 seconds, and the clock is pinned at BASE, so this
    // object's remaining life is the ceiling to the second.
    let object = signed(
        &key,
        &plain_header(&key),
        &format!(r#","exp":{}"#, BASE + 300),
    );

    server
        .validate_signed_authorization_request("app", &object)
        .await
        .expect(
            "an object whose remaining life is EXACTLY max_request_object_lifetime must be \
             accepted: the ceiling is the largest allowed lifetime, not the smallest refused one",
        );

    // And one second past it is refused, so the test pins the edge rather than just the permissive
    // side of it.
    let too_long = signed(
        &key,
        &plain_header(&key),
        &format!(r#","exp":{}"#, BASE + 301),
    );
    assert!(
        server
            .validate_signed_authorization_request("app", &too_long)
            .await
            .is_err(),
        "one second past the ceiling must be refused, or the bound is not a bound"
    );
}
