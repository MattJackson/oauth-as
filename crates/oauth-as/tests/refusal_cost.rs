// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! What a REFUSAL costs, on the paths where the caller chooses the rate.
//!
//! `tests/allocation.rs` states the rule this file enforces elsewhere: a refusal is work the
//! attacker buys, so a refused request must not do work a successful one would not. The gates
//! there cover the token endpoint. These cover three more refusals whose descriptions come from a
//! FIXED set of strings and were being built with `format!` at request time anyway, plus the two
//! signing paths that formatted a value fixed at construction.
//!
//! # Why a separate binary, and one `#[test]`
//!
//! Same reason as `tests/allocation.rs` and `tests/allocation_paths.rs`: a `#[global_allocator]`
//! is process wide, and `std`'s harness starts one OS thread per `#[test]` outside any lock this
//! crate can take, so the whole file is one `#[test]` running its gates in sequence.

// Same finding, same answer, and this file is where the measurement behind it now lives: clippy
// sees a large `Err` in the closures below that it does not see at the endpoints themselves.
// `AuthorizationError` is 128 bytes and boxing the redirect variant would ADD one heap allocation
// to every redirect-form refusal, which is the path this file exists to keep cheap. See
// `tests/allocation_paths.rs` for the rest of the reasoning and
// `redirectable_authorization_refusal_bound` below for the numbers.
#![allow(clippy::result_large_err)]

mod support;

use std::panic::{catch_unwind, AssertUnwindSafe};

use support::alloc::{measure, CountingAllocator, Delta, TEST_LOCK};

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator;

#[test]
fn refusal_cost_gates() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let gates: &[(&str, fn())] = &[
        (
            "request_object_refusals_borrow_their_description",
            request_object_refusals_borrow_their_description,
        ),
        (
            "token_exchange_token_type_refusal_bound",
            token_exchange_token_type_refusal_bound,
        ),
        (
            "unknown_grant_type_refusal_is_not_sized_by_the_caller",
            unknown_grant_type_refusal_is_not_sized_by_the_caller,
        ),
        (
            "unknown_token_type_refusal_is_not_sized_by_the_caller",
            unknown_token_type_refusal_is_not_sized_by_the_caller,
        ),
        ("jwt_signing_bound", jwt_signing_bound),
        (
            "redirectable_authorization_refusal_bound",
            redirectable_authorization_refusal_bound,
        ),
    ];

    let mut failures = Vec::new();
    for (name, gate) in gates {
        if let Err(cause) = catch_unwind(AssertUnwindSafe(gate)) {
            let msg = cause
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| cause.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "panicked with a non-string payload".to_string());
            failures.push(format!("{name}: {msg}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} refusal gate(s) failed:\n{}",
        failures.len(),
        gates.len(),
        failures.join("\n")
    );
}

fn current_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime")
}

// --------------------------------------------------------------- RFC 9101 request objects

/// RFC 9101 section 6.1: a request object whose segments are not base64url is refused before any
/// signature work, and the refusal names WHICH segment. There are exactly three call sites and
/// three fixed strings, so the description is a `&'static str` and
/// [`oauth_as::ErrorResponse::error_description`] BORROWS it.
///
/// This is the authorization endpoint reached with a `request` parameter, which is unauthenticated:
/// the caller has proved nothing at this point, and a request object is attacker-supplied text of
/// the caller's chosen length. `format!("the {what} is not base64url")` bought a heap copy of one
/// of three constants per refused request.
#[cfg(all(feature = "jar", feature = "jwt-p256"))]
fn request_object_refusals_borrow_their_description() {
    use std::borrow::Cow;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use oauth_as::{
        AuthorizationError, AuthorizationServer, Client, ClientAuth, ClientId, ErrorCode,
        GrantType, JarConfig, MemoryStorage, RegisteredRequestObjectKey, RequestObjectKeys,
        ScopeSet, ServerConfig,
    };

    struct Keys(RegisteredRequestObjectKey);
    impl RequestObjectKeys for Keys {
        fn registered_key(&self, client_id: &ClientId) -> Option<RegisteredRequestObjectKey> {
            (client_id.as_str() == "app").then(|| self.0.clone())
        }
    }

    let rt = current_thread_runtime();
    let key = oauth_as::jwt::EcdsaP256Key::generate("client-key");
    let jwk = key.public_jwk();
    let registered = RegisteredRequestObjectKey::es256_from_jwk_coordinates(
        Some(jwk.kid.clone()),
        &jwk.x,
        &jwk.y,
    )
    .expect("the crate's own JWK must parse");

    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.jar = Some(Box::new(JarConfig::new()));
    let server = AuthorizationServer::new(cfg, MemoryStorage::new())
        .with_request_object_keys(Box::new(Keys(registered)));
    rt.block_on(server.register_client(Client {
        client_id: ClientId::new("app"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::AuthorizationCode],
        redirect_uris: vec!["https://app.example/cb".to_string()],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }))
    .expect("the fixture client must register");

    // ONE FIXTURE PER CALL SITE, and each has to REACH the site it names. `!` is outside the
    // alphabet in every base64 variant, so each of these three is refused for the segment it
    // spoils — but only if nothing earlier answers first, and that is what the previous pair of
    // fixtures got wrong. Their second entry spelled the header `eyJhIjoxfQ` (`{"a":1}`), which is
    // perfectly good base64url and perfectly good JSON, so it was refused at "the header has no
    // alg" — already a `&'static str`, and reached before either of the other two constants. Both
    // `SIGNATURE_NOT_BASE64URL` and `PAYLOAD_NOT_BASE64URL` could have been reverted to `format!`
    // with this gate still green.
    //
    // So the header here is a real one, naming the registered algorithm and key, and the payload
    // fixture is genuinely SIGNED over its spoiled payload: `src/par.rs` decodes the payload only
    // after the signature verifies, so an unsigned fixture would stop at "the signature did not
    // verify" and never reach the third constant either.
    let kid = jwk.kid.clone();
    let header_b64 =
        URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"ES256","kid":"{kid}"}}"#).as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(br#"{"client_id":"app"}"#);
    let bad_payload_signing_input = format!("{header_b64}.!!!!");
    let bad_payload = format!(
        "{bad_payload_signing_input}.{}",
        URL_SAFE_NO_PAD.encode(
            key.sign_signing_input(&bad_payload_signing_input)
                .expect("the fixture key signs")
        )
    );
    let objects = [
        (
            "!!!!.eyJhIjoxfQ.AAAA".to_string(),
            "the header is not base64url",
        ),
        (
            format!("{header_b64}.{payload_b64}.!!!!"),
            "the signature is not base64url",
        ),
        (bad_payload, "the payload is not base64url"),
    ];
    for (object, expected) in &objects {
        match rt.block_on(server.validate_signed_authorization_request("app", object)) {
            Err(AuthorizationError::Direct(error)) => {
                assert_eq!(error.error, ErrorCode::InvalidRequestObject);
                // WHICH constant answered, not merely that some borrowed constant did. Every
                // refusal on this path borrows, so `Cow::Borrowed` alone is satisfied by any
                // earlier gate, and "this call site borrows its description" is exactly the claim
                // that would then go untested.
                assert_eq!(
                    error.error_description.as_deref(),
                    Some(*expected),
                    "the fixture must reach the call site it was built for"
                );
                assert!(
                    matches!(error.error_description, Some(Cow::Borrowed(_))),
                    "a refusal whose description comes from a fixed set must borrow it, not \
                     format it: {:?}",
                    error.error_description
                );
            }
            other => panic!("a non-base64url segment must be refused, got {other:?}"),
        }
    }
}

#[cfg(not(all(feature = "jar", feature = "jwt-p256")))]
fn request_object_refusals_borrow_their_description() {}

// ------------------------------------------------------------------ RFC 8693 token exchange

/// RFC 8693 section 3: a `subject_token_type` that is not one of the registered URNs is refused,
/// and the refusal is one of three fixed sentences naming the parameter.
///
/// Measured through the HTTP surface because that is where the formatting was: the helper builds
/// the description from a `&'static str` parameter with `format!`, and this refusal happens BEFORE
/// the exchange is attempted, so before the presented client credential has been checked.
///
/// The bound is EXACT rather than budgeted. The claim is not "this path is cheap" (parsing a form
/// body is not free); it is "this refusal does not build its description at runtime", and a
/// one-allocation difference is the whole of what that claim is worth. The figure below is the
/// observed one on this crate's own `MemoryStorage`, which is deterministic for a fixed request.
#[cfg(all(feature = "http", feature = "token-exchange"))]
fn token_exchange_token_type_refusal_bound() {
    use oauth_as::{
        AuthorizationServer, Client, ClientAuth, ClientId, GrantType, MemoryStorage, ScopeSet,
        ServerConfig, ServiceBuilder,
    };

    let rt = current_thread_runtime();
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let server = std::sync::Arc::new(AuthorizationServer::new(cfg, MemoryStorage::new()));
    rt.block_on(server.register_client(Client {
        client_id: ClientId::new("svc"),
        auth: ClientAuth::ConfidentialSecretHash {
            hash: oauth_as::SecretHash::sha256("svc-secret"),
        },
        grant_types: vec![GrantType::TokenExchange],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }))
    .expect("the fixture client must register");
    let service = ServiceBuilder::new(server)
        .build()
        .expect("the fixture service must build");

    let body = "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
                &client_id=svc&client_secret=svc-secret\
                &subject_token=whatever&subject_token_type=urn:example:not-registered";
    // Built OUTSIDE the window: the request itself is the caller's cost, not the endpoint's.
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://as.example/token")
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body.to_string())
        .expect("a well formed request");

    let (response, d) = measure(|| rt.block_on(service.handle(request)));
    assert_eq!(response.status(), 400);
    // Observed 9 allocations / 4523 bytes. It was 11 / 4633 before the description stopped being
    // formatted, 10 / 4549 after that and before `TokenTypeIdentifier::parse` stopped `FromStr`
    // copying the caller's value onto the heap to carry it into an error this endpoint discards.
    // The allocation bound is EXACT (each one removed is the whole of its claim); the byte bound
    // carries a little room because most of those bytes are the response buffer the `http` crate
    // hands back, not this crate's.
    //
    // This gate is the one whose fixture was TOO SMALL to see the second of those two: its
    // `urn:example:not-registered` is 27 bytes, so the copy it was buying cost 27 bytes and hid
    // inside the byte bound's slack. `unknown_token_type_refusal_is_not_sized_by_the_caller`
    // below is the gate that can see it.
    check("token exchange token-type refusal", d, (9, 4800));
}

#[cfg(not(all(feature = "http", feature = "token-exchange")))]
fn token_exchange_token_type_refusal_bound() {}

// ------------------------------------------------- refusals the CALLER sizes, not the server
//
// The two gates below exist because the gates above them could not see the defect they were meant
// to bound. Both used a SHORT fixture value (`urn:example:not-registered`, 27 bytes), so a refusal
// that copied that value onto the heap cost 27 bytes and vanished into the byte budget's slack.
// The value is attacker-supplied and the caps allow it to be nearly the whole body
// (`MAX_BODY_BYTES` is 64 KiB and `MAX_FORM_PARAMETERS` is 64, so one parameter can be 60 KiB of
// junk), and both parameters are resolved BEFORE the presented client credential is checked. A
// fixture too small to see caller-controlled cost is a fixture that certifies its absence.
//
// The measurement is a DIFFERENCE rather than an absolute bound, because one caller-sized cost on
// this path is honest and unavoidable: `collect_body` buffers the request body once, which is what
// reading a form body IS, and `MAX_BODY_BYTES` is the thing that bounds it. Everything past that
// one buffer is work the parser bought on the attacker's behalf. So the claim these gates pin is:
// growing a parameter by N bytes grows the endpoint's allocator traffic by N bytes ONCE, and does
// not change the allocation COUNT at all.

/// How much junk one parameter carries. Comfortably inside `MAX_BODY_BYTES` (64 KiB) so the
/// request is ACCEPTED and reaches the parse, which is the point: a body refused for size never
/// gets to buy anything.
#[cfg(feature = "http")]
const CALLER_SIZED: usize = 60 * 1024;

/// Post `body` to the token endpoint and measure the whole refusal, expecting `status`.
#[cfg(feature = "http")]
fn measure_token_post<S, C>(
    rt: &tokio::runtime::Runtime,
    service: &oauth_as::AuthorizationService<S, C>,
    mut body: String,
    status: u16,
) -> Delta
where
    S: oauth_as::Storage,
    C: oauth_as::Clock,
{
    // SHRUNK first, and this is not tidiness: `collect_body` hands the collected `Vec` to
    // `Bytes::from`, which calls `into_boxed_slice`, which REALLOCATES when capacity exceeds
    // length. A body built by `format!` carries geometric slack and one built by `to_string`
    // does not, so without this the fixture's own construction decided whether the endpoint
    // reallocated, and the allocation COUNT below would be measuring the test rather than the
    // server. Measured: it is exactly this that made two identical 33-byte requests report 7 and
    // 8 allocations.
    body.shrink_to_fit();
    // Built OUTSIDE the window: the request is the caller's cost, not the endpoint's. That is what
    // lets these gates charge a 60 KiB parameter to the server at all.
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://as.example/token")
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .expect("a well formed request");
    let (response, d) = measure(|| rt.block_on(service.handle(request)));
    assert_eq!(
        response.status(),
        status,
        "unexpected status for the fixture"
    );
    d
}

/// Assert that a refusal grew by no more than the ONE body buffer that reading the request
/// requires, and that its allocation COUNT did not move at all.
#[cfg(feature = "http")]
fn assert_only_the_body_grew(name: &str, short: Delta, long: Delta, grew_by: usize) {
    assert_eq!(
        long.allocs, short.allocs,
        "{name}: a longer parameter must not buy the endpoint an EXTRA allocation. \
         short {short:?}, long {long:?}"
    );
    let extra = long.bytes.saturating_sub(short.bytes);
    // 512 bytes of slack covers the body buffer's own rounding and the handful of small strings
    // whose CONTENTS, not sizes, differ between the two requests. It is two orders of magnitude
    // below the 60 KiB a second copy costs, so it cannot hide one.
    assert!(
        extra <= grew_by + 512,
        "{name}: growing the parameter by {grew_by} bytes grew the refusal by {extra} bytes, \
         which is more than the single body buffer that reading the request requires. \
         short {short:?}, long {long:?}"
    );
    println!(
        "{name}: +{extra} bytes for a +{grew_by} byte parameter, {} allocs either way",
        long.allocs
    );
}

/// RFC 6749 s5.2 `unsupported_grant_type`, sized by the caller.
///
/// `token_handler` resolves `grant_type` BEFORE client authentication, deliberately (its own
/// comment says so), and then deliberately does NOT echo the value: the `Err` arm is
/// `map_err(|_| ...)`. So the `String` that `FromStr` allocated for the rejection was allocated,
/// copied into, and dropped unread, at whatever rate an unauthenticated caller can open sockets.
#[cfg(feature = "http")]
fn unknown_grant_type_refusal_is_not_sized_by_the_caller() {
    use oauth_as::{AuthorizationServer, MemoryStorage, ServerConfig, ServiceBuilder};

    let rt = current_thread_runtime();
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let server = std::sync::Arc::new(AuthorizationServer::new(cfg, MemoryStorage::new()));
    let service = ServiceBuilder::new(server)
        .build()
        .expect("the fixture service must build");

    let short = "grant_type=password&client_id=svc".to_string();
    let long = format!("grant_type={}&client_id=svc", "A".repeat(CALLER_SIZED));
    let grew_by = long.len() - short.len();

    // WARM the runtime and the router outside every window, for the reason `jwt_signing_bound`
    // does: tokio's first `block_on` allocates a thread-local parker of its own, and the first
    // couple of trips through this endpoint settle one further one-time allocation of their own.
    // Measured: from the third identical request onward the count is stable, and it is stable at
    // the SAME value for every body size, which is the property the assertion below relies on.
    for _ in 0..3 {
        let _ = measure_token_post(&rt, &service, short.clone(), 400);
    }

    let short_cost = measure_token_post(&rt, &service, short, 400);
    let long_cost = measure_token_post(&rt, &service, long, 400);
    assert_only_the_body_grew("unsupported_grant_type", short_cost, long_cost, grew_by);
}

#[cfg(not(feature = "http"))]
fn unknown_grant_type_refusal_is_not_sized_by_the_caller() {}

/// RFC 8693 s3, the same defect one seam along, and the one whose refusal STRING was already
/// fixed: the description stopped being `format!`ed, but the `String` allocated UNDER it by
/// `FromStr` was missed. `token_exchange_response` resolves `subject_token_type` before the
/// exchange is attempted, so before the presented client credential has been checked.
///
/// Note what the measurement corrects about the original finding: the handler resolves three
/// `*_token_type` parameters, but it RETURNS on the first failure, so one request buys ONE
/// discarded copy and not three. One is the whole of the defect; three would have been a different
/// number, and asserting it without measuring would be the sort of claim this file replaces.
#[cfg(all(feature = "http", feature = "token-exchange"))]
fn unknown_token_type_refusal_is_not_sized_by_the_caller() {
    use oauth_as::{
        AuthorizationServer, Client, ClientAuth, ClientId, GrantType, MemoryStorage, ScopeSet,
        ServerConfig, ServiceBuilder,
    };

    let rt = current_thread_runtime();
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let server = std::sync::Arc::new(AuthorizationServer::new(cfg, MemoryStorage::new()));
    rt.block_on(server.register_client(Client {
        client_id: ClientId::new("svc"),
        auth: ClientAuth::ConfidentialSecretHash {
            hash: oauth_as::SecretHash::sha256("svc-secret"),
        },
        grant_types: vec![GrantType::TokenExchange],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }))
    .expect("the fixture client must register");
    let service = ServiceBuilder::new(server)
        .build()
        .expect("the fixture service must build");

    let prefix = "grant_type=urn:ietf:params:oauth:grant-type:token-exchange\
                  &client_id=svc&client_secret=svc-secret\
                  &subject_token=whatever&subject_token_type=";
    let short = format!("{prefix}urn:example:not-registered");
    let long = format!("{prefix}{}", "A".repeat(CALLER_SIZED));
    let grew_by = long.len() - short.len();

    for _ in 0..3 {
        let _ = measure_token_post(&rt, &service, short.clone(), 400);
    }

    let short_cost = measure_token_post(&rt, &service, short, 400);
    let long_cost = measure_token_post(&rt, &service, long, 400);
    assert_only_the_body_grew("subject_token_type", short_cost, long_cost, grew_by);
}

#[cfg(not(all(feature = "http", feature = "token-exchange")))]
fn unknown_token_type_refusal_is_not_sized_by_the_caller() {}

// ------------------------------------------------------------------------- RFC 9068 signing

/// RFC 7515 section 3.1: one compact JWS, measured on its own rather than through an issuance, so
/// that the number is about the serialization and nothing else.
///
/// The signing input and the token are the SAME buffer: `header.payload` is built once, signed in
/// place, and the signature appended to it. Building it with `format!` and then formatting the
/// result again into a second `format!` allocated and fully copied the whole token twice.
#[cfg(feature = "jwt-p256")]
fn jwt_signing_bound() {
    use oauth_as::jwt::{AccessTokenClaims, Audience, EcdsaP256Key, JwtConfig};

    let signer = JwtConfig::new(EcdsaP256Key::generate("sign"), "https://rs.example");
    // `AccessTokenClaims::new` fills empty `authorization_details` and `cnf: None`, which is what
    // this fixture set explicitly before the type became non_exhaustive; `scope` is the one member
    // it wants a value for, and the claims are built OUTSIDE the measured window either way.
    let mut claims = AccessTokenClaims::new(
        "https://as.example",
        4_000_000_000,
        Audience::One("https://rs.example".to_string()),
        "user-1",
        "app",
        1_700_000_000,
        "0123456789abcdef",
    );
    claims.scope = Some("read".to_string());
    // `sign_access_token` is async since the `Es256Signer` seam landed (the signing key may live
    // in a KMS), so the measurement runs it on a runtime built OUTSIDE the window.
    let rt = current_thread_runtime();
    // WARM UP the runtime OUTSIDE the window. Measured: the first `block_on` on a fresh
    // current-thread runtime costs one 64-byte allocation of its own (a thread-local parker), and
    // attributing tokio's one-time setup to this crate's signing path would make the number below
    // a statement about the wrong thing.
    rt.block_on(async {});
    let (token, d) = measure(|| rt.block_on(signer.sign_access_token(&claims)));
    let token = token.expect("the fixture must sign");
    assert_eq!(token.matches('.').count(), 2, "a three part compact JWS");
    // Observed 4 allocations / 826 bytes, against 9 / 1960 when the compact form was assembled
    // with two `format!` calls. Exact rather than budgeted, because the claim is that the token is
    // built ONCE. The four are: the claims JSON, the token buffer, one inside p256's signing, and
    // one `Box::pin` of the signer's future.
    //
    // THAT FOURTH ONE IS NEW IN 0.9.0 and it is bought, not conceded. `JwtConfig` holds
    // `Arc<dyn Es256Signer>` so the signing key can live in a KMS or an HSM, and an object-safe
    // async method has to box its future; there is no shape of this seam that does not. The
    // alternative, a generic `JwtConfig`, is a THIRD monomorphization axis on
    // `AuthorizationServer`, and the second one is measured at 53,548 bytes per additional
    // `(Storage, Clock)` pair. One 80-byte allocation on a path that already allocates three
    // times, against 27% of the crate's default binary surface, is the trade being made here, and
    // it is paid only by a host that configured RFC 9068 tokens at all.
    check("access token signing", d, (4, 1024));
}

#[cfg(not(feature = "jwt-p256"))]
fn jwt_signing_bound() {}

// ------------------------------------------------------- RFC 6749 s4.1.2.1 redirect refusals

/// A REDIRECTABLE authorization refusal, measured against the successful validation it replaces.
///
/// [`oauth_as::AuthorizationErrorRedirect`] holds its `redirect_uri`, `state` and `iss` as owned
/// `String`s, so this refusal allocates. That was raised as a violation of the refusal rule, and
/// the measurement is what settles it: the refusal must not cost MORE than the valid request an
/// attacker could send instead, because reaching this refusal already requires a registered
/// `client_id` and an exactly matching registered `redirect_uri` (OAuth 2.1 s4.1.3), which is the
/// same work a valid request does before it succeeds.
///
/// Both figures are gated, and the relation between them is the point: if the refusal ever
/// becomes the cheaper request to make in volume, this gate says so.
fn redirectable_authorization_refusal_bound() {
    use oauth_as::{
        AuthorizationRequest, AuthorizationServer, Client, ClientAuth, ClientId, GrantType,
        MemoryStorage, ScopeSet, ServerConfig,
    };

    let rt = current_thread_runtime();
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let server = AuthorizationServer::new(cfg, MemoryStorage::new());
    rt.block_on(server.register_client(Client {
        client_id: ClientId::new("app"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::AuthorizationCode],
        redirect_uris: vec!["https://app.example/cb".to_string()],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }))
    .expect("the fixture client must register");

    let challenge =
        oauth_as::pkce::code_challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    let valid: [(&str, &str); 6] = [
        ("response_type", "code"),
        ("client_id", "app"),
        ("redirect_uri", "https://app.example/cb"),
        ("scope", "read"),
        ("state", "xyz"),
        ("code_challenge_method", "S256"),
    ];
    let mut with_challenge = valid.to_vec();
    with_challenge.push(("code_challenge", challenge.as_str()));
    let good = AuthorizationRequest::from_pairs(with_challenge.iter().copied());
    let (ok, valid_cost) = measure(|| rt.block_on(server.validate_authorization_request(&good)));
    assert!(ok.is_ok(), "the fixture request must validate");

    // The SAME request with the PKCE challenge removed: RFC 7636 with OAuth 2.1 makes that a
    // refusal, and it is redirectable because the redirect URI matched a registered one.
    let bad = AuthorizationRequest::from_pairs(valid.iter().copied());
    let (refused, refusal_cost) =
        measure(|| rt.block_on(server.validate_authorization_request(&bad)));
    assert!(
        matches!(refused, Err(oauth_as::AuthorizationError::Redirect(_))),
        "a missing code_challenge must be reported to the client, not to the user"
    );

    assert!(
        refusal_cost.allocs <= valid_cost.allocs,
        "a redirectable refusal must not cost more than the valid request it replaces: \
         refusal {refusal_cost:?} against valid {valid_cost:?}"
    );
    // Observed 6 allocations / 71 bytes against the valid request's 8: the owned redirect URI,
    // the echoed state, the RFC 9207 issuer identifier, and the request's own borrowed parameters.
    // The refusal is CHEAPER than the request it replaces, which is what the rule actually asks.
    check("redirectable authorization refusal", refusal_cost, (7, 512));
    println!(
        "redirectable refusal: {} allocs against a valid request's {}",
        refusal_cost.allocs, valid_cost.allocs
    );
}

/// Check one measurement against its bound and report the observed figure either way, in the same
/// idiom as `tests/allocation_paths.rs`.
fn check(name: &str, d: Delta, bound: (usize, usize)) {
    let (allocs, bytes) = bound;
    assert!(
        d.allocs <= allocs,
        "{name} allocation count regressed past {allocs}: {d:?}"
    );
    assert!(
        d.bytes <= bytes,
        "{name} allocation bytes regressed past {bytes}: {d:?}"
    );
    println!("{name}: {} allocs, {} bytes", d.allocs, d.bytes);
}
