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

    // Segment one is not base64url. `!` is outside the alphabet in every base64 variant.
    for object in ["!!!!.eyJhIjoxfQ.AAAA", "eyJhIjoxfQ.eyJhIjoxfQ.!!!!"] {
        match rt.block_on(server.validate_signed_authorization_request("app", object)) {
            Err(AuthorizationError::Direct(error)) => {
                assert_eq!(error.error, ErrorCode::InvalidRequestObject);
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
    // Observed 10 allocations / 4549 bytes, against 11 / 4633 before the description stopped
    // being formatted. The allocation bound is EXACT (the one removed is the whole claim); the
    // byte bound carries a little room because most of those bytes are the response buffer the
    // `http` crate hands back, not this crate's.
    check("token exchange token-type refusal", d, (10, 4800));
}

#[cfg(not(all(feature = "http", feature = "token-exchange")))]
fn token_exchange_token_type_refusal_bound() {}

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
    let claims = AccessTokenClaims {
        iss: "https://as.example".to_string(),
        exp: 4_000_000_000,
        aud: Audience::One("https://rs.example".to_string()),
        sub: "user-1".to_string(),
        client_id: "app".to_string(),
        iat: 1_700_000_000,
        jti: "0123456789abcdef".to_string(),
        scope: Some("read".to_string()),
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        #[cfg(feature = "mtls")]
        cnf: None,
    };
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
