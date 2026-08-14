// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! THE STEP-UP HAS TO REACH THE RESOURCE SERVER, AND THERE ARE TWO ROUTES, NOT ONE.
//!
//! RFC 9470 section 6 is titled "Authentication Information Conveyed via Access Token" and it has
//! exactly two subsections, because this crate's access tokens have exactly two shapes and they
//! reach a resource server differently:
//!
//! - section 6.2, RFC 7662 introspection, is the only channel an OPAQUE token has: it carries
//!   nothing itself;
//! - section 6.1, the RFC 9068 JWT, is read OFFLINE by a resource server that never introspects at
//!   all.
//!
//! Through 0.9.1 this crate did 6.2 and not 6.1. That is the half that matters least for the
//! deployment step-up is aimed at: the resource server that sent the
//! `insufficient_user_authentication` challenge (section 3) is the one that has to decide whether
//! the token it now holds actually answers it, and a resource server verifying signatures locally
//! had nothing in the token to decide with. It would have had to take the client's word for the
//! step-up, which is the whole thing the challenge exists to avoid.
//!
//! `tests/step_up.rs` owns the introspection route. This file owns the JWT one.

#![cfg(all(feature = "consent", feature = "jwt-p256"))]

mod support;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::jwt::{AccessTokenFormat, EcdsaP256Key, JwtConfig};
use oauth_as::server::UserApproval;
use oauth_as::{
    Authentication, AuthenticationRequirement, AuthorizationRequest, AuthorizationServer, ClientId,
    MemoryStorage, ServerConfig, TokenRequest,
};
use support::{
    confidential_client, ManualClock, CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET, RFC7636_VERIFIER,
};

const APP: &str = "confidential-app";
/// The instant [`ManualClock::at_epoch`] starts at, so a test can name an `auth_time` against it.
const NOW: u64 = 1_700_000_000;

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// A server that signs RFC 9068 access tokens, so the wire token is a JWT whose claims can be read
/// the way an offline resource server reads them.
async fn signing_server(clock: ManualClock) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.access_token_format = AccessTokenFormat::Jwt(Box::new(JwtConfig::new(
        EcdsaP256Key::generate("step-up-test-kid"),
        "https://rs.example",
    )));
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), clock);
    srv.register_client(confidential_client()).await.unwrap();
    srv
}

/// The claims of a signed access token, as an offline resource server would read them: decode the
/// payload segment, and never ask this server anything.
fn claims_of(access_token: &str) -> serde_json::Value {
    let parts: Vec<&str> = access_token.split('.').collect();
    assert_eq!(parts.len(), 3, "the wire token must be a JWS compact form");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).expect("payload base64url"))
        .expect("payload JSON")
}

/// One authorization-code flow, driven with whatever the host reports about the login, ending in
/// the signed access token the client would present to a resource server.
async fn issued_jwt(
    srv: &AuthorizationServer<MemoryStorage, ManualClock>,
    requirement: &AuthenticationRequirement,
    authentication: Option<&Authentication>,
) -> String {
    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let request = AuthorizationRequest::from_pairs([
        ("response_type", "code"),
        ("client_id", APP),
        ("redirect_uri", CONFIDENTIAL_REDIRECT),
        ("scope", "read"),
        ("state", "step-up-state"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]);
    let validated = srv
        .validate_authorization_request(&request)
        .await
        .expect("the request itself is well formed");
    let response = srv
        .issue_authorization_code_with_authentication(
            UserApproval::granted(&validated, "user-1"),
            requirement,
            authentication,
        )
        .await
        .expect("the reported authentication satisfies the requirement");
    srv.token(TokenRequest::AuthorizationCode {
        client_id: ClientId::new(APP),
        client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
        code: response.code,
        redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
        code_verifier: Some(RFC7636_VERIFIER.to_string()),
    })
    .await
    .expect("the code redeems")
    .access_token
}

/// The parameters a client puts on the authorization request after being challenged (section 4).
fn requirement(acr_values: Option<&str>, max_age: Option<&str>) -> AuthenticationRequirement {
    let mut pairs: Vec<(&str, &str)> = vec![("client_id", APP)];
    if let Some(a) = acr_values {
        pairs.push(("acr_values", a));
    }
    if let Some(m) = max_age {
        pairs.push(("max_age", m));
    }
    AuthenticationRequirement::from_pairs(pairs).expect("well-formed step-up parameters")
}

/// RFC 9470 s6.1 with RFC 9068 s2.2.1: a token minted from a satisfied step-up states the
/// authentication it rests on IN THE TOKEN, so the resource server that sent the challenge can
/// check the answer without calling this server at all.
#[tokio::test]
async fn a_stepped_up_jwt_carries_acr_and_auth_time() {
    let srv = signing_server(ManualClock::at_epoch()).await;
    let auth = Authentication::at(at(NOW - 30)).with_acr("urn:acr:mfa");
    let token = issued_jwt(
        &srv,
        &requirement(Some("urn:acr:mfa"), Some("300")),
        Some(&auth),
    )
    .await;

    let claims = claims_of(&token);
    assert_eq!(
        claims.get("acr").and_then(|v| v.as_str()),
        Some("urn:acr:mfa"),
        "an offline resource server has no other way to see which class was satisfied: {claims}"
    );
    assert_eq!(
        claims.get("auth_time").and_then(|v| v.as_u64()),
        Some(NOW - 30),
        "auth_time is WHEN THE USER LOGGED IN, not when the token was minted: {claims}"
    );
}

/// The `max_age` half on its own. A host that reports an authentication with no `acr` still owes
/// the resource server the instant, because `max_age` is the requirement it answers.
#[tokio::test]
async fn auth_time_is_present_even_when_the_host_reported_no_acr() {
    let srv = signing_server(ManualClock::at_epoch()).await;
    let auth = Authentication::at(at(NOW - 60));
    let token = issued_jwt(&srv, &requirement(None, Some("300")), Some(&auth)).await;

    let claims = claims_of(&token);
    assert_eq!(
        claims.get("auth_time").and_then(|v| v.as_u64()),
        Some(NOW - 60),
        "{claims}"
    );
    assert!(
        claims.get("acr").is_none(),
        "a class the host never reported must be ABSENT rather than null, or a careless resource \
         server reads it as answered: {claims}"
    );
}

/// A host that reports nothing puts nothing in the token. The two members must be absent rather
/// than null for the same reason `cnf` and `act` are: a member present and null invites a reader
/// to treat it as a freshness they have checked.
#[tokio::test]
async fn an_ordinary_grants_jwt_states_no_authentication() {
    let srv = signing_server(ManualClock::at_epoch()).await;
    let token = issued_jwt(&srv, &AuthenticationRequirement::none(), None).await;

    let claims = claims_of(&token);
    assert!(claims.get("acr").is_none(), "{claims}");
    assert!(claims.get("auth_time").is_none(), "{claims}");
}

/// THE REFRESH PATH, which is where a step-up is defeated if it is defeated at all. A rotation is
/// not a new authentication (RFC 9470 s6, and `RefreshTokenRecord::authentication`), so the
/// refreshed JWT must state the ORIGINAL `auth_time`. Restamping it would let any client answer
/// any `max_age` by refreshing, and the offline resource server is exactly the party that could
/// not tell.
#[tokio::test]
async fn a_refreshed_jwt_states_the_original_auth_time() {
    let clock = ManualClock::at_epoch();
    let srv = signing_server(clock.clone()).await;
    let auth = Authentication::at(at(NOW - 30)).with_acr("urn:acr:mfa");
    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let request = AuthorizationRequest::from_pairs([
        ("response_type", "code"),
        ("client_id", APP),
        ("redirect_uri", CONFIDENTIAL_REDIRECT),
        ("scope", "read"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]);
    let validated = srv
        .validate_authorization_request(&request)
        .await
        .expect("well formed");
    let response = srv
        .issue_authorization_code_with_authentication(
            UserApproval::granted(&validated, "user-1"),
            &requirement(Some("urn:acr:mfa"), Some("300")),
            Some(&auth),
        )
        .await
        .expect("issued");
    let first = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new(APP),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            code: response.code,
            redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await
        .expect("the code redeems");

    // An hour passes, and the client refreshes. `auth_time` is a statement about the LOGIN, so it
    // does not move; `iat` is a statement about the token, so it does.
    clock.advance(Duration::from_secs(3_600));
    let refreshed = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new(APP),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            refresh_token: first.refresh_token.expect("a refresh chain was issued"),
            scope: None,
        })
        .await
        .expect("the chain rotates");

    let claims = claims_of(&refreshed.access_token);
    assert_eq!(
        claims.get("auth_time").and_then(|v| v.as_u64()),
        Some(NOW - 30),
        "a rotation is not a new login: restamping this defeats every max_age by refreshing: \
         {claims}"
    );
    assert_eq!(
        claims.get("acr").and_then(|v| v.as_str()),
        Some("urn:acr:mfa"),
        "{claims}"
    );
    assert_eq!(
        claims.get("iat").and_then(|v| v.as_u64()),
        Some(NOW + 3_600),
        "the token's own issuance instant DOES move: {claims}"
    );
}
