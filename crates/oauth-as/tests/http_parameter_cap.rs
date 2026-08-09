// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The cap on how many form or query parameters one request may carry.
//!
//! `MAX_BODY_BYTES` bounds how many BYTES an anonymous caller can make this service hold. It does
//! not bound the WORK, because decoding is per parameter and not per byte: measured with
//! `benches/http_surface.rs` before the cap existed, a `POST /token` cost 2.65 us with no extra
//! parameters and 83.33 us with 1024 ignored ones, and 64 KiB of `&a=b` pairs is roughly 2300 of
//! them. That is three orders of magnitude of amplification bought with one unauthenticated
//! packet, against a service whose cheapest answer (a 404) is 163 ns.
//!
//! So the count is capped as well as the size, and this file is the wire proof of it: over the
//! cap is refused, at the cap still works, and the refusal happens for the query string of a GET
//! as well as for the body of a POST, because the authorization endpoint reads its parameters
//! from a URL that `MAX_BODY_BYTES` never applied to at all.

#![cfg(feature = "http")]

use std::sync::Arc;

use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::grant::GrantType;
use oauth_as::http::{Body, ConsentDecision, MAX_FORM_PARAMETERS};
use oauth_as::scope::ScopeSet;
use oauth_as::server::{AuthorizationServer, ServerConfig, SystemClock};
use oauth_as::store::MemoryStorage;

const SECRET: &str = "a-high-entropy-registered-client-secret";

/// A service with one confidential client, auto-approving at the consent seam so the
/// authorization endpoint reaches a redirect rather than a "not wired" refusal.
async fn service() -> oauth_as::http::AuthorizationService<MemoryStorage, SystemClock> {
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
    srv.register_client(Client {
        client_id: ClientId::new("confidential-app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.to_string(),
        },
        grant_types: vec![GrantType::ClientCredentials, GrantType::AuthorizationCode],
        redirect_uris: vec!["https://app.example/cb".to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    })
    .await
    .unwrap();
    oauth_as::http::ServiceBuilder::new(Arc::new(srv))
        .with_subject_resolver(|_headers| Some("user-1".to_string()))
        .with_consent_resolver(|_request| ConsentDecision::Approve)
        .build()
        .expect("service")
}

/// `extra` parameters the server has no use for, appended to `base`.
fn with_extras(base: &str, extra: usize) -> String {
    let mut body = base.to_string();
    for i in 0..extra {
        body.push_str(&format!("&unknown_parameter_{i}=some%20encoded%20value"));
    }
    body
}

fn post(uri: &str, body: String) -> http::Request<Body> {
    http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .expect("a well-formed request")
}

/// The token endpoint is the one an unauthenticated caller can drive hardest: it decodes the form
/// BEFORE it knows whether the client exists, so the decode is work an attacker buys.
#[tokio::test]
async fn a_token_request_over_the_parameter_cap_is_refused() {
    let service = service().await;
    let base =
        format!("grant_type=client_credentials&client_id=confidential-app&client_secret={SECRET}");
    // Three real parameters plus enough junk to cross the cap.
    let body = with_extras(&base, MAX_FORM_PARAMETERS);
    let response = service.handle(post("/token", body)).await;
    assert_eq!(
        response.status(),
        http::StatusCode::PAYLOAD_TOO_LARGE,
        "a request carrying more than MAX_FORM_PARAMETERS parameters must be refused before it \
         is decoded"
    );
}

/// The other half of the cap, and the half that matters for not breaking anybody: a request with
/// as many parameters as the cap allows is answered normally.
#[tokio::test]
async fn a_token_request_at_the_parameter_cap_is_answered() {
    let service = service().await;
    let base =
        format!("grant_type=client_credentials&client_id=confidential-app&client_secret={SECRET}");
    // Exactly at the cap: three real parameters and the rest junk the server ignores.
    let body = with_extras(&base, MAX_FORM_PARAMETERS - 3);
    let response = service.handle(post("/token", body)).await;
    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "a request at the cap must still be served: the cap is a ceiling on abuse, not a change \
         to what a conforming client may send"
    );
}

/// RFC 6749 s4.1.1 parameters arrive in a URL, so `MAX_BODY_BYTES` never bounded them. The cap
/// has to be on the parse, not on the body, or this endpoint keeps the amplification the token
/// endpoint just lost.
#[tokio::test]
async fn an_authorization_request_over_the_parameter_cap_is_refused() {
    let service = service().await;
    let base = "response_type=code&client_id=confidential-app\
                &redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=read\
                &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
                &code_challenge_method=S256";
    let query = with_extras(base, MAX_FORM_PARAMETERS);
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("/authorize?{query}"))
        .body(Body::empty())
        .expect("a well-formed request");
    let response = service.handle(request).await;
    assert_eq!(
        response.status(),
        http::StatusCode::PAYLOAD_TOO_LARGE,
        "the authorization endpoint's parameters come from the URL, which the body cap never saw"
    );
    assert!(
        response.headers().get(http::header::LOCATION).is_none(),
        "a refusal this early has not validated the redirect URI, so it must not redirect"
    );
}
