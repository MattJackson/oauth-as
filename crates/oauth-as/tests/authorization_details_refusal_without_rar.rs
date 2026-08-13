// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! `authorization_details` must be REFUSED by a build that supports no authorization detail type,
//! at every door the parameter can arrive through.
//!
//! RFC 9396 section 5 requires an authorization server to refuse an `authorization_details` it
//! will not honour, and `src/error.rs` states why the code is not feature gated: "the build that
//! has the most to refuse is the build WITHOUT `rar`, which supports no authorization detail type
//! whatsoever and therefore meets section 5's condition on every request that carries the
//! parameter". The build in question is the SHIPPED DEFAULT: the workspace's `default` feature
//! list is empty.
//!
//! `tests/jar_authorization_details_refusal.rs` already pins the RFC 9101 signed request object.
//! That was one door of four. The other three are here, and until this file existed all three
//! accepted the parameter and dropped it: the client received a code, redeemed it, and held a
//! token that says nothing about the permission it asked for and had no way to notice.
//!
//! WHY REFUSING IS THE ONLY HONEST ANSWER, restated for the plain (unsigned) request: RFC 6749
//! section 3.1 does say an unrecognized parameter is ignored, but `authorization_details` is not
//! unrecognized here. This crate knows exactly what it is, publishes
//! `authorization_details_types_supported` in its RFC 8414 metadata, and knows that it supports
//! none of them. Ignoring a parameter you understand and cannot honour is the case section 5 was
//! written about.

#![cfg(all(feature = "http", not(feature = "rar")))]

use std::sync::Arc;

use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::grant::GrantType;
use oauth_as::http::{ApprovalDecision, Body, ServiceBuilder};
use oauth_as::scope::ScopeSet;
use oauth_as::server::{AuthorizationServer, ServerConfig, SystemClock};
use oauth_as::store::MemoryStorage;

const REDIRECT_URI: &str = "https://app.example/cb";
/// RFC 7636 appendix B's challenge, so PKCE is satisfied and the only thing wrong with the
/// requests below is the parameter under test.
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// A minimal RFC 9396 section 2 value: one object with a `type`. Percent-encoded where it has to
/// cross a query string.
const DETAILS: &str = r#"[{"type":"payment_initiation"}]"#;
const DETAILS_ESCAPED: &str = "%5B%7B%22type%22%3A%22payment_initiation%22%7D%5D";

type Service = oauth_as::http::AuthorizationService<MemoryStorage, SystemClock>;

fn client() -> Client {
    Client {
        client_id: ClientId::new("app"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::AuthorizationCode],
        redirect_uris: vec![REDIRECT_URI.to_string()],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

fn config() -> ServerConfig {
    // `mut` only under `par`, which is the one branch that assigns: without the feature there is
    // no PAR door to open and the binding must not be declared mutable.
    #[cfg_attr(not(feature = "par"), allow(unused_mut))]
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    #[cfg(feature = "par")]
    {
        cfg.par = Some(Box::new(oauth_as::par::ParConfig::new()));
    }
    cfg
}

async fn service() -> Service {
    let srv = AuthorizationServer::new(config(), MemoryStorage::new());
    srv.register_client(client()).await.expect("registered");
    ServiceBuilder::new(Arc::new(srv))
        .with_subject_resolver(|_headers| Some("user-1".to_string()))
        .with_approval_resolver(|_request| ApprovalDecision::Approve)
        .build()
        .expect("service")
}

fn get(uri: &str) -> http::Request<Body> {
    http::Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::from(String::new()))
        .expect("a well-formed request")
}

fn post(uri: &str, body: &str) -> http::Request<Body> {
    http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .expect("a well-formed request")
}

fn body_text(response: http::Response<Body>) -> String {
    String::from_utf8_lossy(&response.into_body().into_bytes()).into_owned()
}

/// DOOR ONE: `GET /authorize`, the plain query-string request.
///
/// The answer is a REDIRECT carrying `error=invalid_authorization_details`, not a status code:
/// RFC 6749 section 4.1.2.1 says an error is delivered to the redirection URI once that URI is
/// known to be valid, and it is, so the client learns about this the way it learns about every
/// other refusal of its request.
#[tokio::test]
async fn the_authorization_endpoint_refuses_authorization_details() {
    let service = service().await;
    let response = service
        .handle(get(&format!(
            "/authorize?response_type=code&client_id=app&redirect_uri={REDIRECT_URI}\
             &code_challenge={CHALLENGE}&code_challenge_method=S256\
             &authorization_details={DETAILS_ESCAPED}"
        )))
        .await;

    let location = response
        .headers()
        .get("location")
        .map(|v| v.to_str().expect("ASCII").to_string())
        .unwrap_or_default();
    assert!(
        location.contains("error=invalid_authorization_details"),
        "RFC 9396 s5: a detail this build cannot honour must be refused, not dropped. Got status \
         {} and location {location:?}",
        response.status()
    );
    assert!(
        !location.contains("code="),
        "no code may be minted for a request whose stated permission this build did not grant: \
         {location}"
    );
}

/// DOOR TWO: `POST /token`. RFC 9396 section 6 makes `authorization_details` a parameter of the
/// token request in its own right, independent of `grant_type`, so a client may send it here
/// having sent nothing at the authorization endpoint. `client_credentials` reaches issuance
/// without passing the authorization endpoint at all.
///
/// The code below is deliberately not a real one: the refusal under test must come BEFORE any
/// grant lookup, so what this asserts is which error arrives, and `invalid_grant` would mean the
/// parameter was never looked at.
#[tokio::test]
async fn the_token_endpoint_refuses_authorization_details() {
    let service = service().await;
    let response = service
        .handle(post(
            "/token",
            &format!(
                "grant_type=authorization_code&code=not-a-real-code&client_id=app\
                 &redirect_uri={REDIRECT_URI}&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\
                 &authorization_details={DETAILS_ESCAPED}"
            ),
        ))
        .await;
    let body = body_text(response);
    assert!(
        body.contains("invalid_authorization_details"),
        "RFC 9396 s5 and s6: the token endpoint carries this parameter too, and this build \
         honours none of it: {body}"
    );
}

/// DOOR THREE: the RFC 9126 push. Section 2.1 says the pushed request is processed "as if it were
/// submitted directly to the authorization endpoint", so a parameter the authorization endpoint
/// refuses must be refused here as well, and refusing at push time is strictly better for the
/// client: it still holds the request and is told which parameter is wrong, rather than receiving
/// a handle that can never be spent.
#[cfg(feature = "par")]
#[tokio::test]
async fn the_pushed_authorization_request_endpoint_refuses_authorization_details() {
    let service = service().await;
    let response = service
        .handle(post(
            "/par",
            &format!(
                "response_type=code&client_id=app&redirect_uri={REDIRECT_URI}\
                 &code_challenge={CHALLENGE}&code_challenge_method=S256\
                 &authorization_details={DETAILS_ESCAPED}"
            ),
        ))
        .await;
    let body = body_text(response);
    assert!(
        body.contains("invalid_authorization_details"),
        "RFC 9126 s2.1: the push is the authorization request, so it inherits the authorization \
         endpoint's answer: {body}"
    );
}

/// The boundary, so none of the above is a ban on the ordinary request: the SAME requests without
/// the parameter must be unaffected. A refusal that also refused requests carrying nothing would
/// be a worse defect than the drop it replaced.
#[tokio::test]
async fn a_request_without_the_parameter_is_untouched() {
    let service = service().await;
    let response = service
        .handle(get(&format!(
            "/authorize?response_type=code&client_id=app&redirect_uri={REDIRECT_URI}\
             &code_challenge={CHALLENGE}&code_challenge_method=S256"
        )))
        .await;
    let location = response
        .headers()
        .get("location")
        .map(|v| v.to_str().expect("ASCII").to_string())
        .unwrap_or_default();
    assert!(
        location.contains("code="),
        "an approved request that asked for no authorization detail must still get its code: {location}"
    );
    assert!(
        !location.contains("error="),
        "and must not be refused by the guard the parameter's absence does not trip: {location}"
    );
    // `DETAILS` is spelled here so the unescaped form is not dead weight in this file and the
    // escaped constant above can be checked against it by eye.
    assert!(DETAILS.contains("payment_initiation"));
}
