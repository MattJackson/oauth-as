// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! WHAT AN RFC 8693 EXCHANGE CAN AUTHENTICATE WITH OVER HTTP, AND WHAT IT MUST REFUSE.
//!
//! Two defects of the same family, both invisible to a suite that drives the library API:
//!
//! 1. The token-exchange arm of `token_handler` forwarded only `client_secret`. RFC 8693 s2.1
//!    authenticates the client "as described in Section 2.3 of [RFC6749]", which is a reference to
//!    every method the server offers, and this server offers `private_key_jwt` and
//!    `client_secret_jwt` and advertises them in its RFC 8414 document. An assertion arrives in
//!    `client-assertion`, not in `client_secret`, so an assertion-authenticated confidential
//!    client was answered `invalid_client` on a grant the metadata document promises it. The first
//!    repair of this arm restored the SECRET only, so half the defect survived the fix for the
//!    other half.
//!
//! 2. The same arm RETURNS before the RFC 9449 s4.3 `DPoP` header is read. A client sending a
//!    proof therefore got the header ignored entirely: no duplicate-header check, no verification,
//!    and an issued token with no `jkt`. `crate::token_exchange`'s own module documentation argues
//!    at length that a silent sender-constraint downgrade is "the one answer that is definitely
//!    wrong", about the SUBJECT token, and the same module was then issuing a silently unbound
//!    token to a DPoP client. The two halves of one module disagreed.
//!
//! Both are asserted OVER THE WIRE, never through `exchange_token`, because the library API cannot
//! see either: neither the assertion parameters nor the `DPoP` header exist at that layer.

#![cfg(all(feature = "http", feature = "token-exchange"))]

use std::sync::Arc;

use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::grant::GrantType;
use oauth_as::http::{AuthorizationService, Body, ServiceBuilder};
use oauth_as::scope::ScopeSet;
use oauth_as::server::{AuthorizationServer, ServerConfig, SystemClock};
use oauth_as::store::MemoryStorage;
use serde_json::Value;

const ISSUER: &str = "https://as.example";
const VERIFICATION_URI: &str = "https://as.example/device";
/// The audience an RFC 7523 assertion has to name, spelled out rather than derived so that a
/// change to the default endpoint layout fails here instead of silently changing what is proven.
const TOKEN_ENDPOINT: &str = "https://as.example/token";
const SECRET: &str = "a-high-entropy-registered-client-secret";

type Service = AuthorizationService<MemoryStorage, SystemClock>;

struct Wire {
    status: http::StatusCode,
    body: String,
}

impl Wire {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }

    fn error(&self) -> Option<String> {
        self.json()
            .get("error")
            .and_then(|v| v.as_str())
            .map(str::to_string)
    }

    /// RFC 6749 s5.2's `error_description`, which on this endpoint is the only thing that says
    /// WHICH of several checks answering with the same code and status actually fired.
    fn description(&self) -> Option<String> {
        self.json()
            .get("error_description")
            .and_then(|v| v.as_str())
            .map(str::to_string)
    }
}

async fn post_form(service: &Service, path: &str, body: String) -> Wire {
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("{ISSUER}{path}"))
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(Body::from(body))
        .expect("a well formed request");
    let response = service.handle(request).await;
    let status = response.status();
    let body = String::from_utf8_lossy(&response.into_body().into_bytes()).into_owned();
    Wire { status, body }
}

fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

fn exchange_client(client_id: &str, auth: ClientAuth) -> Client {
    Client {
        client_id: ClientId::new(client_id),
        auth,
        // `ClientCredentials` is here only to MINT the subject token this server will then be
        // asked to exchange: RFC 8693 s2.1's subject token has to be a token this server issued,
        // and client credentials is the shortest honest way to get one.
        grant_types: vec![GrantType::ClientCredentials, GrantType::TokenExchange],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").expect("a valid scope set"),
        default_scopes: ScopeSet::parse("read").expect("a valid scope set"),
        name: None,
        registration: None,
    }
}

struct Fixture {
    service: Service,
    server: Arc<AuthorizationServer<MemoryStorage, SystemClock>>,
}

async fn fixture() -> Fixture {
    let cfg = ServerConfig::new(ISSUER, VERIFICATION_URI);
    let server = Arc::new(AuthorizationServer::new(cfg, MemoryStorage::new()));
    server
        .register_client(exchange_client(
            "secret-app",
            ClientAuth::ConfidentialSecret {
                secret: SECRET.to_string(),
            },
        ))
        .await
        .expect("register the shared-secret client");
    #[cfg(feature = "client-assertion")]
    {
        use oauth_as::client_assertion::{AssertionKeys, ClientSecretKey};
        server
            .register_client(exchange_client(
                "csjwt-app",
                ClientAuth::ConfidentialAssertion {
                    keys: AssertionKeys::ClientSecret {
                        secret: ClientSecretKey::new(SECRET)
                            .expect("the fixture secret clears the entropy floor"),
                    },
                },
            ))
            .await
            .expect("register the client_secret_jwt client");
    }
    let service = ServiceBuilder::new(Arc::clone(&server))
        .build()
        .expect("the fixture service must build");
    Fixture { service, server }
}

/// One access token this server issued, minted over the wire so nothing in this file reaches past
/// the HTTP surface.
async fn subject_token(service: &Service) -> String {
    let minted = post_form(
        service,
        "/token",
        format!("grant_type=client_credentials&client_id=secret-app&client_secret={SECRET}"),
    )
    .await;
    assert_eq!(
        minted.status,
        http::StatusCode::OK,
        "the fixture subject token must be issued: {}",
        minted.body
    );
    minted
        .json()
        .get("access_token")
        .and_then(|v| v.as_str())
        .expect("RFC 6749 s5.1 requires access_token")
        .to_string()
}

/// RFC 8693 s2.1 with RFC 7521 s4.2: an assertion-authenticated confidential client can exchange.
///
/// This is the assertion that was failing. It answered `invalid_client`, because the arm forwarded
/// `client_secret` (which is `None` for this client) and nothing else, and `exchange_token`
/// refuses a client it could not authenticate as confidential.
#[cfg(feature = "client-assertion")]
#[tokio::test]
async fn an_assertion_authenticated_client_may_exchange_a_token_over_http() {
    let fx = fixture().await;
    let subject = subject_token(&fx.service).await;

    let exchanged = post_form(
        &fx.service,
        "/token",
        format!(
            "grant_type={}&client_id=csjwt-app\
             &subject_token={subject}&subject_token_type={}\
             &client_assertion_type={}&client_assertion={}",
            urlencode(oauth_as::grant::TOKEN_EXCHANGE_GRANT_URN),
            urlencode("urn:ietf:params:oauth:token-type:access_token"),
            urlencode(oauth_as::client_assertion::CLIENT_ASSERTION_TYPE),
            client_secret_jwt("csjwt-exchange-1"),
        ),
    )
    .await;

    assert_eq!(
        exchanged.status,
        http::StatusCode::OK,
        "RFC 8693 s2.1 authenticates the client per RFC 6749 s2.3, which includes RFC 7523 \
         assertions: {}",
        exchanged.body
    );
    // RFC 8693 s2.2.1 makes `issued_token_type` REQUIRED, so its presence is what distinguishes a
    // real exchange response from an ordinary token response that happened to have status 200.
    assert_eq!(
        exchanged
            .json()
            .get("issued_token_type")
            .and_then(|v| v.as_str()),
        Some("urn:ietf:params:oauth:token-type:access_token"),
        "RFC 8693 s2.2.1: {}",
        exchanged.body
    );
    let issued = exchanged
        .json()
        .get("access_token")
        .and_then(|v| v.as_str())
        .expect("an exchange returns a token")
        .to_string();
    assert!(
        fx.server
            .introspect(&issued)
            .await
            .expect("the store answers")
            .is_some(),
        "the exchanged token must actually exist in the store"
    );
}

/// RFC 9449: a `DPoP` header on a token-exchange request is REFUSED, not ignored.
///
/// The proof used here is deliberately NOT a valid one, and that is the point: before the fix this
/// request answered 200 with a plain bearer token, so the header's contents never mattered. Any
/// answer other than a refusal means the header was dropped on the floor. A refusal that named the
/// proof invalid would also be acceptable to this assertion; what is not acceptable is success.
#[cfg(feature = "dpop")]
#[tokio::test]
async fn a_dpop_proof_on_a_token_exchange_is_refused_rather_than_silently_dropped() {
    let fx = fixture().await;
    let subject = subject_token(&fx.service).await;

    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("{ISSUER}/token"))
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header("DPoP", "eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiIxIn0.AAAA")
        .body(Body::from(format!(
            "grant_type={}&client_id=secret-app&client_secret={SECRET}\
             &subject_token={subject}&subject_token_type={}",
            urlencode(oauth_as::grant::TOKEN_EXCHANGE_GRANT_URN),
            urlencode("urn:ietf:params:oauth:token-type:access_token"),
        )))
        .expect("a well formed request");
    let response = fx.service.handle(request).await;
    let status = response.status();
    let body = String::from_utf8_lossy(&response.into_body().into_bytes()).into_owned();
    let wire = Wire { status, body };

    assert_ne!(
        wire.status,
        http::StatusCode::OK,
        "a client that presented a DPoP proof must not be handed an unbound bearer token and \
         told nothing: {}",
        wire.body
    );
    assert_eq!(
        wire.error().as_deref(),
        Some("invalid_dpop_proof"),
        "RFC 9449 s5: the refusal has to name the proof as the reason, or the operator who \
         enabled DPoP cannot tell what happened: {}",
        wire.body
    );
}

/// The duplicate-header rule of RFC 9449 s4.3 (1) reaches this grant too, which it could not while
/// the check sat after the dispatch.
///
/// THE STATUS CODE CANNOT SAY WHICH RULE ANSWERED, and that is the whole difficulty of testing an
/// ordering. Two things refuse this request: the duplicate-header check, and the blanket refusal
/// of any `DPoP` header on a token exchange. Both are `invalid_dpop_proof` and both are 400, and
/// the sibling above proves a SINGLE garbage proof on this same grant already answers 400 — so a
/// duplicate-header check that had slipped back behind the dispatch would leave this test green
/// while the property it is named for was gone. Only the description distinguishes them, so the
/// description is what is asserted.
#[cfg(feature = "dpop")]
#[tokio::test]
async fn two_dpop_headers_are_refused_on_a_token_exchange_as_on_every_other_grant() {
    let fx = fixture().await;
    let subject = subject_token(&fx.service).await;

    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("{ISSUER}/token"))
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header("DPoP", "eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiIxIn0.AAAA")
        .header("DPoP", "eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiIyIn0.AAAA")
        .body(Body::from(format!(
            "grant_type={}&client_id=secret-app&client_secret={SECRET}\
             &subject_token={subject}&subject_token_type={}",
            urlencode(oauth_as::grant::TOKEN_EXCHANGE_GRANT_URN),
            urlencode("urn:ietf:params:oauth:token-type:access_token"),
        )))
        .expect("a well formed request");
    let response = fx.service.handle(request).await;
    let status = response.status();
    let body = String::from_utf8_lossy(&response.into_body().into_bytes()).into_owned();

    assert_eq!(
        status,
        http::StatusCode::BAD_REQUEST,
        "RFC 9449 s4.3 (1): exactly one DPoP header, on every grant this endpoint serves: {body}"
    );
    let wire = Wire { status, body };
    assert_eq!(wire.error().as_deref(), Some("invalid_dpop_proof"));
    assert!(
        wire.description()
            .unwrap_or_default()
            .contains("more than one DPoP header"),
        "the DUPLICATE-header rule has to be what refused, not the token-exchange blanket refusal \
         that would answer this request identically: {}",
        wire.body
    );
}

/// The shared-secret path, kept alongside the two above so that a change that made the DPoP
/// refusal fire for everybody would not pass as a green suite.
#[tokio::test]
async fn a_shared_secret_client_still_exchanges_with_no_dpop_header() {
    let fx = fixture().await;
    let subject = subject_token(&fx.service).await;

    let exchanged = post_form(
        &fx.service,
        "/token",
        format!(
            "grant_type={}&client_id=secret-app&client_secret={SECRET}\
             &subject_token={subject}&subject_token_type={}",
            urlencode(oauth_as::grant::TOKEN_EXCHANGE_GRANT_URN),
            urlencode("urn:ietf:params:oauth:token-type:access_token"),
        ),
    )
    .await;
    assert_eq!(
        exchanged.status,
        http::StatusCode::OK,
        "RFC 8693 s2.1 over HTTP with client_secret_post: {}",
        exchanged.body
    );
}

/// An RFC 7523 s3 claim set naming this server's token endpoint as the audience, signed with the
/// registered client secret (`client_secret_jwt`, HS256). No ES256 backend is needed, so this
/// proof runs on every build that has `client-assertion` at all.
#[cfg(feature = "client-assertion")]
fn client_secret_jwt(jti: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs();
    let claims = serde_json::json!({
        "iss": "csjwt-app",
        "sub": "csjwt-app",
        "aud": TOKEN_ENDPOINT,
        "exp": now + 120,
        "iat": now,
        "jti": jti,
    });
    oauth_as::jwt::compact_jws(
        br#"{"alg":"HS256","typ":"JWT"}"#,
        &serde_json::to_vec(&claims).expect("serializable claims"),
        |input| oauth_as::jwt::hmac_sha256(SECRET.as_bytes(), input.as_bytes()).to_vec(),
    )
}
