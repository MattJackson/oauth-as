// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Four seams in the HTTP surface where a mutation sweep found nothing constraining what a
//! credential IS: how a bearer token is taken off a header, how the token endpoint refuses two
//! authentication methods at once, which form parameters are audiences, and whether an approval
//! the user did not ask to be remembered gets remembered anyway.
//!
//! Each test names the mutant it kills. What they have in common is that they are all about a
//! request the existing suite never sends: a header too short to hold the scheme, a header holding
//! a DIFFERENT scheme, a request carrying two credentials, and an approval that is only an
//! approval.

#![cfg(feature = "http")]

use std::sync::{Arc, Mutex};

use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::grant::GrantType;
use oauth_as::http::{Body, ConsentDecision};
use oauth_as::scope::ScopeSet;
use oauth_as::server::{AuthorizationServer, ServerConfig, SystemClock};
use oauth_as::store::MemoryStorage;

const SECRET: &str = "a-high-entropy-registered-client-secret";
const REDIRECT: &str = "https://app.example/cb";
/// RFC 7636 appendix B's verifier, so the challenge below is a real S256 challenge.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn client() -> Client {
    Client {
        client_id: ClientId::new("app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.to_string(),
        },
        grant_types: vec![
            GrantType::ClientCredentials,
            GrantType::AuthorizationCode,
            #[cfg(feature = "token-exchange")]
            GrantType::TokenExchange,
        ],
        redirect_uris: vec![REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

fn post(uri: &str, body: String) -> http::Request<Body> {
    http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .expect("a well-formed request")
}

async fn body_of(response: http::Response<Body>) -> serde_json::Value {
    let bytes = response.into_body().into_bytes();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

// ------------------------------------------------------------------- the RFC 6750 s2.1 header

/// KILLS: `http.rs replace < with == in bearer_token`.
///
/// `raw.len() < 7` is what guarantees that `raw[..7]` is in bounds. Narrowed to `== 7`, every
/// Authorization header SHORTER than the scheme falls straight through it and the slice PANICS:
/// `byte index 7 is out of bounds`. This crate is a library, so that panic unwinds into the host's
/// own request handler, from a header an unauthenticated caller chose. `Authorization: Basic` on
/// the registration endpoint is enough to send it.
///
/// The expected answer is an ordinary refusal, and the test asserts a status rather than merely
/// "did not panic", so that it keeps meaning something after the bound is fixed.
#[tokio::test]
async fn an_authorization_header_too_short_to_hold_the_scheme_is_refused_not_a_panic() {
    let service = registration_service(None).await;
    for header in ["Basic", "B", "Bearer", "bearer"] {
        let request = http::Request::builder()
            .method("POST")
            .uri("/register")
            .header("content-type", "application/json")
            .header("authorization", header)
            .body(Body::from(
                r#"{"redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code"],"response_types":["code"]}"#,
            ))
            .expect("a well-formed request");
        let status = service.handle(request).await.status();
        assert!(
            status.is_client_error() || status.is_success(),
            "an Authorization header of {} bytes must be answered, not crashed on, got {status}",
            header.len()
        );
    }
}

/// KILLS: `http.rs replace || with && in bearer_token`.
///
/// The two halves of `raw.len() < 7 || !raw[..7].eq_ignore_ascii_case("bearer ")` are "long enough
/// to be a Bearer header" and "actually is one". Joined with `&&`, a header that is long enough
/// but names a DIFFERENT scheme is accepted, and the seven bytes of that other scheme's name are
/// simply cut off the front: `Authorization: Basic aGVsbG8=` presents `GVsbG8=` as a bearer token.
///
/// What a real deployment loses is the meaning of the one argument RFC 7591 section 5 gives a
/// host's registration policy. `initial_access_token` is documented as the bearer credential the
/// caller presented; handing it a mangled slice of a Basic credential is both a wrong answer (a
/// policy that gates registration on "was a token presented" now opens for any Authorization
/// header at all) and a credential leaking into a host callback that was told it would never see
/// one.
#[tokio::test]
async fn a_credential_in_another_scheme_is_not_read_as_a_bearer_token() {
    let seen: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let service = registration_service(Some(Arc::clone(&seen))).await;

    let request = http::Request::builder()
        .method("POST")
        .uri("/register")
        .header("content-type", "application/json")
        // A real Basic credential: base64("alice:hunter2").
        .header("authorization", "Basic YWxpY2U6aHVudGVyMg==")
        .body(Body::from(
            r#"{"redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code"],"response_types":["code"]}"#,
        ))
        .expect("a well-formed request");
    let _ = service.handle(request).await;

    let seen = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(
        seen,
        vec![None],
        "the policy must be told that NO bearer token was presented, not handed a slice of \
         somebody's Basic credential"
    );
}

async fn registration_service(
    seen: Option<Arc<Mutex<Vec<Option<String>>>>>,
) -> oauth_as::http::AuthorizationService<MemoryStorage, SystemClock> {
    use oauth_as::{
        RegistrationAttempt, RegistrationConfig, RegistrationDecision, RegistrationPolicy,
    };

    struct Recording(Option<Arc<Mutex<Vec<Option<String>>>>>);
    impl RegistrationPolicy for Recording {
        fn authorize(&self, attempt: &RegistrationAttempt<'_>) -> RegistrationDecision {
            if let Some(seen) = &self.0 {
                seen.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(attempt.initial_access_token.map(str::to_string));
            }
            RegistrationDecision::Allow
        }
    }

    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.registration = Some(Box::new(RegistrationConfig::new()));
    let srv = AuthorizationServer::new(cfg, MemoryStorage::new())
        .with_registration_policy(Box::new(Recording(seen)));
    oauth_as::http::ServiceBuilder::new(Arc::new(srv))
        .with_subject_resolver(|_headers| Some("user-1".to_string()))
        .with_consent_resolver(|_request| ConsentDecision::Approve)
        .build()
        .expect("service")
}

// ------------------------------------------------------------- RFC 6749 s2.3: one method only

/// KILLS: `http.rs replace || with && in credentials_where`.
///
/// RFC 6749 section 2.3 allows a client exactly one authentication method per request, and the
/// guard `if basic || body_secret.is_some()` is what refuses an RFC 7523 assertion presented
/// alongside one of the older two. Weakened to `&&`, only the client that sends BOTH of the other
/// two is refused, so an assertion arriving with a `Basic` header sails through.
///
/// That is not a tidiness rule. The Basic header and the assertion can name DIFFERENT clients, and
/// the assertion is the one that wins: the request authenticates as the assertion's subject while
/// every log, proxy and WAF in front of this server sees the Basic client id. A server that
/// resolves the ambiguity by precedence is a server whose behaviour differs from the next one's,
/// which is exactly what section 2.3 removes.
#[cfg(feature = "client_assertion")]
#[tokio::test]
async fn an_assertion_presented_alongside_basic_credentials_is_refused() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use oauth_as::client_assertion::{AssertionKeys, ClientSecretKey, CLIENT_ASSERTION_TYPE};
    use oauth_as::jwt::{compact_jws, hmac_sha256};

    // A client that authenticates by assertion, so the assertion below is the credential the
    // registration actually expects and the Basic header is unambiguously the second one.
    let mut asserting = client();
    asserting.client_id = ClientId::new("assert-app");
    asserting.auth = ClientAuth::ConfidentialAssertion {
        keys: AssertionKeys::ClientSecret {
            secret: ClientSecretKey::new(SECRET.to_string()).expect("a long enough secret"),
        },
    };

    let srv = AuthorizationServer::new(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        MemoryStorage::new(),
    );
    srv.register_client(client()).await.unwrap();
    srv.register_client(asserting).await.unwrap();
    let service = oauth_as::http::ServiceBuilder::new(Arc::new(srv))
        .with_subject_resolver(|_headers| Some("user-1".to_string()))
        .with_consent_resolver(|_request| ConsentDecision::Approve)
        .build()
        .expect("service");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = serde_json::json!({
        "iss": "assert-app",
        "sub": "assert-app",
        "aud": "https://as.example/token",
        "exp": now + 120,
        "iat": now,
        "jti": "assertion-with-basic",
    });
    let assertion = compact_jws(
        br#"{"alg":"HS256","typ":"JWT"}"#,
        &serde_json::to_vec(&claims).unwrap(),
        |input| hmac_sha256(SECRET.as_bytes(), input.as_bytes()).to_vec(),
    );

    let body = format!(
        "grant_type=client_credentials&client_assertion_type={}&client_assertion={assertion}",
        urlencode(CLIENT_ASSERTION_TYPE)
    );
    let mut request = post("/token", body);
    request.headers_mut().insert(
        http::header::AUTHORIZATION,
        format!("Basic {}", STANDARD.encode(format!("assert-app:{SECRET}")))
            .parse()
            .expect("a header value"),
    );

    let response = service.handle(request).await;
    assert_eq!(
        response.status(),
        http::StatusCode::BAD_REQUEST,
        "RFC 6749 s2.3: two client authentication methods in one request is invalid_request"
    );
    assert_eq!(
        body_of(response)
            .await
            .get("error")
            .and_then(|v| v.as_str()),
        Some("invalid_request"),
        "and it must be refused rather than resolved by precedence"
    );
}

/// Percent-encode the few characters the assertion type URN needs. Written out rather than pulled
/// in, because one `:` and one `/` are the whole requirement.
#[cfg(feature = "client_assertion")]
fn urlencode(raw: &str) -> String {
    raw.chars()
        .map(|c| match c {
            ':' => "%3A".to_string(),
            '/' => "%2F".to_string(),
            other => other.to_string(),
        })
        .collect()
}

// ------------------------------------------------------- RFC 9470 s4: remembering an approval

/// KILLS: `http.rs replace && with || in authorize_handler`.
///
/// `if remember && issued.is_ok()` is what makes `ConsentDecision::ApproveAndRemember` the ONLY
/// way a consent record is written. Turned into `||`, a plain `Approve` records one too.
///
/// The variant's own documentation is the specification this violates: remembering "is a statement
/// about a user's intent and this crate never sees a user. It will not remember a consent nobody
/// asked it to remember." The user-visible consequence is that the NEXT authorization request from
/// the same client is handed a `remembered` consent, so a host that skips its prompt when one
/// exists (which is the entire reason the value is passed to the resolver) never asks again. One
/// approval silently becomes standing consent.
#[cfg(feature = "consent")]
#[tokio::test]
async fn an_approval_that_was_not_remembered_is_not_recorded() {
    let srv = AuthorizationServer::new(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        MemoryStorage::new(),
    );
    srv.register_client(client()).await.unwrap();
    let srv = Arc::new(srv);
    let service = oauth_as::http::ServiceBuilder::new(Arc::clone(&srv))
        .with_subject_resolver(|_headers| Some("user-1".to_string()))
        // Approve, and say nothing about remembering. This is the decision a host makes when the
        // user ticked nothing.
        .with_consent_resolver(|_request| ConsentDecision::Approve)
        .build()
        .expect("service");

    let challenge = oauth_as::pkce::code_challenge_s256(VERIFIER);
    let query = format!(
        "response_type=code&client_id=app&redirect_uri={}&scope=read\
         &code_challenge={challenge}&code_challenge_method=S256",
        urlencode_uri(REDIRECT)
    );
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("/authorize?{query}"))
        .body(Body::empty())
        .expect("a well-formed request");
    let response = service.handle(request).await;
    assert_eq!(
        response.status(),
        http::StatusCode::FOUND,
        "the approval must still mint a code: this test is about what was REMEMBERED"
    );

    let remembered = srv
        .remembered_consent(&ClientId::new("app"), "user-1")
        .await
        .expect("the store answers");
    assert!(
        remembered.is_none(),
        "an Approve is not an ApproveAndRemember: nothing asked for this consent to be kept"
    );
}

/// The two characters a redirect URI needs escaping in a query string.
#[cfg(feature = "consent")]
fn urlencode_uri(raw: &str) -> String {
    raw.chars()
        .map(|c| match c {
            ':' => "%3A".to_string(),
            '/' => "%2F".to_string(),
            other => other.to_string(),
        })
        .collect()
}

// ------------------------------------------------------- RFC 8693 s2.1.1: which parameter is an
// audience

/// KILLS: `http.rs replace == with != in token_exchange_response`.
///
/// `form.iter().filter(|(k, _)| k == "audience")` is the one place the HTTP surface decides which
/// form parameters are RFC 8693 section 2.1.1 audiences. Inverted, it collects the value of every
/// parameter that is NOT `audience`: `grant_type`, `subject_token`, `subject_token_type` and the
/// client credentials all become audiences the request is asking for.
///
/// None of them was granted by the subject token, so `narrow_resources` refuses the lot and EVERY
/// token exchange this server is asked to perform comes back `invalid_target`. The grant is
/// entirely dead over HTTP, and nothing saw it, because the exchange suite drives the library API
/// directly and never posts a form.
#[cfg(feature = "token-exchange")]
#[tokio::test]
async fn a_token_exchange_posted_as_a_form_reaches_the_grant() {
    let srv = AuthorizationServer::new(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        MemoryStorage::new(),
    );
    srv.register_client(client()).await.unwrap();
    let srv = Arc::new(srv);
    let service = oauth_as::http::ServiceBuilder::new(Arc::clone(&srv))
        .with_subject_resolver(|_headers| Some("user-1".to_string()))
        .with_consent_resolver(|_request| ConsentDecision::Approve)
        .build()
        .expect("service");

    // A subject token, minted by the ordinary client credentials grant over the same surface.
    let subject = body_of(
        service
            .handle(post(
                "/token",
                format!("grant_type=client_credentials&client_id=app&client_secret={SECRET}"),
            ))
            .await,
    )
    .await;
    let subject_token = subject
        .get("access_token")
        .and_then(|v| v.as_str())
        .expect("a subject token")
        .to_string();

    let body = format!(
        "grant_type={}&subject_token={subject_token}&subject_token_type={}\
         &client_id=app&client_secret={SECRET}",
        urlencode_urn("urn:ietf:params:oauth:grant-type:token-exchange"),
        urlencode_urn("urn:ietf:params:oauth:token-type:access_token"),
    );
    let response = service.handle(post("/token", body)).await;
    let status = response.status();
    let json = body_of(response).await;
    assert_eq!(
        status,
        http::StatusCode::OK,
        "an exchange naming no audience at all must not be refused as though it named one: {json}"
    );
    assert!(
        json.get("access_token").and_then(|v| v.as_str()).is_some(),
        "RFC 8693 s2.2.1 requires an access_token in the response: {json}"
    );
}

#[cfg(feature = "token-exchange")]
fn urlencode_urn(raw: &str) -> String {
    raw.chars()
        .map(|c| match c {
            ':' => "%3A".to_string(),
            '/' => "%2F".to_string(),
            other => other.to_string(),
        })
        .collect()
}
