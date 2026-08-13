// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! What this service SAYS when it refuses, and in what order it does the work behind a refusal.
//!
//! A refusal is read by an operator, and it sends them somewhere. Three of them sent them to the
//! wrong place, and each is a different kind of wrong:
//!
//! - The authorization endpoint told a fully wired host that it "must supply a subject resolver"
//!   when the truth was that nobody was signed in. The host had supplied one; it answered `None`,
//!   which its own documentation defines as "nobody is logged in".
//! - RFC 8693 token exchange refused a presented DPoP proof (correctly: this server cannot bind a
//!   token through that grant) and reported it as `DpopFailure::Malformed`, whose `Display` is
//!   "the DPoP proof is not a well formed JWT". The proof was never parsed. That sends the
//!   operator to the client's author about a JWS that is probably perfectly well formed, when the
//!   answer is a server capability the operator controls.
//! - RFC 7592 `PUT` parsed up to 64 KiB of a stranger's JSON before it looked at the bearer token,
//!   on the one plane of this service where the credential is not optional. `src/http.rs` states
//!   the rule this breaks beside `MAX_FORM_PARAMETERS`: "a refusal is work an attacker sets the
//!   rate of".
//!
//! The fourth is not a message but a URL: `registration_client_uri` is minted by this server and
//! handed to a client as the address of its own registration, so a client id that needs escaping
//! has to be escaped there rather than assumed away.

#![cfg(feature = "http")]

use std::sync::Arc;
// Used only by the `dpop` + `token-exchange` test below. Imported ungated, a plain `http` build
// fails `-D warnings` on an unused import, which is what the clippy feature-combination loop does
// and what an `--all-features` run cannot see: with every feature on, nothing is unused.
#[cfg(all(feature = "dpop", feature = "token-exchange"))]
use std::sync::Mutex;

use oauth_as::client::{Client, ClientAuth, ClientId, DynamicRegistration, SecretHash};
use oauth_as::grant::GrantType;
use oauth_as::http::{ApprovalDecision, Body, ServiceBuilder};
use oauth_as::registration::RegistrationConfig;
use oauth_as::scope::ScopeSet;
use oauth_as::server::{AuthorizationServer, ServerConfig, SystemClock};
use oauth_as::store::MemoryStorage;
use serde_json::Value;

const REDIRECT_URI: &str = "https://app.example/cb";
/// RFC 7636 appendix B challenge.
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

type Service = oauth_as::http::AuthorizationService<MemoryStorage, SystemClock>;

fn public_client() -> Client {
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

async fn server_with(
    cfg: ServerConfig,
    clients: Vec<Client>,
) -> AuthorizationServer<MemoryStorage> {
    let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
    for client in clients {
        srv.register_client(client).await.expect("registered");
    }
    srv
}

fn authorize_request() -> http::Request<Body> {
    http::Request::builder()
        .method("GET")
        .uri(format!(
            "/authorize?response_type=code&client_id=app&redirect_uri={REDIRECT_URI}\
             &code_challenge={CHALLENGE}&code_challenge_method=S256"
        ))
        .body(Body::from(String::new()))
        .expect("a well-formed request")
}

async fn body_of(response: http::Response<Body>) -> Value {
    let bytes = response.into_body().into_bytes();
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "body is not JSON ({e}): {:?}",
            String::from_utf8_lossy(&bytes)
        )
    })
}

fn description(body: &Value) -> String {
    body.get("error_description")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

/// A host that wired NOTHING. This one really must be told to supply a resolver.
#[tokio::test]
async fn an_unwired_host_is_told_to_supply_a_subject_resolver() {
    let srv = server_with(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        vec![public_client()],
    )
    .await;
    let service = ServiceBuilder::new(Arc::new(srv)).build().expect("service");

    let response = service.handle(authorize_request()).await;
    assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    let why = description(&body_of(response).await);
    assert!(
        why.contains("subject resolver"),
        "a host with no resolver installed is the case that sentence was written for: {why}"
    );
}

/// A host that wired BOTH seams, visited by a browser with no session. The resolver answered
/// `None`, which its own type documents as "nobody is logged in", and the host is not the party
/// with a mistake to fix.
#[tokio::test]
async fn a_signed_out_visitor_is_not_told_the_host_forgot_to_wire_a_resolver() {
    let srv = server_with(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        vec![public_client()],
    )
    .await;
    let service = ServiceBuilder::new(Arc::new(srv))
        // Wired, and answering honestly: this visitor is not signed in.
        .with_subject_resolver(|_headers| None)
        .with_approval_resolver(|_request| ApprovalDecision::Approve)
        .build()
        .expect("service");

    let response = service.handle(authorize_request()).await;
    assert_eq!(
        response.status(),
        http::StatusCode::FORBIDDEN,
        "no code may be minted for a request no resource owner stands behind"
    );
    let why = description(&body_of(response).await);
    assert!(
        !why.contains("must supply a subject resolver"),
        "the host DID supply one and it answered None; telling an operator to install what they \
         installed sends them to the wrong file: {why}"
    );
    assert!(
        why.contains("signed in") || why.contains("no authenticated resource owner"),
        "the refusal must still say what is missing: {why}"
    );
}

// --------------------------------------------------- RFC 7592: authenticate before you parse

fn management_config() -> ServerConfig {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let mut registration = RegistrationConfig::new();
    registration.allowed_scopes = ScopeSet::parse("read").unwrap();
    cfg.registration = Some(Box::new(registration));
    cfg
}

/// A client that exists, holds a registration, and is therefore manageable, so the only thing
/// standing between the caller below and this registration is the bearer token it does not have.
fn managed_client(client_id: &str) -> Client {
    Client {
        client_id: ClientId::new(client_id),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::AuthorizationCode],
        redirect_uris: vec![REDIRECT_URI.to_string()],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: Some(Box::new(DynamicRegistration {
            registration_access_token_hash: SecretHash::sha256("the-registration-access-token"),
            client_id_issued_at: Some(0),
            client_secret_expires_at: None,
            token_endpoint_auth_method: "none".to_string(),
        })),
    }
}

async fn management_service() -> Service {
    let srv = server_with(management_config(), vec![managed_client("app")]).await;
    ServiceBuilder::new(Arc::new(srv)).build().expect("service")
}

/// RFC 7592 s2.2 `PUT`, with no credential and a body that is not JSON.
///
/// The token is what this request is missing, and it is missing it before the first byte of the
/// body means anything. Answering `invalid_client_metadata` is both the wrong status for the
/// caller and, for the server, a full JSON parse bought by an anonymous request.
#[tokio::test]
async fn an_unauthenticated_management_put_is_refused_before_its_body_is_parsed() {
    let service = management_service().await;
    let request = http::Request::builder()
        .method("PUT")
        .uri("/register/app")
        .header("content-type", "application/json")
        // Not JSON, and deliberately: a parse-first handler answers about THIS, which proves it
        // read it.
        .body(Body::from("{ this is not json".to_string()))
        .expect("a well-formed request");

    let response = service.handle(request).await;
    assert_eq!(
        response.status(),
        http::StatusCode::UNAUTHORIZED,
        "the missing credential is the refusal; the body is a stranger's bytes and must not be \
         parsed to reach it"
    );
}

/// The other side of the same order, so it is a REORDERING and not a new refusal: a caller holding
/// the registration access token still gets the metadata error its body earns.
#[tokio::test]
async fn an_authenticated_management_put_still_reports_a_body_that_is_not_metadata() {
    let service = management_service().await;
    let request = http::Request::builder()
        .method("PUT")
        .uri("/register/app")
        .header("content-type", "application/json")
        .header("authorization", "Bearer the-registration-access-token")
        .body(Body::from("{ this is not json".to_string()))
        .expect("a well-formed request");

    let response = service.handle(request).await;
    assert_eq!(
        response.status(),
        http::StatusCode::BAD_REQUEST,
        "an authenticated caller is entitled to be told its document could not be read"
    );
    assert_eq!(
        body_of(response)
            .await
            .get("error")
            .and_then(|v| v.as_str()),
        Some("invalid_client_metadata"),
    );
}

// ------------------------------------------- RFC 7592 s3: the URL this server hands the client

/// `registration_client_uri` is `{registration_endpoint}/{client_id}` (RFC 7592 s3), minted here
/// and used by the client verbatim. The ids this server mints are 32 hex characters, so nothing
/// reachable through dynamic registration needs escaping; a host that calls `register_client`
/// directly supplies its own id, and a space in one turns the URL this server minted into a URL
/// that is not a URL at all.
#[tokio::test]
async fn a_minted_management_url_escapes_the_client_id_it_carries() {
    let srv = server_with(management_config(), vec![managed_client("client one")]).await;
    let info = srv
        .read_registration(
            &ClientId::new("client one"),
            "the-registration-access-token",
        )
        .await
        .expect("read");

    assert_eq!(
        info.registration_client_uri.as_deref(),
        Some("https://as.example/register/client%20one"),
        "the segment this server writes into a URL has to be a legal path segment"
    );
}

// ------------------------------------------- RFC 9449 on a grant that cannot bind: what is said

/// A proof presented with RFC 8693 token exchange is refused, and the refusal reaches the audit
/// channel: `tests/client_auth.rs` already pins both. What it does not pin is WHICH failure is
/// reported, and the answer was `Malformed`, whose `Display` is "the DPoP proof is not a well
/// formed JWT" for a proof this server never parsed.
#[cfg(all(feature = "dpop", feature = "token-exchange"))]
#[tokio::test]
async fn a_proof_refused_for_want_of_a_capability_is_not_reported_as_malformed() {
    use oauth_as::events::{Event, EventSink};

    struct Recorder(Arc<Mutex<Vec<String>>>);
    impl EventSink for Recorder {
        fn on_event(&self, event: Event<'_>) {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("{event:?}"));
        }
    }

    let seen = Arc::new(Mutex::new(Vec::new()));
    let srv = AuthorizationServer::new(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        MemoryStorage::new(),
    )
    .with_event_sink(Box::new(Recorder(seen.clone())));
    srv.register_client(Client {
        client_id: ClientId::new("gateway"),
        auth: ClientAuth::ConfidentialSecret {
            secret: "a-high-entropy-registered-client-secret".to_string(),
        },
        grant_types: vec![GrantType::TokenExchange],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    })
    .await
    .expect("registered");
    let service = ServiceBuilder::new(Arc::new(srv)).build().expect("service");

    let request = http::Request::builder()
        .method("POST")
        .uri("/token")
        .header("content-type", "application/x-www-form-urlencoded")
        // A perfectly well formed compact JWS shape, so "malformed" could only ever be a guess.
        .header("DPoP", "a.proof.here")
        .body(Body::from(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=gateway\
             &client_secret=a-high-entropy-registered-client-secret&subject_token=x\
             &subject_token_type=urn:ietf:params:oauth:token-type:access_token"
                .to_string(),
        ))
        .expect("a well-formed request");
    assert_eq!(
        service.handle(request).await.status(),
        http::StatusCode::BAD_REQUEST,
        "the wire answer is unchanged: RFC 9449 s5 invalid_dpop_proof"
    );

    let events = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let refusals: Vec<&String> = events
        .iter()
        .filter(|e| e.contains("DpopProofRefused"))
        .collect();
    assert_eq!(
        refusals.len(),
        1,
        "the refusal must still be reported: {events:?}"
    );
    assert!(
        !refusals[0].contains("Malformed"),
        "this proof was never read, so reporting it as malformed sends the operator to the \
         client's author about a JWS that is probably fine: {:?}",
        refusals[0]
    );
}
