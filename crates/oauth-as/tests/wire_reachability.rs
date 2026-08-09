// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! EVERY CAPABILITY THE RFC 8414 DOCUMENT ADVERTISES, PROVEN REACHABLE OVER HTTP.
//!
//! # Why this file exists, and what it is a reaction to
//!
//! RFC 8693 token exchange was advertised in this server's metadata document and answered
//! `invalid_client` to every client, under every authentication method, over the whole HTTP
//! surface, for an unknown number of commits. The token handler resolved the client's credential
//! and then set `client_secret = None` because every other grant carries its credential on the
//! request context; the exchange arm was never updated, and `exchange_token` refuses a client that
//! is not confidential.
//!
//! Nothing caught it, and the REASON is the point. The token-exchange suite
//! (`tests/token_exchange.rs`) is thorough, and it drives the LIBRARY API
//! (`AuthorizationServer::exchange_token`) directly. It had never posted a form to `/token`. The
//! tests were rigorous at the wrong layer, and a refusal was the expected shape of most of them,
//! so a grant that refused EVERYTHING looked exactly like a suite that was passing.
//!
//! That is a SHAPE of gap rather than one bug, and the shape is: a capability the metadata
//! document PROMISES, whose only proof lives on the library API. So this file drives
//! [`AuthorizationService::handle`] with real `http::Request` values and nothing else. It never
//! calls a grant function directly.
//!
//! # The method: derive the checklist from the ADVERTISEMENT, not from the router
//!
//! A test suite written against the router's `match` arms cannot find this class of defect,
//! because it is written from the same list the router was. So every test below starts by
//! FETCHING the metadata document over HTTP and iterating what it says:
//!
//! - `grant_types_supported` drives [`prove_grant`], whose `match` has a catch-all that PANICS.
//! - `token_endpoint_auth_methods_supported` drives [`prove_auth_method`], likewise.
//! - `response_types_supported` and `code_challenge_methods_supported`, likewise.
//! - every member whose name ends in `_alg_values_supported` drives
//!   [`every_advertised_signing_algorithm_can_be_performed_by_this_build`], likewise, and that one
//!   is discovered by NAME rather than listed, so a new member of the family is swept with no
//!   change here. It is the newest of these and it covers the family where the document became
//!   able to lie: those lists were derived from cargo features, and since the ES256 seam a
//!   feature no longer implies a backend that can perform the algorithm.
//! - every member whose name ends in `_endpoint`, plus `jwks_uri`, is probed for a non-404, with
//!   no per-endpoint list written down anywhere in this file.
//!
//! The consequence is the structural property that was missing: adding a value to any of those
//! lists WITHOUT proving it over the wire is a test failure on the next run, not an oversight
//! nobody notices for weeks. Adding an endpoint is caught with no code change here at all.
//!
//! # What a SUCCESS is worth here, and why refusals are not enough
//!
//! Every grant below is redeemed to a 200 with a real `access_token`. That is deliberate and it is
//! the lesson of the defect: a refusal test cannot tell "correctly refused this bad request" from
//! "refuses everything". Where a capability can only be refused through this service, this file
//! says so LOUDLY and cites the reason rather than asserting the refusal quietly; see
//! [`the_advertised_mtls_methods_cannot_authenticate_through_this_service`].

#![cfg(feature = "http")]

use std::sync::Arc;
use std::time::Duration;

use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::grant::{GrantType, DEVICE_CODE_GRANT_URN};
use oauth_as::http::{AuthorizationService, Body, ConsentDecision, ServiceBuilder};
use oauth_as::scope::ScopeSet;
use oauth_as::server::{AuthorizationServer, ServerConfig, SystemClock};
use oauth_as::store::MemoryStorage;
use serde_json::Value;

const ISSUER: &str = "https://as.example";
const VERIFICATION_URI: &str = "https://as.example/device";
/// The audience an RFC 7523 assertion has to name. Spelled out rather than derived so that a
/// change to the default endpoint layout shows up here as a failing assertion.
const TOKEN_ENDPOINT: &str = "https://as.example/token";

const CONFIDENTIAL: &str = "confidential-app";
const PUBLIC: &str = "public-app";
const SECRET: &str = "a-high-entropy-registered-client-secret";
const REDIRECT: &str = "https://app.example/cb";
/// RFC 7636 appendix B's verifier, so the challenge derived from it is a real S256 challenge.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

// ---------------------------------------------------------------------------------------------
// The wire, and nothing above it
// ---------------------------------------------------------------------------------------------

/// One answer off the service, kept as bytes-plus-status so that assertions are about what a
/// client would actually have received.
struct Wire {
    status: http::StatusCode,
    location: Option<String>,
    body: String,
}

impl Wire {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }

    /// The `access_token` a successful token response must carry (RFC 6749 s5.1), or a panic
    /// naming the whole body. A grant that "succeeded" with no token is the failure this file
    /// exists to catch, so it is never silently tolerated.
    fn access_token(&self, what: &str) -> String {
        assert_eq!(
            self.status,
            http::StatusCode::OK,
            "{what}: expected a 200 token response over HTTP, got {} {}",
            self.status,
            self.body
        );
        self.json()
            .get("access_token")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("{what}: RFC 6749 s5.1 requires access_token: {}", self.body))
            .to_string()
    }
}

type Service = AuthorizationService<MemoryStorage, SystemClock>;

async fn send(service: &Service, request: http::Request<Body>) -> Wire {
    let response = service.handle(request).await;
    let status = response.status();
    let location = response
        .headers()
        .get(http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = String::from_utf8_lossy(&response.into_body().into_bytes()).into_owned();
    Wire {
        status,
        location,
        body,
    }
}

async fn get(service: &Service, path: &str) -> Wire {
    let request = http::Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .expect("a well-formed request");
    send(service, request).await
}

async fn post_form(service: &Service, path: &str, body: String) -> Wire {
    post_form_with(service, path, body, &[]).await
}

async fn post_form_with(
    service: &Service,
    path: &str,
    body: String,
    headers: &[(&str, String)],
) -> Wire {
    let mut builder = http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/x-www-form-urlencoded");
    for (name, value) in headers {
        builder = builder.header(*name, value.as_str());
    }
    let request = builder
        .body(Body::from(body))
        .expect("a well-formed request");
    send(service, request).await
}

/// Percent-encode the characters this file's fixtures actually contain. Written out rather than
/// pulled in: a URL-encoding dependency for one colon and one slash is not a trade this crate's
/// dependency policy makes, and the same three lines already appear in the mutation-gap suite.
fn urlencode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            ':' => out.push_str("%3A"),
            '/' => out.push_str("%2F"),
            '?' => out.push_str("%3F"),
            '&' => out.push_str("%26"),
            '=' => out.push_str("%3D"),
            ' ' => out.push_str("%20"),
            other => out.push(other),
        }
    }
    out
}

/// Read one query parameter out of a redirect `Location`. No URL parser, for the reason above:
/// the values this server puts there are `code`, `state` and `iss`, none of which is escaped in a
/// way a split on `&` and `=` gets wrong.
fn query_param(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?').map(|(_, q)| q)?;
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

// ---------------------------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------------------------

fn scopes() -> ScopeSet {
    ScopeSet::parse("read write").expect("a valid scope catalogue")
}

/// The confidential client, registered for EVERY grant this build compiles in, so that one
/// registration cannot be the reason a grant looks unreachable.
fn confidential_client() -> Client {
    Client {
        client_id: ClientId::new(CONFIDENTIAL),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.to_string(),
        },
        grant_types: vec![
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::ClientCredentials,
            GrantType::DeviceCode,
            #[cfg(feature = "token-exchange")]
            GrantType::TokenExchange,
        ],
        redirect_uris: vec![REDIRECT.to_string()],
        allowed_scopes: scopes(),
        default_scopes: ScopeSet::parse("read").expect("a valid default scope"),
        name: Some("Confidential Fixture".to_string()),
        registration: None,
    }
}

/// The public client: no secret at all, which is what makes it the proof for the `none`
/// authentication method (RFC 8414 s2) and for RFC 7009 s5's public-client revocation.
fn public_client() -> Client {
    Client {
        client_id: ClientId::new(PUBLIC),
        auth: ClientAuth::Public,
        grant_types: vec![
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::DeviceCode,
        ],
        redirect_uris: vec![REDIRECT.to_string()],
        allowed_scopes: scopes(),
        default_scopes: ScopeSet::parse("read").expect("a valid default scope"),
        name: Some("Public Fixture".to_string()),
        registration: None,
    }
}

fn base_config() -> ServerConfig {
    let mut config = ServerConfig::new(ISSUER, VERIFICATION_URI);
    // RFC 8628 s3.5's `slow_down` is correct behaviour and is tested elsewhere; here it would
    // turn the device grant's SUCCESS proof into a timing race, and a wire suite that has to
    // sleep is a wire suite people disable. Zero spacing removes the race without removing the
    // grant: `token_device_code` still walks the whole state machine.
    config.poll_interval = Duration::ZERO;
    #[cfg(feature = "par")]
    {
        config.par = Some(Box::new(oauth_as::par::ParConfig::new()));
    }
    config.registration = Some(Box::new(oauth_as::registration::RegistrationConfig::new()));
    #[cfg(feature = "resource-metadata")]
    {
        config.protected_resources = Some(vec!["https://rs.example/api".to_string()]);
    }
    config
}

/// A registration policy that allows, so the RFC 7591 endpoint the metadata document advertises
/// actually answers. Without a policy the server REFUSES every registration by design, which
/// would make an advertised endpoint unreachable for a reason that is configuration rather than
/// code.
struct AllowRegistration;

impl oauth_as::registration::RegistrationPolicy for AllowRegistration {
    fn authorize(
        &self,
        _attempt: &oauth_as::registration::RegistrationAttempt<'_>,
    ) -> oauth_as::registration::RegistrationDecision {
        oauth_as::registration::RegistrationDecision::Allow
    }
}

struct Fixture {
    server: Arc<AuthorizationServer<MemoryStorage, SystemClock>>,
    service: Service,
}

async fn fixture() -> Fixture {
    let server = AuthorizationServer::new(base_config(), MemoryStorage::new())
        .with_registration_policy(Box::new(AllowRegistration));
    server
        .register_client(confidential_client())
        .await
        .expect("register the confidential client");
    server
        .register_client(public_client())
        .await
        .expect("register the public client");
    #[cfg(feature = "client_assertion")]
    register_assertion_clients(&server).await;
    #[cfg(feature = "mtls")]
    register_mtls_clients(&server).await;

    let server = Arc::new(server);
    let service = ServiceBuilder::new(Arc::clone(&server))
        .with_subject_resolver(|_headers| Some("resource-owner-1".to_string()))
        .with_consent_resolver(|_request| ConsentDecision::Approve)
        // The device verification form's CSRF protection is a BROWSER countermeasure, and this
        // file drives the endpoint with no browser and no session, exactly as the black-box
        // conformance harness does. tests/http_surface.rs owns the proof that the protection
        // works; turning it off here is what lets the device grant be redeemed end to end, which
        // is what this file is for.
        .dangerously_disable_verification_protections()
        .build()
        .expect("the service builds for a coherent configuration");
    Fixture { server, service }
}

/// The metadata document, FETCHED over HTTP. Every checklist in this file is derived from this
/// value and from nothing else.
async fn metadata(service: &Service) -> Value {
    let path = oauth_as::metadata::well_known_path(ISSUER);
    let response = get(service, &path).await;
    assert_eq!(
        response.status,
        http::StatusCode::OK,
        "RFC 8414 s3: the metadata document must be served at {path}: {}",
        response.body
    );
    let doc = response.json();
    assert_eq!(
        doc.get("issuer").and_then(|v| v.as_str()),
        Some(ISSUER),
        "RFC 8414 s3.3: the issuer member must equal the URL the document was fetched from"
    );
    doc
}

/// The strings in an advertised array member, or a panic: a member this file iterates and finds
/// missing means the document changed shape, which is exactly when these checklists must stop
/// passing quietly.
fn advertised(doc: &Value, member: &str) -> Vec<String> {
    doc.get(member)
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("RFC 8414: the document must advertise {member}: {doc}"))
        .iter()
        .map(|v| {
            v.as_str()
                .unwrap_or_else(|| panic!("{member} must hold strings: {doc}"))
                .to_string()
        })
        .collect()
}

/// An advertised absolute URL as the path this service routes it at.
fn path_of(url: &str) -> String {
    url.strip_prefix(ISSUER)
        .unwrap_or_else(|| panic!("{url} is advertised outside the issuer {ISSUER}"))
        .to_string()
}

// ---------------------------------------------------------------------------------------------
// Flows, over the wire
// ---------------------------------------------------------------------------------------------

/// GET the authorization endpoint and hand back the `code` from the redirect.
///
/// `client_secret` is not a parameter here on purpose: the authorization endpoint authenticates
/// nobody (RFC 6749 s4.1.1), so this is the same call for the public and the confidential client
/// and the difference only appears at redemption.
async fn authorization_code(service: &Service, client_id: &str) -> String {
    let challenge = oauth_as::pkce::code_challenge_s256(VERIFIER);
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope=read\
         &state=wire-state&code_challenge={challenge}&code_challenge_method=S256",
        urlencode(REDIRECT)
    );
    let response = get(service, &format!("/authorize?{query}")).await;
    assert_eq!(
        response.status,
        http::StatusCode::FOUND,
        "RFC 6749 s4.1.2: an approved authorization request redirects with a code: {}",
        response.body
    );
    let location = response
        .location
        .unwrap_or_else(|| panic!("a 302 with no Location is not a redirect"));
    assert!(
        location.starts_with(REDIRECT),
        "the code must be delivered to the REGISTERED redirect URI, got {location}"
    );
    assert_eq!(
        query_param(&location, "state").as_deref(),
        Some("wire-state"),
        "RFC 6749 s4.1.2: state must come back unchanged: {location}"
    );
    // RFC 9207 s2, and the document advertises
    // `authorization_response_iss_parameter_supported: true`, so a client is entitled to REQUIRE
    // it. Compared percent-decoded rather than by string, because the issuer is a URL.
    assert!(
        query_param(&location, "iss").is_some(),
        "RFC 9207 s2: the iss parameter must be present: {location}"
    );
    query_param(&location, "code").unwrap_or_else(|| panic!("no code in the redirect: {location}"))
}

/// The authorization code grant, redeemed over `/token`. Returns the whole response so a caller
/// can take the `refresh_token` out of it.
async fn token_authorization_code(
    service: &Service,
    client_id: &str,
    secret: Option<&str>,
) -> Wire {
    let code = authorization_code(service, client_id).await;
    let mut body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}\
         &code_verifier={VERIFIER}&client_id={client_id}",
        urlencode(REDIRECT)
    );
    if let Some(secret) = secret {
        body.push_str(&format!("&client_secret={secret}"));
    }
    post_form(service, "/token", body).await
}

async fn token_client_credentials(service: &Service) -> Wire {
    post_form(
        service,
        "/token",
        format!("grant_type=client_credentials&client_id={CONFIDENTIAL}&client_secret={SECRET}&scope=read"),
    )
    .await
}

async fn token_refresh(service: &Service) -> Wire {
    let issued = token_authorization_code(service, CONFIDENTIAL, Some(SECRET)).await;
    let json = issued.json();
    let refresh = json
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| {
            panic!(
                "the authorization code grant must issue a refresh token here: {}",
                issued.body
            )
        })
        .to_string();
    post_form(
        service,
        "/token",
        format!(
            "grant_type=refresh_token&refresh_token={refresh}\
             &client_id={CONFIDENTIAL}&client_secret={SECRET}"
        ),
    )
    .await
}

/// RFC 8628 end to end over HTTP: start the grant, approve it at the verification endpoint, poll
/// the token endpoint. Every step is a request; nothing is approved through the library API.
async fn token_device_code(service: &Service) -> Wire {
    let started = post_form(
        service,
        "/device_authorization",
        format!("client_id={CONFIDENTIAL}&client_secret={SECRET}&scope=read"),
    )
    .await;
    assert_eq!(
        started.status,
        http::StatusCode::OK,
        "RFC 8628 s3.2: the device authorization endpoint must answer with a grant: {}",
        started.body
    );
    let doc = started.json();
    let device_code = doc
        .get("device_code")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("RFC 8628 s3.2 requires device_code: {}", started.body))
        .to_string();
    let user_code = doc
        .get("user_code")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("RFC 8628 s3.2 requires user_code: {}", started.body))
        .to_string();

    let poll = format!(
        "grant_type={}&device_code={device_code}&client_id={CONFIDENTIAL}&client_secret={SECRET}",
        urlencode(DEVICE_CODE_GRANT_URN)
    );
    // RFC 8628 s3.5: before approval the answer is authorization_pending, and asserting it here
    // is what stops a "success" that was really the server ignoring the approval step.
    let pending = post_form(service, "/token", poll.clone()).await;
    assert_eq!(
        pending.json().get("error").and_then(|v| v.as_str()),
        Some("authorization_pending"),
        "RFC 8628 s3.5: an unapproved device grant is authorization_pending: {}",
        pending.body
    );

    let approved = post_form(
        service,
        &path_of(VERIFICATION_URI),
        format!("user_code={}", urlencode(&user_code)),
    )
    .await;
    assert_eq!(
        approved.status,
        http::StatusCode::OK,
        "the verification endpoint must accept the user code: {}",
        approved.body
    );

    post_form(service, "/token", poll).await
}

#[cfg(feature = "token-exchange")]
async fn token_exchange(service: &Service) -> Wire {
    // The subject token is itself obtained over the wire, so this proof does not depend on the
    // library API at any point.
    let subject = token_client_credentials(service)
        .await
        .access_token("the subject token for an exchange");
    post_form(
        service,
        "/token",
        format!(
            "grant_type={}&subject_token={subject}&subject_token_type={}\
             &client_id={CONFIDENTIAL}&client_secret={SECRET}",
            urlencode(oauth_as::grant::TOKEN_EXCHANGE_GRANT_URN),
            urlencode("urn:ietf:params:oauth:token-type:access_token"),
        ),
    )
    .await
}

// ---------------------------------------------------------------------------------------------
// THE STRUCTURAL LINK: the metadata document decides what has to be proven
// ---------------------------------------------------------------------------------------------

/// Prove ONE advertised `grant_types_supported` value by redeeming it over HTTP.
///
/// The catch-all arm is the point of the whole file: a grant added to
/// [`oauth_as::metadata::AuthorizationServerMetadata::from_config`] with no wire proof fails here
/// on the next run, rather than being advertised and unreachable for weeks as RFC 8693 was.
async fn prove_grant(fx: &Fixture, grant: &str) {
    match grant {
        "authorization_code" => {
            token_authorization_code(&fx.service, CONFIDENTIAL, Some(SECRET))
                .await
                .access_token("RFC 6749 s4.1 authorization_code over HTTP");
        }
        "refresh_token" => {
            token_refresh(&fx.service)
                .await
                .access_token("RFC 6749 s6 refresh_token over HTTP");
        }
        "client_credentials" => {
            token_client_credentials(&fx.service)
                .await
                .access_token("RFC 6749 s4.4 client_credentials over HTTP");
        }
        DEVICE_CODE_GRANT_URN => {
            token_device_code(&fx.service)
                .await
                .access_token("RFC 8628 device_code over HTTP");
        }
        #[cfg(feature = "token-exchange")]
        oauth_as::grant::TOKEN_EXCHANGE_GRANT_URN => {
            token_exchange(&fx.service)
                .await
                .access_token("RFC 8693 token exchange over HTTP");
        }
        other => panic!(
            "grant_types_supported advertises {other:?}, and nothing in this file redeems it over \
             HTTP. Add the wire proof; do not delete this arm. RFC 8693 token exchange was \
             advertised and answered invalid_client to every client for an unknown number of \
             commits precisely because its only tests drove the library API."
        ),
    }
}

/// RFC 8414 s2 `grant_types_supported`, every entry, end to end over `/token`.
#[tokio::test]
async fn every_advertised_grant_type_is_redeemable_over_http() {
    let fx = fixture().await;
    let doc = metadata(&fx.service).await;
    let grants = advertised(&doc, "grant_types_supported");
    assert!(
        grants.len() >= 4,
        "the document is expected to advertise at least the four core grants: {grants:?}"
    );
    for grant in &grants {
        prove_grant(&fx, grant).await;
    }
}

/// Prove ONE advertised `token_endpoint_auth_methods_supported` value by AUTHENTICATING with it
/// over the wire, at the endpoint the document says it applies to.
///
/// Same catch-all rule, same reason. The two RFC 8705 methods are the one place this returns a
/// refusal rather than a token, and they say why in as many words rather than asserting quietly;
/// see [`the_advertised_mtls_methods_cannot_authenticate_through_this_service`].
async fn prove_auth_method(fx: &Fixture, method: &str) {
    match method {
        // RFC 6749 s2.3.1: the credential in an Authorization header.
        "client_secret_basic" => {
            let response = post_form_with(
                &fx.service,
                "/token",
                "grant_type=client_credentials&scope=read".to_string(),
                &[("authorization", basic_header(CONFIDENTIAL, SECRET))],
            )
            .await;
            response.access_token("client_secret_basic over HTTP");
        }
        // RFC 6749 s2.3.1's "NOT RECOMMENDED" alternative, which this server nonetheless
        // advertises and therefore has to accept.
        "client_secret_post" => {
            token_client_credentials(&fx.service)
                .await
                .access_token("client_secret_post over HTTP");
        }
        // RFC 8414 s2: the value a PUBLIC client sends. Proven with the one grant a public client
        // may complete, code + PKCE, because a public client using client_credentials is refused
        // on its merits (RFC 6749 s4.4) and would prove nothing about authentication.
        "none" => {
            token_authorization_code(&fx.service, PUBLIC, None)
                .await
                .access_token("a public client (auth method none) over HTTP");
        }
        #[cfg(all(feature = "client_assertion", feature = "jwt-p256"))]
        oauth_as::client_assertion::PRIVATE_KEY_JWT => {
            assertion_token(&fx.service, PRIVATE_KEY_JWT_CLIENT, &private_key_jwt())
                .await
                .access_token("RFC 7523 private_key_jwt over HTTP");
        }
        // A build with `client_assertion` and no ES256 BACKEND cannot check an ES256 signature, so
        // it refuses every `private_key_jwt` assertion, so it must not name the method. This arm
        // used to be empty, which recorded the gap honestly but left the advertisement unchecked;
        // it is a panic now because the document is derived from the server's installed seams
        // (`AuthorizationServer::metadata`) and this is the build where that has to be true. The
        // fixture installs no verifier, so reaching this arm means the document is inviting
        // clients to use a method that is refused every time.
        #[cfg(all(feature = "client_assertion", not(feature = "jwt-p256")))]
        oauth_as::client_assertion::PRIVATE_KEY_JWT => panic!(
            "this build has no ES256 backend and no host verifier is installed, so every ES256 \
             assertion is refused. The RFC 8414 document must not advertise private_key_jwt here."
        ),
        #[cfg(feature = "client_assertion")]
        oauth_as::client_assertion::CLIENT_SECRET_JWT => {
            assertion_token(&fx.service, CLIENT_SECRET_JWT_CLIENT, &client_secret_jwt())
                .await
                .access_token("RFC 7523 client_secret_jwt over HTTP");
        }
        #[cfg(feature = "mtls")]
        oauth_as::mtls::TLS_CLIENT_AUTH => {
            mtls_is_refused_through_this_service(&fx.service, TLS_CLIENT_AUTH_CLIENT).await;
        }
        #[cfg(feature = "mtls")]
        oauth_as::mtls::SELF_SIGNED_TLS_CLIENT_AUTH => {
            mtls_is_refused_through_this_service(&fx.service, SELF_SIGNED_TLS_CLIENT).await;
        }
        other => panic!(
            "token_endpoint_auth_methods_supported advertises {other:?}, and nothing in this file \
             authenticates with it over HTTP. A method a client reads out of the metadata document \
             and cannot use is the same lie an unroutable endpoint is."
        ),
    }
}

/// RFC 8414 s2 `token_endpoint_auth_methods_supported`, every entry, over the wire.
#[tokio::test]
async fn every_advertised_token_endpoint_auth_method_is_exercised_over_http() {
    let fx = fixture().await;
    let doc = metadata(&fx.service).await;
    let methods = advertised(&doc, "token_endpoint_auth_methods_supported");
    assert!(
        methods.iter().any(|m| m == "none"),
        "this server accepts public clients, so the document must say so: {methods:?}"
    );
    for method in &methods {
        prove_auth_method(&fx, method).await;
    }
}

/// RFC 8414 s2 `response_types_supported` and `code_challenge_methods_supported`.
///
/// Both are constants in the document today, which is exactly why they are iterated rather than
/// asserted: `plain` appearing in the PKCE list would be a downgrade this server cannot honor
/// (RFC 7636 s4.2), and the catch-all is what turns that from a silent advertisement into a
/// failing test.
#[tokio::test]
async fn every_advertised_response_type_and_pkce_method_is_honoured_over_http() {
    let fx = fixture().await;
    let doc = metadata(&fx.service).await;

    for response_type in advertised(&doc, "response_types_supported") {
        match response_type.as_str() {
            "code" => {
                token_authorization_code(&fx.service, CONFIDENTIAL, Some(SECRET))
                    .await
                    .access_token("response_type=code over HTTP");
            }
            other => panic!(
                "response_types_supported advertises {other:?} and nothing here drives it. OAuth \
                 2.1 removes the implicit grant, so any second value needs both an implementation \
                 and a proof."
            ),
        }
    }

    for method in advertised(&doc, "code_challenge_methods_supported") {
        match method.as_str() {
            // Proven by every authorization-code redemption in this file: the challenge is
            // derived with S256 and the verifier is checked at the token endpoint.
            "S256" => {
                token_authorization_code(&fx.service, PUBLIC, None)
                    .await
                    .access_token("RFC 7636 S256 over HTTP");
            }
            other => panic!(
                "code_challenge_methods_supported advertises {other:?}. `plain` is not \
                 implemented and advertising it invites the downgrade RFC 7636 s7.2 warns about."
            ),
        }
    }
}

/// EVERY advertised endpoint answers something other than 404, with no per-endpoint list written
/// down here: the members are discovered by NAME from the served document.
///
/// RFC 8414 s2 names every endpoint member `*_endpoint`, and `jwks_uri` is the one exception,
/// which is why it is the one string spelled out. A member added to the document later is swept
/// automatically, which is the property that keeps this from rotting.
#[tokio::test]
async fn every_advertised_endpoint_is_routed() {
    for (label, service) in service_variants().await {
        let doc = metadata(&service).await;
        let object = doc.as_object().expect("the document is a JSON object");
        let mut probed = 0usize;
        for (member, value) in object {
            let is_endpoint = member.ends_with("_endpoint") || member == "jwks_uri";
            if !is_endpoint {
                continue;
            }
            let url = match value.as_str() {
                Some(url) => url,
                None => panic!("{label}: {member} must be a string: {value}"),
            };
            let path = path_of(url);
            let by_get = get(&service, &path).await;
            let by_post = post_form(&service, &path, String::new()).await;
            assert!(
                by_get.status != http::StatusCode::NOT_FOUND
                    || by_post.status != http::StatusCode::NOT_FOUND,
                "{label}: the document advertises {member} at {url}, and this service 404s on \
                 {path} for both GET and POST. An advertised endpoint that does not answer is a \
                 promise a client cannot recover from."
            );
            probed += 1;
        }
        assert!(
            probed >= 5,
            "{label}: expected at least authorization, token, device, introspection and \
             revocation to be advertised, swept {probed}"
        );
    }
}

/// EVERY `*_alg_values_supported` member the document publishes, swept the same structural way,
/// against the one question those members exist to answer: can this server actually perform the
/// algorithm it is naming?
///
/// # Why this member family needed its own sweep
///
/// The checklists above cover four of the document's capability lists (grant types, auth methods,
/// response types, PKCE methods). The signing-algorithm lists were not among them, and they are
/// the family where the advertisement became able to lie: they were each derived from FEATURE
/// PRESENCE, and since the ES256 seam a feature no longer implies a backend. `client_assertion`
/// compiles the `Es256Verifier` SEAM in; `jwt-p256` is what compiles an implementation of it, and
/// a host may install its own instead. So a build could advertise ES256 with nothing anywhere in
/// the process able to check an ES256 signature.
///
/// # The rule, and what makes it checkable rather than a restatement
///
/// Every algorithm named in any of these members is one of exactly two kinds:
///
/// - HS256 is symmetric (RFC 7518 s3.2). The key is the registered client secret, there is no
///   curve on the path, and any build with the feature can perform it.
/// - ES256 needs a VERIFIER (RFC 7518 s3.4). This fixture installs none, so the only way the
///   process has one is the built-in `jwt-p256` backend.
///
/// The catch-all PANICS, which is the property that makes this sweep worth having: a third
/// algorithm added to any of these lists, or a whole new `*_alg_values_supported` member added to
/// the document, fails here on the next run rather than shipping as an unproven promise.
///
/// The advertisement is then tied back to something driven over the wire: an algorithm named in
/// `token_endpoint_auth_signing_alg_values_supported` must have its RFC 7523 method named in
/// `token_endpoint_auth_methods_supported` too, and every entry in THAT list is redeemed to a
/// real `access_token` by `every_advertised_token_endpoint_auth_method_is_exercised_over_http`.
/// Without that tie this test would only be comparing the document against a cfg.
#[tokio::test]
async fn every_advertised_signing_algorithm_can_be_performed_by_this_build() {
    // TRUE exactly when an ES256 signature can be checked in this process. No fixture in this
    // file installs a host verifier, so the built-in backend is the only source of one.
    let es256_is_checkable = cfg!(feature = "jwt-p256");

    for (label, service) in service_variants().await {
        let doc = metadata(&service).await;
        let object = doc.as_object().expect("the document is a JSON object");
        let methods = advertised(&doc, "token_endpoint_auth_methods_supported");
        let mut swept = 0usize;

        for (member, value) in object {
            if !member.ends_with("_alg_values_supported") {
                continue;
            }
            let algs = advertised(&doc, member);
            assert!(
                !algs.is_empty(),
                "{label}: {member} is present and empty, which advertises a capability with no \
                 algorithm a client could use: {value}"
            );
            for alg in &algs {
                match alg.as_str() {
                    "HS256" => {
                        // RFC 7523 s2.2: the only member that may name HS256 is the token
                        // endpoint's, and only because `client_secret_jwt` is an HMAC over the
                        // registered secret. A DPoP proof or a request object signed HS256 would
                        // be signed with a secret the CLIENT and this server share, which is not
                        // proof of possession of anything (RFC 8725 s3.5).
                        assert_eq!(
                            member, "token_endpoint_auth_signing_alg_values_supported",
                            "{label}: {member} names HS256, and a shared secret is not a \
                             signature for that member's purpose"
                        );
                        assert!(
                            methods.iter().any(|m| m == "client_secret_jwt"),
                            "{label}: HS256 is advertised for client authentication but \
                             client_secret_jwt is not among {methods:?}, so no client can use it"
                        );
                    }
                    "ES256" => {
                        assert!(
                            es256_is_checkable,
                            "{label}: {member} advertises ES256 and this build has no ES256 \
                             backend and no installed host verifier, so every credential a \
                             client signs under it is refused. This is the exact advertisement \
                             that must be derived from the installed verifier and not from a \
                             cargo feature."
                        );
                        if member == "token_endpoint_auth_signing_alg_values_supported" {
                            assert!(
                                methods.iter().any(|m| m == "private_key_jwt"),
                                "{label}: ES256 is advertised for client authentication but \
                                 private_key_jwt is not among {methods:?}"
                            );
                        }
                    }
                    other => panic!(
                        "{label}: {member} advertises {other:?} and nothing here proves this \
                         server can perform it. Adding an algorithm to an RFC 8414 list is a \
                         promise to every client that reads the document, so it needs a proof \
                         here, not just an entry there."
                    ),
                }
            }
            swept += 1;
        }

        // The converse, so the sweep cannot pass by finding nothing. `client_assertion` always
        // produces `token_endpoint_auth_signing_alg_values_supported` (HS256 at minimum, because
        // `client_secret_jwt` needs no backend), so in that build there is at least one member to
        // sweep and a document that dropped the family entirely is caught.
        #[cfg(feature = "client_assertion")]
        assert!(
            swept >= 1,
            "{label}: this build has client_assertion, so the document must carry \
             token_endpoint_auth_signing_alg_values_supported: {doc}"
        );
        let _ = swept;
    }
}

/// The service variants worth sweeping. The signing one exists so that `jwks_uri`, which is
/// advertised exactly when this server signs its access tokens, is covered by the sweep above
/// rather than by a hand-written exception.
async fn service_variants() -> Vec<(&'static str, Service)> {
    // The `mut` is needed only by the `jwt-p256` push below, so without a backend it is an
    // unused_mut, which `-D warnings` makes fatal in exactly the CI job that exists to compile
    // this build. Allowed rather than restructured: the alternative spellings either hide which
    // variant is conditional or rebuild the vector to dodge a lint.
    #[cfg_attr(not(feature = "jwt-p256"), allow(unused_mut))]
    let mut variants = vec![("opaque tokens", fixture().await.service)];
    #[cfg(feature = "jwt-p256")]
    {
        variants.push(("signed access tokens", signing_service().await));
    }
    variants
}

#[cfg(feature = "jwt-p256")]
async fn signing_service() -> Service {
    use oauth_as::jwt::{AccessTokenFormat, EcdsaP256Key, JwtConfig};

    let key = EcdsaP256Key::generate("wire-key");
    let mut config = base_config();
    config.access_token_format = AccessTokenFormat::Jwt(Box::new(
        JwtConfig::new(key, "https://rs.example/api").with_jwks_uri(format!("{ISSUER}/jwks")),
    ));
    let server = AuthorizationServer::new(config, MemoryStorage::new())
        .with_registration_policy(Box::new(AllowRegistration));
    server
        .register_client(confidential_client())
        .await
        .expect("register the confidential client");
    ServiceBuilder::new(Arc::new(server))
        .with_subject_resolver(|_headers| Some("resource-owner-1".to_string()))
        .with_consent_resolver(|_request| ConsentDecision::Approve)
        .build()
        .expect("a signing service builds")
}

/// RFC 7592 s3: the management URL this server MINTS for a dynamically registered client has to
/// be one this server answers on. It carries a path segment no static route table can contain, so
/// it is the one endpoint the sweep above cannot reach, and it gets its own proof.
#[tokio::test]
async fn the_registration_management_url_this_server_mints_is_one_it_answers() {
    let fx = fixture().await;
    let doc = metadata(&fx.service).await;
    let register = doc
        .get("registration_endpoint")
        .and_then(|v| v.as_str())
        .expect("the fixture enables dynamic registration");

    let request = http::Request::builder()
        .method("POST")
        .uri(path_of(register))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code"],"response_types":["code"]}"#,
        ))
        .expect("a well-formed request");
    let created = send(&fx.service, request).await;
    assert_eq!(
        created.status,
        http::StatusCode::CREATED,
        "RFC 7591 s3.2.1: a successful registration is a 201: {}",
        created.body
    );
    let body = created.json();
    let manage = body
        .get("registration_client_uri")
        .and_then(|v| v.as_str())
        .expect("RFC 7592 s3: a manageable registration carries registration_client_uri")
        .to_string();
    let token = body
        .get("registration_access_token")
        .and_then(|v| v.as_str())
        .expect("RFC 7592 s3: and the token that opens it")
        .to_string();

    let read = http::Request::builder()
        .method("GET")
        .uri(path_of(&manage))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("a well-formed request");
    let read = send(&fx.service, read).await;
    assert_eq!(
        read.status,
        http::StatusCode::OK,
        "the registration_client_uri this server minted must be one it answers: {}",
        read.body
    );
}

// ---------------------------------------------------------------------------------------------
// RFC 7009 / RFC 7662: what a PUBLIC client may do at the two protected endpoints
// ---------------------------------------------------------------------------------------------

/// RFC 7009 s2.1 and s5: a PUBLIC client may revoke its own token.
///
/// Section 2.1 scopes credential validation explicitly: the server "first validates the client
/// credentials (in case of a confidential client) and then verifies whether the token was issued
/// to the client making the revocation request". Section 5 spells out the public case: "a valid
/// `client_id`, in the case of a public client". The ownership check is the access control here,
/// and it is a check this server already performs on the token record itself.
///
/// This server issues tokens to public clients through code + PKCE and through the device grant,
/// so refusing them the only standard way to invalidate one leaves a mobile app with no logout
/// that means anything: the token stays live for its whole TTL and the refresh chain outlives the
/// user's decision entirely.
#[tokio::test]
async fn a_public_client_may_revoke_its_own_token_over_http() {
    let fx = fixture().await;
    let issued = token_authorization_code(&fx.service, PUBLIC, None).await;
    let access = issued.access_token("a public client's own access token");

    let revoked = post_form(
        &fx.service,
        "/revoke",
        format!("token={access}&token_type_hint=access_token&client_id={PUBLIC}"),
    )
    .await;
    assert_eq!(
        revoked.status,
        http::StatusCode::OK,
        "RFC 7009 s2.1: a public client revoking its own token is a 200: {}",
        revoked.body
    );

    // The 200 is not the property that matters; RFC 7009 s2.2 makes an unknown token a 200 too.
    // What matters is that the token is GONE, read back through the library so this assertion
    // cannot be satisfied by the endpoint merely answering politely.
    let still_live = fx
        .server
        .introspect(&access)
        .await
        .expect("the store answers");
    assert!(
        still_live.is_none(),
        "the token a public client asked to revoke must actually be revoked"
    );
}

/// RFC 7009 s2.1's ownership check, which is what makes the above safe: naming a public client id
/// is not authentication, so the check has to be against the TOKEN, and it is.
#[tokio::test]
async fn a_public_client_cannot_revoke_a_token_that_is_not_its_own() {
    let fx = fixture().await;
    let victim = token_client_credentials(&fx.service)
        .await
        .access_token("the confidential client's token");

    let attempt = post_form(
        &fx.service,
        "/revoke",
        format!("token={victim}&token_type_hint=access_token&client_id={PUBLIC}"),
    )
    .await;
    // RFC 7009 s2.2: the answer is a 200 either way, because distinguishing "revoked" from "not
    // yours" would make this endpoint an oracle for whether a token string is real.
    assert_eq!(
        attempt.status,
        http::StatusCode::OK,
        "RFC 7009 s2.2: an unrevokable token is still a 200: {}",
        attempt.body
    );
    let survived = fx
        .server
        .introspect(&victim)
        .await
        .expect("the store answers");
    assert!(
        survived.is_some(),
        "a public client must not be able to revoke another client's token by naming its own id"
    );
}

/// RFC 7662 s4: introspection MUST NOT be publicly available, and this refusal STAYS.
///
/// The contrast with revocation above is the whole point, and the two arrived bundled under one
/// citation pair that only supported this half. Revocation is a request to DESTROY a token the
/// caller already holds, checked against that token's owner; introspection is a request to
/// DESCRIBE one, and "authenticated as a public client" is a sentence true of every caller on the
/// internet. A public introspection endpoint describes any token an attacker has merely obtained
/// a copy of.
#[tokio::test]
async fn introspection_stays_closed_to_public_clients_over_http() {
    let fx = fixture().await;
    let issued = token_authorization_code(&fx.service, PUBLIC, None).await;
    let access = issued.access_token("a public client's own access token");

    let response = post_form(
        &fx.service,
        "/introspect",
        format!("token={access}&client_id={PUBLIC}"),
    )
    .await;
    assert_eq!(
        response.json().get("error").and_then(|v| v.as_str()),
        Some("invalid_client"),
        "RFC 7662 s4: the introspection endpoint must not be publicly available: {}",
        response.body
    );
}

/// The confidential path at both endpoints, so that the two tests above are known to be about
/// PUBLIC clients rather than about a pair of endpoints that refuse everybody.
#[tokio::test]
async fn a_confidential_client_introspects_and_revokes_over_http() {
    let fx = fixture().await;
    let access = token_client_credentials(&fx.service)
        .await
        .access_token("a confidential client's token");

    let live = post_form(
        &fx.service,
        "/introspect",
        format!("token={access}&client_id={CONFIDENTIAL}&client_secret={SECRET}"),
    )
    .await;
    assert_eq!(
        live.json().get("active").and_then(|v| v.as_bool()),
        Some(true),
        "RFC 7662 s2.2: the caller's own live token is active: {}",
        live.body
    );

    let revoked = post_form(
        &fx.service,
        "/revoke",
        format!("token={access}&client_id={CONFIDENTIAL}&client_secret={SECRET}"),
    )
    .await;
    assert_eq!(
        revoked.status,
        http::StatusCode::OK,
        "RFC 7009 s2.2: {}",
        revoked.body
    );
    assert!(
        fx.server
            .introspect(&access)
            .await
            .expect("the store answers")
            .is_none(),
        "the revocation must take effect"
    );
}

// ---------------------------------------------------------------------------------------------
// RFC 9126 PAR, over the wire, because the document advertises it
// ---------------------------------------------------------------------------------------------

/// RFC 9126 s5: the presence of `pushed_authorization_request_endpoint` is sufficient for a client
/// to decide it may push. So the push has to work AND the handle it mints has to be redeemable at
/// the authorization endpoint, which is the half a routing test alone would miss.
#[cfg(feature = "par")]
#[tokio::test]
async fn the_advertised_par_endpoint_completes_a_flow_over_http() {
    let fx = fixture().await;
    let doc = metadata(&fx.service).await;
    let endpoint = doc
        .get("pushed_authorization_request_endpoint")
        .and_then(|v| v.as_str())
        .expect("the fixture enables PAR, so the document must advertise it");

    let challenge = oauth_as::pkce::code_challenge_s256(VERIFIER);
    let pushed = post_form(
        &fx.service,
        &path_of(endpoint),
        format!(
            "response_type=code&client_id={CONFIDENTIAL}&client_secret={SECRET}\
             &redirect_uri={}&scope=read&code_challenge={challenge}&code_challenge_method=S256",
            urlencode(REDIRECT)
        ),
    )
    .await;
    assert_eq!(
        pushed.status,
        http::StatusCode::CREATED,
        "RFC 9126 s2.2: a successful push is a 201: {}",
        pushed.body
    );
    let request_uri = pushed
        .json()
        .get("request_uri")
        .and_then(|v| v.as_str())
        .expect("RFC 9126 s2.2 requires request_uri")
        .to_string();

    let redirected = get(
        &fx.service,
        &format!(
            "/authorize?client_id={CONFIDENTIAL}&request_uri={}",
            urlencode(&request_uri)
        ),
    )
    .await;
    assert_eq!(
        redirected.status,
        http::StatusCode::FOUND,
        "a pushed request must be redeemable at the authorization endpoint: {}",
        redirected.body
    );
    let location = redirected.location.expect("a redirect carries a Location");
    let code = query_param(&location, "code").expect("a code in the redirect");

    let token = post_form(
        &fx.service,
        "/token",
        format!(
            "grant_type=authorization_code&code={code}&redirect_uri={}\
             &code_verifier={VERIFIER}&client_id={CONFIDENTIAL}&client_secret={SECRET}",
            urlencode(REDIRECT)
        ),
    )
    .await;
    token.access_token("a PAR-initiated authorization code redemption over HTTP");
}

// ---------------------------------------------------------------------------------------------
// RFC 9728, and where its document actually lives
// ---------------------------------------------------------------------------------------------

/// RFC 9728 s3.1 places the protected resource metadata document under the RESOURCE's own
/// identifier, not under the authorization server's issuer, so this service does NOT serve it and
/// must not be expected to.
///
/// This is a boundary rather than a gap, and the assertion is here so a reader looking for the
/// "second metadata document" finds the answer instead of a hole: the AS half of RFC 9728 is
/// section 4's `protected_resources` member, which this document does carry, and the resource half
/// is the host's, demonstrated by `examples/protected_resource_fixture.rs`.
#[cfg(feature = "resource-metadata")]
#[tokio::test]
async fn the_rfc_9728_resource_document_is_the_resources_to_serve_not_this_servers() {
    let fx = fixture().await;
    let doc = metadata(&fx.service).await;
    let resources = advertised(&doc, "protected_resources");
    assert_eq!(
        resources,
        vec!["https://rs.example/api".to_string()],
        "RFC 9728 s4: the AS states which resources it issues tokens for"
    );

    let path = oauth_as::resource_metadata::well_known_path("https://rs.example/api");
    let response = get(&fx.service, &path).await;
    assert_eq!(
        response.status,
        http::StatusCode::NOT_FOUND,
        "RFC 9728 s3.1 puts this document under the RESOURCE's origin. An authorization server \
         that served it would be asserting something about a resource on the resource's behalf."
    );
}

// ---------------------------------------------------------------------------------------------
// RFC 7523 client assertions, over the wire
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "client_assertion")]
const CLIENT_SECRET_JWT_CLIENT: &str = "csjwt-app";
#[cfg(all(feature = "client_assertion", feature = "jwt-p256"))]
const PRIVATE_KEY_JWT_CLIENT: &str = "pkjwt-app";

/// The ES256 key the `private_key_jwt` fixture signs with. Generated ONCE so the registration and
/// the assertion agree; a per-call key would make every assertion fail for the right reason and
/// prove nothing.
#[cfg(all(feature = "client_assertion", feature = "jwt-p256"))]
fn assertion_key() -> &'static oauth_as::jwt::EcdsaP256Key {
    use std::sync::OnceLock;
    static KEY: OnceLock<oauth_as::jwt::EcdsaP256Key> = OnceLock::new();
    KEY.get_or_init(|| oauth_as::jwt::EcdsaP256Key::generate("wire-assertion-key"))
}

#[cfg(feature = "client_assertion")]
async fn register_assertion_clients(server: &AuthorizationServer<MemoryStorage, SystemClock>) {
    use oauth_as::client_assertion::{AssertionKeys, ClientSecretKey};

    let mut csjwt = confidential_client();
    csjwt.client_id = ClientId::new(CLIENT_SECRET_JWT_CLIENT);
    csjwt.auth = ClientAuth::ConfidentialAssertion {
        keys: AssertionKeys::ClientSecret {
            secret: ClientSecretKey::new(SECRET).expect("the fixture secret clears the floor"),
        },
    };
    server
        .register_client(csjwt)
        .await
        .expect("register the client_secret_jwt client");

    #[cfg(feature = "jwt-p256")]
    {
        let mut pkjwt = confidential_client();
        pkjwt.client_id = ClientId::new(PRIVATE_KEY_JWT_CLIENT);
        pkjwt.auth = ClientAuth::ConfidentialAssertion {
            keys: AssertionKeys::PublicKeys {
                keys: vec![assertion_key().to_public_jwk()],
            },
        };
        server
            .register_client(pkjwt)
            .await
            .expect("register the private_key_jwt client");
    }
}

/// An RFC 7523 s3 claim set naming this server's token endpoint as the audience.
#[cfg(feature = "client_assertion")]
fn assertion_claims(client_id: &str, jti: &str) -> Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs();
    serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": TOKEN_ENDPOINT,
        "exp": now + 120,
        "iat": now,
        "jti": jti,
    })
}

#[cfg(feature = "client_assertion")]
fn client_secret_jwt() -> String {
    client_secret_jwt_with_jti("wire-cs-1")
}

/// The same, with the caller's own `jti`. RFC 7523 s3 makes it single use, so a test that
/// authenticates twice needs two of them; reusing one would be refused as the replay it is.
#[cfg(feature = "client_assertion")]
fn client_secret_jwt_with_jti(jti: &str) -> String {
    oauth_as::jwt::compact_jws(
        br#"{"alg":"HS256","typ":"JWT"}"#,
        &serde_json::to_vec(&assertion_claims(CLIENT_SECRET_JWT_CLIENT, jti))
            .expect("serializable claims"),
        |input| oauth_as::jwt::hmac_sha256(SECRET.as_bytes(), input.as_bytes()).to_vec(),
    )
}

/// RFC 7009 s2.1 AND RFC 7662 s2.1 for a client whose credential is an ASSERTION.
///
/// The token endpoint is not the only endpoint that authenticates a client, and this is the test
/// that says so over the wire. Every protected endpoint in this router resolves a credential the
/// same way, and each one has to PASS it on; revocation dropped it and forwarded only
/// `client_secret`, which for an assertion-authenticated client is `None`, so a `private_key_jwt`
/// or `client_secret_jwt` client could never revoke anything through this service. That is the
/// same defect, in the same shape and from the same cause, as the RFC 8693 token exchange one
/// this whole file was written in reaction to: an arm that was not updated when credentials moved
/// onto the request context, invisible because the revocation suite drives the library API.
///
/// Both endpoints are asserted together on purpose: one authenticates and the other does too, and
/// a fix that reached only the endpoint somebody happened to test is how the first one survived.
#[cfg(feature = "client_assertion")]
#[tokio::test]
async fn an_assertion_authenticated_client_may_introspect_and_revoke_over_http() {
    let fx = fixture().await;
    let access = assertion_token(
        &fx.service,
        CLIENT_SECRET_JWT_CLIENT,
        &client_secret_jwt_with_jti("wire-cs-revoke-issue"),
    )
    .await
    .access_token("RFC 7523 client_secret_jwt over HTTP");

    let live = post_form(
        &fx.service,
        "/introspect",
        assertion_form(
            &format!("token={access}"),
            &client_secret_jwt_with_jti("wire-cs-revoke-introspect"),
        ),
    )
    .await;
    assert_eq!(
        live.json().get("active").and_then(|v| v.as_bool()),
        Some(true),
        "RFC 7662 s2.2: an assertion authenticates at the introspection endpoint too: {}",
        live.body
    );

    let revoked = post_form(
        &fx.service,
        "/revoke",
        assertion_form(
            &format!("token={access}&token_type_hint=access_token"),
            &client_secret_jwt_with_jti("wire-cs-revoke-revoke"),
        ),
    )
    .await;
    assert_eq!(
        revoked.status,
        http::StatusCode::OK,
        "RFC 7009 s2.2: {}",
        revoked.body
    );
    // The 200 proves nothing on its own (s2.2 answers 200 to an unknown token as well), so the
    // token is read back through the library. This is the assertion that was failing: the request
    // was refused with `invalid_client` and the token stayed live.
    assert!(
        fx.server
            .introspect(&access)
            .await
            .expect("the store answers")
            .is_none(),
        "an assertion-authenticated client's revocation must actually revoke"
    );
}

/// One form body carrying the RFC 7521 s4.2 assertion parameters plus whatever the endpoint's own
/// parameters are.
#[cfg(feature = "client_assertion")]
fn assertion_form(endpoint_parameters: &str, assertion: &str) -> String {
    format!(
        "{endpoint_parameters}&client_id={CLIENT_SECRET_JWT_CLIENT}\
         &client_assertion_type={}&client_assertion={assertion}",
        urlencode(oauth_as::client_assertion::CLIENT_ASSERTION_TYPE)
    )
}

#[cfg(all(feature = "client_assertion", feature = "jwt-p256"))]
fn private_key_jwt() -> String {
    oauth_as::jwt::compact_jws(
        br#"{"alg":"ES256","typ":"JWT"}"#,
        &serde_json::to_vec(&assertion_claims(PRIVATE_KEY_JWT_CLIENT, "wire-pk-1"))
            .expect("serializable claims"),
        |input| {
            assertion_key()
                .sign_signing_input(input)
                .expect("the fixture key signs")
        },
    )
}

/// Post an RFC 7523 assertion at the token endpoint, exactly as RFC 7521 s4.2 spells it.
#[cfg(feature = "client_assertion")]
async fn assertion_token(service: &Service, client_id: &str, assertion: &str) -> Wire {
    post_form(
        service,
        "/token",
        format!(
            "grant_type=client_credentials&scope=read&client_id={client_id}\
             &client_assertion_type={}&client_assertion={assertion}",
            urlencode(oauth_as::client_assertion::CLIENT_ASSERTION_TYPE)
        ),
    )
    .await
}

// ---------------------------------------------------------------------------------------------
// RFC 8705, and the one advertised capability this service cannot deliver
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "mtls")]
const TLS_CLIENT_AUTH_CLIENT: &str = "mtls-ca-app";
#[cfg(feature = "mtls")]
const SELF_SIGNED_TLS_CLIENT: &str = "mtls-self-app";

#[cfg(feature = "mtls")]
async fn register_mtls_clients(server: &AuthorizationServer<MemoryStorage, SystemClock>) {
    use oauth_as::mtls::{ExpectedSubject, MtlsClientRegistration, RegisteredCertificates};

    let mut ca = confidential_client();
    ca.client_id = ClientId::new(TLS_CLIENT_AUTH_CLIENT);
    ca.auth = ClientAuth::Mtls {
        registration: MtlsClientRegistration::TlsClientAuth(ExpectedSubject::SanDns(
            "client.example".to_string(),
        )),
    };
    server
        .register_client(ca)
        .await
        .expect("register the tls_client_auth client");

    let mut self_signed = confidential_client();
    self_signed.client_id = ClientId::new(SELF_SIGNED_TLS_CLIENT);
    self_signed.auth = ClientAuth::Mtls {
        registration: MtlsClientRegistration::SelfSignedTlsClientAuth(
            RegisteredCertificates::from_der_certificates([&b"a fixture certificate"[..]])
                .expect("one certificate is a valid registration"),
        ),
    };
    server
        .register_client(self_signed)
        .await
        .expect("register the self_signed_tls_client_auth client");
}

/// A shared assertion so the two RFC 8705 arms of [`prove_auth_method`] say the same thing.
#[cfg(feature = "mtls")]
async fn mtls_is_refused_through_this_service(service: &Service, client_id: &str) {
    let response = post_form(
        service,
        "/token",
        format!("grant_type=client_credentials&scope=read&client_id={client_id}"),
    )
    .await;
    assert_eq!(
        response.json().get("error").and_then(|v| v.as_str()),
        Some("invalid_client"),
        "an mTLS client authenticating through this service sees invalid_client, because the \
         service never sees the TLS layer: {}",
        response.body
    );
}

/// FINDING, recorded rather than papered over: RFC 8705's two authentication methods are
/// ADVERTISED by a build with the `mtls` feature and CANNOT succeed through
/// [`AuthorizationService`], in any configuration.
///
/// `http.rs`'s `Credentials::credential` sets `certificate: None` unconditionally, and it is right
/// to: this service is handed an already-parsed request, it does not terminate TLS, and reading a
/// certificate out of a proxy header here would trust a header on every deployment's behalf rather
/// than on the one host that knows whether its terminator can be trusted. So the limitation is a
/// deliberate trust boundary, not a bug in this file's sense.
///
/// It is still an advertised capability a client cannot use, which is the exact shape of defect
/// this whole file exists to find, so it is pinned here with the consequence spelled out: a host
/// that terminates mTLS must call
/// [`oauth_as::server::AuthorizationServer::token_with_context`] (or the other
/// `*_with_credential` entry points) with a `ClientCredential::certificate` it verified itself,
/// and a host that mounts only this service must not register mTLS clients, because the metadata
/// document will invite them and the token endpoint will refuse them.
///
/// If this test ever goes RED because the token arrived, then either the service grew a way to
/// see a certificate (in which case say so here) or it started trusting a header (in which case
/// read `crate::mtls`'s trust boundary section before going any further).
#[cfg(feature = "mtls")]
#[tokio::test]
async fn the_advertised_mtls_methods_cannot_authenticate_through_this_service() {
    let fx = fixture().await;
    let doc = metadata(&fx.service).await;
    let methods = advertised(&doc, "token_endpoint_auth_methods_supported");
    assert!(
        methods.iter().any(|m| m == oauth_as::mtls::TLS_CLIENT_AUTH)
            && methods
                .iter()
                .any(|m| m == oauth_as::mtls::SELF_SIGNED_TLS_CLIENT_AUTH),
        "an mtls build advertises both RFC 8705 methods: {methods:?}"
    );
    mtls_is_refused_through_this_service(&fx.service, TLS_CLIENT_AUTH_CLIENT).await;
    mtls_is_refused_through_this_service(&fx.service, SELF_SIGNED_TLS_CLIENT).await;
}

// ---------------------------------------------------------------------------------------------
// Small helpers used by more than one proof
// ---------------------------------------------------------------------------------------------

/// RFC 6749 s2.3.1: the id and the secret are each form-urlencoded, joined with a colon, and
/// base64ed. Neither fixture value contains a character the encoding escapes, so this is the
/// straightforward form and stays readable.
fn basic_header(client_id: &str, secret: &str) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}
