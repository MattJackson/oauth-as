// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9126 pushed authorization requests and RFC 9101 signed request objects, over the wire the
//! `http` feature's router actually serves.
//!
//! Why this file exists as a separate suite rather than as more cases in `http_surface.rs`: the
//! property under test is not "PAR works", which `tests/par.rs` already pins through the public
//! API. It is that the ROUTER and the RFC 8414 metadata document agree. That document advertises
//! `pushed_authorization_request_endpoint` exactly when the host enabled PAR, and this crate's
//! router derives its routes from that same document precisely so that an advertised endpoint
//! cannot 404. A client that reads the document and gets a 404 has been lied to in the one place
//! it had no way to check first, and it cannot recover: RFC 9126 section 5 says the member's
//! presence is sufficient for a client to decide it may use PAR.
//!
//! Everything is spoken as HTTP/1.1 by hand, for the reason `http_surface.rs` gives: the status
//! line and the headers (201 rather than 200 per RFC 9126 section 2.2, `Cache-Control: no-store`
//! per RFC 6749 section 5.1) are exactly what a convenience client hides.

// Gated on `axum`, not `http`, because this file binds a real listener and speaks to it: that
// needs `axum::serve` and tokio's net and io, and both arrive with the `axum` feature rather than
// with `http`. `http,par` without `axum` is a legal configuration (a host mounting
// `AuthorizationService` on its own stack), and under it this file must not exist at all. `axum`
// implies `http`, so naming both would be redundant.
#![cfg(all(feature = "axum", feature = "par"))]

use std::net::SocketAddr;
use std::sync::Arc;

use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::grant::GrantType;
use oauth_as::http::{ConsentDecision, ServiceBuilder};
use oauth_as::par::ParConfig;
use oauth_as::scope::ScopeSet;
use oauth_as::server::{AuthorizationServer, ServerConfig};
use oauth_as::store::MemoryStorage;
use serde_json::Value;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const CONFIDENTIAL_ID: &str = "par-confidential";
const SECRET: &str = "par-secret-0123456789";
const REDIRECT_URI: &str = "http://127.0.0.1:9999/cb";
/// RFC 7636 appendix B's verifier and the S256 challenge it hashes to, so the pushed request
/// carries a real challenge rather than a 43-character lookalike.
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// A parsed HTTP/1.1 response, with header names lowercased so lookups need no case juggling.
struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("body is not JSON ({e}): {:?}", self.body))
    }
}

/// One HTTP/1.1 exchange. `Connection: close` means the response ends at EOF, so reading it whole
/// needs no chunked or content-length parsing.
async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&str>,
) -> Resp {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    match body {
        Some(b) => {
            req.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
            req.push_str(&format!("Content-Length: {}\r\n\r\n", b.len()));
            req.push_str(b);
        }
        None => req.push_str("\r\n"),
    }
    stream.write_all(req.as_bytes()).await.expect("write");
    stream.flush().await.expect("flush");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("malformed response: {text:?}"));
    let mut lines = head.split("\r\n");
    let status_line = lines.next().expect("status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no status code in {status_line:?}"));
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Resp {
        status,
        headers,
        body: body.to_string(),
    }
}

/// Bind an ephemeral port and serve a router for a server with PAR enabled.
///
/// The issuer is the bound address, so the RFC 8414 section 3.3 issuer/URL relation holds exactly
/// as it must for a real host, and the advertised PAR endpoint is therefore under the issuer.
async fn start(require_par: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let issuer = format!("http://{addr}");
    let mut config = ServerConfig::new(issuer.clone(), format!("{issuer}/device"));
    config.par = Some(Box::new(ParConfig {
        require_pushed_authorization_requests: require_par,
        ..ParConfig::new()
    }));
    let server = Arc::new(AuthorizationServer::new(config, MemoryStorage::new()));

    let scopes = ScopeSet::from_tokens(["read", "write"]).expect("scopes");
    server
        .register_client(Client {
            client_id: ClientId::new(CONFIDENTIAL_ID),
            auth: ClientAuth::ConfidentialSecret {
                secret: SECRET.to_string(),
            },
            grant_types: vec![GrantType::AuthorizationCode],
            redirect_uris: vec![REDIRECT_URI.to_string()],
            allowed_scopes: scopes.clone(),
            default_scopes: scopes,
            name: None,
            registration: None,
        })
        .await
        .expect("register confidential");

    let service = ServiceBuilder::new(server)
        .with_subject_resolver(|_headers| Some("test-user".to_string()))
        .with_consent_resolver(|_req| ConsentDecision::Approve)
        .build()
        .expect("service");
    let router = axum::Router::from(service);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    addr
}

/// The RFC 8414 document this server publishes.
async fn metadata(addr: SocketAddr) -> Value {
    request(
        addr,
        "GET",
        "/.well-known/oauth-authorization-server",
        &[],
        None,
    )
    .await
    .json()
}

/// The advertised PAR endpoint's PATH, taken from the document rather than assumed, because
/// "advertised" is the whole property under test.
async fn par_path(addr: SocketAddr) -> String {
    let doc = metadata(addr).await;
    let url = doc["pushed_authorization_request_endpoint"]
        .as_str()
        .expect("the document must advertise pushed_authorization_request_endpoint")
        .to_string();
    let issuer = format!("http://{addr}");
    url.strip_prefix(&issuer)
        .unwrap_or_else(|| panic!("advertised PAR endpoint {url} is not under the issuer"))
        .to_string()
}

/// HTTP Basic for the confidential client, per RFC 6749 section 2.3.1.
fn basic() -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{CONFIDENTIAL_ID}:{SECRET}"))
    )
}

/// The form body of a well formed pushed authorization request.
fn push_body() -> String {
    format!(
        "response_type=code&client_id={CONFIDENTIAL_ID}\
         &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb\
         &scope=read&state=xyz\
         &code_challenge={CHALLENGE}&code_challenge_method=S256"
    )
}

/// THE ROUTING PROPERTY. The document advertises the endpoint, so the endpoint answers.
///
/// RFC 9126 section 2.2 fixes the success status at 201, and the body carries a capability handle,
/// so RFC 6749 section 5.1's caching directives apply to it exactly as they do to a token
/// response.
#[tokio::test]
async fn the_advertised_pushed_authorization_request_endpoint_is_served() {
    let addr = start(false).await;
    let path = par_path(addr).await;

    let resp = request(
        addr,
        "POST",
        &path,
        &[("Authorization", &basic())],
        Some(&push_body()),
    )
    .await;

    assert_ne!(
        resp.status, 404,
        "the RFC 8414 document advertises {path} and the router does not serve it"
    );
    assert_eq!(
        resp.status, 201,
        "RFC 9126 s2.2 requires 201 Created: {:?}",
        resp.body
    );
    let body = resp.json();
    let uri = body["request_uri"]
        .as_str()
        .expect("request_uri is REQUIRED (RFC 9126 s2.2)");
    assert!(
        uri.starts_with(oauth_as::par::REQUEST_URI_PREFIX),
        "unexpected request_uri form: {uri}"
    );
    assert!(
        body["expires_in"].as_u64().is_some_and(|n| n > 0),
        "expires_in is REQUIRED and positive (RFC 9126 s2.2)"
    );
    let cache = resp.header("cache-control").unwrap_or_default();
    assert!(
        cache.contains("no-store"),
        "the response carries a capability handle, so RFC 6749 s5.1 applies: {cache:?}"
    );
    assert_eq!(
        resp.header("content-type"),
        Some("application/json;charset=UTF-8")
    );
}

/// RFC 9126 section 2.1 step 1: the client authenticates here exactly as at the token endpoint,
/// so an unauthenticated push is refused in the RFC 6749 section 5.2 shape rather than accepted.
///
/// The 401 carries `WWW-Authenticate` because header credentials were attempted, which is the same
/// rule the token endpoint follows (RFC 9110 section 15.5.2).
#[tokio::test]
async fn a_push_with_the_wrong_secret_is_refused_like_the_token_endpoint() {
    use base64::Engine as _;
    let addr = start(false).await;
    let path = par_path(addr).await;
    let wrong = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("{CONFIDENTIAL_ID}:not-the-secret"))
    );

    let resp = request(
        addr,
        "POST",
        &path,
        &[("Authorization", &wrong)],
        Some(&push_body()),
    )
    .await;

    assert_eq!(resp.status, 401, "body was {:?}", resp.body);
    assert_eq!(resp.json()["error"], "invalid_client");
    assert!(resp.header("www-authenticate").is_some());
}

/// The other half of the routing property: a handle is worth nothing unless the AUTHORIZATION
/// endpoint accepts it. RFC 9126 section 4.
///
/// Section 4 also says every other query parameter is ignored, so this request deliberately sends
/// a `scope=write` alongside the handle that pushed `scope=read`, and the code that comes back
/// must be for what was pushed.
#[tokio::test]
async fn a_request_uri_is_accepted_at_the_authorization_endpoint() {
    let addr = start(false).await;
    let path = par_path(addr).await;
    let pushed = request(
        addr,
        "POST",
        &path,
        &[("Authorization", &basic())],
        Some(&push_body()),
    )
    .await;
    assert_eq!(pushed.status, 201, "body was {:?}", pushed.body);
    let request_uri = pushed.json()["request_uri"]
        .as_str()
        .expect("request_uri")
        .to_string();
    let encoded = request_uri.replace(':', "%3A");

    let authorized = request(
        addr,
        "GET",
        &format!("/authorize?client_id={CONFIDENTIAL_ID}&request_uri={encoded}&scope=write"),
        &[],
        None,
    )
    .await;

    assert_eq!(
        authorized.status, 302,
        "the authorization endpoint did not act on the request_uri: {:?}",
        authorized.body
    );
    let location = authorized.header("location").expect("Location");
    assert!(
        location.starts_with(REDIRECT_URI),
        "redirected somewhere unexpected: {location}"
    );
    assert!(location.contains("code="), "no code in {location}");
    // The pushed `state` travelled with the handle, not with the query.
    assert!(
        location.contains("state=xyz"),
        "no pushed state in {location}"
    );
}

/// RFC 9126 section 4 and section 7.3: a `request_uri` is single use. The second presentation is
/// the replay, and it is refused DIRECTLY rather than redirected, because the redirect URI lives
/// inside a record that no longer exists.
#[tokio::test]
async fn a_request_uri_cannot_be_replayed_through_the_router() {
    let addr = start(false).await;
    let path = par_path(addr).await;
    let request_uri = request(
        addr,
        "POST",
        &path,
        &[("Authorization", &basic())],
        Some(&push_body()),
    )
    .await
    .json()["request_uri"]
        .as_str()
        .expect("request_uri")
        .to_string();
    let encoded = request_uri.replace(':', "%3A");
    let query = format!("/authorize?client_id={CONFIDENTIAL_ID}&request_uri={encoded}");

    let first = request(addr, "GET", &query, &[], None).await;
    assert_eq!(first.status, 302, "first use must succeed");

    let replay = request(addr, "GET", &query, &[], None).await;
    assert_ne!(
        replay.status, 302,
        "a spent request_uri was accepted a second time"
    );
    assert_eq!(replay.json()["error"], "invalid_request_uri");
}

/// The converse of the routing property, and it matters just as much: a host that did NOT enable
/// PAR advertises no endpoint, and this router serves none. An endpoint that mints capability
/// handles should not exist merely because the code to serve it was compiled in.
#[tokio::test]
async fn no_par_endpoint_is_routed_when_the_host_did_not_enable_par() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let issuer = format!("http://{addr}");
    // No `config.par`, which is the default.
    let config = ServerConfig::new(issuer.clone(), format!("{issuer}/device"));
    let server = Arc::new(AuthorizationServer::new(config, MemoryStorage::new()));
    let router = axum::Router::from(ServiceBuilder::new(server).build().expect("service"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let doc = metadata(addr).await;
    assert!(
        doc.get("pushed_authorization_request_endpoint").is_none(),
        "PAR is off, so RFC 9126 s5 has nothing to advertise: {doc}"
    );
    let resp = request(addr, "POST", "/par", &[], Some("client_id=whoever")).await;
    assert_eq!(resp.status, 404, "an unadvertised PAR endpoint was served");
}

/// RFC 9126 section 5 `require_pushed_authorization_requests`: with the policy on, the same
/// parameters sent in the query are refused. That is the downgrade an attacker who can rewrite the
/// URL would otherwise perform, and the router has to be the place it fails, because the query is
/// the only way into that path.
#[tokio::test]
async fn requiring_par_refuses_the_same_request_in_the_query() {
    let addr = start(true).await;
    let doc = metadata(addr).await;
    assert_eq!(doc["require_pushed_authorization_requests"], true);

    let refused = request(
        addr,
        "GET",
        &format!(
            "/authorize?response_type=code&client_id={CONFIDENTIAL_ID}\
             &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&scope=read\
             &code_challenge={CHALLENGE}&code_challenge_method=S256"
        ),
        &[],
        None,
    )
    .await;

    assert_ne!(
        refused.status, 302,
        "PAR was required and a query request was authorized anyway"
    );
    assert_eq!(refused.json()["error"], "invalid_request");

    // And the pushed form still works, or requiring PAR would have turned the server off.
    let path = par_path(addr).await;
    let pushed = request(
        addr,
        "POST",
        &path,
        &[("Authorization", &basic())],
        Some(&push_body()),
    )
    .await;
    assert_eq!(pushed.status, 201, "body was {:?}", pushed.body);
}

// ---------------------------------------------------------------------------------------------
// RFC 9101 JAR, which reaches the authorization endpoint by the same seam
// ---------------------------------------------------------------------------------------------

/// The client's registered request object key, and the private half so this test can sign as the
/// client. A host only ever holds the public half; this file needs both because it plays both
/// parts.
///
/// Every item in this section is gated on `jwt-p256` as well as `jar`, and NOT on `jar` alone,
/// because signing as the client needs a signing KEY: since the ES256 seam `jar` implies `jwt`,
/// which is the trait surface with no curve arithmetic behind it, and `EcdsaP256Key` is the
/// built-in backend's type. Gated on `jar` alone this file did not compile in any build without
/// the backend, which until the no-backend CI job gained `http` was every build except
/// --all-features, so nothing ever tried.
#[cfg(all(feature = "jar", feature = "jwt-p256"))]
struct JarKeys(oauth_as::par::RegisteredRequestObjectKey);

#[cfg(all(feature = "jar", feature = "jwt-p256"))]
impl oauth_as::par::RequestObjectKeys for JarKeys {
    fn registered_key(
        &self,
        client_id: &ClientId,
    ) -> Option<oauth_as::par::RegisteredRequestObjectKey> {
        (client_id.as_str() == CONFIDENTIAL_ID).then(|| self.0.clone())
    }
}

/// A server with signed request objects enabled, served on an ephemeral port.
#[cfg(all(feature = "jar", feature = "jwt-p256"))]
async fn start_jar() -> (SocketAddr, oauth_as::jwt::EcdsaP256Key) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let issuer = format!("http://{addr}");
    let mut config = ServerConfig::new(issuer.clone(), format!("{issuer}/device"));
    config.jar = Some(Box::new(oauth_as::par::JarConfig::new()));
    #[cfg(feature = "par")]
    {
        config.par = Some(Box::new(ParConfig::new()));
    }

    let key = oauth_as::jwt::EcdsaP256Key::generate("client-key");
    let jwk = key.public_jwk();
    let registered = oauth_as::par::RegisteredRequestObjectKey::es256_from_jwk_coordinates(
        Some(jwk.kid.clone()),
        &jwk.x,
        &jwk.y,
    )
    .expect("a JWK this crate emitted registers");

    let server = Arc::new(
        AuthorizationServer::new(config, MemoryStorage::new())
            .with_request_object_keys(Box::new(JarKeys(registered))),
    );
    let scopes = ScopeSet::from_tokens(["read", "write"]).expect("scopes");
    server
        .register_client(Client {
            client_id: ClientId::new(CONFIDENTIAL_ID),
            auth: ClientAuth::ConfidentialSecret {
                secret: SECRET.to_string(),
            },
            grant_types: vec![GrantType::AuthorizationCode],
            redirect_uris: vec![REDIRECT_URI.to_string()],
            allowed_scopes: scopes.clone(),
            default_scopes: scopes,
            name: None,
            registration: None,
        })
        .await
        .expect("register confidential");

    let service = ServiceBuilder::new(server)
        .with_subject_resolver(|_headers| Some("test-user".to_string()))
        .with_consent_resolver(|_req| ConsentDecision::Approve)
        .build()
        .expect("service");
    let router = axum::Router::from(service);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (addr, key)
}

/// Sign a request object as the client would (RFC 9101 section 6.1, ES256 compact JWS).
#[cfg(all(feature = "jar", feature = "jwt-p256"))]
fn request_object(key: &oauth_as::jwt::EcdsaP256Key, issuer: &str) -> String {
    request_object_with(key, issuer, "")
}

/// The same object with `extra` spliced in before the closing brace, so a test can sign a claim
/// the base object does not carry. `extra` is raw JSON and must begin with its own comma.
#[cfg(all(feature = "jar", feature = "jwt-p256"))]
fn request_object_with(key: &oauth_as::jwt::EcdsaP256Key, issuer: &str, extra: &str) -> String {
    let header = format!(
        r#"{{"alg":"ES256","typ":"{}","kid":"{}"}}"#,
        oauth_as::par::REQUEST_OBJECT_TYP,
        key.kid()
    );
    let payload = format!(
        r#"{{"iss":"{CONFIDENTIAL_ID}","aud":"{issuer}","client_id":"{CONFIDENTIAL_ID}",
            "response_type":"code","redirect_uri":"{REDIRECT_URI}","scope":"read","state":"jarstate",
            "code_challenge":"{CHALLENGE}","code_challenge_method":"S256"{extra}}}"#
    );
    oauth_as::jwt::compact_jws(header.as_bytes(), payload.as_bytes(), |signing_input| {
        key.sign_signing_input(signing_input)
            .expect("sign the request object")
    })
}

/// RFC 9101 section 5.1: a `request` parameter at the authorization endpoint is the request, and
/// this router has to hand it to the verifier rather than treat it as an unknown parameter. A
/// server that ignored it would authorize whatever the QUERY said, which is precisely the request
/// the signature was there to stop anyone editing.
#[cfg(all(feature = "jar", feature = "jwt-p256"))]
#[tokio::test]
async fn a_signed_request_object_is_accepted_at_the_authorization_endpoint() {
    let (addr, key) = start_jar().await;
    let object = request_object(&key, &format!("http://{addr}"));

    // `scope=write` in the query is the tampering: RFC 9101 section 6.3 says only the object's own
    // parameters count, so the code that comes back must be for the signed `scope=read`.
    let resp = request(
        addr,
        "GET",
        &format!("/authorize?client_id={CONFIDENTIAL_ID}&request={object}&scope=write"),
        &[],
        None,
    )
    .await;

    assert_eq!(
        resp.status, 302,
        "the authorization endpoint ignored the request object: {:?}",
        resp.body
    );
    let location = resp.header("location").expect("Location");
    assert!(location.starts_with(REDIRECT_URI), "went to {location}");
    assert!(location.contains("code="), "no code in {location}");
    assert!(
        location.contains("state=jarstate"),
        "the signed state did not survive: {location}"
    );
}

/// RFC 9101 section 5: a client MUST NOT send both. Refused rather than resolved by precedence,
/// because a server that silently prefers one is a server whose choice an intermediary can rely
/// on.
#[cfg(all(feature = "jar", feature = "jwt-p256"))]
#[tokio::test]
async fn request_and_request_uri_together_are_refused() {
    let (addr, key) = start_jar().await;
    let object = request_object(&key, &format!("http://{addr}"));

    let resp = request(
        addr,
        "GET",
        &format!(
            "/authorize?client_id={CONFIDENTIAL_ID}&request={object}\
             &request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aanything"
        ),
        &[],
        None,
    )
    .await;

    assert_ne!(resp.status, 302, "one of the two was silently preferred");
    assert_eq!(resp.json()["error"], "invalid_request");
}

// ---------------------------------------------------------------------------------------------
// RFC 9470 step-up: the two parameters that decide whether a code may be minted at all
// ---------------------------------------------------------------------------------------------

/// THE ATTACK. A resource server refuses a call with `insufficient_user_authentication` and
/// `max_age="0"`, so the client does exactly what RFC 9470 section 4 tells it to: it re-asks for
/// authorization with `max_age=0`, and because this deployment uses PAR it pushes that to the PAR
/// endpoint. If the two step-up parameters do not survive the push, the requirement at the
/// authorization endpoint is empty, `satisfied_by` has nothing to check, and a code is minted
/// against whatever session the browser already had: the user is never asked to re-authenticate,
/// and the resource server is handed a token that claims a freshness it does not have.
///
/// This host wires no authentication reporter, so it reports NOTHING, which satisfies no non-empty
/// requirement. That is the correct answer here: the refusal is what proves the parameter arrived.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_pushed_max_age_still_has_to_be_satisfied_before_a_code_is_minted() {
    let addr = start(false).await;
    let path = par_path(addr).await;
    let pushed = request(
        addr,
        "POST",
        &path,
        &[("Authorization", &basic())],
        Some(&format!(
            "{}&max_age=0&acr_values=urn%3Aacr%3Aphr",
            push_body()
        )),
    )
    .await;
    assert_eq!(pushed.status, 201, "body was {:?}", pushed.body);
    let request_uri = pushed.json()["request_uri"]
        .as_str()
        .expect("request_uri")
        .to_string();
    let encoded = request_uri.replace(':', "%3A");

    // RFC 9126 s4: only the pushed parameters count, so the query carries nothing but the handle,
    // exactly as a conforming client sends it.
    let authorized = request(
        addr,
        "GET",
        &format!("/authorize?client_id={CONFIDENTIAL_ID}&request_uri={encoded}"),
        &[],
        None,
    )
    .await;

    assert_eq!(authorized.status, 302, "body was {:?}", authorized.body);
    let location = authorized.header("location").expect("Location");
    assert!(
        !location.contains("code="),
        "the pushed max_age was dropped, so a code was minted against an unchecked session: \
         {location}"
    );
    assert!(
        location.contains("error=insufficient_user_authentication"),
        "RFC 9470 s3 is the answer to an unsatisfied step-up request: {location}"
    );
}

/// The other half of RFC 9126 section 4, and of RFC 9101 section 6.3 which it builds on: a
/// parameter in the QUERY alongside a `request_uri` counts for nothing, INCLUDING these two. A
/// server that read `max_age` off the query would let anything that can rewrite the browser's URL
/// (which is the threat PAR exists to remove) force a re-authentication prompt on every request,
/// and, in the mirror case, would be reading the one part of a PAR request that an intermediary
/// can still touch.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_max_age_in_the_query_beside_a_request_uri_is_ignored() {
    let addr = start(false).await;
    let path = par_path(addr).await;
    let pushed = request(
        addr,
        "POST",
        &path,
        &[("Authorization", &basic())],
        Some(&push_body()),
    )
    .await;
    assert_eq!(pushed.status, 201, "body was {:?}", pushed.body);
    let request_uri = pushed.json()["request_uri"]
        .as_str()
        .expect("request_uri")
        .to_string();
    let encoded = request_uri.replace(':', "%3A");

    let authorized = request(
        addr,
        "GET",
        &format!("/authorize?client_id={CONFIDENTIAL_ID}&request_uri={encoded}&max_age=0"),
        &[],
        None,
    )
    .await;

    assert_eq!(authorized.status, 302, "body was {:?}", authorized.body);
    let location = authorized.header("location").expect("Location");
    assert!(
        location.contains("code="),
        "nothing was pushed asking for a step-up, so the query's max_age must not have created \
         one: {location}"
    );
}

/// RFC 9101 section 6.3, on the two parameters where reading the query instead of the object is
/// worst: the whole point of a signed request object is that an intermediary cannot rewrite it,
/// and `max_age` read off the unsigned query is a `max_age` an intermediary CAN rewrite. A client
/// answering a step-up challenge puts it inside the object (section 4); a server that looks only
/// at the query never sees it.
#[cfg(all(feature = "jar", feature = "jwt-p256", feature = "consent"))]
#[tokio::test]
async fn a_max_age_inside_the_signed_object_is_the_one_that_counts() {
    let (addr, key) = start_jar().await;
    let object = request_object_with(
        &key,
        &format!("http://{addr}"),
        r#","max_age":0,"acr_values":"urn:acr:phr""#,
    );

    let resp = request(
        addr,
        "GET",
        &format!("/authorize?client_id={CONFIDENTIAL_ID}&request={object}"),
        &[],
        None,
    )
    .await;

    assert_eq!(resp.status, 302, "body was {:?}", resp.body);
    let location = resp.header("location").expect("Location");
    assert!(
        !location.contains("code="),
        "the signed max_age was ignored and a code was minted anyway: {location}"
    );
    assert!(
        location.contains("error=insufficient_user_authentication"),
        "RFC 9470 s3 is the answer to an unsatisfied step-up request: {location}"
    );
}

/// The mirror: a `max_age` an intermediary APPENDED to the query of a JAR request counts for
/// nothing, because RFC 9101 section 6.3 says the server MUST use only the object's parameters
/// "even if the same parameter is provided in the query parameter".
#[cfg(all(feature = "jar", feature = "jwt-p256", feature = "consent"))]
#[tokio::test]
async fn a_max_age_appended_to_the_query_of_a_signed_request_is_ignored() {
    let (addr, key) = start_jar().await;
    let object = request_object(&key, &format!("http://{addr}"));

    let resp = request(
        addr,
        "GET",
        &format!("/authorize?client_id={CONFIDENTIAL_ID}&request={object}&max_age=0"),
        &[],
        None,
    )
    .await;

    assert_eq!(resp.status, 302, "body was {:?}", resp.body);
    let location = resp.header("location").expect("Location");
    assert!(
        location.contains("code="),
        "the signed object asked for no step-up, so the query must not have created one: \
         {location}"
    );
}
