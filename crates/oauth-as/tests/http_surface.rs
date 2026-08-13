// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The optional `http` feature's wire surface, driven over a real socket.
//!
//! These tests bind an ephemeral port and speak HTTP/1.1 by hand rather than going through a
//! client library. That is deliberate: the things under test here are the STATUS LINE and the
//! HEADERS the RFCs mandate (`Cache-Control: no-store`, `WWW-Authenticate` on a 401, the absence
//! of a redirect), and a convenience client is exactly the layer that hides them. Writing the
//! bytes means the assertions are about what went on the wire.
//!
//! The bias of the file is toward REFUSALS. An authorization server that never says no passes a
//! happy-path suite while being unusable, so most of what follows drives the error paths and
//! pins the code, the status, and the headers each one is required to carry.

#![cfg(feature = "axum")]

use std::net::SocketAddr;
use std::sync::Arc;

use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::grant::GrantType;
use oauth_as::http::{ApprovalDecision, ServiceBuilder};
use oauth_as::scope::ScopeSet;
use oauth_as::server::{AuthorizationServer, ServerConfig};
use oauth_as::store::MemoryStorage;
use serde_json::Value;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const PUBLIC_ID: &str = "test-public";
const CONFIDENTIAL_ID: &str = "test-confidential";
const SECRET: &str = "test-secret-0123456789";
const REDIRECT_URI: &str = "http://127.0.0.1:9999/cb";
/// Deliberately full of HTML metacharacters: it is rendered on the verification page.
const PUBLIC_NAME: &str = "Acme <TV> & \"Friends\"";
/// RFC 7636 appendix B verifier, and the challenge it hashes to.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// A parsed HTTP/1.1 response. Header names are lowercased so lookups need no case juggling.
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

    /// Whether the body is something other than a JSON object, which is how a refusal that is
    /// NOT an RFC 6749 s5.2 error is told apart from one that is.
    fn json_is_absent(&self) -> bool {
        serde_json::from_str::<Value>(&self.body).is_err()
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("body is not JSON ({e}): {:?}", self.body))
    }
}

/// Speak one HTTP/1.1 request/response exchange. `Connection: close` means the response ends at
/// EOF, so no chunked/length parsing is needed to read it whole.
async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&str>,
) -> Resp {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n",
        addr = addr
    );
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    match body {
        Some(b) => {
            // A caller that supplied its own Content-Type is testing that header, so it is not
            // overwritten here.
            let has_ct = extra_headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
            if !has_ct {
                req.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
            }
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

/// Which host-supplied seams a test server has wired.
///
/// Each one is a thing this library refuses to invent, and each default is the REFUSING one, so a
/// test that does not name a seam is testing the unwired behaviour on purpose.
#[derive(Default, Clone, Copy)]
struct Wiring {
    /// [`ServiceBuilder::with_subject_resolver`]: a logged-in user.
    subject: bool,
    /// [`ServiceBuilder::with_approval_resolver`]: the RFC 6749 s10.12 consent step.
    consent: Consent,
    /// [`ServiceBuilder::with_csrf_tokens`]: session-bound CSRF tokens for the device form.
    csrf: bool,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Consent {
    /// No resolver at all: the authorization endpoint must refuse.
    #[default]
    Unwired,
    Approve,
    Deny,
    /// The realistic shape: the resolver renders its own consent screen.
    Screen,
}

impl Wiring {
    /// Everything a browser-facing host must wire.
    fn full() -> Self {
        Wiring {
            subject: true,
            consent: Consent::Approve,
            csrf: true,
        }
    }

    fn subject_only() -> Self {
        Wiring {
            subject: true,
            ..Wiring::default()
        }
    }
}

/// The test host's session store for CSRF tokens: session id (from a `Cookie: sid=...`) to the
/// one token currently outstanding for it. A real host would use its own session storage; what
/// matters for the tests is that `consume` REMOVES, which is what makes a token single use.
type CsrfSessions = Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>;

/// The session id this request carries, from a `Cookie: sid=...`. `None` means not signed in.
fn session_id(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get("cookie")?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|c| c.trim().strip_prefix("sid="))
        .map(str::to_string)
        .next()
}

/// The cookie header value a test client sends to be "signed in" as `VICTIM_SESSION`.
const VICTIM_SESSION: &str = "sid=victim-session";

/// Bind an ephemeral port, serve the router on it, and hand back the address. The issuer is set
/// from the bound address so the RFC 8414 s3.3 issuer/URL match holds, exactly as a host must.
async fn start(seed_subject: bool) -> SocketAddr {
    start_wired(match seed_subject {
        true => Wiring::full(),
        false => Wiring::default(),
    })
    .await
    .0
}

/// As [`start`], but with the seams named explicitly, and returning the host's CSRF session store
/// so a test can play the part of a browser holding the token it was issued.
async fn start_wired(wiring: Wiring) -> (SocketAddr, CsrfSessions) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let issuer = format!("http://{addr}");
    let mut config = ServerConfig::new(issuer.clone(), format!("{issuer}/device"));
    // RFC 7662 is now advertised only where the host NAMES the endpoint (see
    // `AuthorizationServerMetadata::introspection_endpoint`), so this fixture names it: the
    // document-membership sweep below and the round trip through `/introspect` are both about the
    // endpoint being published AND answering, which is the opted-in deployment.
    config.introspection_endpoint = Some(format!("{issuer}/introspect"));
    let server = Arc::new(AuthorizationServer::new(config, MemoryStorage::new()));

    let scopes = ScopeSet::from_tokens(["read", "write"]).expect("scopes");
    server
        .register_client(Client {
            client_id: ClientId::new(PUBLIC_ID),
            auth: ClientAuth::Public,
            grant_types: vec![
                GrantType::AuthorizationCode,
                GrantType::DeviceCode,
                GrantType::RefreshToken,
            ],
            redirect_uris: vec![REDIRECT_URI.to_string()],
            allowed_scopes: scopes.clone(),
            default_scopes: scopes.clone(),
            // A client name is registration data, and under RFC 7591 dynamic registration it is
            // attacker-supplied. The metacharacters are here so every test that renders it also
            // proves it is escaped.
            name: Some(PUBLIC_NAME.to_string()),
            registration: None,
        })
        .await
        .expect("register public");
    server
        .register_client(Client {
            client_id: ClientId::new(CONFIDENTIAL_ID),
            auth: ClientAuth::ConfidentialSecret {
                secret: SECRET.to_string(),
            },
            grant_types: vec![GrantType::ClientCredentials, GrantType::AuthorizationCode],
            redirect_uris: vec![REDIRECT_URI.to_string()],
            allowed_scopes: scopes.clone(),
            default_scopes: scopes,
            name: None,
            registration: None,
        })
        .await
        .expect("register confidential");

    let sessions: CsrfSessions = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    let mut builder = ServiceBuilder::new(server);
    if wiring.subject {
        // A host reads its own session; this one calls every request the same user, which is
        // what makes the CSRF tests meaningful (the attacker's forced request resolves to the
        // VICTIM, exactly as it would with a real cookie).
        builder = builder.with_subject_resolver(|_headers| Some("test-user".to_string()));
    }
    builder = match wiring.consent {
        Consent::Unwired => builder,
        Consent::Approve => builder.with_approval_resolver(|_req| ApprovalDecision::Approve),
        Consent::Deny => builder.with_approval_resolver(|_req| ApprovalDecision::Deny),
        Consent::Screen => builder.with_approval_resolver(|req| {
            let mut body = String::from("Allow ");
            body.push_str(req.client_id.as_str());
            body.push_str(" scope ");
            body.push_str(&req.scope.to_string());
            // A plain `http::Response`, which is the whole point of the seam: a host builds the
            // consent screen with the HTTP vocabulary it already has, not with this crate's
            // framework of the week.
            let mut screen = http::Response::new(oauth_as::http::Body::from(body));
            *screen.status_mut() = http::StatusCode::OK;
            ApprovalDecision::Respond(Box::new(screen))
        }),
    };
    if wiring.csrf {
        let issue = Arc::clone(&sessions);
        let consume = Arc::clone(&sessions);
        builder = builder.with_csrf_tokens(
            move |headers| {
                let sid = session_id(headers)?;
                let token = format!("csrf-for-{sid}");
                issue.lock().unwrap().insert(sid, token.clone());
                Some(token)
            },
            // REMOVES, so a token works exactly once.
            move |headers| consume.lock().unwrap().remove(&session_id(headers)?),
        );
    }
    let router = axum::Router::from(builder.build().expect("service"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (addr, sessions)
}

/// RFC 8414 s3.1/s3.3: the document is served at the well-known path, its issuer equals the URL
/// it was fetched from, and every endpoint it advertises answers rather than 404ing. An
/// advertised endpoint that does not exist is a metadata lie the client cannot recover from.
#[tokio::test]
async fn advertised_endpoints_do_not_404() {
    let addr = start(true).await;
    let meta = request(
        addr,
        "GET",
        "/.well-known/oauth-authorization-server",
        &[],
        None,
    )
    .await;
    assert_eq!(meta.status, 200);
    let doc = meta.json();
    assert_eq!(doc["issuer"], format!("http://{addr}"));

    for key in [
        "authorization_endpoint",
        "token_endpoint",
        "device_authorization_endpoint",
        "introspection_endpoint",
        "revocation_endpoint",
    ] {
        let url = doc[key].as_str().unwrap_or_else(|| panic!("{key} missing"));
        let path = url
            .strip_prefix(&format!("http://{addr}"))
            .unwrap_or_else(|| panic!("{key} is not under the issuer: {url}"));
        let method = if key == "authorization_endpoint" {
            "GET"
        } else {
            "POST"
        };
        let body = if method == "POST" {
            Some("junk=junk")
        } else {
            None
        };
        let resp = request(addr, method, path, &[], body).await;
        assert_ne!(resp.status, 404, "advertised {key} 404s at {path}");
        assert_ne!(resp.status, 405, "advertised {key} rejects its own method");
    }
}

/// RFC 6749 s5.1: a successful token response MUST carry `Cache-Control: no-store` and
/// `Pragma: no-cache`. These responses contain a bearer credential; a cache that keeps one hands
/// it to the next reader.
#[tokio::test]
async fn token_success_is_no_store() {
    let addr = start(true).await;
    let resp = request(
        addr,
        "POST",
        "/token",
        &[],
        Some(&format!(
            "grant_type=client_credentials&client_id={CONFIDENTIAL_ID}&client_secret={SECRET}"
        )),
    )
    .await;
    assert_eq!(resp.status, 200, "body: {}", resp.body);
    assert!(
        resp.header("cache-control")
            .is_some_and(|v| v.to_ascii_lowercase().contains("no-store")),
        "RFC 6749 s5.1 requires Cache-Control: no-store, got {:?}",
        resp.header("cache-control")
    );
    assert!(
        resp.header("pragma")
            .is_some_and(|v| v.to_ascii_lowercase().contains("no-cache")),
        "RFC 6749 s5.1 requires Pragma: no-cache"
    );
    assert_eq!(resp.json()["token_type"], "Bearer");
}

/// The verification page must refuse to be FRAMED, and must not be cached.
///
/// Found by the 0.9.1 audit. This is the only HTML this server renders and the only response a
/// browser executes, and it had neither a framing refusal nor `no_store` — it was the single
/// response constructor in `http.rs` that skipped `no_store` entirely.
///
/// Why framing is the serious half: the page's cross-site defence is `Sec-Fetch-Site:
/// same-origin`, which test C1 below relies on. A document inside a cross-site iframe posting to
/// its OWN origin sends exactly that header, so the defence is satisfied by a clickjack and stops
/// nothing. The attacker starts a device grant for a client they control, frames the verification
/// page invisibly over bait, and the victim's click lands on Approve — the same account takeover
/// C1 pins, reached by a route C1 does not cover.
///
/// The caching half: the body carries a live single-use CSRF token and the client, scope and user
/// code of a third party's pending grant.
#[tokio::test]
async fn the_verification_page_refuses_framing_and_caching() {
    let addr = start(true).await;
    let page = request(addr, "GET", "/device", &[("Cookie", VICTIM_SESSION)], None).await;
    assert_eq!(page.status, 200, "body: {}", page.body);
    assert!(
        page.header("content-type")
            .is_some_and(|v| v.starts_with("text/html")),
        "this test is only meaningful on the HTML page, got {:?}",
        page.header("content-type")
    );

    let csp = page
        .header("content-security-policy")
        .expect("the verification page must carry a Content-Security-Policy");
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "without frame-ancestors the page can be clickjacked into approving an attacker's device \
         grant, because a framed document satisfies the Sec-Fetch-Site check: {csp:?}"
    );
    assert!(
        csp.contains("form-action 'self'"),
        "the approval form must not be redirectable off-origin: {csp:?}"
    );
    assert_eq!(
        page.header("x-frame-options").map(str::to_ascii_uppercase),
        Some("DENY".to_string()),
        "browsers that do not enforce frame-ancestors need X-Frame-Options"
    );
    assert!(
        page.header("cache-control")
            .is_some_and(|v| v.to_ascii_lowercase().contains("no-store")),
        "the page carries a live CSRF token and a third party's pending grant, got {:?}",
        page.header("cache-control")
    );
    assert_eq!(
        page.header("x-content-type-options")
            .map(str::to_ascii_lowercase),
        Some("nosniff".to_string())
    );
    assert_eq!(page.header("referrer-policy"), Some("no-referrer"));
}

/// RFC 6749 s5.2: when the client authenticated via the `Authorization` header and that
/// authentication failed, the response MUST be 401 AND MUST carry `WWW-Authenticate`.
#[tokio::test]
async fn failed_basic_auth_is_401_with_challenge() {
    let addr = start(true).await;
    let basic = base64_standard(&format!("{CONFIDENTIAL_ID}:wrong-secret"));
    let resp = request(
        addr,
        "POST",
        "/token",
        &[("Authorization", &format!("Basic {basic}"))],
        Some("grant_type=client_credentials"),
    )
    .await;
    assert_eq!(resp.status, 401, "body: {}", resp.body);
    let challenge = resp
        .header("www-authenticate")
        .expect("RFC 6749 s5.2: a 401 for header auth MUST include WWW-Authenticate");
    assert!(
        challenge.starts_with("Basic realm="),
        "challenge must name the Basic scheme and a realm, got {challenge:?}"
    );
    assert_eq!(resp.json()["error"], "invalid_client");
}

/// RFC 6749 s2.3.1: Basic credentials are form-urlencoded BEFORE being base64ed. A client whose
/// id or secret contains a reserved character round-trips only if the server decodes them.
#[tokio::test]
async fn basic_credentials_are_form_urldecoded() {
    let addr = start(true).await;
    // `test-secret-0123456789` percent-encoded in a way a conforming client is allowed to use.
    let basic = base64_standard(&format!("{CONFIDENTIAL_ID}:test%2Dsecret%2D0123456789"));
    let resp = request(
        addr,
        "POST",
        "/token",
        &[("Authorization", &format!("Basic {basic}"))],
        Some("grant_type=client_credentials"),
    )
    .await;
    assert_eq!(
        resp.status, 200,
        "RFC 6749 s2.3.1 requires the credentials to be form-urldecoded; body: {}",
        resp.body
    );
}

/// RFC 6749 s5.2: a client-authentication failure that was NOT presented in the `Authorization`
/// header is a 400. Answering 401 without a challenge would violate RFC 9110 s15.5.2.
#[tokio::test]
async fn failed_body_auth_is_400_not_401() {
    let addr = start(true).await;
    let resp = request(
        addr,
        "POST",
        "/token",
        &[],
        Some(&format!(
            "grant_type=client_credentials&client_id={CONFIDENTIAL_ID}&client_secret=wrong"
        )),
    )
    .await;
    assert_eq!(resp.status, 400, "body: {}", resp.body);
    assert!(resp.header("www-authenticate").is_none());
    assert_eq!(resp.json()["error"], "invalid_client");
}

/// RFC 6749 s2.3: "The client MUST NOT use more than one authentication method in each request."
#[tokio::test]
async fn two_authentication_methods_is_invalid_request() {
    let addr = start(true).await;
    let basic = base64_standard(&format!("{CONFIDENTIAL_ID}:{SECRET}"));
    let resp = request(
        addr,
        "POST",
        "/token",
        &[("Authorization", &format!("Basic {basic}"))],
        Some(&format!(
            "grant_type=client_credentials&client_id={CONFIDENTIAL_ID}&client_secret={SECRET}"
        )),
    )
    .await;
    assert_eq!(resp.status, 400, "body: {}", resp.body);
    assert_eq!(resp.json()["error"], "invalid_request");
}

/// RFC 6749 s5.2: an unknown grant_type has its own code, and a missing one is a malformed
/// request. Collapsing either into a bare 400 tells the client nothing it can act on.
#[tokio::test]
async fn grant_type_dispatch_refusals() {
    let addr = start(true).await;
    let unknown = request(
        addr,
        "POST",
        "/token",
        &[],
        Some(&format!("grant_type=magic-beans&client_id={PUBLIC_ID}")),
    )
    .await;
    assert_eq!(unknown.status, 400);
    assert_eq!(unknown.json()["error"], "unsupported_grant_type");

    let missing = request(
        addr,
        "POST",
        "/token",
        &[],
        Some(&format!("client_id={PUBLIC_ID}")),
    )
    .await;
    assert_eq!(missing.status, 400);
    assert_eq!(missing.json()["error"], "invalid_request");
}

/// RFC 6749 s4.1.2.1: until the client and the redirect URI are validated there is no address
/// the server may safely send an error to, so it MUST NOT redirect. A server that redirects here
/// is the redirect-URI attack.
#[tokio::test]
async fn authorization_endpoint_does_not_redirect_before_validation() {
    let addr = start(true).await;

    // No client_id at all.
    let bare = request(addr, "GET", "/authorize", &[], None).await;
    assert_eq!(bare.status, 400, "body: {}", bare.body);
    assert!(bare.header("location").is_none());
    assert_eq!(bare.json()["error"], "invalid_request");

    // Unknown client_id.
    let unknown = request(
        addr,
        "GET",
        "/authorize?response_type=code&client_id=nobody&redirect_uri=http%3A%2F%2Fevil.example%2Fcb",
        &[],
        None,
    )
    .await;
    assert_eq!(unknown.status, 400);
    assert!(unknown.header("location").is_none());

    // Known client, UNREGISTERED redirect_uri: still no redirect (OAuth 2.1 s4.1.3 exact match).
    let bad_redirect = request(
        addr,
        "GET",
        &format!(
            "/authorize?response_type=code&client_id={PUBLIC_ID}\
             &redirect_uri=http%3A%2F%2Fevil.example%2Fcb"
        ),
        &[],
        None,
    )
    .await;
    assert_eq!(bad_redirect.status, 400);
    assert!(
        bad_redirect.header("location").is_none(),
        "an unregistered redirect_uri must never be redirected to"
    );
}

/// The other side of the same rule: once the client and redirect URI ARE validated, protocol
/// errors go back to the client as a redirect (RFC 6749 s4.1.2.1), carrying `state`.
#[tokio::test]
async fn authorization_errors_after_validation_do_redirect() {
    let addr = start(true).await;
    let resp = request(
        addr,
        "GET",
        &format!(
            "/authorize?response_type=token&client_id={PUBLIC_ID}\
             &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&state=xyz"
        ),
        &[],
        None,
    )
    .await;
    assert_eq!(resp.status, 302);
    let location = resp.header("location").expect("302 needs Location");
    assert!(location.starts_with(REDIRECT_URI), "got {location}");
    assert!(
        location.contains("error=unsupported_response_type"),
        "{location}"
    );
    assert!(location.contains("state=xyz"), "{location}");
}

/// The happy path exists too: a complete request with PKCE issues a code by redirect when the
/// host's subject resolver names an authenticated resource owner.
#[tokio::test]
async fn authorization_issues_a_code_when_a_subject_is_resolved() {
    let addr = start(true).await;
    let resp = request(
        addr,
        "GET",
        &format!(
            "/authorize?response_type=code&client_id={PUBLIC_ID}\
             &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&state=s1\
             &code_challenge={CHALLENGE}&code_challenge_method=S256"
        ),
        &[],
        None,
    )
    .await;
    assert_eq!(resp.status, 302, "body: {}", resp.body);
    let location = resp.header("location").expect("Location").to_string();
    let code = location
        .split(['?', '&'])
        .find_map(|p| p.strip_prefix("code="))
        .expect("no code in redirect");

    let token = request(
        addr,
        "POST",
        "/token",
        &[],
        Some(&format!(
            "grant_type=authorization_code&code={code}&client_id={PUBLIC_ID}\
             &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&code_verifier={VERIFIER}"
        )),
    )
    .await;
    assert_eq!(token.status, 200, "body: {}", token.body);
    assert!(token.json()["access_token"].is_string());
}

/// With no host-supplied resolver there is no authenticated resource owner, so the request is
/// refused DIRECTLY rather than redirected: telling the client `access_denied` at its redirect
/// URI would claim a user refused when no user was ever asked.
///
/// `start(false)` leaves the subject AND the approval seam unwired, and both answer with the same
/// status and the same `access_denied`, differing only in the description. So the description is
/// asserted: without it this test was equally satisfied by the approval refusal one step later,
/// and could not tell the subject seam from a subject the library invented.
#[tokio::test]
async fn authorization_without_a_resolver_refuses_directly() {
    let addr = start(false).await;
    let resp = request(
        addr,
        "GET",
        &format!(
            "/authorize?response_type=code&client_id={PUBLIC_ID}\
             &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb\
             &code_challenge={CHALLENGE}&code_challenge_method=S256"
        ),
        &[],
        None,
    )
    .await;
    assert_eq!(resp.status, 403, "body: {}", resp.body);
    assert!(resp.header("location").is_none());
    assert_eq!(resp.json()["error"], "access_denied");
    assert!(
        resp.json()["error_description"]
            .as_str()
            .is_some_and(|d| d.contains("subject resolver")),
        "the refusal must name the seam that produced it: {}",
        resp.body
    );
}

/// RFC 8628 s3.1/3.2 over the wire, then the verification UI: GET renders a form, POST of
/// `user_code` approves, and the device's next poll gets its token.
#[tokio::test]
async fn device_flow_over_http() {
    let addr = start(true).await;
    let start_resp = request(
        addr,
        "POST",
        "/device_authorization",
        &[],
        Some(&format!("client_id={PUBLIC_ID}")),
    )
    .await;
    assert_eq!(start_resp.status, 200, "body: {}", start_resp.body);
    let doc = start_resp.json();
    let device_code = doc["device_code"]
        .as_str()
        .expect("device_code")
        .to_string();
    let user_code = doc["user_code"].as_str().expect("user_code").to_string();
    assert_eq!(doc["verification_uri"], format!("http://{addr}/device"));

    // Before approval: RFC 8628 s3.5 authorization_pending.
    let pending = request(
        addr,
        "POST",
        "/token",
        &[],
        Some(&format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code\
             &device_code={device_code}&client_id={PUBLIC_ID}"
        )),
    )
    .await;
    assert_eq!(pending.status, 400);
    assert_eq!(pending.json()["error"], "authorization_pending");

    let (form, csrf) = verification_form(addr, "").await;
    assert_eq!(form.status, 200);
    assert!(
        form.body.contains("name=\"user_code\""),
        "the verification page must offer a user_code field: {}",
        form.body
    );

    // The user's own browser: same origin, the CSRF token from the form it was served, and an
    // affirmative Approve (RFC 6749 s10.12, RFC 8628 s3.3).
    let approve = request(
        addr,
        "POST",
        "/device",
        &[
            ("Cookie", VICTIM_SESSION),
            ("Origin", &format!("http://{addr}")),
        ],
        Some(&format!(
            "user_code={}&csrf_token={csrf}&action=approve",
            user_code.replace('-', "%2D")
        )),
    )
    .await;
    assert_eq!(approve.status, 200, "body: {}", approve.body);

    let issued = request(
        addr,
        "POST",
        "/token",
        &[],
        Some(&format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code\
             &device_code={device_code}&client_id={PUBLIC_ID}"
        )),
    )
    .await;
    // The poll interval has not elapsed, so RFC 8628 s3.5 slow_down is the correct answer here;
    // what matters is that the approval took effect and the grant is no longer pending.
    assert!(
        issued.status == 200 || issued.json()["error"] == "slow_down",
        "unexpected post-approval poll: {} {}",
        issued.status,
        issued.body
    );
}

/// RFC 7662 s2.2: introspection answers about the CALLER's own token, and `active: false` is the
/// whole answer for anything else. RFC 7009 s2.2: revoking an unknown token is a 200.
#[tokio::test]
async fn introspection_and_revocation() {
    let addr = start(true).await;
    let token: Value = request(
        addr,
        "POST",
        "/token",
        &[],
        Some(&format!(
            "grant_type=client_credentials&client_id={CONFIDENTIAL_ID}&client_secret={SECRET}"
        )),
    )
    .await
    .json();
    let access = token["access_token"].as_str().expect("access_token");

    let live = request(
        addr,
        "POST",
        "/introspect",
        &[],
        Some(&format!(
            "token={access}&client_id={CONFIDENTIAL_ID}&client_secret={SECRET}"
        )),
    )
    .await;
    assert_eq!(live.status, 200, "body: {}", live.body);
    assert_eq!(live.json()["active"], true);

    let revoked = request(
        addr,
        "POST",
        "/revoke",
        &[],
        Some(&format!(
            "token={access}&token_type_hint=access_token\
             &client_id={CONFIDENTIAL_ID}&client_secret={SECRET}"
        )),
    )
    .await;
    assert_eq!(revoked.status, 200, "body: {}", revoked.body);

    let after = request(
        addr,
        "POST",
        "/introspect",
        &[],
        Some(&format!(
            "token={access}&client_id={CONFIDENTIAL_ID}&client_secret={SECRET}"
        )),
    )
    .await;
    assert_eq!(after.json()["active"], false);

    // RFC 7009 s2.2: an unknown token is still a 200, so the endpoint cannot be used to test
    // whether a token string is real.
    let unknown = request(
        addr,
        "POST",
        "/revoke",
        &[],
        Some(&format!(
            "token=never-existed&client_id={CONFIDENTIAL_ID}&client_secret={SECRET}"
        )),
    )
    .await;
    assert_eq!(unknown.status, 200);
}

// ---------------------------------------------------------------------------------------------
// Attack tests. Each one drives an attack end to end and requires the server to refuse.
// ---------------------------------------------------------------------------------------------

/// Start a device grant for the public client and return `(device_code, user_code)`.
async fn begin_device_grant(addr: SocketAddr) -> (String, String) {
    let doc = request(
        addr,
        "POST",
        "/device_authorization",
        &[],
        Some(&format!("client_id={PUBLIC_ID}")),
    )
    .await
    .json();
    (
        doc["device_code"]
            .as_str()
            .expect("device_code")
            .to_string(),
        doc["user_code"].as_str().expect("user_code").to_string(),
    )
}

/// Poll the device token endpoint once.
async fn poll_device(addr: SocketAddr, device_code: &str) -> Resp {
    request(
        addr,
        "POST",
        "/token",
        &[],
        Some(&format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code\
             &device_code={device_code}&client_id={PUBLIC_ID}"
        )),
    )
    .await
}

/// Scrape the CSRF token out of a rendered form, which is the only way a browser gets it: it is
/// bound to the session, so an attacker on another origin cannot read it.
fn csrf_token_in(body: &str) -> String {
    let marker = "name=\"csrf_token\" value=\"";
    let start = body
        .find(marker)
        .unwrap_or_else(|| panic!("no CSRF token in the rendered form: {body}"))
        + marker.len();
    let rest = &body[start..];
    rest[..rest.find('"').expect("unterminated value")].to_string()
}

/// GET the verification page as a signed-in browser would, and return the page plus its token.
async fn verification_form(addr: SocketAddr, query: &str) -> (Resp, String) {
    let page = request(
        addr,
        "GET",
        &format!("/device{query}"),
        &[("Cookie", VICTIM_SESSION)],
        None,
    )
    .await;
    let token = csrf_token_in(&page.body);
    (page, token)
}

/// C1. ATTACK: cross-site forced device approval, which is account takeover.
///
/// The attacker starts a device grant for a client they control, hosts an auto-submitting HTML
/// form at their own origin targeting the AS verification URI with that `user_code`, and waits
/// for any AS-authenticated victim to load the page. A plain form POST is a CORS "simple
/// request", so there is no preflight to stop it and the victim's session cookie rides along.
/// The AS resolves the subject from those ambient credentials and binds the attacker's grant to
/// the VICTIM; the attacker then polls the token endpoint and holds the victim's tokens.
///
/// RFC 6749 s10.12 requires the AS to implement CSRF protection for its authorization endpoint
/// and to ensure a malicious client cannot obtain authorization without the resource owner's
/// awareness and explicit consent. RFC 8628 s3.3 leaves the interaction shape to the
/// implementation but does not license removing that.
///
/// THE ATTACKER IS GIVEN A VALID CSRF TOKEN HERE, which no real attacker could read across
/// origins. That is deliberate, and it is what the 0.9.1 audit found missing: until then this
/// test posted no `csrf_token` at all, so the token check refused it one step later and deleting
/// the origin check entirely left the test green. Handing the attacker the victim's real token
/// leaves the ORIGIN check as the only thing standing between the request and the approval, so
/// the refusal this asserts can only have come from that check.
#[tokio::test]
async fn c1_cross_origin_form_post_must_not_approve_a_device_grant() {
    // FULLY wired: this attack must fail against a host that did everything right, not only
    // against one that wired nothing.
    let (addr, _sessions) = start_wired(Wiring::full()).await;
    let (device_code, user_code) = begin_device_grant(addr).await;

    // The victim's own browser loaded the verification page, so the host has a token outstanding
    // for that session, and it is the one the next POST on that cookie will be checked against.
    let (_page, csrf) = verification_form(addr, "").await;

    // Exactly what a browser sends for a cross-origin <form method="post"> submission, except for
    // the token: the victim's cookie rides along, and the request carries the token the host would
    // accept, so nothing but the origin can refuse it.
    let forced = request(
        addr,
        "POST",
        "/device",
        &[
            ("Cookie", VICTIM_SESSION),
            ("Origin", "https://attacker.example"),
            ("Sec-Fetch-Site", "cross-site"),
            ("Referer", "https://attacker.example/setup-your-tv"),
        ],
        Some(&format!(
            "user_code={}&csrf_token={csrf}&action=approve",
            user_code.replace('-', "%2D")
        )),
    )
    .await;
    assert_eq!(
        forced.status, 403,
        "a cross-origin form POST must be refused, got {} {}",
        forced.status, forced.body
    );
    assert!(
        forced.body.contains("did not come from this site"),
        "the refusal must be the ORIGIN check, not the token check the attacker just satisfied: {}",
        forced.body
    );

    // The decisive assertion: the grant must still be waiting for a real user.
    let poll = poll_device(addr, &device_code).await;
    assert_eq!(
        poll.json()["error"],
        "authorization_pending",
        "the attacker's grant was approved by a cross-site request: {} {}",
        poll.status,
        poll.body
    );
}

/// C1. ATTACK: the same forced approval with no CSRF token at all.
///
/// Even without the cross-site headers, a host that wired no CSRF seam must not approve, because
/// there is nothing tying this POST to a form the resource owner was actually shown. RFC 6749
/// s10.12. A library with no session store cannot mint the token itself, so "no seam wired" has
/// to mean REFUSE, never "proceed unprotected".
#[tokio::test]
async fn c1_device_approval_without_a_csrf_token_is_refused() {
    let (addr, _sessions) = start_wired(Wiring::full()).await;
    let (device_code, user_code) = begin_device_grant(addr).await;

    let forced = request(
        addr,
        "POST",
        "/device",
        &[
            ("Cookie", VICTIM_SESSION),
            ("Origin", &format!("http://{addr}")),
        ],
        Some(&format!(
            "user_code={}&action=approve",
            user_code.replace('-', "%2D")
        )),
    )
    .await;
    assert!(
        forced.status >= 400,
        "an approval with no CSRF token must be refused, got {} {}",
        forced.status,
        forced.body
    );
    assert_eq!(
        poll_device(addr, &device_code).await.json()["error"],
        "authorization_pending",
        "the grant was approved without a CSRF token"
    );
}

/// C1. A host that wired no CSRF seam must not be handed an unprotected form to submit.
///
/// RFC 6749 s10.12: the protection is the AS's obligation, so the failure mode of an unwired host
/// is a refusal, not a form that works and is forgeable.
#[tokio::test]
async fn c1_verification_form_is_not_rendered_without_a_csrf_seam() {
    let (addr, _sessions) = start_wired(Wiring::subject_only()).await;
    let page = request(addr, "GET", "/device", &[("Cookie", VICTIM_SESSION)], None).await;
    assert!(
        !page.body.contains("<form"),
        "a host with no CSRF seam must not be served a submittable form: {}",
        page.body
    );

    // And the direct POST an attacker would send anyway is refused too, since a host that never
    // renders the form is not a host that stopped anyone from posting to it.
    let (device_code, user_code) = begin_device_grant(addr).await;
    let forced = request(
        addr,
        "POST",
        "/device",
        &[
            ("Cookie", VICTIM_SESSION),
            ("Origin", &format!("http://{addr}")),
        ],
        Some(&format!(
            "user_code={}&action=approve",
            user_code.replace('-', "%2D")
        )),
    )
    .await;
    assert!(forced.status >= 400, "body: {}", forced.body);
    assert_eq!(
        poll_device(addr, &device_code).await.json()["error"],
        "authorization_pending"
    );
}

/// C1. The approval POST must require `application/x-www-form-urlencoded`.
///
/// Defence in depth for RFC 6749 s10.12: a body this server will not parse cannot be smuggled in
/// as a cross-origin "simple request" from a form or a no-preflight `fetch`.
#[tokio::test]
async fn c1_device_approval_requires_form_urlencoded_content_type() {
    let (addr, _sessions) = start_wired(Wiring::full()).await;
    let (device_code, user_code) = begin_device_grant(addr).await;
    // Everything else about this request is correct, so the content type is the only thing that
    // can be refusing it.
    let (_page, csrf) = verification_form(addr, "").await;

    let forced = request(
        addr,
        "POST",
        "/device",
        &[
            ("Content-Type", "text/plain;charset=UTF-8"),
            ("Cookie", VICTIM_SESSION),
            ("Origin", &format!("http://{addr}")),
        ],
        Some(&format!(
            "user_code={}&csrf_token={csrf}&action=approve",
            user_code.replace('-', "%2D")
        )),
    )
    .await;
    assert_eq!(
        forced.status, 415,
        "a non-form content type must be refused: {}",
        forced.body
    );
    assert_eq!(
        poll_device(addr, &device_code).await.json()["error"],
        "authorization_pending"
    );
}

/// C2. ATTACK: remote phishing over `verification_uri_complete` (RFC 8628 s5.4).
///
/// The attacker starts a device grant for their own client and mails the victim the deep link
/// ("click here to finish setting up your TV"). RFC 8628 s5.4 notes that this member removes the
/// one friction point, typing the code, that makes the attack harder, and s3.3 is explicit that
/// the AS SHOULD display information about the device and require an explicit confirmation step.
/// A page that shows a bare input and an Approve button shows the victim nothing they could
/// notice, so it must name the client and the scope being asked for.
#[tokio::test]
async fn c2_verification_page_names_the_client_and_the_scope() {
    let (addr, _sessions) = start_wired(Wiring::full()).await;
    let (_device_code, user_code) = begin_device_grant(addr).await;

    // The deep link RFC 8628 s3.3.1 defines, which is the phishing vector s5.4 describes.
    let (page, _csrf) = verification_form(
        addr,
        &format!("?user_code={}", user_code.replace('-', "%2D")),
    )
    .await;
    assert_eq!(page.status, 200, "body: {}", page.body);
    assert!(
        page.body.contains("Acme") && page.body.contains("Friends"),
        "RFC 8628 s3.3: the page must name the client asking for access: {}",
        page.body
    );
    assert!(
        page.body.contains("read") && page.body.contains("write"),
        "RFC 8628 s3.3: the page must state the scope being granted: {}",
        page.body
    );
    // The client name is registration data and, under RFC 7591, attacker-supplied.
    assert!(
        !page.body.contains("<TV>") && page.body.contains("&lt;TV&gt;"),
        "the client name must be HTML-escaped: {}",
        page.body
    );
}

/// C2. ATTACK: the deep link must not be one click from approval on a page that says nothing.
///
/// RFC 8628 s3.3 requires an explicit confirmation step, so a POST that carries no affirmative
/// approval action is not consent and must not approve.
#[tokio::test]
async fn c2_approval_requires_an_affirmative_action() {
    let (addr, _sessions) = start_wired(Wiring::full()).await;
    let (device_code, user_code) = begin_device_grant(addr).await;
    let (_page, csrf) = verification_form(addr, "").await;

    // A correct, same-origin, CSRF-token-bearing submission that carries no decision: this is
    // stage one of the form, "I have typed my code", and it must approve nothing.
    let bare = request(
        addr,
        "POST",
        "/device",
        &[
            ("Cookie", VICTIM_SESSION),
            ("Origin", &format!("http://{addr}")),
        ],
        Some(&format!(
            "user_code={}&csrf_token={csrf}",
            user_code.replace('-', "%2D")
        )),
    )
    .await;
    // What it does instead is show the user what they would be approving.
    assert!(
        bare.body.contains("Acme") && bare.body.contains("read write"),
        "stage one must answer with the consent screen: {}",
        bare.body
    );
    assert_eq!(
        poll_device(addr, &device_code).await.json()["error"],
        "authorization_pending",
        "a POST with no affirmative action approved the grant: {} {}",
        bare.status,
        bare.body
    );
}

/// C4. ATTACK: silent authorization at the authorization endpoint.
///
/// A cross-site top-level navigation to `/authorize` makes a logged-in user's browser hand a
/// registered client an authorization code with no consent step anywhere. RFC 6749 s10.12
/// requires the AS to ensure the resource owner is aware of and explicitly consents to the
/// authorization; PKCE and the registered redirect URI bound WHO can redeem the code, not WHETHER
/// the user agreed to issue it.
#[tokio::test]
async fn c4_authorization_endpoint_must_not_issue_a_code_without_consent() {
    // A host that wired identity and nothing else: the exact configuration that used to be a
    // silently auto-approving authorization server.
    let (addr, _sessions) = start_wired(Wiring::subject_only()).await;
    let resp = request(
        addr,
        "GET",
        &format!(
            "/authorize?response_type=code&client_id={PUBLIC_ID}\
             &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&state=s1\
             &code_challenge={CHALLENGE}&code_challenge_method=S256"
        ),
        &[],
        None,
    )
    .await;
    let location = resp.header("location").unwrap_or_default().to_string();
    assert!(
        !location.contains("code="),
        "a code was issued with no consent step: {} {location}",
        resp.status
    );
}

/// C12. RFC 8414 s3.1: for an issuer with a path component the well-known string is inserted
/// BETWEEN the host and the path, so `https://as.example/tenant1` publishes at
/// `https://as.example/.well-known/oauth-authorization-server/tenant1`.
///
/// Security relevant because RFC 8414 s3.3's issuer/URL identity check is a mix-up
/// countermeasure: a document served where the check cannot pass trains clients to skip it, and
/// in a multi-tenant deployment every tenant would collide on the one bare path.
#[tokio::test]
async fn c12_well_known_document_lives_under_the_issuer_path() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let issuer = format!("http://{addr}/tenant1");
    let config = ServerConfig::new(issuer.clone(), format!("{issuer}/device"));
    let server = Arc::new(AuthorizationServer::new(config, MemoryStorage::new()));
    let router = axum::Router::from(ServiceBuilder::new(server).build().expect("service"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let doc = request(
        addr,
        "GET",
        "/.well-known/oauth-authorization-server/tenant1",
        &[],
        None,
    )
    .await;
    assert_eq!(
        doc.status, 200,
        "RFC 8414 s3.1 path for a tenant issuer: {}",
        doc.body
    );
    assert_eq!(doc.json()["issuer"], issuer);

    // And the endpoints it advertises are served at their own full paths, not at the bare ones.
    let token = request(addr, "POST", "/tenant1/token", &[], Some("junk=junk")).await;
    assert_ne!(token.status, 404, "advertised token_endpoint 404s");
}

/// C1. The other side of the rule: a real browser submission of the form this server rendered
/// approves, and the token it carried does not work a second time.
///
/// Single use is what stops a token captured once (a shared machine, a leaked log, a referrer)
/// from being replayed later, which is why RFC 6749 s10.12's protection is specified as bound to
/// the session rather than merely secret.
#[tokio::test]
async fn c1_a_same_origin_submission_with_the_issued_token_approves_exactly_once() {
    let (addr, _sessions) = start_wired(Wiring::full()).await;
    let (device_code, user_code) = begin_device_grant(addr).await;
    let (_page, csrf) = verification_form(addr, "").await;

    let body = format!(
        "user_code={}&csrf_token={csrf}&action=approve",
        user_code.replace('-', "%2D")
    );
    let headers = [
        ("Cookie", VICTIM_SESSION),
        ("Origin", &format!("http://{addr}")),
    ];
    let approve = request(addr, "POST", "/device", &headers, Some(&body)).await;
    assert_eq!(approve.status, 200, "body: {}", approve.body);

    // A second grant, and a REPLAY of the same token: the host consumed it, so it is spent.
    let (second_device_code, second_user_code) = begin_device_grant(addr).await;
    let replay = request(
        addr,
        "POST",
        "/device",
        &headers,
        Some(&format!(
            "user_code={}&csrf_token={csrf}&action=approve",
            second_user_code.replace('-', "%2D")
        )),
    )
    .await;
    assert_eq!(
        replay.status, 403,
        "a consumed CSRF token must not work twice: {}",
        replay.body
    );
    assert_eq!(
        poll_device(addr, &second_device_code).await.json()["error"],
        "authorization_pending"
    );

    // The first approval did take effect.
    let issued = poll_device(addr, &device_code).await;
    assert!(
        issued.status == 200 || issued.json()["error"] == "slow_down",
        "unexpected post-approval poll: {} {}",
        issued.status,
        issued.body
    );
}

/// C1/C2. Deny is available and terminal (RFC 8628 s3.3 leaves the deny path to the
/// implementation; a user who did not start the flow needs a way to say so, and RFC 8628 s3.5
/// then requires `access_denied` at the device's next poll).
#[tokio::test]
async fn a_denied_device_grant_reports_access_denied() {
    let (addr, _sessions) = start_wired(Wiring::full()).await;
    let (device_code, user_code) = begin_device_grant(addr).await;
    let (_page, csrf) = verification_form(addr, "").await;

    let deny = request(
        addr,
        "POST",
        "/device",
        &[
            ("Cookie", VICTIM_SESSION),
            ("Origin", &format!("http://{addr}")),
        ],
        Some(&format!(
            "user_code={}&csrf_token={csrf}&action=deny",
            user_code.replace('-', "%2D")
        )),
    )
    .await;
    assert_eq!(deny.status, 200, "body: {}", deny.body);
    assert_eq!(
        poll_device(addr, &device_code).await.json()["error"],
        "access_denied"
    );
}

/// C4. The consent seam's three answers, each doing what RFC 6749 s4.1.2 / s4.1.2.1 says it
/// should: approve issues a code, deny is `access_denied` AT THE REDIRECT URI (a refusal is an
/// answer the client is entitled to), and a rendered screen issues nothing at all.
#[tokio::test]
async fn c4_the_consent_seam_decides_what_the_authorization_endpoint_does() {
    let query = format!(
        "/authorize?response_type=code&client_id={PUBLIC_ID}\
         &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&state=s1\
         &code_challenge={CHALLENGE}&code_challenge_method=S256"
    );

    let (approve_addr, _a) = start_wired(Wiring::full()).await;
    let approved = request(approve_addr, "GET", &query, &[], None).await;
    assert_eq!(approved.status, 302, "body: {}", approved.body);
    assert!(approved
        .header("location")
        .is_some_and(|l| l.contains("code=")));

    let (deny_addr, _d) = start_wired(Wiring {
        subject: true,
        consent: Consent::Deny,
        csrf: false,
    })
    .await;
    let denied = request(deny_addr, "GET", &query, &[], None).await;
    assert_eq!(denied.status, 302, "body: {}", denied.body);
    let location = denied.header("location").expect("Location").to_string();
    assert!(location.starts_with(REDIRECT_URI), "{location}");
    assert!(location.contains("error=access_denied"), "{location}");
    assert!(
        location.contains("state=s1"),
        "the client must be able to correlate its own refusal: {location}"
    );
    assert!(!location.contains("code="), "{location}");

    // A host that renders its own consent screen: the router serves it unchanged and mints
    // nothing, so the flow finishes on a later request when the user has actually answered.
    let (screen_addr, _s) = start_wired(Wiring {
        subject: true,
        consent: Consent::Screen,
        csrf: false,
    })
    .await;
    let screen = request(screen_addr, "GET", &query, &[], None).await;
    assert_eq!(screen.status, 200, "body: {}", screen.body);
    assert!(screen.header("location").is_none(), "nothing was issued");
    assert!(
        screen.body.contains(PUBLIC_ID) && screen.body.contains("read write"),
        "the host's own screen is served unchanged: {}",
        screen.body
    );
}

/// Base64 (standard alphabet, padded) as RFC 7617 requires for the Basic scheme.
fn base64_standard(s: &str) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    STANDARD.encode(s.as_bytes())
}

/// A server that signs its access tokens: the same fixture as [`start_wired`] plus an ES256 key
/// and a `jwks_uri` under the issuer. Returns the address and the key identifier the JWKS must
/// name.
// A signing KEY, so `jwt-p256` and not `jwt`: since the ES256 seam `jwt` is the trait surface
// with no curve arithmetic behind it, and `EcdsaP256Key` is the built-in backend's type.
// Gated on `jwt` alone this file did not compile in an `axum` build without the backend.
#[cfg(feature = "jwt-p256")]
async fn start_signing() -> (SocketAddr, String) {
    use oauth_as::jwt::{AccessTokenFormat, EcdsaP256Key, JwtConfig};

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let issuer = format!("http://{addr}");
    let mut config = ServerConfig::new(issuer.clone(), format!("{issuer}/device"));
    let kid = "wire-test-key-1".to_string();
    config.access_token_format = AccessTokenFormat::Jwt(Box::new(
        JwtConfig::new(EcdsaP256Key::generate(kid.clone()), "https://rs.example")
            .with_jwks_uri(format!("{issuer}/jwks")),
    ));
    let server = Arc::new(AuthorizationServer::new(config, MemoryStorage::new()));
    let scopes = ScopeSet::from_tokens(["read", "write"]).expect("scopes");
    server
        .register_client(Client {
            client_id: ClientId::new(CONFIDENTIAL_ID),
            auth: ClientAuth::ConfidentialSecret {
                secret: SECRET.to_string(),
            },
            grant_types: vec![GrantType::ClientCredentials],
            redirect_uris: vec![REDIRECT_URI.to_string()],
            allowed_scopes: scopes.clone(),
            default_scopes: scopes,
            name: None,
            registration: None,
        })
        .await
        .expect("register confidential");
    let router = axum::Router::from(ServiceBuilder::new(server).build().expect("service"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (addr, kid)
}

/// RFC 8414 s2 and RFC 7517 s5: a signing AS advertises `jwks_uri`, that URI answers with a
/// non-empty `keys` array, and the key it publishes is the one it signs with. A resource server
/// that cannot fetch these bytes cannot verify a single RFC 9068 token, so the advertised URI
/// 404ing is the same unrecoverable lie as any other missing endpoint.
#[cfg(feature = "jwt-p256")]
#[tokio::test]
async fn a_signing_server_serves_the_key_set_it_advertises() {
    let (addr, kid) = start_signing().await;
    let meta = request(
        addr,
        "GET",
        "/.well-known/oauth-authorization-server",
        &[],
        None,
    )
    .await
    .json();
    let uri = meta["jwks_uri"]
        .as_str()
        .expect("a signing AS must advertise jwks_uri");
    assert_eq!(uri, format!("http://{addr}/jwks"));

    let resp = request(addr, "GET", "/jwks", &[], None).await;
    assert_eq!(resp.status, 200, "body: {}", resp.body);
    // RFC 7517 s8.5.1 registers this media type for a JWK Set.
    assert_eq!(
        resp.header("content-type"),
        Some("application/jwk-set+json")
    );
    let jwks = resp.json();
    let keys = jwks["keys"].as_array().expect("RFC 7517 s5 keys array");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kid"], kid);
    assert_eq!(keys[0]["kty"], "EC");
    assert_eq!(keys[0]["crv"], "P-256");
    assert_eq!(keys[0]["alg"], "ES256");
    // RFC 7517 s6.2.2.1: `d` is the PRIVATE key parameter. Publishing it would hand every reader
    // the ability to mint tokens this server would be believed to have issued.
    assert!(
        keys[0].get("d").is_none() && !resp.body.contains("\"d\""),
        "the key set must carry public parameters only: {}",
        resp.body
    );

    // And the token the wire actually hands out is the JWS compact form of RFC 7515 s3.1 rather
    // than an opaque string, signed under the advertised kid. The signature itself is verified
    // against this JWKS in tests/jwt.rs.
    let token = request(
        addr,
        "POST",
        "/token",
        &[],
        Some(&format!(
            "grant_type=client_credentials&client_id={CONFIDENTIAL_ID}&client_secret={SECRET}"
        )),
    )
    .await
    .json();
    let access_token = token["access_token"].as_str().expect("access_token");
    let parts: Vec<&str> = access_token.split('.').collect();
    assert_eq!(parts.len(), 3, "RFC 7515 s3.1 compact form: {access_token}");
    assert!(parts.iter().all(|p| !p.is_empty()));
    let header = {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let raw = URL_SAFE_NO_PAD.decode(parts[0]).expect("base64url header");
        serde_json::from_slice::<Value>(&raw).expect("JOSE header JSON")
    };
    // RFC 9068 s2.1 fixes typ; the kid is what lets a verifier pick the right key from the set.
    assert_eq!(header["typ"], "at+jwt");
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["kid"], kid);
}

/// The other direction, which matters just as much: a server with opaque tokens has no keys, so
/// it must neither advertise `jwks_uri` nor route one. An advertised key set that verifies
/// nothing teaches resource servers to trust a document that is not true.
#[tokio::test]
async fn an_opaque_server_advertises_no_key_set_and_routes_none() {
    let addr = start(true).await;
    let meta = request(
        addr,
        "GET",
        "/.well-known/oauth-authorization-server",
        &[],
        None,
    )
    .await
    .json();
    assert!(
        meta.get("jwks_uri").is_none(),
        "opaque tokens: nothing to publish"
    );
    assert_eq!(request(addr, "GET", "/jwks", &[], None).await.status, 404);
}

// ---------------------------------------------------------------------------------------------
// The routing layer itself, now that it is this crate's rather than a framework's. Every
// assertion below is about bytes on the wire, which is the only place the difference shows.
// ---------------------------------------------------------------------------------------------

/// RFC 9110 s9.3.2: HEAD is GET with the body dropped, and the header fields SHOULD be identical.
/// A health check or a cache that probes with HEAD must get the length it would have got from
/// GET, not a 405 and not a zero.
#[tokio::test]
async fn head_answers_like_get_with_no_body() {
    let addr = start(true).await;
    let path = "/.well-known/oauth-authorization-server";
    let get = request(addr, "GET", path, &[], None).await;
    let head = request(addr, "HEAD", path, &[], None).await;

    assert_eq!(head.status, 200);
    assert_eq!(head.body, "", "HEAD must not carry a body");
    assert_eq!(
        head.header("content-type"),
        get.header("content-type"),
        "HEAD and GET must describe the same representation"
    );
    assert_eq!(
        head.header("content-length").and_then(|v| v.parse().ok()),
        Some(get.body.len()),
        "HEAD must report the length GET would have sent"
    );
}

/// RFC 9110 s15.5.6: a 405 MUST carry `Allow`. Without it a client cannot tell a wrong method from
/// a route that does not exist, which on an authorization server is the difference between "retry
/// as a POST" and "this deployment has no such endpoint".
#[tokio::test]
async fn the_wrong_method_is_405_with_an_allow_header() {
    let addr = start(true).await;

    // The token endpoint is POST only (RFC 6749 s3.2: "The client MUST use the HTTP POST method").
    let resp = request(addr, "GET", "/token", &[], None).await;
    assert_eq!(resp.status, 405);
    assert_eq!(resp.header("allow"), Some("POST"));

    // The authorization endpoint is a browser navigation, so GET; a POST to it is the same error.
    let resp = request(addr, "POST", "/authorize", &[], Some("x=1")).await;
    assert_eq!(resp.status, 405);
    assert_eq!(resp.header("allow"), Some("GET, HEAD"));

    // A path this server does not serve at all is a 404, not a 405: there is no `Allow` to give.
    let resp = request(addr, "POST", "/not-an-endpoint", &[], Some("x=1")).await;
    assert_eq!(resp.status, 404);
    assert_eq!(resp.header("allow"), None);
}

/// The body cap, over a socket. These endpoints buffer the whole body before parsing and are
/// reachable BEFORE the client is authenticated (`client_secret_post` puts the credential in the
/// body), so an unbounded body is a memory exhaustion primitive available to anyone who can open
/// a socket. 64 KiB is the stated ceiling; a body over it is refused rather than buffered.
#[tokio::test]
async fn a_body_over_the_cap_is_refused_at_the_token_endpoint() {
    let addr = start(true).await;

    // Just inside the cap: accepted as a request, and refused on its MERITS (an OAuth error),
    // which is what proves the cap did not fire.
    let inside = format!(
        "grant_type=client_credentials&client_id=x&junk={}",
        "a".repeat(60_000)
    );
    let resp = request(addr, "POST", "/token", &[], Some(&inside)).await;
    assert_ne!(resp.status, 413, "60 KB is inside the 64 KiB cap");
    assert_eq!(resp.json()["error"], "invalid_client");

    // Over it: refused as a body, before any of it is parsed.
    let over = format!("grant_type=client_credentials&junk={}", "a".repeat(70_000));
    let resp = oversized(addr, &over).await;
    assert_eq!(resp.status, 413, "an oversized body must be refused");
    // The refusal must not be an OAuth error, because nothing was parsed to have an error about.
    assert!(resp.json_is_absent(), "{:?}", resp.body);
}

/// [`request`], but tolerating the connection reset a refused body earns.
///
/// The server answers 413 and closes WITHOUT draining the rest of the request, which is the whole
/// point of the cap: it must not read what it has already refused. On a socket that means the
/// peer may see ECONNRESET while it is still writing or reading, so this exchange treats a reset
/// after a complete response head as the end of the response rather than as a failure.
async fn oversized(addr: SocketAddr, body: &str) -> Resp {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let req = format!(
        "POST /token HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    // The write itself may be reset once the server has refused and closed.
    let _ = stream.write_all(req.as_bytes()).await;
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("no response at all: {text:?}"));
    let mut lines = head.split("\r\n");
    let status_line = lines.next().expect("status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no status code in {status_line:?}"));
    Resp {
        status,
        headers: lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
            .collect(),
        body: body.to_string(),
    }
}
