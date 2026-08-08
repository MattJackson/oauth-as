// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! What the interactive endpoints SAY, and which status they say it with.
//!
//! `tests/http_surface.rs` drives the attacks and pins the refusals. What a mutation run showed it
//! does not pin is the ordinary outcome text: the approve and deny arms could be swapped, every
//! message the verification page renders could be dropped, the storage and rate-limit statuses
//! could collapse into a plain 400, and the subject resolver could be replaced by a constant.
//! Every one of those is something a real user or a real operator reads and acts on.
//!
//! The subject one is not cosmetic at all. `Inner::subject` is what says "this request has an
//! authenticated resource owner"; a version of it that always answers `Some(_)` turns an
//! unauthenticated visitor into whoever it names, and the existing test for the unwired case did
//! not catch that because it left the CONSENT seam unwired too, so the refusal came from the
//! consent check one step later.

#![cfg(feature = "http")]

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use oauth_as::authorization::AuthorizationCodeRecord;
use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::device::{DeviceGrant, DeviceGrantState};
use oauth_as::events::{Attempt, RateLimitDecision, RateLimiter};
use oauth_as::grant::GrantType;
use oauth_as::http::{ConsentDecision, RouterBuilder};
use oauth_as::scope::ScopeSet;
use oauth_as::server::{AuthorizationServer, ServerConfig, SystemClock};
use oauth_as::store::{MemoryStorage, Storage, StorageError};
use oauth_as::token::{IssuedToken, RefreshTokenRecord};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const PUBLIC_ID: &str = "verification-client";
const REDIRECT_URI: &str = "http://127.0.0.1:9999/cb";
/// RFC 7636 appendix B verifier and the challenge it hashes to.
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// The cookie a "signed in" test browser sends.
const SESSION: &str = "sid=a-browser-session";
/// The subject the resolver names, chosen so it cannot be confused with anything a degenerate
/// implementation would invent.
const SUBJECT: &str = "resource-owner-alice";

// ---------------------------------------------------------------------------------------------
// A minimal HTTP/1.1 client, so the assertions are about the status line and the bytes.
// ---------------------------------------------------------------------------------------------

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
}

async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: Option<&str>,
) -> Resp {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (k, v) in extra {
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
        .unwrap_or_else(|| panic!("no status in {status_line:?}"));
    Resp {
        status,
        headers: lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
            .collect(),
        body: body.to_string(),
    }
}

/// Scrape the CSRF token out of a rendered form. A browser gets it the same way: it is bound to
/// the session, so nothing on another origin can read it.
fn csrf_token_in(body: &str) -> String {
    let marker = "name=\"csrf_token\" value=\"";
    let start = body
        .find(marker)
        .unwrap_or_else(|| panic!("no CSRF token in the rendered form: {body}"))
        + marker.len();
    let rest = &body[start..];
    rest[..rest.find('"').expect("unterminated value")].to_string()
}

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// A store that behaves exactly like [`MemoryStorage`] except that the user-code lookup always
/// fails, which is the one way `approve_device` can return `DeviceApprovalError::Storage`.
///
/// Everything else delegates, so nothing about the rest of the flow changes: the only difference a
/// test can observe is what the verification endpoint does when the host's store is broken.
struct LookupFails(MemoryStorage);

impl Storage for LookupFails {
    fn get_client(
        &self,
        client_id: &ClientId,
    ) -> impl Future<Output = Result<Option<Client>, StorageError>> + Send {
        self.0.get_client(client_id)
    }
    fn put_client(&self, client: Client) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.0.put_client(client)
    }
    fn delete_client(
        &self,
        client_id: &ClientId,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send {
        self.0.delete_client(client_id)
    }
    fn put_device_grant(
        &self,
        grant: DeviceGrant,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.0.put_device_grant(grant)
    }
    fn get_device_grant(
        &self,
        device_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceGrant>, StorageError>> + Send {
        self.0.get_device_grant(device_code)
    }
    fn find_device_grant_by_user_code(
        &self,
        normalized_user_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceGrant>, StorageError>> + Send {
        let _ = normalized_user_code;
        std::future::ready(Err(StorageError::new("the user code index is unavailable")))
    }
    fn take_device_grant(
        &self,
        device_code: &str,
    ) -> impl Future<Output = Result<Option<DeviceGrant>, StorageError>> + Send {
        self.0.take_device_grant(device_code)
    }
    fn put_authorization_code(
        &self,
        record: AuthorizationCodeRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.0.put_authorization_code(record)
    }
    fn take_authorization_code(
        &self,
        code: &str,
    ) -> impl Future<Output = Result<Option<AuthorizationCodeRecord>, StorageError>> + Send {
        self.0.take_authorization_code(code)
    }
    fn put_token(
        &self,
        token: IssuedToken,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.0.put_token(token)
    }
    fn get_token(
        &self,
        access_token: &str,
    ) -> impl Future<Output = Result<Option<IssuedToken>, StorageError>> + Send {
        self.0.get_token(access_token)
    }
    fn delete_token(
        &self,
        access_token: &str,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.0.delete_token(access_token)
    }
    fn put_refresh_token(
        &self,
        record: RefreshTokenRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.0.put_refresh_token(record)
    }
    fn get_refresh_token(
        &self,
        refresh_token: &str,
    ) -> impl Future<Output = Result<Option<RefreshTokenRecord>, StorageError>> + Send {
        self.0.get_refresh_token(refresh_token)
    }
    fn take_refresh_token(
        &self,
        refresh_token: &str,
    ) -> impl Future<Output = Result<Option<RefreshTokenRecord>, StorageError>> + Send {
        self.0.take_refresh_token(refresh_token)
    }
    fn revoke_token_family(
        &self,
        family_id: &str,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send {
        self.0.revoke_token_family(family_id)
    }
    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
    fn claim_replay_id(
        &self,
        id: &str,
        expires_at: std::time::SystemTime,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send {
        self.0.claim_replay_id(id, expires_at)
    }
    fn sweep_expired(
        &self,
        now: std::time::SystemTime,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send {
        self.0.sweep_expired(now)
    }
}

/// A host limiter that refuses every user-code entry, which is what RFC 8628 section 5.1 asks a
/// deployment to do once a caller has been guessing.
struct RefuseCodeEntry;

impl RateLimiter for RefuseCodeEntry {
    fn check(&self, attempt: Attempt<'_>) -> RateLimitDecision {
        match attempt {
            Attempt::DeviceUserCodeEntry => RateLimitDecision::Deny,
            _ => RateLimitDecision::Allow,
        }
    }
}

/// Which seams a fixture wires. Every default is the refusing one.
#[derive(Default, Clone, Copy)]
struct Wiring {
    subject: bool,
    consent: bool,
    csrf: bool,
}

fn test_client() -> Client {
    Client {
        client_id: ClientId::new(PUBLIC_ID),
        auth: ClientAuth::Public,
        grant_types: vec![
            GrantType::AuthorizationCode,
            GrantType::DeviceCode,
            GrantType::RefreshToken,
        ],
        redirect_uris: vec![REDIRECT_URI.to_string()],
        allowed_scopes: ScopeSet::from_tokens(["read"]).expect("scopes"),
        default_scopes: ScopeSet::from_tokens(["read"]).expect("scopes"),
        name: Some("Test Device".to_string()),
        registration: None,
    }
}

/// Bind a port, serve a router over `store`, and hand back the address and the server, so a test
/// can ask the server what it recorded as well as what it said.
async fn serve<S: Storage + 'static>(
    store: S,
    wiring: Wiring,
    limiter: Option<Box<dyn RateLimiter>>,
) -> (SocketAddr, Arc<AuthorizationServer<S, SystemClock>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let issuer = format!("http://{addr}");
    let config = ServerConfig::new(issuer.clone(), format!("{issuer}/device"));
    let mut server = AuthorizationServer::new(config, store);
    if let Some(limiter) = limiter {
        server = server.with_rate_limiter(limiter);
    }
    let server = Arc::new(server);
    server
        .register_client(test_client())
        .await
        .expect("register");

    let mut builder = RouterBuilder::new(Arc::clone(&server));
    if wiring.subject {
        builder = builder.with_subject_resolver(|_headers| Some(SUBJECT.to_string()));
    }
    if wiring.consent {
        builder = builder.with_consent_resolver(|_req| ConsentDecision::Approve);
    }
    if wiring.csrf {
        // A host session store: one outstanding token per session, and `consume` REMOVES.
        let sessions: Arc<std::sync::Mutex<std::collections::HashMap<String, String>>> =
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let issue = Arc::clone(&sessions);
        let consume = Arc::clone(&sessions);
        builder = builder.with_csrf_tokens(
            move |headers| {
                let sid = session_id(headers)?;
                let token = format!("csrf-for-{sid}");
                issue.lock().unwrap().insert(sid, token.clone());
                Some(token)
            },
            move |headers| consume.lock().unwrap().remove(&session_id(headers)?),
        );
    }
    let router = builder.build().expect("router");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (addr, server)
}

fn session_id(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("cookie")?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|c| c.trim().strip_prefix("sid="))
        .map(str::to_string)
        .next()
}

fn browser_headers(addr: SocketAddr) -> [(&'static str, String); 2] {
    [
        ("Cookie", SESSION.to_string()),
        ("Origin", format!("http://{addr}")),
    ]
}

async fn get_form(addr: SocketAddr, query: &str) -> (Resp, String) {
    let page = request(
        addr,
        "GET",
        &format!("/device{query}"),
        &[("Cookie", SESSION)],
        None,
    )
    .await;
    let token = csrf_token_in(&page.body);
    (page, token)
}

async fn begin_device_grant(addr: SocketAddr) -> (String, String) {
    let resp = request(
        addr,
        "POST",
        "/device_authorization",
        &[],
        Some(&format!("client_id={PUBLIC_ID}")),
    )
    .await;
    let doc: serde_json::Value =
        serde_json::from_str(&resp.body).unwrap_or_else(|e| panic!("{e}: {}", resp.body));
    (
        doc["device_code"]
            .as_str()
            .expect("device_code")
            .to_string(),
        doc["user_code"].as_str().expect("user_code").to_string(),
    )
}

// ---------------------------------------------------------------------------------------------
// The resource owner
// ---------------------------------------------------------------------------------------------

/// RFC 6749 s10.12: a code represents a resource owner's decision, so there has to BE a resource
/// owner. The subject resolver is the only thing that can name one, and a host that did not wire
/// it must get a refusal rather than a subject the library invented.
///
/// The consent seam IS wired here, deliberately. With both unwired the refusal comes from the
/// consent check, one step later, and an implementation that answered `Some("")` for every request
/// would look identical.
#[tokio::test]
async fn without_a_subject_resolver_the_authorization_endpoint_refuses_and_issues_nothing() {
    let (addr, _server) = serve(
        MemoryStorage::new(),
        Wiring {
            subject: false,
            consent: true,
            csrf: false,
        },
        None,
    )
    .await;

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

    assert_eq!(resp.status, 403, "body: {}", resp.body);
    assert!(
        resp.header("location").is_none(),
        "no user refused, so there is nothing to tell the client at its redirect URI"
    );
    assert!(
        resp.body.contains("subject resolver"),
        "the refusal must name the seam the host has to wire: {}",
        resp.body
    );
}

/// The other direction: the subject the resolver NAMES is the subject that ends up on the grant.
/// A resolver whose answer is ignored in favour of a constant would bind every device grant to the
/// same fictional user.
#[tokio::test]
async fn the_resolved_subject_is_the_one_recorded_on_the_grant() {
    let (addr, server) = serve(
        MemoryStorage::new(),
        Wiring {
            subject: true,
            consent: true,
            csrf: true,
        },
        None,
    )
    .await;
    let (device_code, user_code) = begin_device_grant(addr).await;
    let (_page, csrf) = get_form(addr, "").await;

    let headers = browser_headers(addr);
    let approve = request(
        addr,
        "POST",
        "/device",
        &[
            (headers[0].0, headers[0].1.as_str()),
            (headers[1].0, headers[1].1.as_str()),
        ],
        Some(&format!(
            "user_code={}&csrf_token={csrf}&action=approve",
            user_code.replace('-', "%2D")
        )),
    )
    .await;
    assert_eq!(approve.status, 200, "body: {}", approve.body);

    let grant = server
        .store()
        .get_device_grant(&device_code)
        .await
        .expect("storage")
        .expect("the grant is still there");
    // RFC 8628 s3.3: approval binds a third party's grant to the logged-in user, so the identity
    // the host named is the identity the grant has to carry.
    match &grant.state {
        DeviceGrantState::Approved { subject } => assert_eq!(
            subject, SUBJECT,
            "the grant must be bound to the user the host's resolver named"
        ),
        other => panic!("the grant should be approved, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// What the page says
// ---------------------------------------------------------------------------------------------

/// RFC 8628 s3.3 leaves the interaction to the implementation, which makes the words the whole of
/// the contract with the human. Approve and deny must not be able to swap places: a user who
/// pressed Deny and was told "Approved" has been told the opposite of what happened.
#[tokio::test]
async fn approve_and_deny_each_say_what_they_did() {
    for (action, expected) in [
        ("approve", "Approved. You can return to your device."),
        ("deny", "Request denied."),
    ] {
        let (addr, _server) = serve(
            MemoryStorage::new(),
            Wiring {
                subject: true,
                consent: true,
                csrf: true,
            },
            None,
        )
        .await;
        let (_device_code, user_code) = begin_device_grant(addr).await;
        let (_page, csrf) = get_form(addr, "").await;
        let headers = browser_headers(addr);

        let resp = request(
            addr,
            "POST",
            "/device",
            &[
                (headers[0].0, headers[0].1.as_str()),
                (headers[1].0, headers[1].1.as_str()),
            ],
            Some(&format!(
                "user_code={}&csrf_token={csrf}&action={action}",
                user_code.replace('-', "%2D")
            )),
        )
        .await;
        assert_eq!(resp.status, 200, "body: {}", resp.body);
        assert!(
            resp.body.contains(expected),
            "the {action} outcome must say so, got: {}",
            resp.body
        );
    }
}

/// A code that was typed and matches nothing pending has to say so. Rendering the entry form again
/// with no explanation is how a user retypes the same wrong code forever, and on the deep-link
/// path of RFC 8628 s3.3.1 it is also how a phishing link looks indistinguishable from a real one.
#[tokio::test]
async fn an_unrecognised_code_says_it_was_not_recognised() {
    let (addr, _server) = serve(
        MemoryStorage::new(),
        Wiring {
            subject: true,
            consent: true,
            csrf: true,
        },
        None,
    )
    .await;
    let (page, _csrf) = get_form(addr, "?user_code=ZZZZ%2DZZZZ").await;
    assert_eq!(page.status, 200, "body: {}", page.body);
    assert!(
        page.body.contains("That code was not recognised."),
        "body: {}",
        page.body
    );
}

/// A submission with no code at all is a different mistake and gets a different sentence, plus the
/// 400 that says the request was not usable. An empty page here is a dead end.
#[tokio::test]
async fn an_empty_submission_asks_for_the_code() {
    let (addr, _server) = serve(
        MemoryStorage::new(),
        Wiring {
            subject: true,
            consent: true,
            csrf: true,
        },
        None,
    )
    .await;
    let (_page, csrf) = get_form(addr, "").await;
    let headers = browser_headers(addr);

    let resp = request(
        addr,
        "POST",
        "/device",
        &[
            (headers[0].0, headers[0].1.as_str()),
            (headers[1].0, headers[1].1.as_str()),
        ],
        Some(&format!("csrf_token={csrf}")),
    )
    .await;
    assert_eq!(resp.status, 400, "body: {}", resp.body);
    assert!(
        resp.body.contains("Enter the code shown on your device."),
        "body: {}",
        resp.body
    );
}

// ---------------------------------------------------------------------------------------------
// Which status the failures carry
// ---------------------------------------------------------------------------------------------

/// A broken store is the server's fault, not the user's, and 5xx is what says so. Collapsing it
/// into the 400 every other approval failure uses tells the user to fix their code and tells the
/// host's monitoring that its users are typing badly.
#[tokio::test]
async fn a_storage_failure_during_approval_is_a_500_not_a_400() {
    let (addr, _server) = serve(
        LookupFails(MemoryStorage::new()),
        Wiring {
            subject: true,
            consent: true,
            csrf: true,
        },
        None,
    )
    .await;
    let (_page, csrf) = get_form(addr, "").await;
    let headers = browser_headers(addr);

    let resp = request(
        addr,
        "POST",
        "/device",
        &[
            (headers[0].0, headers[0].1.as_str()),
            (headers[1].0, headers[1].1.as_str()),
        ],
        Some(&format!(
            "user_code=WDJB%2DMJHT&csrf_token={csrf}&action=approve"
        )),
    )
    .await;
    assert_eq!(resp.status, 500, "body: {}", resp.body);
    assert!(
        resp.body.contains("Something went wrong. Try again."),
        "body: {}",
        resp.body
    );
    // And it must not leak the store's own message, which is for the host's logs.
    assert!(
        !resp.body.contains("user code index"),
        "the store's message reached the browser: {}",
        resp.body
    );
}

/// RFC 8628 s5.1 makes rate limiting user-code entry part of what makes the code's entropy
/// adequate, so a host that installed a limiter needs its refusal to be visible as a refusal. 429
/// is the honest status and the one a reverse proxy is already counting.
///
/// The message deliberately says nothing about whether the code was real: that is exactly the
/// question the throttle exists to stop being asked.
#[tokio::test]
async fn a_throttled_code_entry_is_a_429_that_reveals_nothing() {
    let (addr, _server) = serve(
        MemoryStorage::new(),
        Wiring {
            subject: true,
            consent: true,
            csrf: true,
        },
        Some(Box::new(RefuseCodeEntry)),
    )
    .await;
    let (_device_code, user_code) = begin_device_grant(addr).await;
    let (_page, csrf) = get_form(addr, "").await;
    let headers = browser_headers(addr);

    let resp = request(
        addr,
        "POST",
        "/device",
        &[
            (headers[0].0, headers[0].1.as_str()),
            (headers[1].0, headers[1].1.as_str()),
        ],
        Some(&format!(
            "user_code={}&csrf_token={csrf}&action=approve",
            user_code.replace('-', "%2D")
        )),
    )
    .await;
    assert_eq!(resp.status, 429, "body: {}", resp.body);
    assert!(
        resp.body.contains("Too many attempts. Wait and try again."),
        "body: {}",
        resp.body
    );
    assert!(
        !resp.body.contains("not recognised"),
        "a throttled attempt must not report whether the code existed: {}",
        resp.body
    );
}
