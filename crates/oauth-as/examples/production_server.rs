// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A worked PRODUCTION wiring of this crate: every host obligation in one file, with what
//! breaks if you get each one wrong.
//!
//! # Why this file exists
//!
//! The other example in this directory, `conformance_server.rs`, is a CONFORMANCE FIXTURE. It
//! auto-approves authorization requests, disables the device form's CSRF protection and signs
//! with a key printed in an RFC. It says so at every one of those sites, but it was still the
//! only worked wiring a reader had, and what a reader does with the only worked wiring is copy
//! it. This file is the one to copy.
//!
//! # The obligations, in the order they appear below
//!
//! Each is a thing THIS LIBRARY WILL NOT DO FOR YOU, by design, because it cannot: it never sees
//! a socket, a session, a user or a database.
//!
//! 1. STORAGE with genuinely atomic `take_*` and `claim_replay_id`. Get this wrong and refresh
//!    tokens double-spend across nodes, and reuse detection, the single most valuable security
//!    signal this crate produces, stops firing. See [`HostStorage`].
//! 2. A RATE LIMITER. RFC 8628 s5.1 makes the device user code's entropy adequate only IN
//!    COMBINATION WITH rate limiting of code entry. See the `with_rate_limiter` call in `main`.
//! 3. A CONSENT step that actually asks a human. RFC 6749 s10.12. See [`consent_resolver`].
//! 4. A CSRF seam on the device verification form. RFC 6749 s10.12 again, and it is the
//!    difference between a device grant and an account takeover. See [`csrf_issue`].
//! 5. A SUBJECT resolver that reads a session your server established. A host that returns a
//!    value copied out of an unvalidated request header has authenticated NOBODY. See
//!    [`subject_resolver`].
//! 6. A SWEEPER. Nothing in this crate runs on a timer, so nothing reclaims expired records
//!    unless the host asks. The device authorization endpoint takes no credential from a public
//!    client, so a host that never sweeps has handed anyone who can open a socket an unbounded
//!    allocation loop. See [`spawn_sweeper`].
//! 7. AN AUDIT SINK, because the two compromise events revoke silently otherwise. See
//!    [`StderrEventSink`].
//! 8. SIGNING KEY MANAGEMENT AND ROTATION, if you turn on RFC 9068 JWT access tokens. See
//!    `configure_signing`.
//! 9. TLS, and the listener it terminates on. See the comment above `axum::serve` in [`serve`].
//!
//! # Running it
//!
//! ```text
//! OAUTH_AS_CLIENT_SECRET=$(openssl rand -hex 32) OAUTH_AS_DEV_LOGIN=1 \
//!   cargo run -p oauth-as --features axum --example production_server
//! ```
//!
//! It refuses to start without a client secret, because a server that invents a default
//! credential has published that credential to everyone who can read its source.
//!
//! There is ONE thing this example cannot demonstrate honestly, and it is fenced off by name:
//! authenticating a user. This crate has no login page and will not grow one, so the session
//! everything else hangs off has to come from somewhere, and here it comes from
//! `OAUTH_AS_DEV_LOGIN=1` plus a loopback issuer. See [`dev_login_handler`]. Everything else in
//! this file is what a real deployment does.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use http::{header, HeaderMap, HeaderValue, StatusCode};

use oauth_as::client::{Client, ClientAuth, ClientId, SecretHash};
use oauth_as::events::{Event, EventSink};
use oauth_as::grant::GrantType;
use oauth_as::http::{
    AuthorizationService, Body, ConsentDecision, ConsentRequest, Response, ServiceBuilder,
};
use oauth_as::rate_limit::{FixedWindowRateLimiter, RateLimitConfig};
use oauth_as::scope::ScopeSet;
use oauth_as::server::{AuthorizationServer, ServerConfig, SystemClock};
use oauth_as::store::{MemoryStorage, Storage};

// ---------------------------------------------------------------------------------------------
// 1. STORAGE
// ---------------------------------------------------------------------------------------------

/// The store this example runs on, and the one thing here a real deployment MUST replace.
///
/// `MemoryStorage` is used because an example cannot ship a database, and a hand-rolled fake
/// would teach the wrong lesson twice: it would be as unreplicated as this one, and it would
/// bury the contract under a hundred lines of nothing. So the contract is written down instead.
/// A REAL implementation of it, over PostgreSQL, lives in `crates/oauth-as-postgres` in this
/// repository, and its two-connection test proves the property below over genuinely separate
/// connections rather than asserting it.
///
/// # Why a real deployment cannot use this type
///
/// It is a `HashMap` behind a `Mutex` in one process. Restart the process and every device grant
/// in flight, every authorization code mid-redirect, every live access token and every refresh
/// chain is gone: users are logged out, and devices waiting for approval fail. Run two processes
/// and they do not share a store at all, so a code minted by node A cannot be redeemed at node B,
/// and, far worse, a refresh token spent on node A is still unspent on node B.
///
/// # What the replacement MUST guarantee
///
/// Not "should". These are the clauses the server's security properties rest on, and a store can
/// violate every one of them while compiling and passing a single-node test suite.
///
/// * `take_device_grant`, `take_authorization_code`, `take_refresh_token` (and the RFC 9126
///   `take_pushed_request`) are ATOMIC REMOVE-AND-RETURN. Exactly one concurrent caller may be
///   handed the record; every other must be told it is gone. In SQL that is `DELETE ... RETURNING`
///   as ONE statement, or a conditional update; in Redis it is `GETDEL` or a Lua script. IT IS NOT
///   `SELECT` FOLLOWED BY `DELETE`.
///
///   READ-THEN-DELETE IS THE WORST BUG YOU CAN SHIP HERE. Two nodes both read the same live
///   refresh record, both delete it, both mint a new access token and a new refresh token: the
///   token double-spends. The damage does not stop at the extra token. Refresh reuse detection
///   (OAuth 2.1 draft s6.1, RFC 9700 s4.14.2) works by noticing that a SUPERSEDED record was
///   presented; a store that lets two callers each believe they were the first supersession
///   produces no such record, so the one signal that says "this refresh token is in the hands of
///   two parties" is DESTROYED. It fails silently, and it fails in exactly the case it exists
///   for: the thief and the honest client both keep working and nobody is ever told.
///
/// * `claim_replay_id` is an ATOMIC CLAIM-IF-ABSENT: `INSERT ... ON CONFLICT DO NOTHING` with the
///   affected row count checked, or `SET NX`. It is what makes RFC 7523 client assertions (s3,
///   `jti` single use) and RFC 9449 DPoP proofs (s4.3) single use. Look-then-insert means anyone
///   who observed one request can send it again.
///
/// * `put_device_grant` upserts by `device_code` AND keeps the user-code index consistent: a put
///   that changes a grant's user code retires the old index entry, and a put whose user code is
///   already indexed for a DIFFERENT device code is REFUSED rather than repointing the index.
///   Repointing lets an attacker aim a victim's typed code at a grant of the attacker's.
///
/// * Storage errors must be errors, never empty results. This crate fails CLOSED on a storage
///   error precisely because it trusts the store to say "I do not know" rather than "no".
///
/// # How to check yours
///
/// Not by reading it. Turn on this crate's `test-util` feature and run
/// `oauth_as::storage_conformance` against YOUR store, from YOUR test suite, against YOUR
/// database. It exists because none of the above is observable from inside this crate.
type HostStorage = MemoryStorage;

// ---------------------------------------------------------------------------------------------
// 7. AUDIT
// ---------------------------------------------------------------------------------------------

/// Where the server's events go. Writes to stderr because an example must not pick a host's
/// logging framework; a real host pushes these onto whatever it already runs.
///
/// This crate logs NOTHING by itself. Without a sink the two events below happen silently, which
/// means an operator learns about a stolen refresh token from a support ticket about being logged
/// out rather than from an alert.
///
/// `on_event` is called SYNCHRONOUSLY inside the request, so a slow sink slows the token endpoint
/// and a panicking sink panics the request. This one formats a line and returns; anything
/// expensive belongs on a channel with the work done elsewhere.
struct StderrEventSink;

impl EventSink for StderrEventSink {
    fn on_event(&self, event: Event<'_>) {
        match event {
            // EVIDENCE OF COMPROMISE. Both mean a credential is in two places at once. A
            // deployment should PAGE on these, not merely log them: by the time either fires the
            // server has already revoked, so what is left to decide is whether an account was
            // taken over and who has to be told.
            Event::RefreshTokenReuseDetected {
                client_id,
                family_id,
                records_revoked,
            } => eprintln!(
                "ALERT refresh_token_reuse client={client_id} family={family_id} \
                 revoked={records_revoked}"
            ),
            Event::AuthorizationCodeReplayDetected {
                client_id,
                family_id,
                tokens_revoked,
            } => eprintln!(
                "ALERT authorization_code_replay client={client_id} family={family_id:?} \
                 revoked={tokens_revoked}"
            ),
            // Everything else is ordinary operational record. `Event` is `#[non_exhaustive]`, so
            // this arm is also what keeps a host compiling when a later release adds one.
            other => eprintln!("event {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// HOST STATE: sessions, CSRF tokens, and one-shot consent approvals
// ---------------------------------------------------------------------------------------------

/// Everything the HOST owns and this crate refuses to: who is logged in, what CSRF token each
/// session holds, and which consent decisions a user has just made.
///
/// In one process behind mutexes for the same reason the store is: an example cannot ship Redis.
/// A real deployment puts all three wherever its sessions already live, and the single-node
/// caveat on [`HostStorage`] applies here word for word.
#[derive(Default)]
struct HostState {
    /// session id -> subject. The ONLY thing that decides who a request is.
    sessions: Mutex<HashMap<String, String>>,
    /// session id -> the one CSRF token that session currently holds.
    csrf: Mutex<HashMap<String, String>>,
    /// session id -> consent approvals this session has made and not yet spent. One-shot: see
    /// [`consent_resolver`].
    approvals: Mutex<HashMap<String, Vec<String>>>,
}

/// A 256 bit random identifier, hex encoded. Session ids and CSRF tokens are both secrets an
/// attacker wins by guessing, so both come from the OS CSPRNG and neither is derived from
/// anything about the user.
fn random_id() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("OS randomness");
    let mut out = String::with_capacity(64);
    for byte in buf {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The session id this request carries, from the host's own cookie.
///
/// A COOKIE THIS SERVER SET, not a header a caller chose. See [`subject_resolver`] for why that
/// distinction is the whole of the identity model.
fn session_id(headers: &HeaderMap) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookies.split(';') {
        if let Some(value) = part.trim().strip_prefix("session=") {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------------------------
// 5. SUBJECT RESOLUTION
// ---------------------------------------------------------------------------------------------

/// Who this request is, according to the HOST's session store.
///
/// # A HOST THAT READS AN UNVALIDATED HEADER HERE HAS AUTHENTICATED NOBODY
///
/// Worth being blunt about, because the shape of the seam invites the mistake. The resolver is
/// handed a `HeaderMap` and asked for a subject, and the shortest thing that compiles is:
///
/// ```text
/// .with_subject_resolver(|h| h.get("X-User-Id").and_then(|v| v.to_str().ok()).map(str::to_owned))
/// ```
///
/// That server issues an authorization code, an access token and a refresh token for ANY subject
/// ANY caller names. It is not weak authentication, it is none: the attacker types the victim's
/// user id into a header. The header form is acceptable ONLY when a reverse proxy STRIPS that
/// header from every inbound request and re-adds it after authenticating, and if you cannot point
/// at the configuration line that strips it, you do not have that.
///
/// What is safe is what this does: take an opaque identifier the SERVER minted, look it up in
/// storage the SERVER controls, and return the subject recorded there. `None` means no session,
/// and the authorization endpoint then refuses with 403 rather than inventing a user.
fn subject_resolver(state: &Arc<HostState>, headers: &HeaderMap) -> Option<String> {
    let sid = session_id(headers)?;
    state
        .sessions
        .lock()
        .expect("session mutex")
        .get(&sid)
        .cloned()
}

// ---------------------------------------------------------------------------------------------
// 4. CSRF
// ---------------------------------------------------------------------------------------------

/// Mint the CSRF token for a form this session is about to be shown.
///
/// Called by the service when it renders the RFC 8628 verification form, and by this example's
/// own consent page, deliberately through the same store: two CSRF schemes in one host is one
/// scheme plus a bug.
///
/// The token is bound to the SESSION, which is what makes it a countermeasure at all. A token
/// that is merely random but not session bound can be fetched by an attacker from their own
/// session and posted with the victim's cookies.
fn csrf_issue(state: &Arc<HostState>, headers: &HeaderMap) -> Option<String> {
    let sid = session_id(headers)?;
    // No session means no token can be bound to one, so there is nothing to issue and the
    // service renders no form. That is the right answer: a form that works and is forgeable is
    // worse than no form at all.
    if !state
        .sessions
        .lock()
        .expect("session mutex")
        .contains_key(&sid)
    {
        return None;
    }
    let token = random_id();
    state
        .csrf
        .lock()
        .expect("csrf mutex")
        .insert(sid, token.clone());
    Some(token)
}

/// Take back the token this session was last issued, AND invalidate it.
///
/// The removal is the point: it is what makes the token single use, so a token captured from one
/// page cannot be replayed against a second submission. The service compares what was submitted
/// with what this returns, in constant time, and refuses on a mismatch or on `None`.
fn csrf_consume(state: &Arc<HostState>, headers: &HeaderMap) -> Option<String> {
    let sid = session_id(headers)?;
    state.csrf.lock().expect("csrf mutex").remove(&sid)
}

// ---------------------------------------------------------------------------------------------
// 3. CONSENT
// ---------------------------------------------------------------------------------------------

/// What a consent approval is recorded as: this exact client asking for this exact scope.
///
/// THE KEY IS THE REQUEST, not the client. An approval recorded as "the user said yes to client
/// X" would be spent by a later request from client X for a WIDER scope, which is precisely the
/// escalation a consent screen exists to prevent.
fn approval_key(client_id: &str, scope: &ScopeSet) -> String {
    format!("{client_id}|{scope}")
}

/// The RFC 6749 s10.12 consent step: has this user KNOWINGLY agreed to this exact request?
///
/// # Why an auto-approving resolver is a vulnerability and not a shortcut
///
/// RFC 6749 s10.12 requires the server to "ensure that the malicious client cannot obtain
/// authorization without the awareness and explicit consent of the resource owner". An
/// authorization endpoint that mints a code as soon as it knows WHO the user is satisfies neither
/// half. Any cross-site top-level navigation, a link in an email, a redirect from a page the
/// victim visited, makes a logged-in victim's browser hand a registered client a code the victim
/// never agreed to issue. PKCE and exact redirect URI matching bound WHO may redeem that code;
/// they say nothing about whether it should have existed. This is the same finding that put the
/// CSRF seam on the device form, applied to the other interactive endpoint.
///
/// # What a real consent screen MUST show
///
/// * WHICH CLIENT is asking, by its registered display name and not only by `client_id`. A user
///   cannot evaluate an opaque identifier.
/// * THE EXACT SCOPE that will be granted, in words the user can act on. Not "this app would like
///   access", which is a request for a signature on a blank page.
/// * An approval that takes an AFFIRMATIVE ACTION, with refusal equally available. RFC 8628 s5.4
///   (Remote Phishing) is explicit for the device flow, where `verification_uri_complete` removes
///   the one friction point the attack had to beat: whatever that deep link lands on must still
///   name the client and the scope, with approval one deliberate click away. The same reasoning
///   applies here, and it is why this returns a PAGE rather than a decision on first sight.
///
/// # How this one works
///
/// First arrival: no approval on file, so it returns [`ConsentDecision::Respond`] with a page
/// naming the client and the scope and carrying a session-bound CSRF token. The user posts it to
/// `/consent`, the host records a ONE-SHOT approval and redirects back to the identical
/// authorization request, and this resolver finds the approval, SPENDS it, and approves.
///
/// One-shot matters. An approval left on file would let a later cross-site navigation ride it
/// without the user being asked, which reopens exactly the hole above. A host that wants "do not
/// ask me again" turns on the `consent` feature and returns `ConsentDecision::ApproveAndRemember`
/// instead, so that the remembering is recorded as the user's deliberate choice, is visible to
/// them, and can be withdrawn, rather than being an accident of cache lifetime.
fn consent_resolver(state: &Arc<HostState>, request: &ConsentRequest<'_>) -> ConsentDecision {
    let sid = match session_id(request.headers) {
        Some(sid) => sid,
        // The subject resolver already refused this case, so reaching it would mean the two seams
        // disagree about what a session is. Refusing is the only safe answer to that.
        None => return ConsentDecision::Deny,
    };

    let key = approval_key(request.client_id.as_str(), request.scope);
    {
        let mut approvals = state.approvals.lock().expect("approvals mutex");
        if let Some(pending) = approvals.get_mut(&sid) {
            if let Some(index) = pending.iter().position(|k| *k == key) {
                // SPENT here, not merely read: see the one-shot argument above.
                pending.swap_remove(index);
                return ConsentDecision::Approve;
            }
        }
    }

    let token = match csrf_issue(state, request.headers) {
        Some(token) => token,
        None => return ConsentDecision::Deny,
    };

    // `request.uri` is the whole authorization request, so posting it back and redirecting to it
    // round-trips the user to the IDENTICAL request they were shown. Re-deriving it from parts
    // would risk displaying one request and resuming a different one.
    let page = consent_page(
        request.client_id.as_str(),
        request.scope,
        &request.uri.to_string(),
        &token,
    );
    ConsentDecision::Respond(Box::new(html(StatusCode::OK, page)))
}

/// The consent screen. Deliberately plain: what matters is that it names the client, lists the
/// scope one line at a time, and offers Allow and Deny as two equal buttons, so that neither is
/// what happens by default or by accident.
fn consent_page(client_id: &str, scope: &ScopeSet, return_to: &str, csrf: &str) -> String {
    let mut scopes = String::new();
    for s in scope.iter() {
        // Every interpolated value is escaped. `client_id` and the scope have both been validated
        // by the server before the resolver sees them, and `return_to` is this server's own URI,
        // but a consent screen that trusts its inputs is one XSS away from being an approval an
        // attacker clicks on the user's behalf.
        scopes.push_str(&format!("<li><code>{}</code></li>", escape(s.as_str())));
    }
    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Authorize</title></head>\
         <body><h1>Authorize access</h1>\
         <p><strong>{client}</strong> is asking to act on your behalf.</p>\
         <p>It will be allowed to:</p><ul>{scopes}</ul>\
         <form method=\"post\" action=\"/consent\">\
         <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
         <input type=\"hidden\" name=\"return_to\" value=\"{return_to}\">\
         <button type=\"submit\" name=\"action\" value=\"allow\">Allow</button>\
         <button type=\"submit\" name=\"action\" value=\"deny\">Deny</button>\
         </form></body></html>",
        client = escape(client_id),
        scopes = scopes,
        csrf = escape(csrf),
        return_to = escape(return_to),
    )
}

/// The consent form's submission. THIS IS THE HOST'S ENDPOINT, mounted alongside the crate's
/// service below: the library serves the protocol and never the user experience.
fn consent_submit(state: &Arc<HostState>, headers: &HeaderMap, body: &[u8]) -> Response {
    // Cheapest guard first, and it costs a conforming browser nothing.
    if !is_form(headers) {
        return html(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "<p>Expected a form submission.</p>".to_string(),
        );
    }
    let sid = match session_id(headers) {
        Some(sid) => sid,
        None => {
            return html(
                StatusCode::FORBIDDEN,
                "<p>You are not signed in.</p>".to_string(),
            )
        }
    };
    let form = parse_form(&String::from_utf8_lossy(body));

    // CSRF, consumed (and therefore invalidated) before anything is decided. Without this the
    // consent screen is decoration: an attacker posts this endpoint from their own page, the
    // victim's browser attaches the session cookie, and the approval is on file before the user
    // has seen anything at all.
    let expected = csrf_consume(state, headers);
    let presented = form.get("csrf_token").cloned().unwrap_or_default();
    if !expected.is_some_and(|e| constant_time_eq(&e, &presented)) {
        return html(
            StatusCode::FORBIDDEN,
            "<p>That form has expired. Start again.</p>".to_string(),
        );
    }

    // `return_to` came back through the browser, so it is attacker-influenced text. Accepting an
    // absolute URL here would make this endpoint an open redirector, which is a phishing
    // primitive, and one that borrows the authorization server's own reputation. Origin-relative
    // only, and `//host` is rejected because a browser reads that as an absolute URL with the
    // current scheme.
    let return_to = form.get("return_to").cloned().unwrap_or_default();
    if !return_to.starts_with('/') || return_to.starts_with("//") {
        return html(StatusCode::BAD_REQUEST, "<p>Bad request.</p>".to_string());
    }

    if form.get("action").map(String::as_str) != Some("allow") {
        // A refusal records nothing. A host that would rather answer the CLIENT immediately
        // returns `ConsentDecision::Deny` from the resolver instead, which is RFC 6749 s4.1.2.1
        // `access_denied` at the client's registered redirect URI.
        return html(
            StatusCode::OK,
            "<p>Not authorized. You can close this page.</p>".to_string(),
        );
    }

    // What was approved is derived from the request being RESUMED, never from the form: a hidden
    // field naming the scope would let whoever submits it widen what was granted.
    let (client_id, scope) = match approved_request(&return_to) {
        Some(pair) => pair,
        None => return html(StatusCode::BAD_REQUEST, "<p>Bad request.</p>".to_string()),
    };
    state
        .approvals
        .lock()
        .expect("approvals mutex")
        .entry(sid)
        .or_default()
        .push(approval_key(&client_id, &scope));

    see_other(&return_to)
}

/// Re-derive what the user just approved from the authorization request they are being returned
/// to. `None` when the request names no client, which the authorization endpoint would refuse
/// anyway.
///
/// The scope is read from the request as the CLIENT sent it. If the client omitted it, the
/// client's registered default applies, and the empty set recorded here will not match the
/// resolver's key, so the user is asked again rather than being silently granted something they
/// were never shown. Asking twice is a poor experience; approving something that was never
/// displayed is a defect.
fn approved_request(return_to: &str) -> Option<(String, ScopeSet)> {
    let query = return_to.split_once('?').map(|(_, q)| q).unwrap_or("");
    let pairs = parse_form(query);
    let client_id = pairs.get("client_id")?.clone();
    let scope = match pairs.get("scope") {
        Some(s) => ScopeSet::parse(s).ok()?,
        None => ScopeSet::empty(),
    };
    Some((client_id, scope))
}

// ---------------------------------------------------------------------------------------------
// 6. THE SWEEPER
// ---------------------------------------------------------------------------------------------

/// Reclaim expired records on an interval, forever.
///
/// # Why the host has to do this
///
/// This crate has NO background tasks, no global statics and no lazy singletons, deliberately: a
/// host that compiles it in but never turns it on pays nothing at runtime, and that property is
/// worth more than the convenience of a timer nobody asked for. The consequence is that
/// `Storage::sweep_expired` is called by the host or by nobody.
///
/// # What "by nobody" costs
///
/// Not untidiness. THE DEVICE AUTHORIZATION ENDPOINT TAKES NO CREDENTIAL FROM A PUBLIC CLIENT:
/// RFC 8628 s3.1 is a POST carrying a `client_id`, which RFC 6749 s2.2 says is not a secret. Each
/// one allocates a device grant plus a user-code index entry that live for `device_code_ttl` (600
/// seconds by default), and anyone who can open a socket can send them in a loop. Without a sweep
/// those records are never reclaimed, long after they stop being usable, so the store grows until
/// the process dies. The same applies, more slowly, to expired authorization codes, expired access
/// tokens, spent refresh records held open for the reuse-detection window, and claimed replay ids.
///
/// Expiry ITSELF is enforced on read, so a store that is never swept is not INSECURE, it is
/// UNBOUNDED. That is why this is a liveness obligation rather than a correctness one, and why
/// getting the interval a bit wrong is fine while never running it is not.
///
/// # Choosing the interval
///
/// 60 seconds here, well under the 600 second device code TTL, so dead grants are reclaimed
/// within one interval of dying rather than accumulating a TTL at a time. A busy deployment on a
/// real database should sweep more often and in bounded batches; a quiet one can sweep less
/// often. The number that matters is not this one, it is that the task exists.
///
/// # Running it
///
/// One task per PROCESS, not per request. It must be safe to call concurrently with request
/// handling (that is part of the trait's contract), so on a multi-node deployment every node
/// sweeping is harmless: the operation is idempotent. A host that would rather not have N nodes
/// deleting the same rows runs it on one node, or from a scheduled job that calls the same method.
///
/// A sweep failure is logged and retried on the next tick. It must NEVER end the task and never
/// take the process down: a database blip is not a reason to stop issuing tokens, and a task that
/// returned on an error is a sweeper that has silently stopped, which is the worst outcome here
/// because the symptom appears hours later as memory growth.
fn spawn_sweeper<S>(server: Arc<AuthorizationServer<S>>, every: Duration)
where
    S: Storage + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(every);
        loop {
            // The first tick fires immediately, which is what we want: a process that has just
            // restarted onto a shared store may have a backlog waiting for it.
            ticker.tick().await;
            match server.store().sweep_expired(SystemTime::now()).await {
                Ok(0) => {}
                Ok(n) => eprintln!("sweep reclaimed {n} expired records"),
                Err(e) => eprintln!("sweep failed, retrying next tick: {e}"),
            }
        }
    });
}

// ---------------------------------------------------------------------------------------------
// 8. SIGNING KEYS AND ROTATION
// ---------------------------------------------------------------------------------------------

/// Configure RFC 9068 `at+jwt` access tokens, if the host has given this server a key.
///
/// OPAQUE TOKENS ARE THE DEFAULT AND ARE OFTEN THE RIGHT ANSWER: a resource server that can call
/// RFC 7662 introspection learns the token's state at the moment it asks, which a signed token
/// cannot tell it. Signing earns its keep when resource servers are separate processes that
/// should not make a network call per request. The cost of turning it on is key management, which
/// is the whole of this function.
///
/// # The key
///
/// Loaded from a file the host controls, or in a real deployment from a KMS or a sealed secret.
/// NEVER from the source tree. The signing key is the single secret that decides which access
/// tokens the entire deployment believes: anyone holding it mints tokens for any user, any client
/// and any scope, and revoking tokens does not fix a leaked key. See the banner in
/// `conformance_server.rs` for what a hard-coded one costs.
///
/// # Rotation, which is not optional
///
/// You will rotate this key, on a schedule or on a compromise. RFC 7517 s4.5 `kid` is what makes
/// that survivable: the token names the key it was signed with, so a verifier SELECTS rather than
/// trial-verifying, and two generations can be live at once.
///
/// [`oauth_as::jwt::JwtConfig::rotate_to`] promotes a new active key and RETIRES the previous one,
/// keeping the retired PUBLIC half in the JWKS. That retention is the entire point: swapping the
/// key without it makes every unexpired access token unverifiable the moment a resource server
/// refetches the key set, which is an outage for tokens that had done nothing wrong.
///
/// The rule for dropping a retired key
/// ([`oauth_as::jwt::JwtConfig::forget_retired_key_breaking_its_live_tokens`], named so it is hard
/// to call by accident): keep it published for AT LEAST `access_token_ttl` after the rotation that
/// retired it, plus however long your resource servers cache the key set. Drop it sooner and you
/// have broken live tokens.
///
/// This example rotates at STARTUP, which is the honest shape for a config-driven server: the
/// previous key is still in the configuration, the new one is promoted over it, and both are
/// published. A deployment that rotates without a restart rebuilds the service with the new
/// configuration and swaps it in, which is the host's business and not something this crate hides.
#[cfg(feature = "jwt")]
fn configure_signing(
    config: &mut ServerConfig,
    issuer: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use oauth_as::jwt::{AccessTokenFormat, EcdsaP256Key, JwtConfig};

    let path = match std::env::var("OAUTH_AS_SIGNING_KEY_PKCS8") {
        Ok(path) => path,
        // No key configured: opaque access tokens, which is this crate's default and the shape
        // that needs no key management at all.
        Err(_) => return Ok(()),
    };
    let kid = std::env::var("OAUTH_AS_SIGNING_KID").unwrap_or_else(|_| "as-es256-1".to_string());
    let key = EcdsaP256Key::from_pkcs8_der(kid, &std::fs::read(&path)?)?;

    // RFC 9068 s2.2 `aud`: which resource server these tokens are for. A token with no meaningful
    // audience is a token every resource accepts, which turns any one compromised resource into a
    // path into all of them. Required rather than defaulted, for that reason.
    let audience = std::env::var("OAUTH_AS_AUDIENCE")
        .map_err(|_| "OAUTH_AS_AUDIENCE is required when signing access tokens")?;
    let jwks_uri = format!("{}/jwks", issuer.trim_end_matches('/'));
    let mut jwt = JwtConfig::new(key, audience).with_jwks_uri(jwks_uri);

    // A rotation the operator asked for: the key above is what this server was signing with, and
    // this is the new one. `rotate_to` signs with the new key and keeps publishing the old one.
    if let Ok(next_path) = std::env::var("OAUTH_AS_SIGNING_KEY_PKCS8_NEXT") {
        let next_kid =
            std::env::var("OAUTH_AS_SIGNING_KID_NEXT").unwrap_or_else(|_| "as-es256-2".to_string());
        let next = EcdsaP256Key::from_pkcs8_der(next_kid, &std::fs::read(&next_path)?)?;
        jwt = jwt.rotate_to(next);
        // What a host does NOT do here is forget the retired key in the same deployment that
        // retired it. It has to outlive every token signed under it; see this function's docs.
        eprintln!(
            "signing key rotated; still publishing retired kids: {:?}",
            jwt.retired_kids().collect::<Vec<_>>()
        );
    }

    config.access_token_format = AccessTokenFormat::Jwt(Box::new(jwt));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// THE ONE DISHONEST PART, FENCED OFF BY NAME
// ---------------------------------------------------------------------------------------------

/// ############################################################################
/// # DEVELOPMENT ONLY. THIS AUTHENTICATES NOBODY. NEVER SHIP IT.              #
/// ############################################################################
///
/// Mints a session for whatever subject the caller names, so that the rest of this file can be
/// exercised end to end without a login page.
///
/// It is here because the alternative was worse. Every other obligation in this file can be
/// demonstrated honestly; authentication cannot, because this crate has no user store, no
/// password hashing, no MFA and no federation, and will not grow them. An example that faked a
/// login inline, in the middle of the wiring, would be teaching the fake. So the fake is one
/// function, named after what it is, armed only by an explicit environment variable, and
/// additionally REFUSED unless the issuer is loopback, so that a copied deployment cannot arm it
/// by accident on a public host.
///
/// What replaces it: your existing login. Authenticate the user however you already do, mint a
/// session id from a CSPRNG, store the subject against it server side, and set it as a cookie
/// with `HttpOnly`, `Secure`, `SameSite=Lax` and a path. The cookie below sets `HttpOnly` and
/// `SameSite=Lax` but NOT `Secure`, because this mode only ever runs over loopback HTTP; a real
/// one sets it. `SameSite=Lax` is load bearing rather than cosmetic: it is what stops a
/// cross-site POST from carrying the session at all, which is defence in depth underneath the
/// CSRF tokens above.
fn dev_login_handler(state: &Arc<HostState>, query: &str) -> Response {
    let subject = parse_form(query)
        .get("sub")
        .cloned()
        .unwrap_or_else(|| "dev-user".to_string());
    let sid = random_id();
    state
        .sessions
        .lock()
        .expect("session mutex")
        .insert(sid.clone(), subject.clone());

    let mut response = html(
        StatusCode::OK,
        format!(
            "<p>Development session opened for <code>{}</code>.</p>",
            escape(&subject)
        ),
    );
    let cookie = format!("session={sid}; HttpOnly; SameSite=Lax; Path=/");
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

// ---------------------------------------------------------------------------------------------
// WIRING
// ---------------------------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::var("OAUTH_AS_ADDR").unwrap_or_else(|_| "127.0.0.1:8915".to_string());
    // RFC 8414 s3.3: the issuer MUST be the URL the metadata document is fetched from. A real
    // deployment behind TLS sets this to its https origin from CONFIGURATION, never from a
    // request header: an issuer taken from `Host` is an issuer an attacker can choose, and every
    // RFC 9207 `iss` check downstream would then be comparing against the attacker's value.
    let issuer = std::env::var("OAUTH_AS_ISSUER").unwrap_or_else(|_| format!("http://{addr}"));

    // NO DEFAULT CREDENTIAL. A server that invents one has published it, because its source is
    // published. This is the same reason the conformance fixture's hard-coded secret is fenced
    // off by name: the difference between a fixture and a backdoor is whether anyone can reach it.
    let client_secret = std::env::var("OAUTH_AS_CLIENT_SECRET").map_err(|_| {
        "set OAUTH_AS_CLIENT_SECRET to the secret this example's confidential client presents"
    })?;

    // The dev login is armed only on an explicit flag AND a loopback issuer. Two conditions
    // rather than one, because a flag alone survives being copied into a deployment's environment
    // file, and the second cannot be satisfied by accident in production.
    let dev_login = match (
        std::env::var("OAUTH_AS_DEV_LOGIN").as_deref() == Ok("1"),
        issuer.starts_with("http://127.0.0.1") || issuer.starts_with("http://localhost"),
    ) {
        (true, true) => true,
        (true, false) => {
            return Err("OAUTH_AS_DEV_LOGIN refuses to arm for a non-loopback issuer".into())
        }
        (false, _) => false,
    };

    // RFC 8628 s3.2: where the user is sent to approve a device. Under the issuer here, so the
    // service serves it; a host with its own branded page points this elsewhere and calls
    // `AuthorizationServer::approve_device` from its own handler.
    let verification_uri = format!("{}/device", issuer.trim_end_matches('/'));
    let mut config = ServerConfig::new(issuer.clone(), verification_uri);
    // RFC 8414 s2 `scopes_supported`: publishing the catalogue lets a client see what it may ask
    // for without probing for it.
    config.scopes_supported = Some(vec!["read".to_string(), "write".to_string()]);
    // RFC 7591 dynamic client registration stays OFF (`config.registration` is unset). If you turn
    // it on you MUST also install a `RegistrationPolicy`, or every registration is refused. RFC
    // 7591 s5 is why refusing is the default: an open registration endpoint lets anyone on the
    // internet mint a client, which weakens every threat model that assumed controlling a
    // registered client was hard.
    #[cfg(feature = "jwt")]
    configure_signing(&mut config, &issuer)?;

    let server = AuthorizationServer::new(config, HostStorage::new())
        // Obligation 7. Without this the two compromise events revoke silently.
        .with_event_sink(Box::new(StderrEventSink))
        // Obligation 2. RFC 8628 s5.1: the user code's entropy is adequate only in combination
        // with a throttle on code entry, so this is not optional for any deployment offering the
        // device grant.
        //
        // This limiter ships with the crate and is a FLOOR, not a ceiling. Read `oauth_as::
        // rate_limit`'s module docs before deciding it is enough: it is PER PROCESS (N nodes means
        // N times the budget), it RESETS ON RESTART, and its device bucket is GLOBAL because this
        // crate has no caller identity to key on. A deployment with more than one node, or one
        // that can see a client address, should put its own limiter behind the same `RateLimiter`
        // trait and keep this one underneath as a backstop.
        //
        // The window is shortened from the default because a shorter window narrows the
        // fixed-window boundary artefact (a burst straddling the boundary can land up to twice the
        // budget). The budgets themselves are left at the crate's defaults, which that module
        // derives from the actual guessing arithmetic rather than picking round numbers.
        .with_rate_limiter(Box::new(FixedWindowRateLimiter::with_config(
            RateLimitConfig::default().with_window(Duration::from_secs(30)),
        )));
    let server = Arc::new(server);

    register_clients(&server, &client_secret).await?;

    // Obligation 6.
    spawn_sweeper(Arc::clone(&server), Duration::from_secs(60));

    let host = Arc::new(HostState::default());

    let service = {
        let subject_state = Arc::clone(&host);
        let consent_state = Arc::clone(&host);
        let issue_state = Arc::clone(&host);
        let consume_state = Arc::clone(&host);
        ServiceBuilder::new(Arc::clone(&server))
            // Obligation 5. Reads a server-minted session, never a caller-supplied header.
            .with_subject_resolver(move |headers| subject_resolver(&subject_state, headers))
            // Obligation 3. Never returns `Approve` on first sight of a request.
            .with_consent_resolver(move |request| consent_resolver(&consent_state, request))
            // Obligation 4. Both halves, session bound, single use.
            .with_csrf_tokens(
                move |headers| csrf_issue(&issue_state, headers),
                move |headers| csrf_consume(&consume_state, headers),
            )
            // NOTE what is NOT called here: `dangerously_disable_verification_protections`. It
            // exists for non-browser test harnesses, and on a browser-reachable endpoint it
            // re-enables the complete RFC 6749 s10.12 forced-approval chain, which is account
            // takeover needing no interaction beyond loading a page.
            .build()?
    };

    serve(addr, issuer, service, host, dev_login).await
}

/// Mount the service under the host's own HTTP server, with the host's own routes in front.
///
/// The service is an `async fn` from an `http::Request` to an `http::Response` and knows nothing
/// about any framework, which is the point: the HOST owns the listener. axum is used here because
/// this crate ships a one-function adapter for it behind the `axum` feature; a host on hyper, or
/// on anything else that speaks `http` 1.x, calls `service.handle(request)` from wherever it
/// already dispatches, and needs no feature at all.
///
/// The host's routes are matched FIRST and the OAuth service is the fallback (that is what
/// `Router::from(service)` is). That ordering is the normal shape of an embedded authorization
/// server: the consent screen, the login, the branding and the error pages are the host's, and
/// the protocol endpoints are the library's.
async fn serve<S>(
    addr: String,
    issuer: String,
    service: AuthorizationService<S, SystemClock>,
    host: Arc<HostState>,
    dev_login: bool,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: Storage + Send + Sync + 'static,
{
    use axum::routing::{get, post};

    let consent_state = Arc::clone(&host);
    let mut router = axum::Router::new().route(
        "/consent",
        post(move |headers: HeaderMap, body: axum::body::Bytes| {
            let state = Arc::clone(&consent_state);
            async move { into_axum(consent_submit(&state, &headers, &body)) }
        }),
    );
    if dev_login {
        eprintln!("WARNING: OAUTH_AS_DEV_LOGIN is on. /dev-login authenticates nobody.");
        let login_state = Arc::clone(&host);
        router = router.route(
            "/dev-login",
            get(move |uri: http::Uri| {
                let state = Arc::clone(&login_state);
                let query = uri.query().unwrap_or_default().to_string();
                async move { into_axum(dev_login_handler(&state, &query)) }
            }),
        );
    }
    let router = router.merge(axum::Router::from(service));

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("oauth-as listening on {addr} (issuer {issuer})");
    // TLS IS THE HOST'S JOB AND IT IS NOT OPTIONAL. Every credential this server handles moves
    // over this listener: client secrets in POST bodies, authorization codes in redirects, access
    // and refresh tokens in responses, session cookies on every interactive request. A plaintext
    // listener is acceptable ONLY behind a proxy that terminates TLS on a network you control. In
    // production this is `axum-server` with rustls, or a reverse proxy, and either way the
    // certificate and its renewal are yours. This crate never sees a socket and cannot check any
    // of it for you.
    axum::serve(listener, router).await?;
    Ok(())
}

/// The service's response, in the body type the host's server wants. One line, and it is the
/// whole of what a host's own handlers pay for speaking the same vocabulary as the service.
fn into_axum(response: Response) -> axum::response::Response {
    response.map(|body| axum::body::Body::from(body.into_bytes()))
}

/// The clients this server knows about.
///
/// A real deployment loads these from its own configuration or its own admin surface. What
/// matters here is the SHAPE of a registration, not where it came from.
async fn register_clients<S>(
    server: &AuthorizationServer<S>,
    confidential_secret: &str,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: Storage,
{
    let scopes = ScopeSet::from_tokens(["read", "write"])?;

    // A PUBLIC client: a native, browser or device app. It holds no secret, because a secret
    // shipped inside an application the user can read is not a secret. Possession of the
    // `client_id` therefore proves nothing, and the flows compensate: PKCE (mandatory in this
    // crate, S256 only) for the code flow, and human interaction for the device flow.
    server
        .register_client(Client {
            client_id: ClientId::new("example-device-app"),
            auth: ClientAuth::Public,
            grant_types: vec![
                GrantType::AuthorizationCode,
                GrantType::DeviceCode,
                GrantType::RefreshToken,
            ],
            // EXACT match, no wildcards, no prefixes. The redirect URI is the address an
            // authorization code is delivered to, so a loose match is a code delivered to an
            // attacker (RFC 9700 s4.1).
            redirect_uris: vec!["http://127.0.0.1:8917/cb".to_string()],
            allowed_scopes: scopes.clone(),
            // The narrowest thing that is useful, not everything the client MAY have. A default
            // is what a client that asks for nothing gets, and it should not be the maximum.
            default_scopes: ScopeSet::from_tokens(["read"])?,
            // Shown on the consent screen. A client with no name forces the user to evaluate a
            // bare identifier, which they cannot do.
            name: Some("Example device app".to_string()),
            registration: None,
        })
        .await?;

    // A CONFIDENTIAL client, stored as a ONE-WAY VERIFIER rather than as its secret.
    //
    // `ClientAuth::ConfidentialSecret` (the plaintext variant) exists and is legitimate for a host
    // that resolves secrets from a vault at request time, but storing plaintext means a leak of
    // the client table is a leak of every client's working credential, and you cannot honestly
    // tell a customer their secret is unrecoverable. The built-in scheme here is SHA-256 of the
    // secret, which is right for a HIGH ENTROPY machine-generated secret (this one should be 32
    // random bytes) and WRONG for anything a human chose: for that, store an argon2id or scrypt
    // verifier through `SecretHash::custom` and install a `SecretVerifier` that checks it.
    server
        .register_client(Client {
            client_id: ClientId::new("example-service"),
            auth: ClientAuth::ConfidentialSecretHash {
                hash: SecretHash::sha256(confidential_secret),
            },
            // No `AuthorizationCode` and no redirect URI: this client acts for itself and never
            // for a user. RFC 6749 s4.4 client credentials has no resource owner, which is also
            // why this crate issues it no refresh token.
            grant_types: vec![GrantType::ClientCredentials],
            redirect_uris: vec![],
            allowed_scopes: scopes,
            default_scopes: ScopeSet::from_tokens(["read"])?,
            name: Some("Example backend service".to_string()),
            registration: None,
        })
        .await?;

    Ok(())
}

// ---------------------------------------------------------------------------------------------
// SMALL HELPERS. Nothing here is OAuth; it is the plumbing any HTML-serving host has to have.
// ---------------------------------------------------------------------------------------------

/// Minimal HTML escaping for the values interpolated into the consent screen.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// An HTML response in the type [`ConsentDecision::Respond`] carries: a plain `http::Response`,
/// which is the one HTTP vocabulary every Rust server agrees on.
fn html(status: StatusCode, body: String) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

/// 303, not 302: the browser must switch the resumed request back to GET after this POST.
fn see_other(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(value) => {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::SEE_OTHER;
            response.headers_mut().insert(header::LOCATION, value);
            response
        }
        Err(_) => html(StatusCode::BAD_REQUEST, "<p>Bad request.</p>".to_string()),
    }
}

fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .map(str::trim)
                .is_some_and(|t| t.eq_ignore_ascii_case("application/x-www-form-urlencoded"))
        })
}

/// `application/x-www-form-urlencoded` parsing, enough for the two forms this file serves.
fn parse_form(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in text.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(percent_decode(k), percent_decode(v));
    }
    out
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Constant-time comparison for the CSRF token.
///
/// A CSRF token is a secret the submitter is claiming to know, so `==` leaks how much of it
/// matched through timing, exactly as comparing a password would. Over fixed-width digests so
/// that the loop bound does not depend on either input's length either. This crate does the same
/// for the token IT checks; this is the host's half of the same comparison.
fn constant_time_eq(a: &str, b: &str) -> bool {
    use sha2::{Digest as _, Sha256};
    let da = Sha256::digest(a.as_bytes());
    let db = Sha256::digest(b.as_bytes());
    let mut diff = 0u8;
    for i in 0..da.len() {
        diff |= da[i] ^ db[i];
    }
    diff == 0
}
