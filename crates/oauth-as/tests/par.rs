// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9126 pushed authorization requests, driven through the crate's public API the way a host
//! would drive them.
//!
//! The tests that matter here are the ATTACKS, and each one is written as the attack rather than
//! as an exercise of the code path:
//!
//! - [`a_request_uri_cannot_be_used_twice`]: the handle is captured (or the client is buggy) and
//!   presented a second time. RFC 9126 section 4 and section 7.3.
//! - [`a_request_uri_belonging_to_another_client_is_refused`]: request URI swapping, RFC 9126
//!   section 7.5, with the second half that matters just as much: the rightful owner's handle must
//!   still work afterwards, or refusing the swap has bought a denial of service instead.
//! - [`a_client_cannot_push_a_request_that_names_another_client`]: an authenticated client lodges
//!   a request under a victim's identity and hands the handle to a browser.
//! - [`requiring_par_refuses_the_same_request_in_the_query`]: the downgrade. An attacker who can
//!   rewrite the URL strips PAR and sends the parameters directly.
//! - [`an_expired_request_uri_is_refused`]: a handle held until the flow is stale.

#![cfg(feature = "par")]

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// A revocation-barrier deadline far enough out that the barrier stands for the whole test.
/// Local rather than shared: this file does not otherwise pull in the test support module.
fn far_future() -> SystemTime {
    std::time::UNIX_EPOCH + Duration::from_secs(4_000_000_000)
}

/// The whole window, for a test about the CASCADE rather than about when a grant was established.
fn far_future_window() -> oauth_as::store::RevocationWindow {
    oauth_as::store::RevocationWindow {
        recorded_at: far_future(),
        until: far_future(),
    }
}

use oauth_as::{
    AuthorizationError, AuthorizationRequest, AuthorizationServer, AuthorizationServerMetadata,
    Client, ClientAuth, ClientId, Clock, ErrorCode, GrantType, MemoryStorage, ParConfig, ScopeSet,
    ServerConfig, Storage, REQUEST_URI_PREFIX,
};

/// RFC 7636 appendix B's verifier, so the challenge below is a real S256 challenge rather than a
/// 43-character string that happens to look like one.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

#[derive(Clone)]
struct TestClock(Arc<Mutex<SystemTime>>);

impl TestClock {
    fn new() -> Self {
        TestClock(Arc::new(Mutex::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )))
    }

    fn advance(&self, by: Duration) {
        let mut now = self.0.lock().unwrap();
        *now += by;
    }
}

impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}

fn client(id: &str) -> Client {
    Client {
        client_id: ClientId::new(id),
        auth: ClientAuth::ConfidentialSecret {
            secret: format!("{id}-secret"),
        },
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        redirect_uris: vec![format!("https://{id}.example/cb")],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

fn config() -> ServerConfig {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.par = Some(Box::new(ParConfig::new()));
    cfg
}

async fn server_with(
    cfg: ServerConfig,
    clock: TestClock,
) -> AuthorizationServer<MemoryStorage, TestClock> {
    let server = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), clock);
    server.register_client(client("app")).await.unwrap();
    server.register_client(client("other")).await.unwrap();
    server
}

fn challenge() -> String {
    oauth_as::pkce::code_challenge_s256(VERIFIER)
}

/// The parameters of a well-formed authorization request for `app`.
fn pushed_parameters(challenge: &str) -> Vec<(&str, &str)> {
    vec![
        ("response_type", "code"),
        ("client_id", "app"),
        ("redirect_uri", "https://app.example/cb"),
        ("scope", "read"),
        ("state", "opaque-state"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ]
}

#[tokio::test]
async fn a_pushed_request_comes_back_as_a_single_use_urn_handle() {
    let clock = TestClock::new();
    let server = server_with(config(), clock).await;
    let challenge = challenge();

    let pushed = server
        .pushed_authorization_request(
            &ClientId::new("app"),
            Some("app-secret"),
            &pushed_parameters(&challenge),
        )
        .await
        .expect("a well-formed pushed request is accepted");

    // RFC 9126 s2.2: the URN form, with a cryptographically strong random part, and a lifetime.
    assert!(
        pushed.request_uri.starts_with(REQUEST_URI_PREFIX),
        "expected the RFC 9126 s2.2 URN form, got {}",
        pushed.request_uri
    );
    let reference = &pushed.request_uri[REQUEST_URI_PREFIX.len()..];
    assert_eq!(reference.len(), 64, "expected 32 bytes of hex entropy");
    assert_eq!(pushed.expires_in, 60);
    assert_eq!(
        pushed.http_status(),
        201,
        "RFC 9126 s2.2 states 201, not 200"
    );

    let validated = server
        .validate_pushed_authorization_request("app", &pushed.request_uri)
        .await
        .expect("the handle resolves to the pushed request");
    assert_eq!(validated.client_id, ClientId::new("app"));
    assert_eq!(validated.redirect_uri, "https://app.example/cb");
    assert_eq!(validated.scope, ScopeSet::parse("read").unwrap());
    assert_eq!(validated.state.as_deref(), Some("opaque-state"));
    assert_eq!(validated.code_challenge, challenge);
}

/// ATTACK, RFC 9126 s4 and s7.3. A `request_uri` is a capability: whoever holds it can start the
/// authorization it describes. The client is required to use it once; the SERVER is what makes
/// that true, because a captured handle is replayed by someone who has read no RFC.
#[tokio::test]
async fn a_request_uri_cannot_be_used_twice() {
    let clock = TestClock::new();
    let server = server_with(config(), clock).await;
    let challenge = challenge();

    let pushed = server
        .pushed_authorization_request(
            &ClientId::new("app"),
            Some("app-secret"),
            &pushed_parameters(&challenge),
        )
        .await
        .unwrap();

    server
        .validate_pushed_authorization_request("app", &pushed.request_uri)
        .await
        .expect("the first use is the legitimate one");

    let replay = server
        .validate_pushed_authorization_request("app", &pushed.request_uri)
        .await;
    match replay {
        Err(AuthorizationError::Direct(error)) => {
            assert_eq!(error.error, ErrorCode::InvalidRequestUri);
        }
        other => panic!("a replayed request_uri must be refused, got {other:?}"),
    }
}

/// ATTACK, RFC 9126 s2.2 ("the request_uri value MUST be bound to the client that posted the
/// authorization request") and s7.5 (request URI swapping). An attacker who controls a registered
/// client captures a handle and substitutes it into an authorization request of its own.
///
/// The second half is the part that is easy to get wrong: the refusal must not consume the handle,
/// or anybody who can guess or observe one has a free denial of service against the real client.
#[tokio::test]
async fn a_request_uri_belonging_to_another_client_is_refused() {
    let clock = TestClock::new();
    let server = server_with(config(), clock).await;
    let challenge = challenge();

    let pushed = server
        .pushed_authorization_request(
            &ClientId::new("app"),
            Some("app-secret"),
            &pushed_parameters(&challenge),
        )
        .await
        .unwrap();

    let stolen = server
        .validate_pushed_authorization_request("other", &pushed.request_uri)
        .await;
    match stolen {
        Err(AuthorizationError::Direct(error)) => {
            assert_eq!(error.error, ErrorCode::InvalidRequestUri);
        }
        other => panic!("a request_uri must be bound to the client that pushed it, got {other:?}"),
    }

    let rightful = server
        .validate_pushed_authorization_request("app", &pushed.request_uri)
        .await
        .expect("refusing the swap must not burn the legitimate client's handle");
    assert_eq!(rightful.client_id, ClientId::new("app"));
}

/// ATTACK, RFC 9126 s2.1: an authenticated client pushes a request naming a DIFFERENT client, so
/// that the handle it receives starts an authorization attributed to the victim (and delivered to
/// the victim's registered redirect URI, which the attacker may control a path on).
#[tokio::test]
async fn a_client_cannot_push_a_request_that_names_another_client() {
    let clock = TestClock::new();
    let server = server_with(config(), clock).await;
    let challenge = challenge();

    let mut parameters = pushed_parameters(&challenge);
    parameters[1] = ("client_id", "other");
    parameters[2] = ("redirect_uri", "https://other.example/cb");

    let error = server
        .pushed_authorization_request(&ClientId::new("app"), Some("app-secret"), &parameters)
        .await
        .expect_err("a client may push only its own request");
    assert_eq!(error.error, ErrorCode::InvalidRequest);
}

/// RFC 9126 s2.1 step 2: `request_uri` MUST NOT be provided at the PAR endpoint. Chaining handles
/// would let a captured one be re-lodged under another client's identity.
#[tokio::test]
async fn a_pushed_request_may_not_carry_request_uri() {
    let clock = TestClock::new();
    let server = server_with(config(), clock).await;
    let challenge = challenge();

    let mut parameters = pushed_parameters(&challenge);
    parameters.push(("request_uri", "urn:ietf:params:oauth:request_uri:whatever"));

    let error = server
        .pushed_authorization_request(&ClientId::new("app"), Some("app-secret"), &parameters)
        .await
        .expect_err("RFC 9126 s2.1 rejects a pushed request_uri");
    assert_eq!(error.error, ErrorCode::InvalidRequest);
}

/// RFC 9126 s2.1 step 3: the pushed request is validated exactly as the authorization endpoint
/// would validate it, so the client hears about a bad request on the back channel instead of after
/// a browser redirect. Each case here is a check the authorization endpoint already performs, and
/// the point of the test is that pushing does not skip any of them.
#[tokio::test]
async fn a_pushed_request_is_validated_at_push_time() {
    let clock = TestClock::new();
    let server = server_with(config(), clock).await;
    let challenge = challenge();

    // What each case is, the parameters it pushes, and the RFC 6749 s5.2 code it must come back
    // with. Named rather than inlined so a failure says which check went missing.
    type Case<'a> = (&'a str, Vec<(&'a str, &'a str)>, ErrorCode);
    let cases: Vec<Case<'_>> = vec![
        (
            "a redirect_uri that is not registered",
            {
                let mut p = pushed_parameters(&challenge);
                p[2] = ("redirect_uri", "https://attacker.example/cb");
                p
            },
            ErrorCode::InvalidRequest,
        ),
        (
            "no PKCE challenge at all",
            pushed_parameters(&challenge)
                .into_iter()
                .filter(|(name, _)| *name != "code_challenge" && *name != "code_challenge_method")
                .collect(),
            ErrorCode::InvalidRequest,
        ),
        (
            "PKCE downgraded to plain",
            {
                let mut p = pushed_parameters(&challenge);
                p[6] = ("code_challenge_method", "plain");
                p
            },
            ErrorCode::InvalidRequest,
        ),
        (
            "a scope outside the registration",
            {
                let mut p = pushed_parameters(&challenge);
                p[3] = ("scope", "read write admin");
                p
            },
            ErrorCode::InvalidScope,
        ),
        (
            "an RFC 8707 resource indicator with a fragment",
            {
                let mut p = pushed_parameters(&challenge);
                p.push(("resource", "https://rs.example/api#frag"));
                p
            },
            ErrorCode::InvalidTarget,
        ),
        (
            "response_type=token, which OAuth 2.1 removed",
            {
                let mut p = pushed_parameters(&challenge);
                p[0] = ("response_type", "token");
                p
            },
            ErrorCode::UnsupportedResponseType,
        ),
    ];

    for (what, parameters, expected) in cases {
        let error = server
            .pushed_authorization_request(&ClientId::new("app"), Some("app-secret"), &parameters)
            .await
            .err()
            .unwrap_or_else(|| panic!("{what} must be refused at push time"));
        assert_eq!(error.error, expected, "wrong error code for: {what}");
    }
}

/// The same list, one case at a time, so a failure names the case. (Kept separate from the loop
/// above, which asserts the SHAPE of the answer: a JSON error body, never a redirect.)
#[tokio::test]
async fn push_time_validation_answers_with_the_token_endpoint_error_shape() {
    let clock = TestClock::new();
    let server = server_with(config(), clock).await;
    let challenge = challenge();

    let mut unregistered = pushed_parameters(&challenge);
    unregistered[2] = ("redirect_uri", "https://attacker.example/cb");
    let error = server
        .pushed_authorization_request(&ClientId::new("app"), Some("app-secret"), &unregistered)
        .await
        .expect_err("an unregistered redirect_uri is refused");
    // RFC 9126 s2.3: the section 4.1.2.1 errors that may not be redirected become invalid_request
    // in a token-endpoint-shaped JSON body, with a 400.
    assert_eq!(error.error, ErrorCode::InvalidRequest);
    assert_eq!(error.http_status(), 400);
    assert!(error.error_description.is_some());
}

/// RFC 9126 s2.1 step 1: the client authenticates as it would at the token endpoint. Pushing is
/// what lets the server refuse fraudulent requests early, and that only holds if the caller has
/// actually proved who it is.
#[tokio::test]
async fn a_push_with_the_wrong_secret_is_refused() {
    let clock = TestClock::new();
    let server = server_with(config(), clock).await;
    let challenge = challenge();

    let error = server
        .pushed_authorization_request(
            &ClientId::new("app"),
            Some("not-the-secret"),
            &pushed_parameters(&challenge),
        )
        .await
        .expect_err("client authentication is not optional here");
    assert_eq!(error.error, ErrorCode::InvalidClient);
}

/// ATTACK, RFC 9126 s4: an expired handle MUST be rejected. An attacker who obtains a handle from
/// a log or a crash dump hours later must not be able to start the flow it describes.
#[tokio::test]
async fn an_expired_request_uri_is_refused() {
    let clock = TestClock::new();
    let server = server_with(config(), clock.clone()).await;
    let challenge = challenge();

    let pushed = server
        .pushed_authorization_request(
            &ClientId::new("app"),
            Some("app-secret"),
            &pushed_parameters(&challenge),
        )
        .await
        .unwrap();

    clock.advance(Duration::from_secs(61));

    match server
        .validate_pushed_authorization_request("app", &pushed.request_uri)
        .await
    {
        Err(AuthorizationError::Direct(error)) => {
            assert_eq!(error.error, ErrorCode::InvalidRequestUri)
        }
        other => panic!("an expired request_uri must be refused, got {other:?}"),
    }
}

/// ATTACK, RFC 9126 s4 (the policy paragraph). A deployment that requires PAR is defending against
/// exactly one thing: an attacker who can put parameters in the browser's URL simply not using
/// PAR. If the query path still works, requiring PAR bought nothing.
#[tokio::test]
async fn requiring_par_refuses_the_same_request_in_the_query() {
    let clock = TestClock::new();
    let mut cfg = config();
    let mut par = ParConfig::new();
    par.require_pushed_authorization_requests = true;
    cfg.par = Some(Box::new(par));
    let server = server_with(cfg, clock).await;
    let challenge = challenge();

    let query = AuthorizationRequest::from_pairs(pushed_parameters(&challenge));
    match server.validate_authorization_request(&query).await {
        Err(AuthorizationError::Direct(error)) => {
            assert_eq!(error.error, ErrorCode::InvalidRequest)
        }
        other => {
            panic!("with PAR required, a query authorization request must be refused: {other:?}")
        }
    }

    // ... and the pushed form of the identical request still works, or "required" would just mean
    // "broken".
    let pushed = server
        .pushed_authorization_request(
            &ClientId::new("app"),
            Some("app-secret"),
            &pushed_parameters(&challenge),
        )
        .await
        .unwrap();
    server
        .validate_pushed_authorization_request("app", &pushed.request_uri)
        .await
        .expect("PAR is required, not broken");
}

/// RFC 9101 s6.3, which RFC 9126 s4 builds on: the server uses ONLY the parameters that were
/// pushed, "even if the same parameter is provided in the query parameter".
///
/// The tamper this test describes cannot be expressed against
/// `validate_pushed_authorization_request`, and that is the finding rather than a gap in the test:
/// the function accepts the client id and the handle, and nothing else, so there is no argument
/// through which a query-string `scope` or `redirect_uri` could reach validation. What is asserted
/// here is the consequence, which WOULD change if somebody later added a "merge the query in"
/// convenience: the resolved request is byte for byte the pushed one.
#[tokio::test]
async fn only_the_pushed_parameters_are_used() {
    let clock = TestClock::new();
    let server = server_with(config(), clock).await;
    let challenge = challenge();

    let pushed = server
        .pushed_authorization_request(
            &ClientId::new("app"),
            Some("app-secret"),
            &pushed_parameters(&challenge),
        )
        .await
        .unwrap();

    // What an intermediary would append to the redirect if it could:
    //   &scope=read%20write&redirect_uri=https://attacker.example/cb&state=attacker
    let validated = server
        .validate_pushed_authorization_request("app", &pushed.request_uri)
        .await
        .unwrap();
    assert_eq!(
        validated.scope,
        ScopeSet::parse("read").unwrap(),
        "the pushed scope must win over anything in the query"
    );
    assert_eq!(validated.redirect_uri, "https://app.example/cb");
    assert_eq!(validated.state.as_deref(), Some("opaque-state"));
}

/// RFC 9126 s7.4: the client's policy may change between the push and the authorization request,
/// so the request is validated again at the authorization endpoint rather than trusted because it
/// was validated once.
///
/// THE HANDLE HAS TO SURVIVE FOR THIS TO MEAN ANYTHING, which is why the policy is CHANGED rather
/// than the client DELETED. Deletion cascades the handle away (`MemoryStorage::delete_client`
/// retains out every pushed request the client owns), so `take_pushed_authorization_request`
/// answers `None` and the refusal is `invalid_request_uri` — an unknown-handle refusal that
/// `validate_direct_authorization_request`, which IS the revalidation, is never reached to make.
/// A test that only asked for `AuthorizationError::Direct(_)` could not tell those two apart, and
/// the cascade alone would have satisfied it. Here the registration stays, its redirect URI list
/// no longer contains the one that was pushed, and the refusal is the REVALIDATION's:
/// `invalid_request`, direct rather than redirected, because a redirect URI this client is no
/// longer registered for is not somewhere an error may be sent (RFC 6749 s4.1.2.1).
#[tokio::test]
async fn a_handle_is_revalidated_against_the_client_policy_of_the_moment() {
    let clock = TestClock::new();
    let server = server_with(config(), clock).await;
    let challenge = challenge();

    let pushed = server
        .pushed_authorization_request(
            &ClientId::new("app"),
            Some("app-secret"),
            &pushed_parameters(&challenge),
        )
        .await
        .unwrap();

    // RFC 7592 s2.2: the registration is UPDATED while the handle is outstanding, moving the
    // client off the redirect URI its pushed request names.
    let mut moved = client("app");
    moved.redirect_uris = vec!["https://app.example/moved".to_string()];
    server.store().put_client(moved).await.unwrap();

    match server
        .validate_pushed_authorization_request("app", &pushed.request_uri)
        .await
    {
        Err(AuthorizationError::Direct(error)) => assert_eq!(
            error.error,
            ErrorCode::InvalidRequest,
            "the refusal must come from revalidating the pushed parameters, not from the handle \
             being unknown: {error:?}"
        ),
        other => panic!("a superseded policy must not authorize: {other:?}"),
    }
}

/// The OTHER refusal, kept separate so neither can stand in for the other: RFC 7592 s2.3 deletion
/// takes the client's outstanding artifacts with it, so the handle is not merely unusable, it is
/// GONE, and the answer is the unknown-handle one of RFC 9126 s2.2.
#[tokio::test]
async fn deleting_the_client_takes_its_outstanding_handles_with_it() {
    let clock = TestClock::new();
    let server = server_with(config(), clock).await;
    let challenge = challenge();

    let pushed = server
        .pushed_authorization_request(
            &ClientId::new("app"),
            Some("app-secret"),
            &pushed_parameters(&challenge),
        )
        .await
        .unwrap();

    assert!(server
        .store()
        .delete_client(&ClientId::new("app"), far_future_window())
        .await
        .unwrap());
    assert!(
        server
            .store()
            .take_pushed_authorization_request(&pushed.request_uri)
            .await
            .unwrap()
            .is_none(),
        "the cascade must have reclaimed the handle itself, not merely orphaned it"
    );
}

/// RFC 9126 s5: the endpoint is advertised exactly when it is served, and the policy member states
/// its value rather than leaving a client to guess the default.
#[test]
fn metadata_advertises_par_only_when_the_host_enabled_it() {
    let off = AuthorizationServerMetadata::from_config(&ServerConfig::new(
        "https://as.example",
        "https://as.example/device",
    ));
    assert_eq!(off.pushed_authorization_request_endpoint, None);
    assert_eq!(off.require_pushed_authorization_requests, None);

    let on = AuthorizationServerMetadata::from_config(&config());
    assert_eq!(
        on.pushed_authorization_request_endpoint.as_deref(),
        Some("https://as.example/par")
    );
    assert_eq!(on.require_pushed_authorization_requests, Some(false));

    let mut required = config();
    let mut par = ParConfig::new();
    par.require_pushed_authorization_requests = true;
    required.par = Some(Box::new(par));
    let document =
        serde_json::to_value(AuthorizationServerMetadata::from_config(&required)).unwrap();
    assert_eq!(document["require_pushed_authorization_requests"], true);
    assert_eq!(
        document["pushed_authorization_request_endpoint"],
        "https://as.example/par"
    );
}

/// Nothing in this crate evicts on a timer, so a handle that is never redeemed is reclaimed only
/// by the host's sweep, exactly like an abandoned device grant.
#[tokio::test]
async fn sweep_expired_reclaims_abandoned_handles() {
    let clock = TestClock::new();
    let server = server_with(config(), clock.clone()).await;
    let challenge = challenge();

    server
        .pushed_authorization_request(
            &ClientId::new("app"),
            Some("app-secret"),
            &pushed_parameters(&challenge),
        )
        .await
        .unwrap();

    assert_eq!(
        server.store().sweep_expired(clock.now()).await.unwrap(),
        0,
        "a live handle is not dead"
    );
    clock.advance(Duration::from_secs(61));
    assert_eq!(
        server.store().sweep_expired(clock.now()).await.unwrap(),
        1,
        "an expired handle is reclaimed"
    );
}

// ------------------------------------------------- the grant instant a client barrier compares

/// A store that deletes the client from inside the read the push derives its write from, and moves
/// the clock while doing it.
///
/// The clock advance is what makes the test discriminate. Without it, entry and write are the same
/// instant, a barrier recorded between them cannot be expressed, and both the fixed and the
/// defective orderings refuse — the "passes with the defect reintroduced" failure that has already
/// caught three tests in this repo.
struct DeleteDuringRead {
    inner: MemoryStorage,
    clock: TestClock,
    /// The window the deletion records. Deliberately NOT `far_future_window()`: a far-future
    /// `recorded_at` refuses every push unconditionally and would make this test pass either way.
    window: oauth_as::store::RevocationWindow,
    armed: Arc<Mutex<Option<ClientId>>>,
}

impl Storage for DeleteDuringRead {
    /// The read `authenticate_client` makes. It answers truthfully, moves the clock past the
    /// barrier, and then deletes — which is exactly where a concurrent RFC 7592 section 2.3
    /// request would land: after the push began, before it writes.
    async fn get_client(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<Arc<Client>>, oauth_as::StorageError> {
        let found = self.inner.get_client(client_id).await?;
        let armed = {
            let mut slot = self.armed.lock().unwrap_or_else(|e| e.into_inner());
            slot.take()
        };
        if let (Some(id), true) = (armed, found.is_some()) {
            self.clock.advance(Duration::from_secs(60));
            self.inner.delete_client(&id, self.window).await?;
        }
        Ok(found)
    }

    oauth_as::delegate_storage! {
        to inner;
        put_client, compare_and_swap_client, delete_client,
        put_device_grant, get_device_grant, find_device_grant_by_user_code,
        take_device_grant, compare_and_swap_device_grant,
        put_authorization_code, compare_and_swap_authorization_code, take_authorization_code,
        put_pushed_authorization_request, take_pushed_authorization_request,
        put_token, get_token, delete_token,
        put_refresh_token, get_refresh_token, take_refresh_token, revoke_token_family,
        put_consent, compare_and_swap_consent, get_consent, find_consent,
        consents_for_subject, revoke_consent,
        claim_replay_id,
        sweep_expired,
    }
}

/// A push whose client is deleted mid-request must not mint a handle.
///
/// THE STRAIGHTFORWARD HALF, and what this test actually pins: whatever the ordering inside the
/// endpoint, a `delete_client` landing while a push is in flight must leave no `request_uri`
/// behind. A handle outliving its registration is the seventh resurrection site, and it is the
/// expensive one: a host that re-provisions the same `client_id` inside the handle's 60 second
/// lifetime — which the store contract explicitly permits — resolves it against the NEW
/// registration, carrying the deleted client's `redirect_uri`, `scope` and `code_challenge`.
///
/// WHAT THIS TEST DOES NOT DISCRIMINATE, said plainly because a test that quietly proves less than
/// its name suggests is the failure mode this suite keeps hitting. The 0.9.1 audit reported that
/// `pushed_at` was stamped after `authenticate_client` and that a deletion in that window would be
/// admitted by the barrier comparison. Reading the code settles it the other way:
/// `validate_direct_authorization_request` re-reads the registration (`server.rs`, "unknown
/// client_id"), so a deletion landing before that read is refused THERE, and one landing after it
/// is later than `pushed_at` under either stamping and is refused by the barrier. There is no
/// ordering that separates the two, and this test passes with the stamp in either position —
/// verified by moving it and re-running.
///
/// The stamp was moved to request entry anyway, and the reason is worth writing down: it makes the
/// refusal below true of the window its own comment names, and it stops the barrier's correctness
/// depending on a second registration read that a later refactor would be entitled to remove as
/// redundant. Defence in depth, not a fix for a reachable defect.
#[tokio::test]
async fn a_push_is_refused_when_the_client_is_deleted_mid_request() {
    let clock = TestClock::new();
    let entry = clock.now();
    let armed: Arc<Mutex<Option<ClientId>>> = Arc::new(Mutex::new(None));
    let store = DeleteDuringRead {
        inner: MemoryStorage::new(),
        clock: clock.clone(),
        window: oauth_as::store::RevocationWindow {
            recorded_at: entry + Duration::from_secs(30),
            until: far_future(),
        },
        armed: armed.clone(),
    };
    let server = AuthorizationServer::with_clock(config(), store, clock.clone());
    server.register_client(client("app")).await.unwrap();

    // Armed only now, so the registration above is written through an unarmed store.
    *armed.lock().unwrap() = Some(ClientId::new("app"));

    let challenge = challenge();
    let pushed = server
        .pushed_authorization_request(
            &ClientId::new("app"),
            Some("app-secret"),
            &pushed_parameters(&challenge),
        )
        .await;

    assert!(
        pushed.is_err(),
        "a handle was minted for a registration deleted while the push was in flight: the push \
         dates from the authentication, which happened before the deletion, so the barrier covers \
         it — got {pushed:?}"
    );
    assert!(
        clock.now() > entry + Duration::from_secs(30),
        "the trigger did not advance the clock, so the write did not cross the barrier and this \
         test proves nothing"
    );
}

/// `expires_in` is a POSITIVE integer (RFC 9126 section 2.2), whatever TTL the host configured.
///
/// FOUND BY THE 0.9.1 AUDIT. `ParConfig::request_uri_ttl` is a plain public field with no
/// validating constructor, so a sub-second `Duration` reported `expires_in: 0` — a handle a
/// conforming client treats as already dead and abandons, from a push that answered `201`. A zero
/// duration was worse still: `expires_at` equalled `now`, so the handle was refused on its first
/// presentation, and nothing in either answer pointed at the TTL.
///
/// Clamped rather than rejected, for the reason `user_code_length` clamps: a misconfiguration must
/// not become a runtime failure in front of a user.
#[tokio::test]
async fn a_sub_second_ttl_still_reports_a_usable_lifetime() {
    let clock = TestClock::new();
    let mut cfg = config();
    let mut par = ParConfig::new();
    par.request_uri_ttl = Duration::from_millis(500);
    cfg.par = Some(Box::new(par));
    let server = server_with(cfg, clock.clone()).await;

    let challenge = challenge();
    let pushed = server
        .pushed_authorization_request(
            &ClientId::new("app"),
            Some("app-secret"),
            &pushed_parameters(&challenge),
        )
        .await
        .expect("a short TTL is a configuration choice, not a refusal");

    assert!(
        pushed.expires_in >= 1,
        "RFC 9126 s2.2 makes expires_in a positive integer; a client told 0 abandons a handle the \
         server is still honouring: {}",
        pushed.expires_in
    );

    // And the handle the client was told about must actually resolve, which is the half that
    // catches a clamp applied to the reported number but not to the recorded deadline.
    assert!(
        server
            .validate_pushed_authorization_request("app", &pushed.request_uri)
            .await
            .is_ok(),
        "the handle died before the lifetime its own response promised"
    );
}
