// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 7591 dynamic client registration, from outside the crate.
//!
//! Two halves, and the first is the one that matters. RFC 7591 section 5 says an open registration
//! endpoint lets anyone on the internet create a client, and this crate's own security review
//! noted that dynamic registration turns "the attacker must control a registered client" from a
//! real obstacle into a form submission. So before any wire shape is checked at all, this file
//! pins that registration is OFF, that turning it on is not by itself enough, and that what a
//! registrant can obtain is bounded.
//!
//! The second half is the wire: the section 2 request shape, the section 3.2.1 response, and the
//! section 3.2.2 error registry, which is NOT the RFC 6749 section 5.2 one.

mod support;

use std::sync::Mutex;

use oauth_as::{
    AuthorizationServer, AuthorizationServerMetadata, ClientId, ClientMetadata, Event, EventSink,
    GrantType, MemoryStorage, RegistrationAttempt, RegistrationConfig, RegistrationDecision,
    RegistrationErrorCode, RegistrationFailure, RegistrationPolicy, ScopeSet, ServerConfig,
    Storage, TokenRequest,
};

// ------------------------------------------------------------------------------- fixtures

/// A policy that says yes to everything, which is what an OPEN registration endpoint is. Spelled
/// out here rather than defaulted anywhere in the library, which is the point of the seam.
struct OpenPolicy;

impl RegistrationPolicy for OpenPolicy {
    fn authorize(&self, _attempt: &RegistrationAttempt<'_>) -> RegistrationDecision {
        RegistrationDecision::Allow
    }
}

/// The RFC 7591 section 1.2 initial access token pattern: a host-issued bearer token that the
/// registration request must present.
struct InitialAccessToken(&'static str);

impl RegistrationPolicy for InitialAccessToken {
    fn authorize(&self, attempt: &RegistrationAttempt<'_>) -> RegistrationDecision {
        match attempt.initial_access_token {
            Some(t) if t == self.0 => RegistrationDecision::Allow,
            _ => RegistrationDecision::Deny,
        }
    }
}

fn registration_config() -> RegistrationConfig {
    let mut cfg = RegistrationConfig::new();
    cfg.allowed_scopes = ScopeSet::parse("read write").unwrap();
    cfg
}

fn server_config(registration: Option<RegistrationConfig>) -> ServerConfig {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.registration = registration.map(Box::new);
    cfg
}

fn code_client_metadata() -> ClientMetadata {
    ClientMetadata {
        redirect_uris: vec!["https://app.example/cb".to_string()],
        client_name: Some("Test App".to_string()),
        ..ClientMetadata::default()
    }
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime")
}

/// A sink that keeps the `Debug` rendering of every event, exactly as `tests/events.rs` does.
#[derive(Default)]
struct Transcript(Mutex<Vec<String>>);

impl EventSink for Transcript {
    fn on_event(&self, event: Event<'_>) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(format!("{event:?}"));
    }
}

struct TranscriptHandle(std::sync::Arc<Transcript>);

impl EventSink for TranscriptHandle {
    fn on_event(&self, event: Event<'_>) {
        self.0.on_event(event)
    }
}

// -------------------------------------------------------------------------------- policy

/// RFC 7591 section 5. Registration must not be reachable on a server whose host never asked for
/// it: a default-on client-minting endpoint is the abuse vector the section describes, and no
/// amount of later policy helps a deployment that did not know the endpoint was there.
#[tokio::test]
async fn registration_is_off_unless_the_host_turns_it_on() {
    let srv = AuthorizationServer::new(server_config(None), MemoryStorage::new());
    let failure = srv
        .register_dynamic_client(&code_client_metadata(), None)
        .await
        .expect_err("registration must be off by default");
    assert!(
        matches!(failure, RegistrationFailure::Disabled),
        "expected Disabled, got {failure:?}"
    );
    assert_eq!(failure.http_status(), 404);
    // And the default configuration really is the one a host gets from `ServerConfig::new`.
    assert!(
        ServerConfig::new("https://as.example", "https://as.example/device")
            .registration
            .is_none()
    );
}

/// Enabling the endpoint is NOT the same as saying who may use it. With no
/// [`RegistrationPolicy`] installed every registration is refused, because a host that set a
/// config field and installed nothing has not decided anything, and the fail-open reading of that
/// is an anonymous client factory (RFC 7591 section 5).
#[tokio::test]
async fn a_server_with_no_policy_installed_registers_nobody() {
    let srv = AuthorizationServer::new(
        server_config(Some(registration_config())),
        MemoryStorage::new(),
    );
    let failure = srv
        .register_dynamic_client(&code_client_metadata(), Some("any-token"))
        .await
        .expect_err("no policy means no registration");
    assert!(
        matches!(failure, RegistrationFailure::Unauthorized),
        "expected Unauthorized, got {failure:?}"
    );
    assert_eq!(failure.http_status(), 401);
}

/// The policy seam is the host's, and RFC 7591 section 1.2's initial access token is one shape it
/// can take. The library passes the presented token through uninterpreted and honours the answer.
#[tokio::test]
async fn the_policy_seam_decides_who_may_register() {
    let srv = AuthorizationServer::new(
        server_config(Some(registration_config())),
        MemoryStorage::new(),
    )
    .with_registration_policy(Box::new(InitialAccessToken("let-me-in")));

    let failure = srv
        .register_dynamic_client(&code_client_metadata(), None)
        .await
        .expect_err("no initial access token");
    assert!(matches!(failure, RegistrationFailure::Unauthorized));

    let failure = srv
        .register_dynamic_client(&code_client_metadata(), Some("wrong"))
        .await
        .expect_err("wrong initial access token");
    assert!(matches!(failure, RegistrationFailure::Unauthorized));

    srv.register_dynamic_client(&code_client_metadata(), Some("let-me-in"))
        .await
        .expect("the right token registers");
}

/// The policy sees the metadata BEFORE anything is written, so a host can refuse on content (a
/// redirect URI on a domain it will not serve, a `client_name` impersonating the deployment) and
/// nothing reaches the store.
///
/// The assertion that carries the name is the STORE: this runs over `NoWrites`, which panics on
/// `put_client`, so a policy refusal that wrote the row first would abort here rather than pass.
/// Until the 0.9.1 audit this test held a `MemoryStorage` it never read again, and the only sister
/// test that installed `NoWrites` was refused by the limiter one step EARLIER, so no test drove
/// the policy-deny path against a store that objected to being written to.
#[tokio::test]
async fn a_policy_refusal_writes_nothing() {
    struct RefuseByName;
    impl RegistrationPolicy for RefuseByName {
        fn authorize(&self, attempt: &RegistrationAttempt<'_>) -> RegistrationDecision {
            match attempt.metadata.client_name.as_deref() {
                Some(name) if name.contains("as.example") => RegistrationDecision::Deny,
                _ => RegistrationDecision::Allow,
            }
        }
    }
    let store = NoWrites {
        inner: MemoryStorage::new(),
    };
    let srv = AuthorizationServer::new(server_config(Some(registration_config())), store)
        .with_registration_policy(Box::new(RefuseByName));

    let mut metadata = code_client_metadata();
    metadata.client_name = Some("Sign in with as.example".to_string());
    let failure = srv
        .register_dynamic_client(&metadata, None)
        .await
        .expect_err("the host refused this one");
    assert!(matches!(failure, RegistrationFailure::Unauthorized));
}

// -------------------------------------------------------------------------------- throttle

/// A limiter that refuses registration and allows everything else, plus a record of what it was
/// asked and told. A policy decides on CONTENT; this decides on VOLUME, and the two are different
/// instruments for different attacks.
#[derive(Default)]
struct RegistrationThrottle {
    deny: bool,
    seen: Mutex<Vec<String>>,
}

impl oauth_as::RateLimiter for RegistrationThrottle {
    fn check(&self, attempt: oauth_as::Attempt<'_>) -> oauth_as::RateLimitDecision {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(format!("check {attempt:?}"));
        match attempt {
            oauth_as::Attempt::ClientRegistration if self.deny => oauth_as::RateLimitDecision::Deny,
            _ => oauth_as::RateLimitDecision::Allow,
        }
    }

    fn record(&self, attempt: oauth_as::Attempt<'_>, outcome: oauth_as::AttemptOutcome) {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(format!("record {attempt:?} {outcome:?}"));
    }
}

/// THE ATTACK: a loop over the registration endpoint of a deployment that opened it.
///
/// This is the one endpoint whose records are PERMANENT. A `Client` carries no expiry and
/// `Storage::sweep_expired` reclaims none of them, so where an unthrottled token endpoint is a
/// burst a deployment rides out, an unthrottled registration endpoint is growth that never comes
/// back. RFC 7591 section 5 describes the endpoint as available to anyone on the internet, and a
/// `RegistrationPolicy` cannot be the answer: it is handed the metadata document, which says
/// nothing about how many of them have arrived.
///
/// The assertion is the STORE, not the return value: the property being bought is that no row was
/// written, so the store this runs against refuses to write one at all.
#[tokio::test]
async fn a_registration_the_hosts_limiter_refuses_writes_no_client() {
    let throttle = std::sync::Arc::new(RegistrationThrottle {
        deny: true,
        seen: Mutex::default(),
    });
    let store = NoWrites {
        inner: MemoryStorage::new(),
    };
    let srv = AuthorizationServer::new(server_config(Some(registration_config())), store)
        .with_registration_policy(Box::new(OpenPolicy))
        .with_rate_limiter(Box::new(ThrottleHandle(throttle.clone())));

    let failure = srv
        .register_dynamic_client(&code_client_metadata(), None)
        .await
        .expect_err("the host's limiter refused this one");

    // The same answer the policy refusal gives, and deliberately: a caller must not learn from the
    // wire whether it was the content or the rate that stopped them.
    assert!(
        matches!(failure, RegistrationFailure::Unauthorized),
        "expected Unauthorized, got {failure:?}"
    );
    assert_eq!(failure.http_status(), 401);

    // The limiter was asked BEFORE the policy: the policy is host code that may do arbitrary work,
    // and a throttle consulted after it has not throttled the expensive part.
    let seen = throttle
        .seen
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    assert_eq!(
        seen,
        vec!["check ClientRegistration".to_string()],
        "the limiter must be asked once, and a refused registration must report no outcome for \
         work that never happened"
    );
}

/// The other side: with the limiter allowing, a registration goes through and the outcome is
/// reported, so a limiter counting abuse rather than traffic has something to count.
#[tokio::test]
async fn an_allowed_registration_reports_its_outcome_to_the_limiter() {
    let throttle = std::sync::Arc::new(RegistrationThrottle::default());
    let srv = AuthorizationServer::new(
        server_config(Some(registration_config())),
        MemoryStorage::new(),
    )
    .with_registration_policy(Box::new(OpenPolicy))
    .with_rate_limiter(Box::new(ThrottleHandle(throttle.clone())));

    let info = srv
        .register_dynamic_client(&code_client_metadata(), None)
        .await
        .expect("the limiter allowed it");
    assert!(!info.client_id.is_empty());

    let seen = throttle
        .seen
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    assert_eq!(
        seen,
        vec![
            "check ClientRegistration".to_string(),
            "record ClientRegistration Succeeded".to_string(),
        ],
        "an allowed registration is checked once and its outcome reported once"
    );
}

/// A registration the VALIDATOR refuses is reported as a failure, which is the shape of somebody
/// probing for what a deployment's ceilings will accept. Without it a caller could hold a
/// failure-weighted limiter open indefinitely by sending documents that never register.
#[tokio::test]
async fn a_registration_refused_by_validation_is_reported_as_a_failure() {
    let throttle = std::sync::Arc::new(RegistrationThrottle::default());
    let srv = AuthorizationServer::new(
        server_config(Some(registration_config())),
        MemoryStorage::new(),
    )
    .with_registration_policy(Box::new(OpenPolicy))
    .with_rate_limiter(Box::new(ThrottleHandle(throttle.clone())));

    // A scope outside the registration ceiling: refused by `validate`, past both the limiter check
    // and the policy.
    let mut metadata = code_client_metadata();
    metadata.scope = Some("read admin".to_string());
    srv.register_dynamic_client(&metadata, None)
        .await
        .expect_err("admin is outside the registration ceiling");

    let seen = throttle
        .seen
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    assert_eq!(
        seen,
        vec![
            "check ClientRegistration".to_string(),
            "record ClientRegistration Failed".to_string(),
        ],
        "a refused document is what a limiter counting abuse needs to count"
    );
}

/// A refusal by the host's POLICY is reported the same way, for the same reason: it is the shape
/// of somebody trying documents until one is accepted.
#[tokio::test]
async fn a_registration_refused_by_policy_is_reported_as_a_failure() {
    let throttle = std::sync::Arc::new(RegistrationThrottle::default());
    let srv = AuthorizationServer::new(
        server_config(Some(registration_config())),
        MemoryStorage::new(),
    )
    .with_registration_policy(Box::new(InitialAccessToken("the-real-one")))
    .with_rate_limiter(Box::new(ThrottleHandle(throttle.clone())));

    srv.register_dynamic_client(&code_client_metadata(), Some("a-guess"))
        .await
        .expect_err("the policy refuses a wrong initial access token");

    let seen = throttle
        .seen
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    assert_eq!(
        seen,
        vec![
            "check ClientRegistration".to_string(),
            "record ClientRegistration Failed".to_string(),
        ],
        "a refused initial access token is exactly what a failure-weighted budget is for"
    );
}

/// A store that PANICS if a client is ever written to it, so "the registration was refused" is
/// proven by the absence of the write rather than by the error the caller happened to get back.
struct NoWrites {
    inner: MemoryStorage,
}

impl Storage for NoWrites {
    async fn put_client(&self, client: oauth_as::Client) -> Result<(), oauth_as::StorageError> {
        panic!(
            "a refused registration wrote a permanent client row: {:?}",
            client.client_id
        );
    }

    oauth_as::delegate_storage! {
        to inner;
        get_client, compare_and_swap_client, delete_client,
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

/// A shared handle, so the test can read what the installed limiter was asked.
struct ThrottleHandle(std::sync::Arc<RegistrationThrottle>);

impl oauth_as::RateLimiter for ThrottleHandle {
    fn check(&self, attempt: oauth_as::Attempt<'_>) -> oauth_as::RateLimitDecision {
        self.0.check(attempt)
    }

    fn record(&self, attempt: oauth_as::Attempt<'_>, outcome: oauth_as::AttemptOutcome) {
        self.0.record(attempt, outcome)
    }
}

// ------------------------------------------------------------------------------ wire shape

/// RFC 7591 section 3.2.1: the response carries `client_id`, the issued `client_secret`,
/// `client_id_issued_at`, and `client_secret_expires_at` (REQUIRED whenever a secret was issued,
/// with 0 meaning it never expires), plus the registered metadata echoed back.
#[tokio::test]
async fn a_registration_returns_the_section_3_2_1_client_information_response() {
    let srv = AuthorizationServer::new(
        server_config(Some(registration_config())),
        MemoryStorage::new(),
    )
    .with_registration_policy(Box::new(OpenPolicy));

    let mut metadata = code_client_metadata();
    metadata.scope = Some("read".to_string());
    let info = srv
        .register_dynamic_client(&metadata, None)
        .await
        .expect("registered");

    assert!(!info.client_id.is_empty());
    assert!(
        info.client_secret.is_some(),
        "the default token_endpoint_auth_method is client_secret_basic, so a secret is issued"
    );
    assert_eq!(
        info.client_secret_expires_at,
        Some(0),
        "RFC 7591 s3.2.1: 0 means the secret does not expire"
    );
    assert!(info.client_id_issued_at.is_some());
    assert_eq!(info.metadata.redirect_uris, metadata.redirect_uris);
    assert_eq!(info.metadata.client_name.as_deref(), Some("Test App"));
    assert_eq!(info.metadata.scope.as_deref(), Some("read"));
    assert_eq!(
        info.metadata.response_types.as_deref(),
        Some(["code".to_string()].as_slice())
    );
    assert_eq!(
        info.metadata.token_endpoint_auth_method.as_deref(),
        Some("client_secret_basic")
    );

    // The JSON is the RFC's, not a Rust rendering of it.
    let json = serde_json::to_value(&info).unwrap();
    assert!(json["client_id"].is_string());
    assert!(json["client_secret"].is_string());
    assert_eq!(json["client_secret_expires_at"], 0);
    assert_eq!(json["redirect_uris"][0], "https://app.example/cb");
    assert_eq!(json["grant_types"][0], "authorization_code");
}

/// RFC 7591 section 2: `token_endpoint_auth_method: none` is a PUBLIC client (RFC 6749 section
/// 2.1), so no secret exists to issue and none may be returned. Returning one would tell the
/// client to authenticate with a credential the token endpoint will refuse.
#[tokio::test]
async fn a_public_registration_gets_no_client_secret() {
    let srv = AuthorizationServer::new(
        server_config(Some(registration_config())),
        MemoryStorage::new(),
    )
    .with_registration_policy(Box::new(OpenPolicy));

    let mut metadata = code_client_metadata();
    metadata.token_endpoint_auth_method = Some("none".to_string());
    let info = srv
        .register_dynamic_client(&metadata, None)
        .await
        .expect("registered");
    assert_eq!(info.client_secret, None);
    assert_eq!(info.client_secret_expires_at, None);
    let json = serde_json::to_value(&info).unwrap();
    assert!(
        json.get("client_secret").is_none(),
        "an absent member is omitted, never null"
    );
}

/// RFC 7591 section 3.2.2 defines its OWN error registry. `invalid_redirect_uri`,
/// `invalid_client_metadata` and `invalid_software_statement` are not RFC 6749 section 5.2 codes
/// and must not be spelled as any of them, so this pins the wire text of all three.
#[tokio::test]
async fn the_error_codes_are_the_rfc_7591_registry_and_not_the_rfc_6749_one() {
    let srv = AuthorizationServer::new(
        server_config(Some(registration_config())),
        MemoryStorage::new(),
    )
    .with_registration_policy(Box::new(OpenPolicy));

    let cases: [(ClientMetadata, &str); 3] = [
        (
            ClientMetadata::default(),
            // No redirect_uris for the default authorization_code grant.
            "invalid_redirect_uri",
        ),
        (
            ClientMetadata {
                token_endpoint_auth_method: Some("private_key_jwt".to_string()),
                ..code_client_metadata()
            },
            "invalid_client_metadata",
        ),
        (
            ClientMetadata {
                software_statement: Some("eyJhbGciOiJub25lIn0.e30.".to_string()),
                ..code_client_metadata()
            },
            "invalid_software_statement",
        ),
    ];

    for (metadata, expected) in cases {
        let failure = srv
            .register_dynamic_client(&metadata, None)
            .await
            .expect_err("refused");
        let body = match failure {
            RegistrationFailure::Invalid(ref e) => e,
            ref other => panic!("expected an RFC 7591 s3.2.2 error, got {other:?}"),
        };
        assert_eq!(body.error.as_str(), expected);
        assert_eq!(
            serde_json::to_value(body).unwrap()["error"],
            serde_json::Value::String(expected.to_string())
        );
        assert_eq!(failure.http_status(), 400, "RFC 7591 s3.2.2 answers 400");
    }

    // And the code enum is genuinely separate from the token-endpoint one: no value overlaps.
    for code in [
        RegistrationErrorCode::InvalidRedirectUri,
        RegistrationErrorCode::InvalidClientMetadata,
        RegistrationErrorCode::InvalidSoftwareStatement,
    ] {
        assert!(
            code.as_str().parse::<oauth_as::GrantType>().is_err(),
            "sanity: these are not grant types either"
        );
        assert!(
            !["invalid_request", "invalid_client", "invalid_grant"].contains(&code.as_str()),
            "{code} collides with an RFC 6749 s5.2 code"
        );
    }
}

/// The whole point of registering: the client that comes out can actually be used. This drives the
/// registration through the token endpoint (RFC 6749 section 4.4 would need client credentials, so
/// this uses the refresh-grant registration's own authentication) to prove the issued secret is
/// the one the token endpoint verifies, and that the registered scope ceiling holds.
#[tokio::test]
async fn a_registered_client_can_authenticate_with_the_secret_it_was_issued() {
    let mut cfg = registration_config();
    cfg.allowed_grant_types = vec![GrantType::ClientCredentials];
    let srv = AuthorizationServer::new(server_config(Some(cfg)), MemoryStorage::new())
        .with_registration_policy(Box::new(OpenPolicy));

    let metadata = ClientMetadata {
        grant_types: Some(vec!["client_credentials".to_string()]),
        response_types: Some(vec![]),
        scope: Some("read".to_string()),
        ..ClientMetadata::default()
    };
    let info = srv
        .register_dynamic_client(&metadata, None)
        .await
        .expect("registered");
    let secret = info.client_secret.clone().expect("confidential");

    let token = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new(info.client_id.clone()),
            client_secret: Some(secret.clone()),
            scope: None,
        })
        .await
        .expect("the issued secret authenticates");
    assert_eq!(token.scope.as_deref(), Some("read"));

    // The secret is stored one-way, so a wrong one is refused and the stored form is not the
    // secret itself.
    let wrong = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new(info.client_id.clone()),
            client_secret: Some(format!("{secret}x")),
            scope: None,
        })
        .await;
    assert!(wrong.is_err());

    let stored = srv
        .store()
        .get_client(&ClientId::new(info.client_id.clone()))
        .await
        .unwrap()
        .expect("registered client is in the store");
    let debug = format!("{stored:?}");
    assert!(
        !debug.contains(&secret),
        "a registered client's Debug must not carry its secret"
    );
}

/// RFC 8414 section 2 `registration_endpoint`: advertised exactly when this server offers
/// registration, and absent otherwise. A client reads its presence as "I may register here".
#[tokio::test]
async fn the_registration_endpoint_is_advertised_only_when_registration_is_enabled() {
    let off = AuthorizationServerMetadata::from_config(&server_config(None));
    assert_eq!(off.registration_endpoint, None);
    let json = serde_json::to_value(&off).unwrap();
    assert!(
        json.get("registration_endpoint").is_none(),
        "an absent member is omitted, never null"
    );

    let on = AuthorizationServerMetadata::from_config(&server_config(Some(registration_config())));
    assert_eq!(
        on.registration_endpoint.as_deref(),
        Some("https://as.example/register")
    );

    let mut custom = registration_config();
    custom.registration_endpoint = Some("https://as.example/clients".to_string());
    let on = AuthorizationServerMetadata::from_config(&server_config(Some(custom)));
    assert_eq!(
        on.registration_endpoint.as_deref(),
        Some("https://as.example/clients")
    );
}

/// The audit channel has to see a client being created, and must carry NO credential while doing
/// it: not the issued secret and not the registration access token (`src/events.rs` module docs).
#[tokio::test]
async fn registration_reaches_the_event_sink_without_carrying_a_credential() {
    let transcript = std::sync::Arc::new(Transcript::default());
    let srv = AuthorizationServer::new(
        server_config(Some(registration_config())),
        MemoryStorage::new(),
    )
    .with_registration_policy(Box::new(OpenPolicy))
    .with_event_sink(Box::new(TranscriptHandle(transcript.clone())));

    let info = srv
        .register_dynamic_client(&code_client_metadata(), None)
        .await
        .expect("registered");

    let events = transcript
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let registered: Vec<&String> = events
        .iter()
        .filter(|e| e.starts_with("ClientRegistered"))
        .collect();
    assert_eq!(registered.len(), 1, "events were: {events:?}");
    assert!(registered[0].contains(&info.client_id));

    let secret = info.client_secret.clone().unwrap();
    let rat = info.registration_access_token.clone().unwrap();
    for event in &events {
        assert!(
            !event.contains(&secret),
            "an event carried the client secret"
        );
        assert!(
            !event.contains(&rat),
            "an event carried the registration access token"
        );
    }
}

/// The efficiency promise applied to this feature: a host that never enables registration must not
/// pay for it. `ServerConfig::registration` is a boxed option, so a disabled deployment carries one
/// null pointer and allocates nothing, and the `Client` every request clones grows by the same
/// eight bytes rather than by a whole registration record.
#[test]
fn a_host_that_never_registers_anything_pays_one_pointer() {
    assert_eq!(
        std::mem::size_of::<Option<Box<RegistrationConfig>>>(),
        std::mem::size_of::<usize>(),
        "the registration config must be one pointer on ServerConfig"
    );
    assert_eq!(
        std::mem::size_of::<Option<Box<oauth_as::DynamicRegistration>>>(),
        std::mem::size_of::<usize>(),
        "the registration record must be one pointer on Client, which every request clones"
    );
    // The same budget `tests/allocation.rs` pins, which is the point: the two must move together
    // or one of them is not a gate. The `rar` term matches the one there, for the same reason and
    // with the same shape: RFC 9396 s10's `authorization_details_types_supported` is an
    // `Option<Vec<String>>`, three words, and a deployment that does not enable rich authorization
    // requests must not be made to pay for it.
    //
    // `RESOURCE_SERVERS` is 0.9.2's `ServerConfig::resource_servers`, an `Option<Box<[_]>>` that
    // bought the RFC 7662 resource-server introspection channel. Named rather than folded into the
    // base for the same reason every other term here is named: a bare `+ 16` is a number nobody
    // can audit. `tests/allocation.rs` carries the measurements and the argument for the shape.
    const RESOURCE_SERVERS: usize = 16;
    assert!(
        std::mem::size_of::<ServerConfig>()
            <= 448 + RESOURCE_SERVERS + if cfg!(feature = "rar") { 24 } else { 0 },
        "ServerConfig grew past its size budget: {}",
        std::mem::size_of::<ServerConfig>()
    );

    let rt = rt();
    let cfg = server_config(None);
    rt.block_on(async {
        let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
        assert!(srv
            .register_dynamic_client(&code_client_metadata(), None)
            .await
            .is_err());
    });
    let _ = support::RFC7636_VERIFIER;
}

// ------------------------------------------------------------------------------- the wire

/// The `http` feature's routes for RFC 7591 and RFC 7592, driven over a real socket for the same
/// reason `tests/http_surface.rs` gives: the things being pinned here are the STATUS LINE (201 for
/// section 3.2.1, 204 for RFC 7592 section 2.3) and the headers, which a convenience client hides.
#[cfg(feature = "axum")]
mod wire {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use oauth_as::http::ServiceBuilder;
    use oauth_as::{
        AuthorizationServer, MemoryStorage, RegistrationConfig, ScopeSet, ServerConfig,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

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

        fn json(&self) -> serde_json::Value {
            serde_json::from_str(&self.body)
                .unwrap_or_else(|e| panic!("body is not JSON ({e}): {:?}", self.body))
        }
    }

    async fn request(
        addr: SocketAddr,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<&str>,
    ) -> Resp {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
        if let Some(token) = bearer {
            req.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        match body {
            Some(b) => {
                req.push_str("Content-Type: application/json\r\n");
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
        Resp {
            status,
            headers: lines
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
                .collect(),
            body: body.to_string(),
        }
    }

    /// Bind an ephemeral port and serve a router over a server configured with `registration`.
    async fn serve(registration: Option<RegistrationConfig>, policy: bool) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut cfg = ServerConfig::new(
            format!("http://{addr}"),
            format!("http://{addr}/device_verify"),
        );
        cfg.registration = registration.map(Box::new);
        let mut srv = AuthorizationServer::new(cfg, MemoryStorage::new());
        if policy {
            srv = srv.with_registration_policy(Box::new(super::OpenPolicy));
        }
        let router =
            axum::Router::from(ServiceBuilder::new(Arc::new(srv)).build().expect("service"));
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        addr
    }

    fn registration_config() -> RegistrationConfig {
        let mut cfg = RegistrationConfig::new();
        cfg.allowed_scopes = ScopeSet::parse("read write").unwrap();
        cfg
    }

    const METADATA: &str =
        r#"{"redirect_uris":["https://app.example/cb"],"client_name":"Wire App"}"#;

    /// RFC 7591 s3.2.1: "201 Created". The body carries a client secret and a registration access
    /// token, so RFC 6749 s5.1's `Cache-Control: no-store` applies exactly as on the token plane.
    #[tokio::test]
    async fn a_registration_request_answers_201_with_no_store() {
        let addr = serve(Some(registration_config()), true).await;
        let resp = request(addr, "POST", "/register", None, Some(METADATA)).await;
        assert_eq!(resp.status, 201, "body was {:?}", resp.body);
        assert!(resp
            .header("cache-control")
            .is_some_and(|v| v.contains("no-store")));
        let json = resp.json();
        assert!(json["client_id"].is_string());
        assert!(json["registration_client_uri"]
            .as_str()
            .expect("RFC 7592 s3")
            .ends_with(json["client_id"].as_str().unwrap()));
    }

    /// A host that never enabled registration serves NO registration route. Not a 401, not a 403:
    /// the endpoint is not there, and RFC 7591 s5 is why it must not be reachable by default.
    #[tokio::test]
    async fn a_server_with_registration_off_routes_nothing_there() {
        let addr = serve(None, true).await;
        let resp = request(addr, "POST", "/register", None, Some(METADATA)).await;
        assert_eq!(resp.status, 404);
        // And the discovery document does not promise one.
        let meta = request(
            addr,
            "GET",
            "/.well-known/oauth-authorization-server",
            None,
            None,
        )
        .await;
        assert!(meta.json().get("registration_endpoint").is_none());
    }

    /// A policy refusal is an RFC 6750 s3 bearer-token failure, so the 401 carries a `Bearer`
    /// challenge and NOT the `Basic` one the token endpoint uses: this endpoint cannot be
    /// satisfied with client credentials, and telling a client otherwise wastes a round trip.
    #[tokio::test]
    async fn a_refused_registration_answers_401_with_a_bearer_challenge() {
        let addr = serve(Some(registration_config()), false).await;
        let resp = request(addr, "POST", "/register", Some("nope"), Some(METADATA)).await;
        assert_eq!(resp.status, 401);
        assert_eq!(resp.header("www-authenticate"), Some("Bearer"));
    }

    /// RFC 7591 s3.2.2 on a body that is not metadata at all, and the code is from the section
    /// 3.2.2 registry rather than RFC 6749 s5.2's.
    #[tokio::test]
    async fn a_malformed_body_is_an_rfc_7591_error_object() {
        let addr = serve(Some(registration_config()), true).await;
        let resp = request(addr, "POST", "/register", None, Some("not json")).await;
        assert_eq!(resp.status, 400);
        assert_eq!(resp.json()["error"], "invalid_client_metadata");
    }

    /// RFC 7592 s2.1/s2.2/s2.3 at the `registration_client_uri` the registration handed back:
    /// GET reads, PUT replaces, DELETE removes and answers 204 with no body.
    #[tokio::test]
    async fn the_management_endpoint_reads_updates_and_deletes() {
        let addr = serve(Some(registration_config()), true).await;
        let created = request(addr, "POST", "/register", None, Some(METADATA))
            .await
            .json();
        let client_id = created["client_id"].as_str().unwrap().to_string();
        let token = created["registration_access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let path = format!("/register/{client_id}");

        let read = request(addr, "GET", &path, Some(&token), None).await;
        assert_eq!(read.status, 200);
        assert_eq!(read.json()["client_id"], client_id.as_str());

        // Without the token, nothing.
        let anon = request(addr, "GET", &path, None, None).await;
        assert_eq!(anon.status, 401);
        assert_eq!(anon.header("www-authenticate"), Some("Bearer"));

        let updated = request(
            addr,
            "PUT",
            &path,
            Some(&token),
            Some(r#"{"redirect_uris":["https://app.example/other"],"client_name":"Renamed"}"#),
        )
        .await;
        assert_eq!(updated.status, 200);
        assert_eq!(
            updated.json()["redirect_uris"][0],
            "https://app.example/other"
        );

        let deleted = request(addr, "DELETE", &path, Some(&token), None).await;
        assert_eq!(deleted.status, 204, "RFC 7592 s2.3");
        assert!(deleted.body.is_empty());

        // Gone, and the same 401 an unknown registration always got.
        let gone = request(addr, "GET", &path, Some(&token), None).await;
        assert_eq!(gone.status, 401);
    }

    /// The RFC 8414 document advertises the endpoint this router actually serves, so a client that
    /// discovers it can reach it. A mismatch here is the "advertised endpoint that 404s" the
    /// router's own build-time checks exist to prevent.
    #[tokio::test]
    async fn the_advertised_registration_endpoint_is_the_one_that_answers() {
        let addr = serve(Some(registration_config()), true).await;
        let meta = request(
            addr,
            "GET",
            "/.well-known/oauth-authorization-server",
            None,
            None,
        )
        .await
        .json();
        let advertised = meta["registration_endpoint"].as_str().expect("advertised");
        assert_eq!(advertised, format!("http://{addr}/register"));
        let path = advertised.strip_prefix(&format!("http://{addr}")).unwrap();
        let resp = request(addr, "POST", path, None, Some(METADATA)).await;
        assert_eq!(resp.status, 201);
    }
}
