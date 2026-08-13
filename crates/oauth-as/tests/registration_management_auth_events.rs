// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A failed RFC 7592 management authentication must reach the host's audit sink.
//!
//! The token plane already reports every refused client authentication
//! (`Event::ClientAuthenticationFailed`, six sites in `server.rs`). The management plane refused
//! its three ways in silence, so a host that installed an `EventSink` specifically to notice
//! credential guessing saw token-endpoint attempts and nothing at all from the endpoint where the
//! guessed credential REWRITES a registration.
//!
//! That is the endpoint worth watching most. RFC 7592 section 2.2 lets the holder of a
//! registration access token replace the whole metadata document, `redirect_uris` included, which
//! converts directly into authorization codes delivered somewhere else; and `client_id` values are
//! cheap for an attacker to iterate.

use std::sync::Mutex;

use oauth_as::{
    AuthorizationServer, ClientId, ClientMetadata, Event, EventSink, GrantType, MemoryStorage,
    RegistrationAttempt, RegistrationConfig, RegistrationDecision, RegistrationPolicy, ScopeSet,
    ServerConfig,
};

struct OpenPolicy;

impl RegistrationPolicy for OpenPolicy {
    fn authorize(&self, _attempt: &RegistrationAttempt<'_>) -> RegistrationDecision {
        RegistrationDecision::Allow
    }
}

/// Events are recorded as their `Debug` rendering: this file is about WHETHER the host is told and
/// WHAT it is told, and a string transcript says both without pinning the assertion to one shape.
#[derive(Default)]
struct Transcript(Mutex<Vec<String>>);

impl Transcript {
    fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

struct Handle(std::sync::Arc<Transcript>);

impl EventSink for Handle {
    fn on_event(&self, event: Event<'_>) {
        self.0
             .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(format!("{event:?}"));
    }
}

fn server() -> (
    AuthorizationServer<MemoryStorage>,
    std::sync::Arc<Transcript>,
) {
    let mut registration = RegistrationConfig::new();
    registration.allowed_scopes = ScopeSet::parse("read write").unwrap();
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.registration = Some(Box::new(registration));
    let transcript = std::sync::Arc::new(Transcript::default());
    let srv = AuthorizationServer::new(cfg, MemoryStorage::new())
        .with_registration_policy(Box::new(OpenPolicy))
        .with_event_sink(Box::new(Handle(transcript.clone())));
    (srv, transcript)
}

fn metadata() -> ClientMetadata {
    ClientMetadata {
        redirect_uris: vec!["https://app.example/cb".to_string()],
        client_name: Some("Test App".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        scope: Some("read".to_string()),
        ..ClientMetadata::default()
    }
}

/// Path one: a `client_id` that names no registration at all. This is the shape of an attacker
/// walking the client table, and it is the cheapest attempt to make.
#[tokio::test]
async fn an_unknown_client_id_at_the_management_endpoint_is_audited() {
    let (srv, transcript) = server();
    srv.read_registration(&ClientId::new("no-such-client"), "whatever")
        .await
        .expect_err("unknown client");

    let lines = transcript.lines();
    assert_eq!(lines.len(), 1, "expected exactly one event, got {lines:?}");
    assert!(
        lines[0].contains("ClientRegistrationAuthenticationFailed"),
        "wrong event: {lines:?}"
    );
    assert!(
        lines[0].contains("UnknownClient"),
        "wrong reason: {lines:?}"
    );
}

/// Path two: a client the HOST provisioned, which has no registration record and therefore no
/// management credential that could ever verify. A run of these is somebody probing static client
/// ids for a dynamic registration to take over.
#[tokio::test]
async fn a_statically_provisioned_client_probed_for_management_is_audited() {
    let (srv, transcript) = server();
    srv.register_client(oauth_as::Client {
        client_id: ClientId::new("host-provisioned"),
        auth: oauth_as::ClientAuth::Public,
        grant_types: vec![GrantType::AuthorizationCode],
        redirect_uris: vec!["https://app.example/cb".to_string()],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    })
    .await
    .unwrap();

    srv.read_registration(&ClientId::new("host-provisioned"), "whatever")
        .await
        .expect_err("not a dynamic registration");

    let lines = transcript.lines();
    assert_eq!(lines.len(), 1, "expected exactly one event, got {lines:?}");
    assert!(
        lines[0].contains("ClientRegistrationAuthenticationFailed"),
        "wrong event: {lines:?}"
    );
    assert!(
        lines[0].contains("NoDynamicRegistration"),
        "wrong reason: {lines:?}"
    );
}

/// Path three, the one that matters most: a real dynamic registration and a WRONG registration
/// access token. This is the guess that, if it ever lands, rewrites `redirect_uris`.
#[tokio::test]
async fn a_wrong_registration_access_token_is_audited() {
    let (srv, transcript) = server();
    let info = srv
        .register_dynamic_client(&metadata(), None)
        .await
        .expect("registered");

    srv.update_registration(&ClientId::new(info.client_id.clone()), "wrong", &metadata())
        .await
        .expect_err("wrong management credential");

    let lines = transcript.lines();
    // One for the registration itself, one for the refused management attempt.
    assert_eq!(lines.len(), 2, "expected two events, got {lines:?}");
    assert!(
        lines[1].contains("ClientRegistrationAuthenticationFailed"),
        "wrong event: {lines:?}"
    );
    assert!(
        lines[1].contains("SecretMismatch"),
        "wrong reason: {lines:?}"
    );
}

/// The rule the events module doc states: an audit event is a second way out of the process, going
/// to the same logs as `Debug`, so it may not carry a credential. The presented management token is
/// a credential, and it is the one value this event is closest to.
#[tokio::test]
async fn the_audited_attempt_never_carries_the_presented_token() {
    let (srv, transcript) = server();
    let info = srv
        .register_dynamic_client(&metadata(), None)
        .await
        .expect("registered");
    let real = info.registration_access_token.clone().expect("minted");

    srv.read_registration(
        &ClientId::new(info.client_id.clone()),
        "guessed-secret-value",
    )
    .await
    .expect_err("wrong management credential");

    for line in transcript.lines() {
        assert!(
            !line.contains("guessed-secret-value"),
            "the presented credential reached the sink: {line}"
        );
        assert!(
            !line.contains(real.as_str()),
            "a real credential reached the sink: {line}"
        );
    }
}

// ------------------------------------------------------ the fourth and fifth silent refusals
//
// The three paths above are AUTHENTICATION failures. There are two more refusals on these
// endpoints that answer the same bare `401` and reported nothing at all: the host's own
// `RegistrationPolicy` saying no, on the registration plane and on the management plane.
//
// The management one is the one that matters. By the time the policy is consulted, the caller has
// already presented a registration access token this server verified, so a stream of these is a
// client with a WORKING credential repeatedly attempting something the deployment forbids. That is
// a different investigation from a brute force, and it was invisible in both directions: the wire
// answer is deliberately uninformative so that a policy refusing on content does not confirm what
// content it dislikes, which leaves the operator with nothing either.

/// A policy that refuses everything, so the refusal under test is the policy's and nothing else's.
struct ClosedPolicy;

impl RegistrationPolicy for ClosedPolicy {
    fn authorize(&self, _attempt: &RegistrationAttempt<'_>) -> RegistrationDecision {
        RegistrationDecision::Deny
    }
}

fn server_with_closed_policy() -> (
    AuthorizationServer<MemoryStorage>,
    std::sync::Arc<Transcript>,
) {
    let mut registration = RegistrationConfig::new();
    registration.allowed_scopes = ScopeSet::parse("read write").unwrap();
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.registration = Some(Box::new(registration));
    let transcript = std::sync::Arc::new(Transcript::default());
    let srv = AuthorizationServer::new(cfg, MemoryStorage::new())
        .with_registration_policy(Box::new(ClosedPolicy))
        .with_event_sink(Box::new(Handle(transcript.clone())));
    (srv, transcript)
}

/// Path four: RFC 7591 registration refused by the host's policy. No `client_id` exists yet, and
/// none is minted for a refusal, so the event carries `None` rather than inventing one.
#[tokio::test]
async fn a_policy_refused_registration_is_audited() {
    let (srv, transcript) = server_with_closed_policy();
    srv.register_dynamic_client(&metadata(), None)
        .await
        .expect_err("the policy refuses everything");

    let lines = transcript.lines();
    assert_eq!(lines.len(), 1, "expected exactly one event, got {lines:?}");
    assert!(
        lines[0].contains("ClientRegistrationRefusedByPolicy"),
        "wrong event: {lines:?}"
    );
    assert!(
        lines[0].contains("None"),
        "an initial registration has no client id to report: {lines:?}"
    );
}

/// Path five, and the one worth the most: an RFC 7592 section 2.2 UPDATE refused by policy, from a
/// caller who authenticated successfully. The event names the registration, because that is the
/// thing an operator has to go and look at.
#[tokio::test]
async fn a_policy_refused_update_is_audited_and_names_the_registration() {
    // Registered through an open policy, so the client and its token are real.
    let (open, _) = server();
    let registered = open
        .register_dynamic_client(&metadata(), None)
        .await
        .expect("the open policy allows this");
    let client_id = ClientId::new(&registered.client_id);
    let rat = registered
        .registration_access_token
        .expect("management is enabled");

    // The same store, now behind a policy that refuses. This is a deployment that tightened its
    // rules after the client was registered, which is the ordinary way to arrive here.
    let mut registration = RegistrationConfig::new();
    registration.allowed_scopes = ScopeSet::parse("read write").unwrap();
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.registration = Some(Box::new(registration));
    let transcript = std::sync::Arc::new(Transcript::default());
    let closed = AuthorizationServer::new(cfg, MemoryStorage::new())
        .with_registration_policy(Box::new(ClosedPolicy))
        .with_event_sink(Box::new(Handle(transcript.clone())));
    closed
        .register_client(oauth_as::Client {
            client_id: client_id.clone(),
            auth: oauth_as::ClientAuth::Public,
            grant_types: vec![GrantType::AuthorizationCode],
            redirect_uris: vec!["https://app.example/cb".to_string()],
            allowed_scopes: ScopeSet::parse("read").unwrap(),
            default_scopes: ScopeSet::parse("read").unwrap(),
            name: None,
            registration: None,
        })
        .await
        .unwrap();

    // A host-provisioned client has no registration, so this refuses at authentication rather than
    // at the policy. That is path two, already covered; what it proves here is that the transcript
    // separates the two reasons.
    closed
        .update_registration(&client_id, &rat, &metadata())
        .await
        .expect_err("refused");
    let lines = transcript.lines();
    assert_eq!(lines.len(), 1, "expected exactly one event, got {lines:?}");
    assert!(
        lines[0].contains("ClientRegistrationAuthenticationFailed"),
        "a client with no dynamic registration is an AUTH failure, not a policy one: {lines:?}"
    );

    // Now the real shape: a client that IS dynamically registered, refused by policy. Driven on
    // the open server's store, with the policy swapped underneath it.
    let refused = open
        .with_registration_policy(Box::new(ClosedPolicy))
        .with_event_sink(Box::new(Handle(transcript.clone())));
    refused
        .update_registration(&client_id, &rat, &metadata())
        .await
        .expect_err("the policy refuses");

    let lines = transcript.lines();
    let policy_lines: Vec<&String> = lines
        .iter()
        .filter(|l| l.contains("ClientRegistrationRefusedByPolicy"))
        .collect();
    assert_eq!(
        policy_lines.len(),
        1,
        "expected exactly one policy refusal, got {lines:?}"
    );
    assert!(
        policy_lines[0].contains(client_id.as_str()),
        "the event must name the registration an operator has to go and look at: {policy_lines:?}"
    );
}

// ---------------------------------------- the refusal that is NOT an authentication failure
//
// `update_registration` reads the registration, awaits a policy decision and a validation pass,
// and only then writes — through a COMPARE-AND-SWAP, so that a concurrent RFC 7592 section 2.3
// delete landing in that window is not undone by this write. When the swap is lost, the request is
// refused with the same `401` an unknown client gets, and that part is right.
//
// What was wrong is what the host was TOLD. The refusal was reported as
// `ClientAuthFailure::UnknownClient` on the management plane, i.e. as an authentication that
// failed — and reaching that line requires `authenticate_registration` to have SUCCEEDED, so the
// caller held a registration access token this server verified. The only ways to get there are a
// concurrent delete and a second concurrent update, neither of which is anybody guessing anything.
//
// It matters because of what that event is FOR. It is the one signal a host has that somebody is
// walking registration access tokens, and a landed guess rewrites `redirect_uris`. A deployment
// whose own racing clients emit it is a deployment that has learned to ignore it.

/// A store that deletes the registration from inside the read `update_registration` derives its
/// write from, which is exactly where a concurrent section 2.3 delete lands: after the read that
/// authenticated the caller, before the write.
struct DeleteDuringRead {
    inner: MemoryStorage,
    /// Set to the `client_id` to delete, and consumed by the first read that finds one, so the
    /// registration itself is written through an unarmed store.
    armed: std::sync::Arc<Mutex<Option<ClientId>>>,
}

impl oauth_as::Storage for DeleteDuringRead {
    async fn get_client(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<std::sync::Arc<oauth_as::Client>>, oauth_as::StorageError> {
        let found = oauth_as::Storage::get_client(&self.inner, client_id).await?;
        let armed = {
            let mut slot = self.armed.lock().unwrap_or_else(|e| e.into_inner());
            slot.take()
        };
        if let (Some(id), true) = (armed, found.is_some()) {
            let now = std::time::SystemTime::now();
            oauth_as::Storage::delete_client(
                &self.inner,
                &id,
                oauth_as::store::RevocationWindow {
                    recorded_at: now,
                    until: now + std::time::Duration::from_secs(3600),
                },
            )
            .await?;
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

/// A lost compare-and-swap is refused, and is NOT audited as a credential failure.
///
/// The caller here holds the REAL registration access token and is refused anyway, because the
/// registration was deleted underneath them. The `401` is correct. An audit line saying an
/// authentication failed is not, and it is the line an operator uses to detect somebody guessing
/// these tokens.
#[tokio::test]
async fn an_update_that_loses_its_compare_and_swap_is_not_audited_as_a_failed_authentication() {
    let armed: std::sync::Arc<Mutex<Option<ClientId>>> = std::sync::Arc::new(Mutex::new(None));
    let transcript = std::sync::Arc::new(Transcript::default());
    let mut registration = RegistrationConfig::new();
    registration.allowed_scopes = ScopeSet::parse("read write").unwrap();
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.registration = Some(Box::new(registration));
    let srv = AuthorizationServer::new(
        cfg,
        DeleteDuringRead {
            inner: MemoryStorage::new(),
            armed: armed.clone(),
        },
    )
    .with_registration_policy(Box::new(OpenPolicy))
    .with_event_sink(Box::new(Handle(transcript.clone())));

    let info = srv
        .register_dynamic_client(&metadata(), None)
        .await
        .expect("registered");
    let client_id = ClientId::new(info.client_id.clone());
    let token = info
        .registration_access_token
        .clone()
        .expect("a registration mints one");

    // Armed only now, so the registration above went through an unarmed store.
    *armed.lock().unwrap_or_else(|e| e.into_inner()) = Some(client_id.clone());

    srv.update_registration(&client_id, &token, &metadata())
        .await
        .expect_err("the registration was deleted underneath this update");

    // Read BEFORE the probe below, which is itself a genuinely unknown client and audits itself.
    let lines = transcript.lines();

    // The deletion must still stand: that is what the compare-and-swap is for, and a test that
    // only checked the audit line would pass against an implementation that wrote the client back.
    assert!(
        srv.read_registration(&client_id, &token).await.is_err(),
        "the concurrent delete was undone by the update it raced"
    );

    assert!(
        !lines.iter().any(|l| l.contains("AuthenticationFailed")),
        "a caller who authenticated successfully was reported as an authentication failure: \
         {lines:?}"
    );
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("ClientRegistrationUpdated")),
        "the update did not happen and must not be reported as though it did: {lines:?}"
    );
}
