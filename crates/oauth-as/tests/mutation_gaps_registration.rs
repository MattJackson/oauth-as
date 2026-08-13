// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 7591 and RFC 7592 behaviours a `cargo mutants --all-features` sweep of `src/registration.rs`
//! found nothing pinning.
//!
//! Registration is the module where a hole costs the most, and RFC 7591 section 5 says why: an
//! open registration endpoint lets a stranger CREATE a client, so every rule in this module is
//! what stands between "an attacker submitted a form" and "an attacker holds a client identity
//! with credentials". Four of the survivors below sit in the RFC 7592 section 2.2 update path and
//! decide whether the updated client is confidential or public, and whether the secret it already
//! holds keeps working. That is the most security-sensitive arithmetic in the file and none of it
//! was constrained.
//!
//! One survivor is worth calling out because it exposes a test that was not testing what its name
//! said. `src/tests/registration.rs::the_implicit_response_type_is_refused` sends
//! `grant_types: ["implicit"]` alongside `response_types: ["token"]`, and the registration is
//! refused by the GRANT parser, several checks before the response-type loop is reached. The
//! response-type rule itself therefore had no test at all, which is why
//! `replace != with == in validate` survived.

#![cfg(test)]

mod support;

use std::sync::Mutex;
use std::time::Duration;

use oauth_as::registration::{
    ClientMetadata, RegistrationAttempt, RegistrationConfig, RegistrationDecision,
    RegistrationErrorCode, RegistrationFailure, RegistrationPolicy,
};
use oauth_as::{
    AuthorizationServer, ClientId, GrantType, MemoryStorage, ScopeSet, ServerConfig, TokenRequest,
};
use support::ManualClock;

/// Registration is refused outright with no policy installed (RFC 7591 section 5), so every test
/// here has to install one. This is the two-line "open endpoint" a host writes with its eyes open.
struct OpenPolicy;

impl RegistrationPolicy for OpenPolicy {
    fn authorize(&self, _attempt: &RegistrationAttempt<'_>) -> RegistrationDecision {
        RegistrationDecision::Allow
    }
}

fn registration_config() -> RegistrationConfig {
    let mut cfg = RegistrationConfig::new();
    cfg.allowed_scopes = ScopeSet::parse("read write").unwrap();
    cfg
}

fn server(registration: RegistrationConfig) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.registration = Some(Box::new(registration));
    AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch())
        .with_registration_policy(Box::new(OpenPolicy))
}

fn code_metadata() -> ClientMetadata {
    ClientMetadata {
        redirect_uris: vec!["https://app.example/cb".to_string()],
        client_name: Some("Test App".to_string()),
        ..ClientMetadata::default()
    }
}

fn error_code(failure: RegistrationFailure) -> RegistrationErrorCode {
    match failure {
        RegistrationFailure::Invalid(e) => e.error,
        other => panic!("expected an Invalid failure, got {other:?}"),
    }
}

// ------------------------------------------------------------------ validate

/// SURVIVOR: `registration.rs replace != with == in validate`.
///
/// The line is the response-type loop, `if value != RESPONSE_TYPE_CODE { return Err(...) }`.
/// Flipped, this server ACCEPTS a registration asking for any response type except `code`, and
/// REFUSES the only one it actually issues.
///
/// The accepting direction is the dangerous one. OAuth 2.1 removed the implicit grant, and
/// `response_types: ["token"]` is a client saying it expects an access token delivered in a
/// redirect fragment. Registering that tells the client it will get something this server will
/// never send, and it registers, in this server's own client table, a client whose declared
/// behaviour is the flow the protocol deleted. The refusing direction is a plain outage: no
/// client that spells out `["code"]`, which RFC 7591 section 2 invites it to do, can register at
/// all.
///
/// Nothing caught it because the test named for this rule refuses its input one rule earlier: see
/// the module docs.
#[tokio::test]
async fn a_response_type_other_than_code_is_refused_and_code_itself_is_accepted() {
    let srv = server(registration_config());

    // The refusal, with a grant list that is otherwise perfectly valid so the response-type loop
    // is genuinely the rule under test.
    let mut asks_for_token = code_metadata();
    asks_for_token.grant_types = Some(vec!["authorization_code".to_string()]);
    asks_for_token.response_types = Some(vec!["token".to_string()]);
    let failure = srv
        .register_dynamic_client(&asks_for_token, None)
        .await
        .expect_err("this server issues authorization codes only");
    assert_eq!(
        error_code(failure),
        RegistrationErrorCode::InvalidClientMetadata,
        "response_types: [\"token\"] is the implicit grant OAuth 2.1 removed, and registering it \
         would record a client whose declared flow this server will never perform"
    );

    // And the acceptance, which is the half a naive `==` would break: RFC 7591 section 2 lets a
    // client state `["code"]` explicitly, and it must not be punished for doing so.
    let mut asks_for_code = code_metadata();
    asks_for_code.grant_types = Some(vec!["authorization_code".to_string()]);
    asks_for_code.response_types = Some(vec!["code".to_string()]);
    let info = srv
        .register_dynamic_client(&asks_for_code, None)
        .await
        .expect("an explicit response_types of [\"code\"] is exactly what this server issues");
    assert_eq!(
        info.metadata.response_types.as_deref(),
        Some(["code".to_string()].as_slice())
    );
}

// ------------------------------------------------------------------ registered_metadata

/// SURVIVOR: `registration.rs delete ! in registered_metadata`.
///
/// The line is `scope: (!client.allowed_scopes.is_empty()).then(|| ...)`, which is what decides
/// whether an RFC 7592 section 2.1 read echoes the registered scope. Without the `!` the two cases
/// swap: a client that registered `read write` is read back with NO `scope` member at all, and a
/// client that registered none is read back with `scope: ""`.
///
/// Both are wrong on the wire and the first is the one that bites. RFC 7592 section 3 reuses the
/// section 3.2.1 client information response, whose whole job is to tell the client what is
/// actually registered. A client that reads its own registration to find out what it may ask for
/// is told it may ask for nothing, and the natural next step, PUTting that document back under
/// section 2.2, would then genuinely narrow the registration to no scope at all.
#[tokio::test]
async fn a_read_echoes_the_registered_scope_and_omits_it_only_when_there_is_none() {
    let srv = server(registration_config());

    let mut with_scope = code_metadata();
    with_scope.scope = Some("read write".to_string());
    let info = srv
        .register_dynamic_client(&with_scope, None)
        .await
        .expect("registered");
    let token = info.registration_access_token.clone().expect("management");
    let id = ClientId::new(info.client_id.clone());

    let read = srv.read_registration(&id, &token).await.expect("read");
    assert_eq!(
        read.metadata.scope.as_deref(),
        Some("read write"),
        "a read must echo the scope that is registered; a client reads this to find out what it \
         may ask for, and PUTs it back under RFC 7592 s2.2"
    );

    // And the other direction: a registration with no scope has no `scope` member, rather than an
    // empty string, which RFC 6749 s3.3 has no reading for.
    let none = srv
        .register_dynamic_client(&code_metadata(), None)
        .await
        .expect("registered");
    let none_token = none.registration_access_token.clone().expect("management");
    let none_read = srv
        .read_registration(&ClientId::new(none.client_id.clone()), &none_token)
        .await
        .expect("read");
    assert_eq!(none_read.metadata.scope, None);
    let json = serde_json::to_value(&none_read).unwrap();
    assert!(
        json.get("scope").is_none(),
        "an absent scope is OMITTED from the response document, not sent as an empty string: {json}"
    );
}

// ------------------------------------------------------------------ secret expiry arithmetic

/// SURVIVOR: mutants of the secret-expiry arithmetic in `register_dynamic_client`.
///
/// THE OPERATOR IS `saturating_add`, NOT `+`. This header named `replace + with -` and
/// `replace + with *` until 0.9.1, and those describe mutants cargo-mutants will never generate
/// here: the site reads `now.unwrap_or_default().saturating_add(ttl.as_secs())`, because a plain
/// `+` panics in debug and WRAPS in release on a host-configured lifetime. What this case
/// constrains is that the expiry lands a lifetime AFTER the mint, by whatever call produces it.
///
/// The line computes the issued secret's expiry as `now + ttl`. Nothing pinned it because no test
/// anywhere set [`RegistrationConfig::client_secret_ttl`], so the whole `Some(ttl)` arm was
/// unreached: every existing test takes the `None` arm, which is the constant 0 that RFC 7591
/// section 3.2.1 defines as "never expires".
///
/// With `-`, a host that configures a one-hour secret lifetime hands every new client a
/// `client_secret_expires_at` an hour in the PAST, which section 3.2.1 makes a statement that the
/// secret is already dead. A client that honours what it is told will refuse to use a secret that
/// works, and one that does not honour it has learned to ignore the field.
#[tokio::test]
async fn an_issued_secrets_expiry_is_the_issue_time_plus_the_configured_lifetime() {
    let mut cfg = registration_config();
    cfg.client_secret_ttl = Some(Duration::from_secs(3600));
    let srv = server(cfg);

    let info = srv
        .register_dynamic_client(&code_metadata(), None)
        .await
        .expect("registered");
    let issued_at = info.client_id_issued_at.expect("s3.2.1 issue time");
    assert_eq!(
        info.client_secret_expires_at,
        Some(issued_at + 3600),
        "RFC 7591 s3.2.1: with a configured secret lifetime the expiry is the issue time PLUS the \
         lifetime. Anything earlier tells the client the secret it was just handed is already dead"
    );
    assert!(info.client_secret.is_some(), "a secret was issued");
}

/// SURVIVOR: mutants of the same secret-expiry arithmetic in `update_registration`.
///
/// `saturating_add` here too, for the same reason, and this header carried the same wrong
/// `replace + with -` claim until 0.9.1.
///
/// The same arithmetic on the RFC 7592 section 2.2 path, reached when an update mints a secret
/// for a client that had none. Same consequence, and the same reason nothing saw it: no test set
/// a secret lifetime.
#[tokio::test]
async fn a_secret_minted_by_an_update_expires_a_lifetime_after_it_is_minted() {
    let mut cfg = registration_config();
    cfg.client_secret_ttl = Some(Duration::from_secs(3600));
    let srv = server(cfg);

    // Registered PUBLIC, so the update below is the path that mints a secret.
    let mut public = code_metadata();
    public.token_endpoint_auth_method = Some("none".to_string());
    let info = srv
        .register_dynamic_client(&public, None)
        .await
        .expect("registered");
    assert!(info.client_secret.is_none(), "registered public");
    let token = info.registration_access_token.clone().expect("management");
    let id = ClientId::new(info.client_id.clone());

    let mut now_confidential = code_metadata();
    now_confidential.token_endpoint_auth_method = Some("client_secret_basic".to_string());
    let updated = srv
        .update_registration(&id, &token, &now_confidential)
        .await
        .expect("updated");

    // The clock is a `ManualClock` fixed at its epoch, so "now" is the same instant the
    // registration was issued at, and the expiry is exactly one lifetime past it.
    let issued_at = info.client_id_issued_at.expect("s3.2.1 issue time");
    assert_eq!(
        updated.client_secret_expires_at,
        Some(issued_at + 3600),
        "a secret minted by an update expires one configured lifetime after it is minted"
    );
}

// ------------------------------------------------------------------ the update path's auth

/// SURVIVOR: `registration.rs replace != with == in
/// update_registration`.
///
/// The line is `let wants_secret = registered.token_endpoint_auth_method != AUTH_METHOD_NONE`.
/// Flipped, `wants_secret` is true only for a client asking for `none`, so every ordinary update
/// takes the `(None, false)` arm and rewrites the client's authentication to
/// [`oauth_as::ClientAuth::Public`].
///
/// That is a privilege escalation performed by the victim. A confidential client that edits its
/// own `client_name` under RFC 7592 section 2.2 is silently DEMOTED to a public client: the secret
/// it holds is no longer required, and anyone who knows its `client_id`, which RFC 6749 section
/// 2.2 says is not a secret, can authenticate as it at the token endpoint. Nothing in the response
/// says so, because section 2.2 does not return a secret on an update either way.
///
/// The assertion is deliberately made at the TOKEN ENDPOINT rather than on the stored record: what
/// matters is not what the client table says, it is whether an unauthenticated caller can now mint
/// tokens as this client.
#[tokio::test]
async fn an_update_does_not_demote_a_confidential_client_to_a_public_one() {
    let mut cfg = registration_config();
    cfg.allowed_grant_types = vec![GrantType::ClientCredentials];
    let srv = server(cfg);

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
    let token = info.registration_access_token.clone().expect("management");
    let id = ClientId::new(info.client_id.clone());

    // An ordinary metadata edit: a new name, the same authentication method.
    let mut renamed = metadata.clone();
    renamed.client_name = Some("Renamed App".to_string());
    renamed.token_endpoint_auth_method = Some("client_secret_basic".to_string());
    srv.update_registration(&id, &token, &renamed)
        .await
        .expect("updated");

    srv.token(TokenRequest::ClientCredentials {
        client_id: id.clone(),
        client_secret: Some(secret.clone()),
        scope: None,
    })
    .await
    .expect("the secret the client still holds must still authenticate after a rename");

    let unauthenticated = srv
        .token(TokenRequest::ClientCredentials {
            client_id: id.clone(),
            client_secret: None,
            scope: None,
        })
        .await;
    assert!(
        unauthenticated.is_err(),
        "after an ordinary metadata update the client authenticates with NO secret: the update \
         demoted a confidential client to a public one, so anyone holding its client_id, which is \
         not a secret (RFC 6749 s2.2), can mint tokens as it"
    );
}

/// SURVIVOR: `registration.rs replace && with || in
/// update_registration`.
///
/// The line is `let new_secret = (wants_secret && !had_secret).then(...)`: mint a secret only when
/// the client wants one and does not already have one. With `||`, an update mints a FRESH secret
/// on every edit made by a client that already had one.
///
/// The module's own comment says why that is wrong: this server cannot re-issue a secret it does
/// not hold, so rotating on every metadata edit logs the client out of the token endpoint for
/// changing its name. The new secret is returned once, in a response the client may not be
/// reading for a credential it did not ask to rotate, and the one it has stops working the instant
/// the update succeeds.
#[tokio::test]
async fn an_update_does_not_rotate_a_secret_the_client_already_holds() {
    let mut cfg = registration_config();
    cfg.allowed_grant_types = vec![GrantType::ClientCredentials];
    let srv = server(cfg);

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
    let token = info.registration_access_token.clone().expect("management");
    let id = ClientId::new(info.client_id.clone());

    let mut renamed = metadata.clone();
    renamed.client_name = Some("Renamed App".to_string());
    let updated = srv
        .update_registration(&id, &token, &renamed)
        .await
        .expect("updated");

    assert!(
        updated.client_secret.is_none(),
        "an update to a client that already has a secret must not mint another one: the client \
         did not ask to rotate, and the copy it holds stops working the moment this returns"
    );
    srv.token(TokenRequest::ClientCredentials {
        client_id: id.clone(),
        client_secret: Some(secret),
        scope: None,
    })
    .await
    .expect("the secret the client holds still authenticates after an unrelated metadata edit");
}

/// SURVIVOR: `registration.rs delete ! in update_registration`.
///
/// The same expression with the negation dropped: `wants_secret && had_secret`. A PUBLIC client
/// that updates itself to `client_secret_basic` then mints nothing, falls into the `(None, true)`
/// arm, and keeps its existing [`oauth_as::ClientAuth::Public`] authentication.
///
/// The client is told, in the echoed metadata RFC 7591 section 3.2.1 requires to reflect what was
/// actually registered, that its `token_endpoint_auth_method` is now `client_secret_basic`. It is
/// handed no secret to use with it, and the registration is still public underneath. So a
/// deployment that moves a client from public to confidential, which is a security HARDENING step
/// somebody deliberately took, ends up with a client that is still public and a record that says
/// otherwise.
#[tokio::test]
async fn an_update_that_turns_a_public_client_confidential_actually_issues_a_secret() {
    let srv = server(registration_config());

    let mut public = code_metadata();
    public.token_endpoint_auth_method = Some("none".to_string());
    let info = srv
        .register_dynamic_client(&public, None)
        .await
        .expect("registered");
    assert!(info.client_secret.is_none(), "registered public");
    let token = info.registration_access_token.clone().expect("management");
    let id = ClientId::new(info.client_id.clone());

    let mut confidential = code_metadata();
    confidential.token_endpoint_auth_method = Some("client_secret_basic".to_string());
    let updated = srv
        .update_registration(&id, &token, &confidential)
        .await
        .expect("updated");

    assert!(
        updated.client_secret.is_some(),
        "an update that moves a client from public to client_secret_basic must issue the secret \
         that method needs. Without one the response says the client is confidential and the \
         registration underneath is still public, which is a hardening step that silently did \
         nothing"
    );
    assert_eq!(
        updated.metadata.token_endpoint_auth_method.as_deref(),
        Some("client_secret_basic")
    );
}

// ------------------------------------------------------------------ redaction

/// SURVIVOR: `registration.rs replace <impl Debug for
/// RegistrationAttempt>::fmt -> std::fmt::Result with Ok(Default::default())`.
///
/// The hand-written `Debug` exists for one reason: [`RegistrationAttempt::initial_access_token`]
/// is a live bearer credential and this value exists only inside a request path, which is exactly
/// where a host debug-prints things. Replacing the whole body with a silent `Ok(())` renders the
/// attempt as the empty string, and nothing failed, which means the redaction itself was never
/// asserted anywhere: an edit that printed the token verbatim would have been just as invisible.
///
/// The observation is made from inside a [`RegistrationPolicy`], because that is the only place a
/// host is ever handed one of these.
#[tokio::test]
async fn a_registration_attempts_debug_names_its_fields_and_redacts_the_bearer_token() {
    const INITIAL_ACCESS_TOKEN: &str = "iat-super-secret-value";

    #[derive(Default)]
    struct Recording(Mutex<Vec<String>>);

    impl RegistrationPolicy for Recording {
        fn authorize(&self, attempt: &RegistrationAttempt<'_>) -> RegistrationDecision {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("{attempt:?}"));
            RegistrationDecision::Allow
        }
    }

    struct Handle(std::sync::Arc<Recording>);
    impl RegistrationPolicy for Handle {
        fn authorize(&self, attempt: &RegistrationAttempt<'_>) -> RegistrationDecision {
            self.0.authorize(attempt)
        }
    }

    let recorder = std::sync::Arc::new(Recording::default());
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.registration = Some(Box::new(registration_config()));
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch())
        .with_registration_policy(Box::new(Handle(std::sync::Arc::clone(&recorder))));

    let mut metadata = code_metadata();
    metadata.client_name = Some("Debuggable App".to_string());
    srv.register_dynamic_client(&metadata, Some(INITIAL_ACCESS_TOKEN))
        .await
        .expect("registered");

    let seen = recorder.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let rendered = seen.first().expect("the policy saw the attempt").clone();

    assert!(
        !rendered.contains(INITIAL_ACCESS_TOKEN),
        "the initial access token is a live bearer credential and must never reach a debug \
         format: {rendered}"
    );
    assert!(
        rendered.contains("[redacted]"),
        "the Some/None distinction is registration shape rather than a secret, so a presented \
         token must render as [redacted] rather than vanish: {rendered}"
    );
    assert!(
        rendered.contains("RegistrationAttempt") && rendered.contains("initial_access_token"),
        "a redacting Debug still has to be a useful one, or a host debugging a refused \
         registration learns nothing at all: {rendered}"
    );
    assert!(
        rendered.contains("Debuggable App"),
        "the metadata is not a credential and is the whole of what a host is debugging: {rendered}"
    );
}
