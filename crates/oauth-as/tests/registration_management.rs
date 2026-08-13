// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 7592 registration management, from outside the crate.
//!
//! The registration access token of section 2 is a bearer credential that READS, REWRITES and
//! DELETES a registration, so it is at least as powerful as the client secret beside it. Most of
//! this file is about that: that it is required, that a wrong one is refused, that a client cannot
//! manage another client's registration, and that it is not stored where a dump of the client
//! table would yield a working one.
//!
//! The other half is section 2.3's deletion, which has to take with it what the registration was
//! issued. A delete that leaves live access tokens and refresh chains behind is a client that no
//! longer exists still calling resource servers.

mod support;

use oauth_as::server::UserApproval;
use std::sync::Mutex;

use oauth_as::{
    AuthorizationRequest, AuthorizationServer, ClientId, ClientMetadata, Event, EventSink,
    GrantType, MemoryStorage, RegistrationAttempt, RegistrationConfig, RegistrationDecision,
    RegistrationErrorCode, RegistrationFailure, RegistrationPolicy, ScopeSet, ServerConfig,
    Storage, TokenRequest,
};

struct OpenPolicy;

impl RegistrationPolicy for OpenPolicy {
    fn authorize(&self, _attempt: &RegistrationAttempt<'_>) -> RegistrationDecision {
        RegistrationDecision::Allow
    }
}

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

fn registration_config() -> RegistrationConfig {
    let mut cfg = RegistrationConfig::new();
    cfg.allowed_scopes = ScopeSet::parse("read write").unwrap();
    cfg
}

fn server(registration: RegistrationConfig) -> AuthorizationServer<MemoryStorage> {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.registration = Some(Box::new(registration));
    AuthorizationServer::new(cfg, MemoryStorage::new())
        .with_registration_policy(Box::new(OpenPolicy))
}

fn code_client_metadata() -> ClientMetadata {
    ClientMetadata {
        redirect_uris: vec!["https://app.example/cb".to_string()],
        client_name: Some("Test App".to_string()),
        token_endpoint_auth_method: Some("none".to_string()),
        scope: Some("read".to_string()),
        ..ClientMetadata::default()
    }
}

/// RFC 7592 section 3: the registration response tells the client where its registration lives, so
/// it can read, update and delete it without inventing a URL.
#[tokio::test]
async fn a_registration_is_told_where_it_lives_and_hands_back_its_access_token_once() {
    let srv = server(registration_config());
    let info = srv
        .register_dynamic_client(&code_client_metadata(), None)
        .await
        .expect("registered");

    assert_eq!(
        info.registration_client_uri.as_deref(),
        Some(format!("https://as.example/register/{}", info.client_id).as_str())
    );
    let token = info
        .registration_access_token
        .clone()
        .expect("RFC 7592 s3: minted at registration");

    // ... and that is the ONLY time it appears. A read cannot return it, because this server kept
    // a one-way verifier and not the token: see the `registration` module docs.
    let read = srv
        .read_registration(&ClientId::new(info.client_id.clone()), &token)
        .await
        .expect("read");
    assert_eq!(read.registration_access_token, None);
    assert_eq!(read.client_secret, None);
}

/// RFC 7592 section 2: management is authenticated by the registration access token. A missing or
/// wrong one reads, updates and deletes nothing.
#[tokio::test]
async fn management_requires_the_registration_access_token() {
    let srv = server(registration_config());
    let info = srv
        .register_dynamic_client(&code_client_metadata(), None)
        .await
        .expect("registered");
    let client_id = ClientId::new(info.client_id.clone());
    let token = info.registration_access_token.clone().unwrap();

    for wrong in ["", "not-the-token", &format!("{token}x"), &token[..8]] {
        let failure = srv
            .read_registration(&client_id, wrong)
            .await
            .expect_err("a wrong registration access token reads nothing");
        assert!(
            matches!(failure, RegistrationFailure::Unauthorized),
            "expected Unauthorized, got {failure:?}"
        );
        assert_eq!(failure.http_status(), 401);

        assert!(srv
            .update_registration(&client_id, wrong, &code_client_metadata())
            .await
            .is_err());
        assert!(srv.delete_registration(&client_id, wrong).await.is_err());
    }

    // The registration survived every one of those.
    srv.read_registration(&client_id, &token)
        .await
        .expect("the real token still works");
}

/// One registration's token must not manage another's. The token names a REGISTRATION, not a
/// tenant: accepting it for a different `client_id` would make the first registrant able to
/// rewrite every other client's redirect URIs.
#[tokio::test]
async fn one_registrations_token_cannot_manage_another() {
    let srv = server(registration_config());
    let a = srv
        .register_dynamic_client(&code_client_metadata(), None)
        .await
        .expect("registered");
    let b = srv
        .register_dynamic_client(&code_client_metadata(), None)
        .await
        .expect("registered");

    let failure = srv
        .read_registration(
            &ClientId::new(b.client_id.clone()),
            &a.registration_access_token.clone().unwrap(),
        )
        .await
        .expect_err("a's token must not read b");
    assert!(matches!(failure, RegistrationFailure::Unauthorized));
}

/// An unknown `client_id` and a wrong token are ONE answer, exactly as an unknown client and a bad
/// secret collapse into `invalid_client` at the token endpoint (RFC 6749 section 5.2). Telling
/// them apart turns this endpoint into an oracle for which client ids exist.
#[tokio::test]
async fn an_unknown_registration_is_indistinguishable_from_a_wrong_token() {
    let srv = server(registration_config());
    let info = srv
        .register_dynamic_client(&code_client_metadata(), None)
        .await
        .expect("registered");
    let token = info.registration_access_token.clone().unwrap();

    let unknown = srv
        .read_registration(&ClientId::new("no-such-client"), &token)
        .await
        .expect_err("unknown");
    let wrong = srv
        .read_registration(&ClientId::new(info.client_id.clone()), "wrong")
        .await
        .expect_err("wrong token");
    assert_eq!(
        std::mem::discriminant(&unknown),
        std::mem::discriminant(&wrong)
    );
    assert_eq!(unknown.http_status(), wrong.http_status());
}

/// A client the HOST provisioned itself has no registration access token, so RFC 7592 management
/// does not apply to it. Anything else would let a caller who guessed a static client id start
/// probing for a token that can never exist.
#[tokio::test]
async fn a_statically_provisioned_client_cannot_be_managed_dynamically() {
    let srv = server(registration_config());
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

    let failure = srv
        .delete_registration(&ClientId::new("host-provisioned"), "anything")
        .await
        .expect_err("not a dynamic registration");
    assert!(matches!(failure, RegistrationFailure::Unauthorized));
    assert!(srv
        .store()
        .get_client(&ClientId::new("host-provisioned"))
        .await
        .unwrap()
        .is_some());
}

/// RFC 7592 section 2 makes the registration access token a credential, and this crate's rule for
/// a credential at rest is one-way storage (`client::SecretHash`). A dump of the client table must
/// not be a set of working management tokens.
#[tokio::test]
async fn the_registration_access_token_is_not_stored_in_plaintext() {
    let srv = server(registration_config());
    let info = srv
        .register_dynamic_client(&code_client_metadata(), None)
        .await
        .expect("registered");
    let token = info.registration_access_token.clone().unwrap();

    let stored = srv
        .store()
        .get_client(&ClientId::new(info.client_id.clone()))
        .await
        .unwrap()
        .expect("stored");
    let registration = stored.registration.as_deref().expect("dynamic");
    assert_ne!(
        registration.registration_access_token_hash.encoded(),
        token,
        "the stored verifier must not BE the token"
    );
    assert!(!registration
        .registration_access_token_hash
        .encoded()
        .is_empty());
    // The serialized record is what a host actually persists.
    let json = serde_json::to_string(&*stored).unwrap();
    assert!(
        !json.contains(&token),
        "the persisted client carries the registration access token in plaintext"
    );
    assert!(
        !format!("{stored:?}").contains(&token),
        "Debug on a stored client leaks the registration access token"
    );
}

/// RFC 7592 section 2.2: the update REPLACES the metadata, and the same ceilings a fresh
/// registration faces apply again. An update must not be a way around
/// `RegistrationConfig::allowed_scopes` or `allowed_grant_types`.
#[tokio::test]
async fn an_update_replaces_the_metadata_and_cannot_exceed_the_registration_ceiling() {
    let srv = server(registration_config());
    let info = srv
        .register_dynamic_client(&code_client_metadata(), None)
        .await
        .expect("registered");
    let client_id = ClientId::new(info.client_id.clone());
    let token = info.registration_access_token.clone().unwrap();

    let mut updated = code_client_metadata();
    updated.redirect_uris = vec!["https://app.example/other".to_string()];
    updated.client_name = Some("Renamed".to_string());
    let response = srv
        .update_registration(&client_id, &token, &updated)
        .await
        .expect("updated");
    assert_eq!(
        response.metadata.redirect_uris,
        vec!["https://app.example/other".to_string()],
        "the old redirect URI must NOT survive a replacing update"
    );
    assert_eq!(response.metadata.client_name.as_deref(), Some("Renamed"));
    assert_eq!(response.client_id, info.client_id, "client_id is immutable");

    let stored = srv
        .store()
        .get_client(&client_id)
        .await
        .unwrap()
        .expect("stored");
    assert_eq!(
        stored.redirect_uris,
        vec!["https://app.example/other".to_string()]
    );

    // The ceiling holds on update as it did on registration.
    let mut escalate = code_client_metadata();
    escalate.scope = Some("read write admin".to_string());
    let failure = srv
        .update_registration(&client_id, &token, &escalate)
        .await
        .expect_err("outside the ceiling");
    match failure {
        RegistrationFailure::Invalid(e) => {
            assert_eq!(e.error, RegistrationErrorCode::InvalidClientMetadata)
        }
        other => panic!("expected invalid_client_metadata, got {other:?}"),
    }

    let mut escalate = code_client_metadata();
    escalate.grant_types = Some(vec!["client_credentials".to_string()]);
    escalate.response_types = Some(vec![]);
    assert!(srv
        .update_registration(&client_id, &token, &escalate)
        .await
        .is_err());

    // The registration access token still works after the update: rewriting metadata is not a
    // reason to log the client out of its own management endpoint.
    srv.read_registration(&client_id, &token)
        .await
        .expect("still managed by the same token");
}

/// RFC 7592 section 2.3: deleting a registration invalidates what that registration holds. A
/// delete that leaves live tokens behind is a client that no longer exists still calling resource
/// servers, and nothing downstream can tell.
///
/// This drives a full RFC 6749 section 4.1 flow first, so there is a real access token, a real
/// refresh chain and a real outstanding authorization code to be left behind.
#[tokio::test]
async fn deleting_a_registration_invalidates_everything_it_was_issued() {
    let mut cfg = registration_config();
    cfg.allowed_grant_types = vec![GrantType::AuthorizationCode, GrantType::RefreshToken];
    let srv = server(cfg);
    let mut metadata = code_client_metadata();
    metadata.grant_types = Some(vec![
        "authorization_code".to_string(),
        "refresh_token".to_string(),
    ]);
    let info = srv
        .register_dynamic_client(&metadata, None)
        .await
        .expect("registered");
    let client_id = ClientId::new(info.client_id.clone());
    let token = info.registration_access_token.clone().unwrap();

    let verifier = support::RFC7636_VERIFIER;
    let challenge = oauth_as::pkce::code_challenge_s256(verifier);
    let request = AuthorizationRequest::from_pairs([
        ("response_type", "code"),
        ("client_id", info.client_id.as_str()),
        ("redirect_uri", "https://app.example/cb"),
        ("scope", "read"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]);
    let validated = srv.validate_authorization_request(&request).await.unwrap();
    let issued = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .unwrap();
    let tokens = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: client_id.clone(),
            client_secret: None,
            code: issued.code,
            redirect_uri: Some("https://app.example/cb".to_string()),
            code_verifier: Some(verifier.to_string()),
        })
        .await
        .expect("redeemed");
    let access_token = tokens.access_token.clone();
    let refresh_token = tokens.refresh_token.clone().expect("refresh issued");

    // A second, still-outstanding authorization code, so the delete has one to reap.
    let outstanding = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .unwrap()
        .code;

    assert!(srv.introspect(&access_token).await.unwrap().is_some());

    srv.delete_registration(&client_id, &token)
        .await
        .expect("deleted");

    assert!(
        srv.store().get_client(&client_id).await.unwrap().is_none(),
        "the registration itself is gone"
    );
    assert!(
        srv.introspect(&access_token).await.unwrap().is_none(),
        "an access token issued to a deleted client is still live"
    );
    assert!(
        srv.store()
            .get_refresh_token(&refresh_token)
            .await
            .unwrap()
            .is_none(),
        "a refresh chain of a deleted client is still live"
    );
    assert!(
        srv.store()
            .take_authorization_code(&outstanding)
            .await
            .unwrap()
            .is_none(),
        "an outstanding authorization code of a deleted client survived the delete"
    );

    // And the whole registration is unusable, which is the observable half of all of the above.
    assert!(srv
        .token(TokenRequest::RefreshToken {
            client_id: client_id.clone(),
            client_secret: None,
            refresh_token,
            scope: None,
        })
        .await
        .is_err());
    assert!(srv.read_registration(&client_id, &token).await.is_err());
}

/// The audit channel sees an update and a deletion, because both change what a client is allowed
/// to do and a security change nobody can observe is one nobody can investigate.
#[tokio::test]
async fn update_and_deletion_reach_the_event_sink() {
    let transcript = std::sync::Arc::new(Transcript::default());
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.registration = Some(Box::new(registration_config()));
    let srv = AuthorizationServer::new(cfg, MemoryStorage::new())
        .with_registration_policy(Box::new(OpenPolicy))
        .with_event_sink(Box::new(TranscriptHandle(transcript.clone())));

    let info = srv
        .register_dynamic_client(&code_client_metadata(), None)
        .await
        .expect("registered");
    let client_id = ClientId::new(info.client_id.clone());
    let token = info.registration_access_token.clone().unwrap();

    srv.update_registration(&client_id, &token, &code_client_metadata())
        .await
        .expect("updated");
    srv.delete_registration(&client_id, &token)
        .await
        .expect("deleted");

    let events = transcript
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    assert!(
        events
            .iter()
            .any(|e| e.starts_with("ClientRegistrationUpdated")),
        "no update event: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e.starts_with("ClientRegistrationDeleted")),
        "no deletion event: {events:?}"
    );
    for event in &events {
        assert!(
            !event.contains(&token),
            "an event carried the management token"
        );
    }
}

/// A host may enable registration and decline to offer RFC 7592 management (a deployment that
/// provisions and revokes out of band). Then there is no management endpoint, no
/// `registration_client_uri` to advertise, and no registration access token to hand out, because
/// issuing a credential nothing accepts is worse than issuing none.
#[tokio::test]
async fn management_can_be_declined_without_declining_registration() {
    let mut cfg = registration_config();
    cfg.management_enabled = false;
    let srv = server(cfg);
    let info = srv
        .register_dynamic_client(&code_client_metadata(), None)
        .await
        .expect("registered");
    assert_eq!(info.registration_access_token, None);
    assert_eq!(info.registration_client_uri, None);

    let failure = srv
        .read_registration(&ClientId::new(info.client_id.clone()), "anything")
        .await
        .expect_err("management is off");
    assert!(
        matches!(failure, RegistrationFailure::Disabled),
        "expected Disabled, got {failure:?}"
    );
    assert_eq!(failure.http_status(), 404);
}

/// A host policy that admits a registration on content, the way a real deployment does: only
/// redirect URIs under a domain it will actually serve, and no client name impersonating the
/// deployment itself.
struct ContentPolicy;

impl RegistrationPolicy for ContentPolicy {
    fn authorize(&self, attempt: &RegistrationAttempt<'_>) -> RegistrationDecision {
        let uris_ok = attempt
            .metadata
            .redirect_uris
            .iter()
            .all(|u| u.starts_with("https://app.partner.example/"));
        let name_ok = !attempt
            .metadata
            .client_name
            .as_deref()
            .unwrap_or_default()
            .contains("Acme");
        if uris_ok && name_ok {
            RegistrationDecision::Allow
        } else {
            RegistrationDecision::Deny
        }
    }
}

/// RFC 7592 section 2.2 has the client send a COMPLETE replacement metadata document, so every
/// content control the host's policy applied at registration is exactly what an update can
/// rewrite. If the policy is consulted only on the way in, an attacker registers something
/// acceptable and then PUTs the registration into whatever the policy would have refused, and
/// every host control is one request away from void.
///
/// The registration access token authenticates this request but decides nothing about content,
/// and unlike an initial access token it is long lived, so it cannot stand in for admission
/// control. RFC 7591 section 5 puts the abuse decision on the authorization server.
#[tokio::test]
async fn an_update_cannot_smuggle_past_the_registration_policy() {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.registration = Some(Box::new(registration_config()));
    let srv = AuthorizationServer::new(cfg, MemoryStorage::new())
        .with_registration_policy(Box::new(ContentPolicy));

    // Register something the policy is happy with.
    let mut acceptable = code_client_metadata();
    acceptable.redirect_uris = vec!["https://app.partner.example/cb".to_string()];
    acceptable.client_name = Some("Partner App".to_string());
    let info = srv
        .register_dynamic_client(&acceptable, None)
        .await
        .expect("the policy admits this registration");
    let client_id = ClientId::new(info.client_id.clone());
    let token = info.registration_access_token.clone().unwrap();

    // Now try to become something it would have refused: an attacker-controlled redirect target
    // and a name impersonating the deployment.
    let mut hostile = code_client_metadata();
    hostile.redirect_uris = vec!["https://attacker.example/cb".to_string()];
    hostile.client_name = Some("Acme Corp Official Login".to_string());

    let refused = srv
        .update_registration(&client_id, &token, &hostile)
        .await
        .expect_err("the policy must be consulted on update, not only on registration");
    assert!(
        matches!(refused, RegistrationFailure::Unauthorized),
        "expected Unauthorized, got {refused:?}"
    );

    // And the refusal must have written nothing: the registration still points where the policy
    // allowed. A refusal that half-applied would be worse than no check at all.
    let still = srv
        .read_registration(&client_id, &token)
        .await
        .expect("the registration survives a refused update");
    assert_eq!(
        still.metadata.redirect_uris,
        vec!["https://app.partner.example/cb".to_string()],
        "a refused update must not have rewritten the redirect URI"
    );
    assert_eq!(still.metadata.client_name.as_deref(), Some("Partner App"));
}
