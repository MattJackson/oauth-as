// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Shared fixtures for the behavioural tests: a hand-cranked clock (so expiry and poll pacing are
//! tested without sleeping) and the client registrations the suites share.
#![allow(dead_code)]

pub mod alloc;

use oauth_as::server::UserApproval;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::{
    AuthorizationCodeRecord, AuthorizationRequest, AuthorizationServer, Client, ClientAuth,
    ClientId, Clock, DeviceGrant, DeviceGrantState, GrantType, IssuedToken, MemoryStorage,
    RefreshTokenRecord, ScopeSet, ServerConfig, Storage, StorageError, TokenRequest, TokenResponse,
};

/// A clock the test advances by hand. Shared with the server under test.
#[derive(Clone)]
pub struct ManualClock(Arc<Mutex<SystemTime>>);

impl ManualClock {
    pub fn at_epoch() -> Self {
        ManualClock(Arc::new(Mutex::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )))
    }

    pub fn advance(&self, d: Duration) {
        *self.0.lock().unwrap() += d;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}

/// The RFC 7636 appendix B verifier, reused so the PKCE pair in these tests is the spec's own.
pub const RFC7636_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

pub const PUBLIC_REDIRECT: &str = "https://app.example/cb";
pub const SECOND_REDIRECT: &str = "https://app.example/other";

/// A public client with one registered redirect URI: the ordinary OAuth 2.1 native-app shape.
pub fn public_client() -> Client {
    Client {
        client_id: ClientId::new("public-app"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        redirect_uris: vec![PUBLIC_REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("read write admin").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: Some("Public app".into()),
        registration: None,
    }
}

/// A client with TWO registered redirect URIs, so the request must name which one it means.
pub fn two_redirect_client() -> Client {
    Client {
        client_id: ClientId::new("multi-redirect"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::AuthorizationCode],
        redirect_uris: vec![PUBLIC_REDIRECT.to_string(), SECOND_REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// A confidential client that is NOT registered for the authorization code grant.
pub fn device_only_client() -> Client {
    Client {
        client_id: ClientId::new("device-only"),
        auth: ClientAuth::ConfidentialSecret {
            secret: "s3cret-value-for-tests".into(),
        },
        grant_types: vec![GrantType::DeviceCode],
        redirect_uris: vec![PUBLIC_REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

pub async fn server_with(
    clock: ManualClock,
    clients: Vec<Client>,
) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), clock);
    for c in clients {
        srv.register_client(c).await.unwrap();
    }
    srv
}

// ----------------------------------------------------- confidential-client fixtures
//
// Introspection, revocation, and client_credentials all require a client that can
// authenticate with a secret; `public_client()` above deliberately cannot.

pub const CONFIDENTIAL_SECRET: &str = "confidential-secret-for-tests";
pub const CONFIDENTIAL_REDIRECT: &str = "https://conf.example/cb";

/// A confidential client registered for the authorization_code, refresh_token, AND
/// client_credentials grants, so a single fixture can mint both subject-bearing tokens (via the
/// code flow) and client-only tokens.
pub fn confidential_client() -> Client {
    Client {
        client_id: ClientId::new("confidential-app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: CONFIDENTIAL_SECRET.into(),
        },
        grant_types: vec![
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::ClientCredentials,
        ],
        redirect_uris: vec![CONFIDENTIAL_REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("read write admin").unwrap(),
        default_scopes: ScopeSet::parse("read write").unwrap(),
        name: Some("Confidential app".into()),
        registration: None,
    }
}

pub const OTHER_CONFIDENTIAL_SECRET: &str = "other-secret-for-tests";
pub const OTHER_REDIRECT: &str = "https://other.example/cb";

/// A second, independent confidential client, for the "must not affect another client's tokens"
/// tests in introspection and revocation.
pub fn other_confidential_client() -> Client {
    Client {
        client_id: ClientId::new("other-app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: OTHER_CONFIDENTIAL_SECRET.into(),
        },
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        redirect_uris: vec![OTHER_REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: Some("Other app".into()),
        registration: None,
    }
}

pub const CC_SECRET: &str = "cc-secret-value-for-tests";

/// A confidential client registered ONLY for client_credentials, with a default scope narrower
/// than its allowed set, so scope resolution (default / narrow / wide) is exercisable.
pub fn client_credentials_client() -> Client {
    Client {
        client_id: ClientId::new("cc-app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: CC_SECRET.into(),
        },
        grant_types: vec![GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("api:read api:write api:admin").unwrap(),
        default_scopes: ScopeSet::parse("api:read api:write").unwrap(),
        name: None,
        registration: None,
    }
}

/// Drive a full authorization_code redemption for `client_id`, returning the issued token
/// response. Used by suites that need a real, subject-bearing token to introspect or revoke
/// rather than re-deriving the code flow inline.
pub async fn mint_code_token<S: Storage>(
    srv: &AuthorizationServer<S, ManualClock>,
    client_id: &str,
    client_secret: Option<&str>,
    redirect_uri: &str,
    scope: &str,
    subject: &str,
) -> TokenResponse {
    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let req = AuthorizationRequest {
        resource: Vec::new(),
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        response_type: Some("code".to_string().into()),
        client_id: Some(client_id.to_string().into()),
        redirect_uri: Some(redirect_uri.to_string().into()),
        scope: Some(scope.to_string().into()),
        state: Some("mint-code-token-state".to_string().into()),
        code_challenge: Some(challenge.into()),
        code_challenge_method: Some("S256".to_string().into()),
        #[cfg(feature = "consent")]
        acr_values: None,
        #[cfg(feature = "consent")]
        max_age: None,
    };
    let validated = srv
        .validate_authorization_request(&req)
        .await
        .expect("fixture authorization request must validate");
    let response = srv
        .issue_authorization_code(UserApproval::granted(&validated, subject))
        .await
        .expect("fixture code issuance must succeed");
    srv.token(TokenRequest::AuthorizationCode {
        client_id: ClientId::new(client_id),
        client_secret: client_secret.map(str::to_string),
        code: response.code,
        redirect_uri: Some(redirect_uri.to_string()),
        code_verifier: Some(RFC7636_VERIFIER.to_string()),
    })
    .await
    .expect("fixture code redemption must succeed")
}

/// As [`mint_code_token`], but also hands back the (now consumed) authorization code. Suites that
/// test REPLAY need the code string itself, which the token response does not carry.
pub async fn mint_code_token_keeping_code<S: Storage>(
    srv: &AuthorizationServer<S, ManualClock>,
    client_id: &str,
    client_secret: Option<&str>,
    redirect_uri: &str,
    scope: &str,
    subject: &str,
) -> (TokenResponse, String) {
    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let req = AuthorizationRequest {
        resource: Vec::new(),
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        response_type: Some("code".to_string().into()),
        client_id: Some(client_id.to_string().into()),
        redirect_uri: Some(redirect_uri.to_string().into()),
        scope: Some(scope.to_string().into()),
        state: None,
        code_challenge: Some(challenge.into()),
        code_challenge_method: Some("S256".to_string().into()),
        #[cfg(feature = "consent")]
        acr_values: None,
        #[cfg(feature = "consent")]
        max_age: None,
    };
    let validated = srv
        .validate_authorization_request(&req)
        .await
        .expect("fixture authorization request must validate");
    let response = srv
        .issue_authorization_code(UserApproval::granted(&validated, subject))
        .await
        .expect("fixture code issuance must succeed");
    let issued = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new(client_id),
            client_secret: client_secret.map(str::to_string),
            code: response.code.clone(),
            redirect_uri: Some(redirect_uri.to_string()),
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await
        .expect("fixture code redemption must succeed");
    (issued, response.code)
}

/// A [`Storage`] that delegates to [`MemoryStorage`] and lies on demand, so the tests can pin what
/// the server does when the store fails or when generated codes collide. Both switches are off
/// until a test turns them on.
#[derive(Default)]
pub struct FaultStorage {
    inner: MemoryStorage,
    /// When set, every `put_refresh_token` fails. This is the transient-write-failure case that
    /// turns a read-modify-write on someone else's live credential into permanent destruction.
    pub fail_put_refresh: AtomicBool,
    /// When set, every user-code lookup reports a hit, as an unending run of collisions would.
    pub collide_user_codes: AtomicBool,
    /// When set, `revoke_token_family` fails. This is the store failing at the ONE moment the
    /// server is responding to a detected compromise, which is when a truthful audit event matters
    /// most and is the only moment at which a false one can be written.
    pub fail_revoke_token_family: AtomicBool,
    /// When set, `delete_token` fails: the fallback containment on a replayed code, and the leg
    /// that leaves the attacker's access token live if it is dropped.
    pub fail_delete_token: AtomicBool,
    /// When set, `put_authorization_code` fails. Two paths write a code back rather than burning
    /// it: the consumed record after a replay (which is what makes replay detectable a second
    /// time) and the live record after a client-id mismatch (which is what stops a stranger
    /// destroying an honest client's code).
    pub fail_put_authorization_code: AtomicBool,
    /// When set, `get_refresh_token` reports nothing, so the replay path finds no reachable chain
    /// and falls through to deleting the access token by name.
    pub fail_get_refresh: AtomicBool,
    /// The ORDER in which the server consulted the two token lookups.
    ///
    /// RFC 7009 section 2.1 makes `token_type_hint` an optimisation: the server SHOULD look in the
    /// hinted store first, and MUST keep looking if the hint was wrong. "Which store was asked
    /// first" is therefore the whole of the observable behaviour, and it is invisible in the
    /// endpoint's result, because a correct server reaches the same outcome either way. Recording
    /// the order is the only way a test can hold the server to the hint rather than to the outcome.
    pub lookup_order: Mutex<Vec<&'static str>>,
}

impl FaultStorage {
    fn record(&self, what: &'static str) {
        self.lookup_order
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(what);
    }

    /// The recorded lookups, oldest first, and reset ready for the next observation.
    pub fn take_lookup_order(&self) -> Vec<&'static str> {
        std::mem::take(&mut *self.lookup_order.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

impl FaultStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Storage for FaultStorage {
    async fn get_client(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<std::sync::Arc<Client>>, StorageError> {
        self.inner.get_client(client_id).await
    }

    async fn put_client(&self, client: Client) -> Result<(), StorageError> {
        self.inner.put_client(client).await
    }

    async fn delete_client(&self, client_id: &ClientId) -> Result<bool, StorageError> {
        self.inner.delete_client(client_id).await
    }

    async fn put_device_grant(&self, grant: DeviceGrant) -> Result<(), StorageError> {
        self.inner.put_device_grant(grant).await
    }

    async fn get_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        self.inner.get_device_grant(device_code).await
    }

    async fn find_device_grant_by_user_code(
        &self,
        normalized_user_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        if self.collide_user_codes.load(Ordering::SeqCst) {
            // Any non-None answer is a collision as far as the generator is concerned; reusing a
            // real stored grant keeps the value well formed.
            return Ok(Some(colliding_grant(normalized_user_code)));
        }
        self.inner
            .find_device_grant_by_user_code(normalized_user_code)
            .await
    }

    async fn take_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        self.inner.take_device_grant(device_code).await
    }

    async fn put_authorization_code(
        &self,
        record: AuthorizationCodeRecord,
    ) -> Result<(), StorageError> {
        if self.fail_put_authorization_code.load(Ordering::SeqCst) {
            return Err(StorageError::new("injected code write failure"));
        }
        self.inner.put_authorization_code(record).await
    }

    async fn take_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCodeRecord>, StorageError> {
        self.inner.take_authorization_code(code).await
    }

    #[cfg(feature = "par")]
    async fn put_pushed_authorization_request(
        &self,
        record: oauth_as::PushedAuthorizationRequest,
    ) -> Result<(), StorageError> {
        self.inner.put_pushed_authorization_request(record).await
    }

    #[cfg(feature = "par")]
    async fn take_pushed_authorization_request(
        &self,
        request_uri: &str,
    ) -> Result<Option<oauth_as::PushedAuthorizationRequest>, StorageError> {
        self.inner
            .take_pushed_authorization_request(request_uri)
            .await
    }

    async fn put_token(&self, token: IssuedToken) -> Result<(), StorageError> {
        self.inner.put_token(token).await
    }

    async fn get_token(
        &self,
        access_token: &str,
    ) -> Result<Option<std::sync::Arc<IssuedToken>>, StorageError> {
        self.record("get_token");
        self.inner.get_token(access_token).await
    }

    async fn delete_token(&self, access_token: &str) -> Result<(), StorageError> {
        if self.fail_delete_token.load(Ordering::SeqCst) {
            return Err(StorageError::new("injected delete failure"));
        }
        self.inner.delete_token(access_token).await
    }

    async fn put_refresh_token(&self, record: RefreshTokenRecord) -> Result<(), StorageError> {
        if self.fail_put_refresh.load(Ordering::SeqCst) {
            return Err(StorageError::new("injected write failure"));
        }
        self.inner.put_refresh_token(record).await
    }

    async fn get_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<std::sync::Arc<RefreshTokenRecord>>, StorageError> {
        self.record("get_refresh_token");
        if self.fail_get_refresh.load(Ordering::SeqCst) {
            return Ok(None);
        }
        self.inner.get_refresh_token(refresh_token).await
    }

    async fn take_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshTokenRecord>, StorageError> {
        self.inner.take_refresh_token(refresh_token).await
    }

    async fn revoke_token_family(&self, family_id: &str) -> Result<u64, StorageError> {
        if self.fail_revoke_token_family.load(Ordering::SeqCst) {
            return Err(StorageError::new("injected family revocation failure"));
        }
        self.inner.revoke_token_family(family_id).await
    }

    // The consent operations delegate straight through: this store's two fault switches are about
    // the token plane, and a consent path that could not be driven through it is a path no suite
    // can test under a failing store.
    #[cfg(feature = "consent")]
    async fn put_consent(&self, record: oauth_as::ConsentRecord) -> Result<(), StorageError> {
        self.inner.put_consent(record).await
    }

    #[cfg(feature = "consent")]
    async fn get_consent(
        &self,
        consent_id: &str,
    ) -> Result<Option<std::sync::Arc<oauth_as::ConsentRecord>>, StorageError> {
        self.inner.get_consent(consent_id).await
    }

    #[cfg(feature = "consent")]
    async fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> Result<Option<std::sync::Arc<oauth_as::ConsentRecord>>, StorageError> {
        self.inner.find_consent(client_id, subject).await
    }

    #[cfg(feature = "consent")]
    async fn consents_for_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<std::sync::Arc<oauth_as::ConsentRecord>>, StorageError> {
        self.inner.consents_for_subject(subject).await
    }

    #[cfg(feature = "consent")]
    async fn revoke_consent(&self, consent_id: &str) -> Result<u64, StorageError> {
        self.inner.revoke_consent(consent_id).await
    }

    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
    async fn claim_replay_id(
        &self,
        id: &str,
        expires_at: SystemTime,
    ) -> Result<bool, StorageError> {
        self.inner.claim_replay_id(id, expires_at).await
    }

    async fn sweep_expired(&self, now: SystemTime) -> Result<u64, StorageError> {
        self.inner.sweep_expired(now).await
    }
}

/// A well formed grant to answer a forced user-code collision with.
fn colliding_grant(user_code: &str) -> DeviceGrant {
    let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    DeviceGrant {
        device_code: "already-taken-device-code".to_string(),
        user_code: user_code.to_string(),
        client_id: ClientId::new("some-other-client"),
        scope: ScopeSet::parse("read").unwrap(),
        state: DeviceGrantState::Pending,
        created_at: now,
        expires_at: now + Duration::from_secs(600),
        interval: Duration::from_secs(5),
        last_poll_at: None,
    }
}

/// A server over [`FaultStorage`], for the failure-injection suites.
pub async fn fault_server_with(
    clock: ManualClock,
    clients: Vec<Client>,
) -> AuthorizationServer<FaultStorage, ManualClock> {
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let srv = AuthorizationServer::with_clock(cfg, FaultStorage::new(), clock);
    for c in clients {
        srv.register_client(c).await.unwrap();
    }
    srv
}
