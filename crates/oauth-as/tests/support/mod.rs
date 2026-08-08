// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Shared fixtures for the behavioural tests: a hand-cranked clock (so expiry and poll pacing are
//! tested without sleeping) and the client registrations the suites share.
#![allow(dead_code)]

pub mod alloc;

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::{
    AuthorizationRequest, AuthorizationServer, Client, ClientAuth, ClientId, Clock, GrantType,
    MemoryStorage, ScopeSet, ServerConfig, TokenRequest, TokenResponse,
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
    }
}

/// Drive a full authorization_code redemption for `client_id`, returning the issued token
/// response. Used by suites that need a real, subject-bearing token to introspect or revoke
/// rather than re-deriving the code flow inline.
pub async fn mint_code_token(
    srv: &AuthorizationServer<MemoryStorage, ManualClock>,
    client_id: &str,
    client_secret: Option<&str>,
    redirect_uri: &str,
    scope: &str,
    subject: &str,
) -> TokenResponse {
    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let req = AuthorizationRequest {
        response_type: Some("code".to_string().into()),
        client_id: Some(client_id.to_string().into()),
        redirect_uri: Some(redirect_uri.to_string().into()),
        scope: Some(scope.to_string().into()),
        state: Some("mint-code-token-state".to_string().into()),
        code_challenge: Some(challenge.into()),
        code_challenge_method: Some("S256".to_string().into()),
    };
    let validated = srv
        .validate_authorization_request(&req)
        .await
        .expect("fixture authorization request must validate");
    let response = srv
        .issue_authorization_code(&validated, subject)
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
