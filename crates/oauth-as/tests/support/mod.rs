// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Shared fixtures for the behavioural tests: a hand-cranked clock (so expiry and poll pacing are
//! tested without sleeping) and the client registrations the suites share.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientId, Clock, GrantType, MemoryStorage, ScopeSet,
    ServerConfig,
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
