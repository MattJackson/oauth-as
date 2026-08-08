// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 6749 section 2.3 client authentication: the public/confidential split, and the boundary
//! that keeps the token endpoint from being usable to enumerate registered client ids.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientId, Clock, ErrorCode, GrantType, MemoryStorage,
    ScopeSet, ServerConfig, TokenRequest,
};

/// A hand-cranked clock shared between the test and the server under test. Copied locally (per
/// this suite's file-ownership rules) rather than shared, so this file has no dependency on
/// `tests/support`.
#[derive(Clone)]
struct ManualClock(Arc<Mutex<SystemTime>>);

impl ManualClock {
    fn at_epoch() -> Self {
        ManualClock(Arc::new(Mutex::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )))
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}

const SECRET: &str = "hunter2-correct-secret";

/// A public client: no secret exists for it at all.
fn public_client() -> Client {
    Client {
        client_id: ClientId::new("public-client"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::DeviceCode],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
    }
}

/// A confidential client holding `SECRET`, registered for every grant type so each grant's
/// authentication path is reachable through one fixture.
fn confidential_client() -> Client {
    Client {
        client_id: ClientId::new("confidential-client"),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.into(),
        },
        grant_types: vec![
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::ClientCredentials,
            GrantType::DeviceCode,
        ],
        redirect_uris: vec!["https://app.example/cb".into()],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
    }
}

/// A confidential client registered for NO grant type at all, so every grant request against it
/// must fail on the registration check, never on authentication (its secret is presented
/// correctly by every test that uses it).
fn no_grants_client() -> Client {
    Client {
        client_id: ClientId::new("no-grants-client"),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.into(),
        },
        grant_types: vec![],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
    }
}

async fn server_with(clients: Vec<Client>) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    for c in clients {
        srv.register_client(c).await.unwrap();
    }
    srv
}

// ------------------------------------------------------------ ClientAuth::verify boundary cases

/// RFC 6749 section 2.3: a public client has no secret, so presenting one proves nothing and is
/// refused outright, not merely ignored. Accepting any presented secret for a public client would
/// let a client mixup (a caller that thinks it is confidential, talking to a registration that
/// isn't) through silently.
#[test]
fn public_client_accepts_no_secret_and_rejects_any_presented_secret() {
    let auth = ClientAuth::Public;
    assert!(
        auth.verify(None),
        "no secret presented: the only correct case for a public client"
    );
    assert!(
        !auth.verify(Some("")),
        "an empty presented secret is still a presented secret"
    );
    assert!(!auth.verify(Some("anything")));
    assert!(
        !auth.verify(Some(SECRET)),
        "even a string equal to another client's real secret"
    );
}

/// RFC 6749 section 2.3: a confidential client's secret must match exactly. Every near miss that
/// a lazy `starts_with` or length-truncated comparison would let through is exercised here.
#[test]
fn confidential_client_requires_the_exact_secret() {
    let auth = ClientAuth::ConfidentialSecret {
        secret: SECRET.into(),
    };
    assert!(auth.verify(Some(SECRET)), "the exact secret must succeed");
    assert!(!auth.verify(None), "no secret presented");
    assert!(!auth.verify(Some("")), "empty secret presented");
    assert!(
        !auth.verify(Some(&SECRET[..SECRET.len() - 1])),
        "a correct prefix, one byte short, must not verify"
    );
    assert!(
        !auth.verify(Some(&format!("{SECRET}x"))),
        "a superstring of the real secret (the real secret plus one byte) must not verify"
    );
    assert!(
        !auth.verify(Some(&SECRET.to_uppercase())),
        "secrets are compared byte for byte, not case-insensitively"
    );
    assert!(!auth.verify(Some("totally-different")));
}

// -------------------------------------------------------------- AuthorizationServer level

/// The same public/confidential boundary, exercised through the token endpoint rather than
/// `ClientAuth::verify` directly: a public client's device-authorization request carrying a
/// secret it was never issued is refused as `invalid_client`.
#[tokio::test]
async fn public_client_presenting_a_secret_at_the_server_is_invalid_client() {
    let srv = server_with(vec![public_client()]).await;
    let err = srv
        .device_authorization(&ClientId::new("public-client"), Some("unexpected"), None)
        .await
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidClient);
    assert_eq!(err.http_status(), 401);
}

/// RFC 6749 section 2.3 / RFC 6749 section 5.2: an unknown `client_id` and a known client with the
/// wrong secret must be INDISTINGUISHABLE at the token endpoint. If they produced different
/// errors, a caller could use the token endpoint as an oracle to enumerate which client ids are
/// registered by testing candidate ids with a wrong secret and watching for the error to change.
/// This compares the full `ErrorResponse` value (code, description, and uri), not just the code,
/// because a differing description would leak the same distinction through a side channel.
#[tokio::test]
async fn unknown_client_id_and_wrong_secret_produce_the_identical_error() {
    let srv = server_with(vec![confidential_client()]).await;

    let unknown_id = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("this-client-id-was-never-registered"),
            client_secret: Some("does-not-matter".into()),
            scope: None,
        })
        .await
        .unwrap_err();

    let wrong_secret = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("confidential-client"),
            client_secret: Some("wrong-secret".into()),
            scope: None,
        })
        .await
        .unwrap_err();

    assert_eq!(
        unknown_id, wrong_secret,
        "an unknown client_id and a known client with a wrong secret must be the same error \
         value in every field, or the token endpoint becomes a client-id oracle"
    );
    assert_eq!(unknown_id.error, ErrorCode::InvalidClient);
    assert_eq!(unknown_id.http_status(), 401);

    // The same equality holds when no secret at all is presented for the known client, so a
    // caller cannot distinguish "unknown id" from "known id, no credential" either.
    let no_secret = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("confidential-client"),
            client_secret: None,
            scope: None,
        })
        .await
        .unwrap_err();
    assert_eq!(unknown_id, no_secret);
}

/// The same enumeration-resistance property holds on the device-authorization path, which
/// authenticates a client before any grant exists to look up.
#[tokio::test]
async fn unknown_client_id_and_wrong_secret_agree_on_the_device_authorization_path() {
    let srv = server_with(vec![confidential_client()]).await;

    let unknown_id = srv
        .device_authorization(
            &ClientId::new("also-never-registered"),
            Some("irrelevant"),
            None,
        )
        .await
        .unwrap_err();
    let wrong_secret = srv
        .device_authorization(
            &ClientId::new("confidential-client"),
            Some("wrong-secret"),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(unknown_id, wrong_secret);
}

/// RFC 6749 section 3.3 / section 4: a client is refused any grant its registration does not
/// list, and the refusal is `unauthorized_client`, distinct from `invalid_client`. This is
/// checked across every grant type this crate implements: authorization_code, client_credentials,
/// the device code grant, and refresh_token. The fixture client authenticates correctly every
/// time (its secret is presented), so a failure here can only be the registration check, not a
/// mislabeled authentication failure.
#[tokio::test]
async fn client_without_the_grant_in_its_registration_is_unauthorized_client_for_every_grant_type()
{
    let srv = server_with(vec![no_grants_client()]).await;
    let client_id = ClientId::new("no-grants-client");

    let authorization_code = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: client_id.clone(),
            client_secret: Some(SECRET.into()),
            code: "irrelevant-code".into(),
            redirect_uri: None,
            code_verifier: None,
        })
        .await
        .unwrap_err();
    assert_eq!(authorization_code.error, ErrorCode::UnauthorizedClient);

    let client_credentials = srv
        .token(TokenRequest::ClientCredentials {
            client_id: client_id.clone(),
            client_secret: Some(SECRET.into()),
            scope: None,
        })
        .await
        .unwrap_err();
    assert_eq!(client_credentials.error, ErrorCode::UnauthorizedClient);

    let device_code = srv
        .token(TokenRequest::DeviceCode {
            client_id: client_id.clone(),
            client_secret: Some(SECRET.into()),
            device_code: "irrelevant-device-code".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(device_code.error, ErrorCode::UnauthorizedClient);

    let refresh_token = srv
        .token(TokenRequest::RefreshToken {
            client_id: client_id.clone(),
            client_secret: Some(SECRET.into()),
            refresh_token: "irrelevant-refresh-token".into(),
            scope: None,
        })
        .await
        .unwrap_err();
    assert_eq!(refresh_token.error, ErrorCode::UnauthorizedClient);

    // The device-authorization endpoint (not a `token()` request, but the same registration
    // check) refuses the same way.
    let device_authorization = srv
        .device_authorization(&client_id, Some(SECRET), None)
        .await
        .unwrap_err();
    assert_eq!(device_authorization.error, ErrorCode::UnauthorizedClient);
}
