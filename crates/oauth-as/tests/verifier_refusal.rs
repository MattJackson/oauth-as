// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! WITH NO ES256 VERIFIER INSTALLED, EVERY SIGNED CREDENTIAL IS REFUSED.
//!
//! This file is compiled only when a JWS-verifying feature is on and `jwt-p256` is OFF, which is
//! the one configuration in which no verifier exists unless the host installs one. It is the
//! crate's established posture applied to the new seam: an absent consent resolver refuses, an
//! absent registration policy refuses, an absent [`oauth_as::par::RequestObjectKeys`] refuses, and
//! a server that cannot check a signature must never behave as though it had checked one.
//!
//! Every case here is asserted TWICE, against the SAME bytes: refused with no verifier, accepted
//! once a verifier is installed. Without the second half the tests would pass equally well against
//! a server that refuses everything for some unrelated reason, which is not what is being claimed.
//!
//! The installed verifier says `true` to everything, and that is deliberate: it isolates the
//! question "is the seam wired" from the question "is the arithmetic right", which is
//! `signer_conformance` and `signer_conformance_selftest`'s job. A host that installed this one in
//! production would have no signature checking at all, which is why the harness exists.

#![cfg(all(
    not(feature = "jwt-p256"),
    any(feature = "dpop", feature = "jar", feature = "client_assertion")
))]

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use oauth_as::jwt::{compact_jws, Es256Verifier, PublicJwk};

/// Thirty-two bytes of base64url, which is what RFC 7518 section 6.2.1.2 fixes a P-256 coordinate
/// at. Not a point on any curve, and nothing in this file needs it to be: with `jwt-p256` off this
/// build contains no curve arithmetic at all.
fn coordinate(fill: u8) -> String {
    URL_SAFE_NO_PAD.encode([fill; 32])
}

fn a_public_jwk() -> PublicJwk {
    PublicJwk::from_coordinates(&coordinate(0x11), &coordinate(0x22))
        .expect("32 byte coordinates are a well formed JWK")
}

/// Says yes to everything. See the module docs.
struct AlwaysVerifies;

impl Es256Verifier for AlwaysVerifies {
    fn verify(&self, _key: &PublicJwk, _signing_input: &[u8], _signature: &[u8]) -> bool {
        true
    }
}

fn verifier() -> Arc<dyn Es256Verifier> {
    Arc::new(AlwaysVerifies)
}

/// A compact JWS with a well formed 64 byte ES256 signature that is not a signature of anything.
/// RFC 7518 section 3.4 fixes the length, so this is refused for the reason under test rather than
/// for its shape.
fn signed_shaped(header: &serde_json::Value, claims: &serde_json::Value) -> String {
    compact_jws(
        &serde_json::to_vec(header).unwrap(),
        &serde_json::to_vec(claims).unwrap(),
        |_| vec![0x5Au8; 64],
    )
}

// --------------------------------------------------------------------------- RFC 9449 DPoP

#[cfg(feature = "dpop")]
mod dpop {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    use oauth_as::{
        AuthorizationServer, Client, ClientAuth, ClientId, ErrorCode, GrantType, MemoryStorage,
        ScopeSet, ServerConfig, TokenRequest, TokenRequestContext, TokenType,
    };

    const TOKEN_ENDPOINT: &str = "https://as.example/token";
    const SECRET: &str = "confidential-client-secret";

    fn proof() -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        signed_shaped(
            &serde_json::json!({
                "typ": "dpop+jwt",
                "alg": "ES256",
                "jwk": serde_json::to_value(a_public_jwk()).unwrap(),
            }),
            &serde_json::json!({
                "jti": "proof-1",
                "htm": "POST",
                "htu": TOKEN_ENDPOINT,
                "iat": now,
            }),
        )
    }

    async fn server() -> AuthorizationServer<MemoryStorage> {
        let srv = AuthorizationServer::new(
            ServerConfig::new("https://as.example", "https://as.example/device"),
            MemoryStorage::new(),
        );
        srv.register_client(Client {
            client_id: ClientId::new("app"),
            auth: ClientAuth::ConfidentialSecret {
                secret: SECRET.to_string(),
            },
            grant_types: vec![GrantType::ClientCredentials],
            redirect_uris: vec![],
            allowed_scopes: ScopeSet::parse("read").unwrap(),
            default_scopes: ScopeSet::parse("read").unwrap(),
            name: None,
            registration: None,
        })
        .await
        .unwrap();
        srv
    }

    fn request() -> TokenRequest {
        TokenRequest::ClientCredentials {
            client_id: ClientId::new("app"),
            client_secret: Some(SECRET.to_string()),
            scope: None,
        }
    }

    /// RFC 9449 section 4.3 (6): the proof is accepted only if its signature verifies. With
    /// nothing able to perform that check, the only answer that is not a lie is a refusal.
    #[tokio::test]
    async fn a_proof_is_refused_when_no_verifier_is_installed() {
        let srv = server().await;
        let proof = proof();
        let error = srv
            .token_with_context(
                request(),
                TokenRequestContext {
                    dpop_proof: Some(&proof),
                    ..Default::default()
                },
            )
            .await
            .expect_err("a proof no verifier can check must not be honoured");
        assert_eq!(error.error, ErrorCode::InvalidDpopProof);
    }

    /// The SAME bytes, accepted once a verifier exists: the refusal above is about the absent
    /// backend and not about the proof.
    #[tokio::test]
    async fn the_same_proof_is_honoured_once_a_verifier_is_installed() {
        let srv = server().await.with_es256_verifier(verifier());
        let proof = proof();
        let response = srv
            .token_with_context(
                request(),
                TokenRequestContext {
                    dpop_proof: Some(&proof),
                    ..Default::default()
                },
            )
            .await
            .expect("an installed verifier is what makes the proof checkable");
        assert_eq!(response.token_type, TokenType::Dpop);
    }
}

// ------------------------------------------------------------------ RFC 9101 request objects

#[cfg(feature = "jar")]
mod jar {
    use super::*;

    use oauth_as::{
        AuthorizationError, AuthorizationServer, Client, ClientAuth, ClientId, ErrorCode,
        GrantType, JarConfig, MemoryStorage, RegisteredRequestObjectKey, RequestObjectKeys,
        ScopeSet, ServerConfig,
    };

    struct Keys(RegisteredRequestObjectKey);

    impl RequestObjectKeys for Keys {
        fn registered_key(&self, client_id: &ClientId) -> Option<RegisteredRequestObjectKey> {
            (client_id.as_str() == "app").then(|| self.0.clone())
        }
    }

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    fn request_object() -> String {
        signed_shaped(
            &serde_json::json!({ "alg": "ES256", "typ": "oauth-authz-req+jwt" }),
            &serde_json::json!({
                "iss": "app",
                "aud": "https://as.example",
                "client_id": "app",
                "response_type": "code",
                "redirect_uri": "https://app.example/cb",
                "scope": "read",
                "code_challenge": oauth_as::pkce::code_challenge_s256(VERIFIER),
                "code_challenge_method": "S256",
            }),
        )
    }

    async fn server() -> AuthorizationServer<MemoryStorage> {
        let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
        cfg.jar = Some(Box::new(JarConfig::new()));
        let registered = RegisteredRequestObjectKey::es256_from_jwk_coordinates(
            None,
            &coordinate(0x11),
            &coordinate(0x22),
        )
        .expect("32 byte coordinates register");
        let srv = AuthorizationServer::new(cfg, MemoryStorage::new())
            .with_request_object_keys(Box::new(Keys(registered)));
        srv.register_client(Client {
            client_id: ClientId::new("app"),
            auth: ClientAuth::Public,
            grant_types: vec![GrantType::AuthorizationCode],
            redirect_uris: vec!["https://app.example/cb".to_string()],
            allowed_scopes: ScopeSet::parse("read").unwrap(),
            default_scopes: ScopeSet::parse("read").unwrap(),
            name: None,
            registration: None,
        })
        .await
        .unwrap();
        srv
    }

    /// RFC 9101 section 6.3: the request object's signature is what makes its claims the client's
    /// request rather than the URL's. Unverifiable means unusable.
    #[tokio::test]
    async fn a_request_object_is_refused_when_no_verifier_is_installed() {
        let srv = server().await;
        match srv
            .validate_signed_authorization_request("app", &request_object())
            .await
        {
            Err(AuthorizationError::Direct(error)) => {
                assert_eq!(error.error, ErrorCode::InvalidRequestObject);
            }
            other => panic!("an uncheckable request object must be refused, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_same_request_object_is_honoured_once_a_verifier_is_installed() {
        let srv = server().await.with_es256_verifier(verifier());
        let request = srv
            .validate_signed_authorization_request("app", &request_object())
            .await
            .expect("an installed verifier is what makes the object checkable");
        assert_eq!(request.client_id.as_str(), "app");
    }
}

// ------------------------------------------------------------------ RFC 7523 client assertions

#[cfg(feature = "client_assertion")]
mod client_assertion {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    use oauth_as::client_assertion::AssertionKeys;
    use oauth_as::{
        AuthorizationServer, Client, ClientAuth, ClientCredential, ClientId, ErrorCode, GrantType,
        MemoryStorage, ScopeSet, ServerConfig, TokenRequest, TokenRequestContext,
        CLIENT_ASSERTION_TYPE,
    };

    fn assertion() -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        signed_shaped(
            &serde_json::json!({ "alg": "ES256", "typ": "JWT" }),
            &serde_json::json!({
                "iss": "app",
                "sub": "app",
                "aud": "https://as.example/token",
                "jti": "assertion-1",
                "iat": now,
                "exp": now + 60,
            }),
        )
    }

    async fn server() -> AuthorizationServer<MemoryStorage> {
        let srv = AuthorizationServer::new(
            ServerConfig::new("https://as.example", "https://as.example/device"),
            MemoryStorage::new(),
        );
        srv.register_client(Client {
            client_id: ClientId::new("app"),
            auth: ClientAuth::ConfidentialAssertion {
                keys: AssertionKeys::PublicKeys {
                    keys: vec![a_public_jwk()],
                },
            },
            grant_types: vec![GrantType::ClientCredentials],
            redirect_uris: vec![],
            allowed_scopes: ScopeSet::parse("read").unwrap(),
            default_scopes: ScopeSet::parse("read").unwrap(),
            name: None,
            registration: None,
        })
        .await
        .unwrap();
        srv
    }

    fn request() -> TokenRequest {
        TokenRequest::ClientCredentials {
            client_id: ClientId::new("app"),
            client_secret: None,
            scope: None,
        }
    }

    fn context(assertion: &str) -> TokenRequestContext<'_> {
        TokenRequestContext {
            credential: ClientCredential {
                client_assertion: Some(assertion),
                client_assertion_type: Some(CLIENT_ASSERTION_TYPE),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// RFC 7523 section 3 (2): an assertion authenticates only because its signature does. With no
    /// verifier the credential proves nothing, and `invalid_client` is the RFC 6749 section 5.2
    /// answer to a credential that did not authenticate.
    #[tokio::test]
    async fn an_assertion_is_refused_when_no_verifier_is_installed() {
        let srv = server().await;
        let assertion = assertion();
        let error = srv
            .token_with_context(request(), context(&assertion))
            .await
            .expect_err("an uncheckable assertion must not authenticate");
        assert_eq!(error.error, ErrorCode::InvalidClient);
    }

    #[tokio::test]
    async fn the_same_assertion_authenticates_once_a_verifier_is_installed() {
        let srv = server().await.with_es256_verifier(verifier());
        let assertion = assertion();
        srv.token_with_context(request(), context(&assertion))
            .await
            .expect("an installed verifier is what makes the assertion checkable");
    }
}
