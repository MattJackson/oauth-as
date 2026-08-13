// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 7523 `client_secret_jwt` IS SYMMETRIC, SO IT MUST NOT NEED AN ES256 BACKEND.
//!
//! `client_secret_jwt` is an HS256 HMAC over the secret the registration already holds
//! (RFC 7523 section 2.2 with RFC 7518 section 3.2). There is no elliptic curve anywhere on that
//! path: [`oauth_as::client_assertion::AssertionKeys::ClientSecret`] dispatches to
//! `verify_hs256`, which never touches an [`oauth_as::jwt::Es256Verifier`] at all.
//!
//! So this file is compiled exactly where the claim can be checked: `client-assertion` on
//! (`client-assertion = ["jwt"]`, which does NOT pull `jwt-p256`), `jwt-p256` off, and no host
//! verifier installed. That is a build in which the crate contains no curve arithmetic, and a
//! `client_secret_jwt` client must still be able to authenticate.
//!
//! The companion is `tests/verifier_refusal.rs`, which asserts the OTHER half of the same rule:
//! `private_key_jwt` (ES256) in this same build is refused, because a signature this server
//! cannot check has authenticated nobody. Both halves matter. A build that refuses both is
//! broken for symmetric clients; a build that accepts both would be pretending to check a
//! signature.

#![cfg(all(feature = "client-assertion", not(feature = "jwt-p256")))]

use std::time::{SystemTime, UNIX_EPOCH};

use oauth_as::client_assertion::{AssertionKeys, ClientSecretKey};
use oauth_as::jwt::{compact_jws, hmac_sha256};
use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientCredential, ClientId, ErrorCode, GrantType,
    MemoryStorage, ScopeSet, ServerConfig, TokenRequest, TokenRequestContext,
    CLIENT_ASSERTION_TYPE,
};

const ISSUER: &str = "https://as.example";
const TOKEN_ENDPOINT: &str = "https://as.example/token";
const CLIENT: &str = "hmac-app";
const SECRET: &str = "a-high-entropy-registered-client-secret";

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A conforming RFC 7523 section 3 claim set, signed the one way a `client_secret_jwt` client
/// can sign: HMAC-SHA-256 over the registered secret.
fn assertion(jti: &str) -> String {
    let claims = serde_json::json!({
        "iss": CLIENT,
        "sub": CLIENT,
        "aud": TOKEN_ENDPOINT,
        "exp": now_secs() + 120,
        "iat": now_secs(),
        "jti": jti,
    });
    compact_jws(
        br#"{"alg":"HS256","typ":"JWT"}"#,
        &serde_json::to_vec(&claims).unwrap(),
        |input| hmac_sha256(SECRET.as_bytes(), input.as_bytes()).to_vec(),
    )
}

async fn server() -> AuthorizationServer<MemoryStorage> {
    let srv = AuthorizationServer::new(
        ServerConfig::new(ISSUER, "https://as.example/device"),
        MemoryStorage::new(),
    );
    srv.register_client(Client {
        client_id: ClientId::new(CLIENT),
        auth: ClientAuth::ConfidentialAssertion {
            keys: AssertionKeys::ClientSecret {
                secret: ClientSecretKey::new(SECRET).expect("fixture secret clears the floor"),
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
    .expect("the fixture registration is well formed");
    srv
}

fn request() -> TokenRequest {
    TokenRequest::ClientCredentials {
        client_id: ClientId::new(CLIENT),
        client_secret: None,
        scope: None,
    }
}

fn context(assertion: &str) -> TokenRequestContext<'_> {
    TokenRequestContext::new(ClientCredential::assertion(
        Some(CLIENT_ASSERTION_TYPE),
        assertion,
    ))
}

/// The whole point of the file: a valid HMAC assertion authenticates in a build with no ES256
/// backend of any kind.
#[tokio::test]
async fn a_client_secret_jwt_assertion_authenticates_with_no_es256_backend() {
    let srv = server().await;
    let assertion = assertion("hmac-1");
    srv.token_with_context(request(), context(&assertion))
        .await
        .expect("client_secret_jwt is an HMAC and needs no ES256 backend to be checkable");
}

/// And the check is still a CHECK: a tag computed under a different secret is refused in the same
/// build, so the test above cannot be passing because the signature stopped being verified.
#[tokio::test]
async fn a_wrong_hmac_is_still_refused_with_no_es256_backend() {
    let srv = server().await;
    let claims = serde_json::json!({
        "iss": CLIENT,
        "sub": CLIENT,
        "aud": TOKEN_ENDPOINT,
        "exp": now_secs() + 120,
        "iat": now_secs(),
        "jti": "hmac-2",
    });
    let forged = compact_jws(
        br#"{"alg":"HS256","typ":"JWT"}"#,
        &serde_json::to_vec(&claims).unwrap(),
        |input| hmac_sha256(b"not-the-registered-secret-at-all", input.as_bytes()).to_vec(),
    );
    let error = srv
        .token_with_context(request(), context(&forged))
        .await
        .expect_err("an HMAC under the wrong key authenticates nobody");
    assert_eq!(error.error, ErrorCode::InvalidClient);
}

/// RFC 7523 section 3: single use, and it has to survive the fix above. A path that skipped the
/// verifier resolve and skipped the `jti` claim with it would pass the first test and hand out a
/// replayable credential.
#[tokio::test]
async fn the_assertion_is_still_single_use_with_no_es256_backend() {
    let srv = server().await;
    let assertion = assertion("hmac-3");
    srv.token_with_context(request(), context(&assertion))
        .await
        .expect("the first use authenticates");
    let error = srv
        .token_with_context(request(), context(&assertion))
        .await
        .expect_err("RFC 7523 s3 makes the jti single use within the assertion's validity");
    assert_eq!(error.error, ErrorCode::InvalidClient);
}
