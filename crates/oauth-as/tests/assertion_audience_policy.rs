// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The client-assertion audience policy switch (`ServerConfig::assertion_audience`).
//!
//! RFC 7523 section 3 (3) permits a client-authentication assertion to name this server by its
//! token endpoint URL or its issuer identifier, as a string or (RFC 7519 section 4.1.3) inside an
//! array. FAPI 2.0 Security Profile Final narrows that: section 5.3.2.1 item 8 requires the AS to
//! accept ONLY its issuer identifier, and section 5.3.3.1 item 5 requires it "as a string not as an
//! item in an array". `AssertionAudience::IssuerOnly` is that tightening, off by default.
//!
//! These tests pin both ends of the switch through the SHARED `authenticate_client` path — the
//! token endpoint and the PAR endpoint both reach it — and confirm the default posture is
//! unchanged. They are the two FINDINGS.md D4 modules
//! (par-test-token-endpoint-url-as-audience-fails, par-test-array-as-audience-fails) reproduced
//! in-crate.
#![cfg(all(feature = "client-assertion", feature = "jwt-p256"))]

use oauth_as::client_assertion::{AssertionKeys, CLIENT_ASSERTION_TYPE};
use oauth_as::jwt::{compact_jws, EcdsaP256Key, JwsAlg};
use oauth_as::{
    AssertionAudience, AuthorizationServer, Client, ClientAuth, ClientCredential, ClientId,
    ErrorCode, GrantType, MemoryStorage, ScopeSet, ServerConfig, TokenRequest, TokenRequestContext,
};

const ISSUER: &str = "https://as.example";
const TOKEN_ENDPOINT: &str = "https://as.example/token";
const CLIENT_ID: &str = "pkjwt";

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A `private_key_jwt` client registered for both the client-credentials and authorization-code
/// grants, so the SAME registration is exercised at the token and PAR endpoints.
fn pkjwt_client(key: &EcdsaP256Key) -> Client {
    Client {
        client_id: ClientId::new(CLIENT_ID),
        auth: ClientAuth::ConfidentialAssertion {
            keys: AssertionKeys::PublicKeys {
                alg: JwsAlg::Es256,
                keys: vec![key.to_public_jwk()],
            },
        },
        grant_types: vec![GrantType::ClientCredentials, GrantType::AuthorizationCode],
        redirect_uris: vec!["https://app.example/cb".to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

async fn server_with_audience(
    key: &EcdsaP256Key,
    audience: AssertionAudience,
) -> AuthorizationServer<MemoryStorage> {
    let cfg =
        ServerConfig::new(ISSUER, "https://as.example/device").with_assertion_audience(audience);
    let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
    srv.register_client(pkjwt_client(key)).await.unwrap();
    srv
}

/// Sign an ES256 `private_key_jwt` assertion with the `aud` the test chooses.
fn sign(key: &EcdsaP256Key, aud: serde_json::Value, jti: &str) -> String {
    let claims = serde_json::json!({
        "iss": CLIENT_ID,
        "sub": CLIENT_ID,
        "aud": aud,
        "exp": now_secs() + 120,
        "iat": now_secs(),
        "jti": jti,
    });
    compact_jws(
        br#"{"alg":"ES256","typ":"JWT"}"#,
        &serde_json::to_vec(&claims).unwrap(),
        |input| key.sign_signing_input(input).unwrap(),
    )
}

fn cc_request() -> TokenRequest {
    TokenRequest::ClientCredentials {
        client_id: ClientId::new(CLIENT_ID),
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

// ------------------------------------------------------------------ IssuerOnly, the token endpoint

#[tokio::test]
async fn issuer_only_token_endpoint_refuses_the_token_endpoint_url_as_audience() {
    let key = EcdsaP256Key::generate("k");
    let srv = server_with_audience(&key, AssertionAudience::IssuerOnly).await;
    let assertion = sign(&key, serde_json::json!(TOKEN_ENDPOINT), "aud-1");
    let refused = srv
        .token_with_context(cc_request(), context(&assertion))
        .await
        .expect_err("under IssuerOnly the token endpoint URL is not an acceptable aud");
    assert_eq!(refused.error, ErrorCode::InvalidClient);
}

#[tokio::test]
async fn issuer_only_token_endpoint_refuses_an_array_carrying_the_issuer() {
    // The suite's exact payload: aud = [issuer, token_endpoint].
    let key = EcdsaP256Key::generate("k");
    let srv = server_with_audience(&key, AssertionAudience::IssuerOnly).await;
    let assertion = sign(&key, serde_json::json!([ISSUER, TOKEN_ENDPOINT]), "aud-1");
    let refused = srv
        .token_with_context(cc_request(), context(&assertion))
        .await
        .expect_err("under IssuerOnly an array aud is refused even with the issuer in it");
    assert_eq!(refused.error, ErrorCode::InvalidClient);
}

#[tokio::test]
async fn issuer_only_token_endpoint_accepts_the_issuer_as_a_string() {
    let key = EcdsaP256Key::generate("k");
    let srv = server_with_audience(&key, AssertionAudience::IssuerOnly).await;
    let assertion = sign(&key, serde_json::json!(ISSUER), "aud-1");
    srv.token_with_context(cc_request(), context(&assertion))
        .await
        .expect("the issuer identifier as a string is the one accepted aud");
}

// ----------------------------------------------------------------------- IssuerOnly, the PAR leg

#[cfg(feature = "par")]
#[tokio::test]
async fn issuer_only_par_endpoint_refuses_the_url_and_accepts_the_issuer() {
    use oauth_as::ParConfig;

    let key = EcdsaP256Key::generate("k");
    let mut cfg = ServerConfig::new(ISSUER, "https://as.example/device")
        .with_assertion_audience(AssertionAudience::IssuerOnly);
    cfg.par = Some(Box::new(ParConfig::new()));
    let srv = AuthorizationServer::new(cfg, MemoryStorage::new());
    srv.register_client(pkjwt_client(&key)).await.unwrap();

    let challenge =
        oauth_as::pkce::code_challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    let params = vec![
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", "https://app.example/cb"),
        ("scope", "read"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];

    // aud = token endpoint URL: refused at PAR with invalid_client, HTTP 400 or 401 (the D4 module).
    let assertion = sign(&key, serde_json::json!(TOKEN_ENDPOINT), "par-1");
    let refused = srv
        .pushed_authorization_request_with_credential(
            &ClientId::new(CLIENT_ID),
            &ClientCredential::assertion(Some(CLIENT_ASSERTION_TYPE), &assertion),
            &params,
        )
        .await
        .expect_err("PAR must refuse the token endpoint URL as aud under IssuerOnly");
    assert_eq!(refused.error, ErrorCode::InvalidClient);
    assert!(
        matches!(refused.http_status(), 400 | 401),
        "the suite accepts 400 or 401 at PAR; got {}",
        refused.http_status()
    );

    // aud = issuer, as a string: accepted, and PAR mints a handle.
    let assertion = sign(&key, serde_json::json!(ISSUER), "par-2");
    srv.pushed_authorization_request_with_credential(
        &ClientId::new(CLIENT_ID),
        &ClientCredential::assertion(Some(CLIENT_ASSERTION_TYPE), &assertion),
        &params,
    )
    .await
    .expect("the issuer as a string authenticates the PAR push");
}

// ------------------------------------------------------------ the default posture is untouched

#[tokio::test]
async fn the_default_posture_still_accepts_the_token_endpoint_url_and_an_array() {
    // Rfc7523 (the default) is unchanged by the switch existing: the token endpoint URL and an
    // array with a matching member both authenticate, exactly as before D4.
    let key = EcdsaP256Key::generate("k");
    let srv = server_with_audience(&key, AssertionAudience::Rfc7523).await;

    let url_aud = sign(&key, serde_json::json!(TOKEN_ENDPOINT), "def-1");
    srv.token_with_context(cc_request(), context(&url_aud))
        .await
        .expect("the default accepts the token endpoint URL (RFC 7523 s3 (3))");

    let array_aud = sign(
        &key,
        serde_json::json!(["https://other.example/token", TOKEN_ENDPOINT]),
        "def-2",
    );
    srv.token_with_context(cc_request(), context(&array_aud))
        .await
        .expect("the default accepts an array whose member matches (RFC 7519 s4.1.3)");
}
