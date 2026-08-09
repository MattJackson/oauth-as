// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9101 signed request objects, from OUTSIDE the crate: only the public API, the way a host
//! wires it.
//!
//! The attacks that need a client's SIGNATURE live in `src/tests/par.rs`, because minting one
//! means acting as the client and this crate deliberately offers no request-object signer. What is
//! reproduced here is everything an attacker can do WITHOUT the client's key, which is the more
//! interesting half:
//!
//! - [`an_unsigned_request_object_is_refused`]: strip the signature entirely and claim
//!   `alg: none` (RFC 9101 section 10.5, RFC 8725 section 3.1).
//! - [`an_access_token_is_not_a_request_object`]: replay a JWT this issuer really did sign, for a
//!   different purpose, as an authorization request (RFC 9101 section 10.8, cross-JWT confusion).
//! - [`requiring_a_signed_request_object_refuses_the_plain_query_request`]: the downgrade that
//!   RFC 9101 section 10.5 exists to name.

#![cfg(all(feature = "jar", feature = "jwt-p256"))]
// Requires `jwt-p256`, the built-in ES256 backend, because every test below has to PRODUCE a
// signature. `jwt` alone carries the `Es256Signer`/`Es256Verifier` seam and no curve arithmetic at
// all, so in that build there is nothing here that could run.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use oauth_as::jwt::{AccessTokenClaims, Audience, EcdsaP256Key, JwtConfig};
use oauth_as::{
    AuthorizationError, AuthorizationRequest, AuthorizationServer, AuthorizationServerMetadata,
    Client, ClientAuth, ClientId, ErrorCode, GrantType, JarConfig, MemoryStorage,
    RegisteredRequestObjectKey, RequestObjectKeys, ScopeSet, ServerConfig,
};

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

struct Keys(RegisteredRequestObjectKey);

impl RequestObjectKeys for Keys {
    fn registered_key(&self, client_id: &ClientId) -> Option<RegisteredRequestObjectKey> {
        (client_id.as_str() == "app").then(|| self.0.clone())
    }
}

fn client() -> Client {
    Client {
        client_id: ClientId::new("app"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::AuthorizationCode],
        redirect_uris: vec!["https://app.example/cb".to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

fn config(jar: Option<JarConfig>) -> ServerConfig {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.jar = jar.map(Box::new);
    cfg
}

/// The client's registered key, taken from an RFC 7517 JWK exactly as a host would read one out of
/// its registration table. The key happens to be generated here because this test also needs to be
/// able to SIGN with it (as an issuer, further down); a host would only ever hold the public half.
fn registered_key(key: &EcdsaP256Key) -> RegisteredRequestObjectKey {
    let jwk = key.public_jwk();
    RegisteredRequestObjectKey::es256_from_jwk_coordinates(Some(jwk.kid.clone()), &jwk.x, &jwk.y)
        .expect("a JWK this crate emitted registers")
}

async fn server(key: &EcdsaP256Key, jar: Option<JarConfig>) -> AuthorizationServer<MemoryStorage> {
    let server = AuthorizationServer::new(config(jar), MemoryStorage::new())
        .with_request_object_keys(Box::new(Keys(registered_key(key))));
    server.register_client(client()).await.unwrap();
    server
}

fn query_request(challenge: &str) -> Vec<(&'static str, String)> {
    vec![
        ("response_type", "code".to_string()),
        ("client_id", "app".to_string()),
        ("redirect_uri", "https://app.example/cb".to_string()),
        ("scope", "read".to_string()),
        ("code_challenge", challenge.to_string()),
        ("code_challenge_method", "S256".to_string()),
    ]
}

/// ATTACK, RFC 9101 s10.5 with RFC 8725 s3.1. The whole object below is well formed and says
/// exactly what a legitimate request says; the only thing missing is the signature. A server that
/// reads the header's `alg` and believes it will accept an authorization request written by
/// whoever last touched the URL.
#[tokio::test]
async fn an_unsigned_request_object_is_refused() {
    let key = EcdsaP256Key::generate("client-key");
    let server = server(&key, Some(JarConfig::new())).await;

    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        format!(
            r#"{{"client_id":"app","response_type":"code","redirect_uri":"https://app.example/cb","scope":"read write","code_challenge":"{}","code_challenge_method":"S256"}}"#,
            oauth_as::pkce::code_challenge_s256(VERIFIER)
        )
        .as_bytes(),
    );
    let unsigned = format!("{header}.{payload}.");

    match server
        .validate_signed_authorization_request("app", &unsigned)
        .await
    {
        Err(AuthorizationError::Direct(error)) => {
            assert_eq!(error.error, ErrorCode::InvalidRequestObject)
        }
        other => panic!("alg=none must be refused outright, got {other:?}"),
    }
}

/// ATTACK, RFC 9101 s10.8 (cross-JWT confusion, applying RFC 8725 s3.11). Here the signature is
/// genuine: the token really was signed with the key the client registered. It simply was not
/// signed as an authorization request. If a request object is "any JWT that verifies", then every
/// JWT a client ever signs becomes an authorization request it never made.
#[tokio::test]
async fn an_access_token_is_not_a_request_object() {
    let key = EcdsaP256Key::generate("client-key");
    let server = server(&key, Some(JarConfig::new())).await;

    // An RFC 9068 access token, signed with that same key.
    let signer = JwtConfig::new(key.clone(), "https://rs.example");
    let token = signer
        .sign_access_token(&AccessTokenClaims {
            iss: "https://as.example".to_string(),
            exp: 4_000_000_000,
            aud: Audience::One("https://as.example".to_string()),
            sub: "app".to_string(),
            client_id: "app".to_string(),
            iat: 1_700_000_000,
            jti: "jti".to_string(),
            scope: Some("read".to_string()),
            #[cfg(feature = "rar")]
            authorization_details: Default::default(),
            // Not confirmation bound: this fixture is testing that an access token is
            // not a request object, and a binding would say nothing about that.
            //
            // The cfg MATCHES THE FIELD's, which is `any(dpop, mtls)` (see `AccessTokenClaims`),
            // and not `mtls` alone: `cnf` carries the RFC 9449 s6 DPoP thumbprint as well as the
            // RFC 8705 s3.1 certificate one. Gated on `mtls` alone, this file did not compile at
            // all in a `dpop`-without-`mtls` build.
            #[cfg(any(feature = "dpop", feature = "mtls"))]
            cnf: None,
        })
        .await
        .unwrap();

    match server
        .validate_signed_authorization_request("app", &token)
        .await
    {
        Err(AuthorizationError::Direct(error)) => {
            assert_eq!(error.error, ErrorCode::InvalidRequestObject)
        }
        other => panic!("an at+jwt must not be usable as a request object, got {other:?}"),
    }
}

/// ATTACK, RFC 9101 s10.5. A deployment that requires signed request objects is defending against
/// an attacker simply not sending one; if the plain query request still works, the requirement is
/// decoration.
#[tokio::test]
async fn requiring_a_signed_request_object_refuses_the_plain_query_request() {
    let key = EcdsaP256Key::generate("client-key");
    let server = server(
        &key,
        Some(JarConfig {
            require_signed_request_object: true,
        }),
    )
    .await;

    let challenge = oauth_as::pkce::code_challenge_s256(VERIFIER);
    let pairs = query_request(&challenge);
    let request = AuthorizationRequest::from_pairs(pairs.iter().map(|(k, v)| (*k, v.as_str())));

    match server.validate_authorization_request(&request).await {
        Err(AuthorizationError::Direct(error)) => {
            assert_eq!(error.error, ErrorCode::InvalidRequest)
        }
        other => panic!("a plain request must be refused when signing is required: {other:?}"),
    }
}

/// With JAR switched off entirely, a `request` parameter gets the answer RFC 9101 s7 registers for
/// it rather than a parse attempt.
#[tokio::test]
async fn a_request_object_is_refused_outright_when_the_host_did_not_enable_jar() {
    let key = EcdsaP256Key::generate("client-key");
    let server = server(&key, None).await;

    match server
        .validate_signed_authorization_request("app", "a.b.c")
        .await
    {
        Err(AuthorizationError::Direct(error)) => {
            assert_eq!(error.error, ErrorCode::RequestNotSupported)
        }
        other => panic!("expected request_not_supported, got {other:?}"),
    }
}

/// RFC 9101 s4 and s9.2: what the server will verify, and whether it insists on it, are things a
/// client can only learn from the metadata document.
#[test]
fn metadata_states_the_algorithms_and_the_policy() {
    let off = AuthorizationServerMetadata::from_config(&config(None));
    assert_eq!(off.request_object_signing_alg_values_supported, None);
    assert_eq!(off.require_signed_request_object, None);

    let on = AuthorizationServerMetadata::from_config(&config(Some(JarConfig::new())));
    assert_eq!(
        on.request_object_signing_alg_values_supported.as_deref(),
        Some(&["ES256".to_string()][..])
    );
    assert_eq!(on.require_signed_request_object, Some(false));

    // `none` must never appear in the advertised list: advertising it invites the downgrade RFC
    // 9101 s10.5 describes, whatever the verification code does.
    let document = serde_json::to_value(&on).unwrap();
    assert_eq!(
        document["request_object_signing_alg_values_supported"],
        serde_json::json!(["ES256"])
    );
}
