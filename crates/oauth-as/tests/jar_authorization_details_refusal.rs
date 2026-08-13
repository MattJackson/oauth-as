// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A SIGNED `authorization_details` in a build that supports no authorization detail type must be
//! refused, not dropped.
//!
//! RFC 9396 section 5 makes refusal a MUST for an `authorization_details` the server will not
//! honour, and the reason is stated in this crate's own `rar` build: a client whose authorization
//! detail was silently dropped obtains a token it believes says something the token does not say.
//! A build WITHOUT `rar` supports no detail type at all, which is the strongest form of that
//! condition, and until this suite existed it was the build that ignored the parameter hardest:
//! the claim simply had no field to land in.
//!
//! A REQUEST OBJECT is the sharpest case of the general one. The client SIGNED these parameters,
//! and RFC 9101 section 6.3 requires the server to use the object's parameters "even if the same
//! parameter is provided in the query parameter" -- so a parameter dropped here is a parameter
//! dropped from the one form of request whose whole purpose is that it cannot be altered.
//!
//! The posture is the one this module already takes for a request object it cannot process at all
//! (`request_not_supported`): say so.

#![cfg(all(feature = "jar", feature = "jwt-p256", not(feature = "rar")))]
// `not(rar)` is the point: WITH the feature the parameter is honoured and this file has nothing to
// say. `jwt-p256` because every case here has to PRODUCE a client signature, and the `jwt` seam
// alone carries no curve arithmetic.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use oauth_as::jwt::{EcdsaP256Key, Es256Signer};
use oauth_as::{
    AuthorizationError, AuthorizationServer, Client, ClientAuth, ClientId, ErrorCode, GrantType,
    JarConfig, MemoryStorage, RegisteredRequestObjectKey, RequestObjectKeys, ScopeSet,
    ServerConfig,
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

fn registered_key(key: &EcdsaP256Key) -> RegisteredRequestObjectKey {
    let jwk = key.public_jwk();
    RegisteredRequestObjectKey::es256_from_jwk_coordinates(Some(jwk.kid.clone()), &jwk.x, &jwk.y)
        .expect("a JWK this crate emitted registers")
}

async fn server(key: &EcdsaP256Key) -> AuthorizationServer<MemoryStorage> {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.jar = Some(Box::new(JarConfig::new()));
    let server = AuthorizationServer::new(cfg, MemoryStorage::new())
        .with_request_object_keys(Box::new(Keys(registered_key(key))));
    server.register_client(client()).await.unwrap();
    server
}

/// A genuinely signed RFC 9101 request object over `claims`, as the client would mint one.
async fn signed_object(key: &EcdsaP256Key, claims: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(
        format!(
            r#"{{"alg":"ES256","typ":"oauth-authz-req+jwt","kid":"{}"}}"#,
            key.public_jwk().kid
        )
        .as_bytes(),
    );
    let payload = URL_SAFE_NO_PAD.encode(claims.as_bytes());
    let input = format!("{header}.{payload}");
    let signature = key.sign(input.as_bytes()).await.expect("sign");
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn claims(extra: &str) -> String {
    format!(
        r#"{{"client_id":"app","response_type":"code","redirect_uri":"https://app.example/cb","scope":"read","code_challenge":"{}","code_challenge_method":"S256","exp":{},"aud":"https://as.example"{extra}}}"#,
        oauth_as::pkce::code_challenge_s256(VERIFIER),
        now() + 120,
    )
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs()
}

/// RFC 9396 s5: the detail the client signed cannot be honoured by this build, so the request is
/// refused with the code registered for saying so. What must NOT happen is the request succeeding
/// as though the client had asked for a plain `read` and nothing else.
#[tokio::test]
async fn a_signed_authorization_details_is_refused_by_a_build_without_rar() {
    let key = EcdsaP256Key::generate("client-key");
    let server = server(&key).await;
    let object = signed_object(
        &key,
        &claims(
            r#","authorization_details":[{"type":"payment_initiation","instructedAmount":"100"}]"#,
        ),
    )
    .await;

    match server
        .validate_signed_authorization_request("app", &object)
        .await
    {
        Err(AuthorizationError::Direct(error)) => assert_eq!(
            error.error,
            ErrorCode::InvalidAuthorizationDetails,
            "a detail this build cannot honour must be refused with the RFC 9396 s10 code"
        ),
        other => {
            panic!("a signed authorization_details must not be silently dropped, got {other:?}")
        }
    }
}

/// The control. The SAME object without the claim is accepted, so the refusal above is about the
/// parameter and not about the fixture.
#[tokio::test]
async fn the_same_object_without_the_claim_is_accepted() {
    let key = EcdsaP256Key::generate("client-key");
    let server = server(&key).await;
    let object = signed_object(&key, &claims("")).await;

    server
        .validate_signed_authorization_request("app", &object)
        .await
        .expect("a request object carrying no authorization_details is an ordinary request");
}
