// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

use oauth_as::crypto::{CryptoError, CryptoProvider};
use oauth_as::{AuthorizationServer, MemoryStorage, ServerConfig};
use std::sync::Arc;

struct NoEntropy;
impl CryptoProvider for NoEntropy {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        selected().sha256(input)
    }
    fn hmac_sha256(&self, key: &[u8], msg: &[u8]) -> [u8; 32] {
        selected().hmac_sha256(key, msg)
    }
    fn ct_eq(&self, a: &[u8], b: &[u8]) -> bool {
        selected().ct_eq(a, b)
    }
    fn fill_random(&self, _: &mut [u8]) -> Result<(), CryptoError> {
        Err(CryptoError::EntropyUnavailable)
    }
}

#[tokio::test]
async fn unavailable_entropy_returns_server_error_without_issuing_artifacts() {
    use oauth_as::{Client, ClientAuth, ClientId, GrantType, ScopeSet};
    let server = AuthorizationServer::new_with_crypto(
        ServerConfig::new("https://as.example", "https://as.example/verify"),
        MemoryStorage::default(),
        Arc::new(NoEntropy),
    )
    .unwrap();
    let client = Client {
        client_id: ClientId::new("device"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::DeviceCode],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::default(),
        default_scopes: ScopeSet::default(),
        name: None,
        registration: None,
    };
    server.register_client(client).await.unwrap();
    let result = server
        .device_authorization(&ClientId::new("device"), None, None)
        .await;
    assert_eq!(result.unwrap_err().error, oauth_as::ErrorCode::ServerError);
}

#[test]
fn primitive_known_answers() {
    let p = selected();
    assert_eq!(
        oauth_as::pkce::code_challenge_s256_with_crypto(
            &p,
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        ),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    assert_eq!(
        p.hmac_sha256(&[0x0b; 20], b"Hi There"),
        [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7
        ]
    );
    assert!(p.ct_eq(b"same", b"same"));
    assert!(!p.ct_eq(b"same", b"samf"));
    assert!(!p.ct_eq(b"same", b"same\0"));
}

#[cfg(feature = "jwt-p256")]
#[test]
fn key_generation_propagates_entropy_failure() {
    assert!(oauth_as::EcdsaP256Key::try_generate_with_crypto("key", &NoEntropy).is_err());
}

fn selected() -> Arc<dyn CryptoProvider> {
    oauth_as::crypto::default_provider().unwrap()
}

#[cfg(all(feature = "fips", feature = "jwt"))]
#[test]
fn fips_refuses_ed25519_and_does_not_advertise_it() {
    use oauth_as::jwt::JwsAlg;
    let p = oauth_as::crypto::Fips;
    assert!(p.verifier(JwsAlg::EdDsa).is_none());
    assert!(matches!(
        p.signing_key(JwsAlg::EdDsa, "k", &[]),
        Err(CryptoError::UnsupportedAlgorithm("EdDSA"))
    ));
    let server = AuthorizationServer::new_with_crypto(
        ServerConfig::new("https://as.example", "https://as.example/verify"),
        MemoryStorage::default(),
        Arc::new(p),
    )
    .unwrap();
    let metadata = serde_json::to_value(server.metadata()).unwrap();
    for key in [
        "token_endpoint_auth_signing_alg_values_supported",
        "request_object_signing_alg_values_supported",
        "dpop_signing_alg_values_supported",
    ] {
        if let Some(values) = metadata[key].as_array() {
            assert!(!values.iter().any(|v| v.as_str() == Some("EdDSA")));
        }
    }
}
