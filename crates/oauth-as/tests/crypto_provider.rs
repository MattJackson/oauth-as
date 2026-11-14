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
            p.as_ref(),
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

#[cfg(feature = "jwt")]
#[path = "support/provider_vectors.rs"]
mod vectors;

#[test]
fn sha256_known_answer_and_random_fill() {
    let p = selected();
    assert_eq!(
        p.sha256(b"abc"),
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad
        ]
    );
    let mut a = [0; 32];
    let mut b = [0; 32];
    p.fill_random(&mut a).unwrap();
    p.fill_random(&mut b).unwrap();
    assert_ne!(a, b);
    assert!(p.ct_eq(b"", b""));
    // RFC 4231 case 6: key longer than the SHA-256 block, so key normalization is exercised.
    assert_eq!(
        p.hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        ),
        [
            0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5,
            0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f,
            0x0e, 0xe3, 0x7f, 0x54
        ]
    );
}

#[cfg(feature = "jwt")]
#[tokio::test]
async fn rsa_provider_known_answers_and_padding_separation() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
    use oauth_as::jwt::{Jwk, JwsAlg, JwsSigner};
    let p = selected();
    let jwk = Jwk::Rsa {
        n: vectors::N_B64URL.into(),
        e: vectors::E_B64URL.into(),
        kid: Some("ignored".into()),
    };
    assert_eq!(
        jwk.thumbprint_with_crypto(p.as_ref()),
        "IsUn6_e04MaShXFIISMp4kG62LWzMIPy_MvSA5pJgX8"
    );
    // A minimal default RustCrypto build need not contain RSA. The provider matrix enables it.
    if p.verifier(JwsAlg::Rs256).is_none() {
        return;
    }
    let der = vectors::rsa_pkcs8();
    for alg in [JwsAlg::Rs256, JwsAlg::Ps256] {
        let signer = p.signing_key(alg, "rfc", &der).unwrap();
        let sig = signer.sign(vectors::SIGNING_INPUT).await.unwrap();
        let v = p.verifier(alg).unwrap();
        assert!(v.verify(&jwk, vectors::SIGNING_INPUT, sig.as_bytes()));
        assert!(!v.verify(&jwk, b"tampered", sig.as_bytes()));
        assert!(!v.verify(&jwk, vectors::SIGNING_INPUT, &[]));
        let other = if alg == JwsAlg::Rs256 {
            JwsAlg::Ps256
        } else {
            JwsAlg::Rs256
        };
        assert!(!p
            .verifier(other)
            .unwrap()
            .verify(&jwk, vectors::SIGNING_INPUT, sig.as_bytes()));
        if alg == JwsAlg::Rs256 {
            assert_eq!(B64.encode(sig.as_bytes()), vectors::EXPECTED_SIG_B64URL);
        }
    }
}

#[cfg(feature = "jwt-rsa")]
#[test]
fn pss_signing_refuses_failed_entropy_before_issuing_a_signature() {
    let signer = oauth_as::Ps256Signer::from_pkcs8_der("rfc", &vectors::rsa_pkcs8()).unwrap();
    assert!(signer
        .sign_ps256_with_crypto(b"message", &NoEntropy)
        .is_err());
}

#[cfg(all(feature = "jwt", feature = "test-util"))]
#[tokio::test]
async fn es256_signer_passes_independent_contract() {
    use oauth_as::jwt::{Jwk, JwsAlg, JwsVerifier};
    let p = selected();
    if p.verifier(JwsAlg::Es256).is_none() {
        return;
    }
    let mut der = vec![
        0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25,
        0x02, 0x01, 0x01, 0x04, 0x20,
    ];
    der.extend_from_slice(&[1; 32]);
    let signer = p.signing_key(JwsAlg::Es256, "test", &der).unwrap();
    struct V(Arc<dyn CryptoProvider>);
    impl JwsVerifier for V {
        fn alg(&self) -> JwsAlg {
            JwsAlg::Es256
        }
        fn verify(&self, k: &Jwk, m: &[u8], s: &[u8]) -> bool {
            self.0.verifier(JwsAlg::Es256).unwrap().verify(k, m, s)
        }
    }
    let failures = oauth_as::signer_conformance::SignerConformance::new(signer, V(p))
        .run()
        .await;
    assert!(failures.is_empty(), "{failures:?}");
}

#[cfg(all(feature = "fips", feature = "jwt"))]
#[test]
fn fips_rejects_rsa_moduli_outside_approved_bit_lengths() {
    use aws_lc_rs::signature::{self, KeyPair};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
    use oauth_as::jwt::{Jwk, JwsAlg};
    let der = B64.decode(vectors::NONAPPROVED_RSA_DER).unwrap();
    let key = signature::RsaKeyPair::from_pkcs8(&der).unwrap();
    let public = key.public_key();
    let jwk = Jwk::Rsa {
        n: B64.encode(public.modulus().big_endian_without_leading_zero()),
        e: B64.encode(public.exponent().big_endian_without_leading_zero()),
        kid: None,
    };
    let mut signature = vec![0; key.public_modulus_len()];
    key.sign(
        &signature::RSA_PKCS1_SHA256,
        &aws_lc_rs::rand::SystemRandom::new(),
        b"nonapproved modulus",
        &mut signature,
    )
    .unwrap();
    assert!(!oauth_as::crypto::Fips
        .verifier(JwsAlg::Rs256)
        .unwrap()
        .verify(&jwk, b"nonapproved modulus", &signature));
    assert!(matches!(
        oauth_as::crypto::Fips.signing_key(JwsAlg::Rs256, "key", &der),
        Err(CryptoError::InvalidKey)
    ));
}

#[cfg(feature = "jwt")]
#[test]
fn explicit_provider_never_installs_builtin_verifiers() {
    use oauth_as::jwt::{Jwk, JwsAlg, JwsVerifier};
    struct AcceptEverything;
    impl JwsVerifier for AcceptEverything {
        fn alg(&self) -> JwsAlg {
            JwsAlg::Es256
        }
        fn verify(&self, _: &Jwk, _: &[u8], _: &[u8]) -> bool {
            true
        }
    }
    let provider = Arc::new(NoEntropy);
    assert!(oauth_as::crypto::verifiers(provider.clone())
        .installed()
        .next()
        .is_none());
    let server = AuthorizationServer::new_with_crypto(
        ServerConfig::new("https://as.example", "https://as.example/verify"),
        MemoryStorage::default(),
        provider,
    )
    .unwrap();
    let server = server.with_jws_verifier(Arc::new(AcceptEverything));
    let metadata = serde_json::to_value(server.metadata()).unwrap();
    for key in [
        "token_endpoint_auth_signing_alg_values_supported",
        "request_object_signing_alg_values_supported",
        "dpop_signing_alg_values_supported",
    ] {
        if let Some(values) = metadata[key].as_array() {
            assert!(!values.iter().any(|v| JwsAlg::ALL
                .iter()
                .any(|a| v.as_str() == Some(a.jose_name()))));
        }
    }
}

#[tokio::test]
async fn token_issuance_propagates_entropy_failure() {
    use oauth_as::{Client, ClientAuth, ClientId, GrantType, ScopeSet, TokenRequest};
    let server = AuthorizationServer::new_with_crypto(
        ServerConfig::new("https://as.example", "https://as.example/verify"),
        MemoryStorage::default(),
        Arc::new(NoEntropy),
    )
    .unwrap();
    server
        .register_client(Client {
            client_id: ClientId::new("service"),
            auth: ClientAuth::ConfidentialSecret {
                secret: "secret".into(),
            },
            grant_types: vec![GrantType::ClientCredentials],
            redirect_uris: vec![],
            allowed_scopes: ScopeSet::default(),
            default_scopes: ScopeSet::default(),
            name: None,
            registration: None,
        })
        .await
        .unwrap();
    let result = server
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("service"),
            client_secret: Some("secret".into()),
            scope: None,
        })
        .await;
    assert_eq!(result.unwrap_err().error, oauth_as::ErrorCode::ServerError);
}

#[cfg(feature = "jwt")]
#[tokio::test]
async fn ed25519_rfc8032_known_answer() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
    use oauth_as::jwt::{Jwk, JwsAlg, JwsSigner};
    let p = selected();
    let Some(verifier) = p.verifier(JwsAlg::EdDsa) else {
        return;
    };
    let hex = |s: &str| -> Vec<u8> {
        s.as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    };
    // RFC 8032 section 7.1 test 1. RFC 8410 PKCS#8 wrapping of the published seed.
    let mut der = hex("302e020100300506032b657004220420");
    der.extend(hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ));
    let public = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let expected = hex(concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ));
    let key =
        Jwk::from_json(&serde_json::json!({"kty":"OKP", "crv":"Ed25519", "x":B64.encode(public)}))
            .unwrap();
    // RustCrypto's DER codec is independently opt-in; verification needs only jwt-ed25519.
    if !cfg!(all(
        feature = "rustcrypto",
        not(feature = "jwt-ed25519-pkcs8")
    )) {
        let signer = p.signing_key(JwsAlg::EdDsa, "rfc", &der).unwrap();
        assert_eq!(signer.sign(b"").await.unwrap().as_bytes(), expected);
    }
    assert!(verifier.verify(&key, b"", &expected));
    assert!(!verifier.verify(&key, b"changed", &expected));
    assert!(!verifier.verify(&key, b"", &[0; 64]));
}

#[cfg(feature = "jwt")]
#[test]
fn configured_signing_algorithm_must_be_supported_by_the_provider() {
    use oauth_as::jwt::{
        AccessTokenFormat, Jwk, JwsAlg, JwsSignature, JwsSigner, JwtConfig, SignerError,
    };
    struct Key;
    impl JwsSigner for Key {
        fn alg(&self) -> JwsAlg {
            JwsAlg::Rs256
        }
        fn public_jwk(&self) -> Jwk {
            Jwk::Rsa {
                n: vectors::N_B64URL.into(),
                e: vectors::E_B64URL.into(),
                kid: Some("key".into()),
            }
        }
        async fn sign(&self, _: &[u8]) -> Result<JwsSignature, SignerError> {
            Err(SignerError::new("must never be called"))
        }
    }
    let mut config = ServerConfig::new("https://as.example", "https://as.example/verify");
    config.access_token_format = AccessTokenFormat::Jwt(Box::new(JwtConfig::new(Key, "resource")));
    assert!(matches!(
        AuthorizationServer::new_with_crypto(config, MemoryStorage::default(), Arc::new(NoEntropy)),
        Err(CryptoError::UnsupportedAlgorithm("RS256"))
    ));
}

#[cfg(feature = "mtls")]
#[test]
fn certificate_helpers_use_the_selected_provider() {
    use oauth_as::mtls::{CertificateThumbprint, RegisteredCertificates};
    let p = selected();
    let thumbprint = CertificateThumbprint::from_der_with_crypto(p.as_ref(), b"abc");
    assert_eq!(thumbprint.as_bytes(), &p.sha256(b"abc"));
    let expected = RegisteredCertificates::from_thumbprints(vec![thumbprint]).unwrap();
    assert_eq!(
        RegisteredCertificates::from_der_certificates_with_crypto(p.as_ref(), [b"abc".as_slice()])
            .unwrap(),
        expected
    );
    assert_eq!(
        RegisteredCertificates::from_jwks_with_crypto(p.as_ref(), r#"{"keys":[{"x5c":["YWJj"]}]}"#)
            .unwrap(),
        expected
    );
}

#[cfg(feature = "jwt")]
#[test]
fn rfc7638_section_3_1_thumbprint() {
    let key = oauth_as::jwt::Jwk::Rsa {
        n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".into(),
        e: "AQAB".into(), kid: Some("2011-04-29".into()),
    };
    assert_eq!(
        key.thumbprint_with_crypto(selected().as_ref()),
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
}
