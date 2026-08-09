// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! What the probe actually CALLS, plane by plane.
//!
//! Read this alongside the report: a row of `scripts/size-report.sh` means "what a host pays for
//! the code below", so the code below is the definition of every number in it. Nothing here is a
//! reference to a type; every plane drives the surface to a result and feeds it into the
//! accumulator, because `lto = "fat"` deletes anything else and would report the feature at zero.

use std::sync::Arc;

use oauth_as::client::{Client, ClientAuth, ClientId};
use oauth_as::grant::GrantType;
use oauth_as::metadata::AuthorizationServerMetadata;
use oauth_as::scope::ScopeSet;
use oauth_as::server::{AuthorizationServer, ServerConfig, TokenRequest};
use oauth_as::store::{MemoryStorage, Storage};

use crate::blockon::block_on;

pub const ISSUER: &str = "https://as.probe.example";
const PUBLIC_CLIENT: &str = "probe-public";
const CONFIDENTIAL_CLIENT: &str = "probe-confidential";
const CONFIDENTIAL_SECRET: &str = "probe-secret-0123456789abcdefghij";
const REDIRECT_URI: &str = "https://client.probe.example/cb";
// RFC 7636 appendix B's verifier, so the challenge is one the RFC itself publishes.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// Build a config with every endpoint named explicitly, so the HTTP plane knows what paths to
/// dispatch to without re-deriving the defaults.
pub fn config() -> ServerConfig {
    let mut config = ServerConfig::new(ISSUER, format!("{ISSUER}/device"));
    config.authorization_endpoint = Some(format!("{ISSUER}/authorize"));
    config.token_endpoint = Some(format!("{ISSUER}/token"));
    config.device_authorization_endpoint = Some(format!("{ISSUER}/device_authorization"));
    config.introspection_endpoint = Some(format!("{ISSUER}/introspect"));
    config.revocation_endpoint = Some(format!("{ISSUER}/revoke"));
    config.scopes_supported = Some(vec!["read".to_string(), "write".to_string()]);
    // RFC 7591 is the only capability in this crate with no cargo feature of its own, so it is
    // ALWAYS on the core plane. The report's per-feature attribution is what says whether that is
    // costing anything worth a feature gate.
    config.registration = Some(Box::new(oauth_as::registration::RegistrationConfig::new()));
    #[cfg(feature = "f-par")]
    {
        config.par = Some(Box::new(oauth_as::par::ParConfig::new()));
    }
    #[cfg(feature = "f-jar")]
    {
        config.jar = Some(Box::new(oauth_as::par::JarConfig::new()));
    }
    #[cfg(feature = "f-rar")]
    {
        config.authorization_details_types_supported = Some(vec!["probe_payment".to_string()]);
    }
    #[cfg(feature = "f-jwt")]
    {
        config.jwks_uri = Some(format!("{ISSUER}/jwks"));
        config.access_token_format = jwt_format();
    }
    config
}

/// A host-supplied `Es256Signer` that does no arithmetic, for the `f-jwt` row.
///
/// The whole point of the `jwt` row after the seam landed is to measure what a host with its OWN
/// backend pays: the JWS serialization, the JWKS, the claim set, and NO curve. A probe that
/// reached for `EcdsaP256Key` here would link p256 into that row and the number would be a lie.
#[cfg(all(feature = "f-jwt", not(feature = "f-jwt-p256")))]
struct ProbeSigner;

#[cfg(all(feature = "f-jwt", not(feature = "f-jwt-p256")))]
impl oauth_as::jwt::Es256Signer for ProbeSigner {
    fn sign(
        &self,
        _signing_input: &[u8],
    ) -> impl std::future::Future<Output = Result<[u8; 64], oauth_as::jwt::SignerError>> + Send
    {
        async { Ok([0x5Au8; 64]) }
    }

    fn public_jwk(&self) -> oauth_as::jwt::Jwk {
        // 43 base64url characters decode to exactly the 32 bytes RFC 7518 s6.2.1.2 fixes a P-256
        // coordinate at. All-zero rather than a real point, and spelled out rather than encoded,
        // so the probe takes no `base64` dependency of its own: nothing here verifies anything,
        // and a coordinate that is well FORMED is all the JWKS serialization path reads.
        oauth_as::jwt::Jwk {
            kty: "EC",
            crv: "P-256",
            x: "A".repeat(43),
            y: "A".repeat(43),
            kid: "probe-host-1".to_string(),
            use_: "sig",
            alg: "ES256",
        }
    }
}

#[cfg(feature = "f-jwt")]
fn jwt_format() -> oauth_as::jwt::AccessTokenFormat {
    use oauth_as::jwt::{AccessTokenFormat, JwtConfig};
    // Generated rather than hard coded, where there is a key at all: a key material constant in a
    // repository is a habit worth not forming even in a measurement tool, and generation is on the
    // `jwt-p256` cost anyway.
    #[cfg(feature = "f-jwt-p256")]
    let signer = oauth_as::jwt::EcdsaP256Key::generate("probe-es256-1");
    #[cfg(not(feature = "f-jwt-p256"))]
    let signer = ProbeSigner;
    AccessTokenFormat::Jwt(Box::new(
        JwtConfig::new(signer, "https://rs.probe.example").with_jwks_uri(format!("{ISSUER}/jwks")),
    ))
}

/// Allow every registration. A probe, not a policy: see `RegistrationPolicy`'s own docs on why a
/// real host must not write this.
struct AllowAll;

impl oauth_as::registration::RegistrationPolicy for AllowAll {
    fn authorize(
        &self,
        _attempt: &oauth_as::registration::RegistrationAttempt<'_>,
    ) -> oauth_as::registration::RegistrationDecision {
        oauth_as::registration::RegistrationDecision::Allow
    }
}

pub fn server() -> Arc<AuthorizationServer<MemoryStorage>> {
    let server = AuthorizationServer::new(config(), MemoryStorage::new())
        .with_registration_policy(Box::new(AllowAll));
    let server = Arc::new(server);
    block_on(seed(&server));
    server
}

async fn seed(server: &AuthorizationServer<MemoryStorage>) {
    let scopes = ScopeSet::from_tokens(["read", "write"]).expect("static scopes are valid");
    server
        .register_client(Client {
            client_id: ClientId::new(PUBLIC_CLIENT),
            auth: ClientAuth::Public,
            grant_types: vec![
                GrantType::AuthorizationCode,
                GrantType::DeviceCode,
                GrantType::RefreshToken,
            ],
            redirect_uris: vec![REDIRECT_URI.to_string()],
            allowed_scopes: scopes.clone(),
            default_scopes: scopes.clone(),
            name: Some("probe public".to_string()),
            registration: None,
        })
        .await
        .expect("memory storage does not fail");
    server
        .register_client(Client {
            client_id: ClientId::new(CONFIDENTIAL_CLIENT),
            auth: ClientAuth::ConfidentialSecret {
                secret: CONFIDENTIAL_SECRET.to_string(),
            },
            grant_types: vec![
                GrantType::AuthorizationCode,
                GrantType::ClientCredentials,
                GrantType::DeviceCode,
                GrantType::RefreshToken,
            ],
            redirect_uris: vec![REDIRECT_URI.to_string()],
            allowed_scopes: scopes.clone(),
            default_scopes: scopes,
            name: Some("probe confidential".to_string()),
            registration: None,
        })
        .await
        .expect("memory storage does not fail");
}

pub fn run() -> u64 {
    // `mut` is unused when no optional feature is on, which is exactly the default row of the
    // report, so the lint is silenced rather than the structure contorted around it.
    #[allow(unused_mut)]
    let mut acc = core_plane();

    #[cfg(feature = "f-http")]
    {
        acc = acc.wrapping_add(crate::exercise_http::plane());
    }
    #[cfg(feature = "f-jwt")]
    {
        acc = acc.wrapping_add(crate::exercise_jwt::plane());
    }
    #[cfg(feature = "f-mtls")]
    {
        acc = acc.wrapping_add(crate::exercise_features::mtls());
    }
    #[cfg(feature = "f-par")]
    {
        acc = acc.wrapping_add(crate::exercise_features::par());
    }
    #[cfg(feature = "f-jar")]
    {
        acc = acc.wrapping_add(crate::exercise_features::jar());
    }
    #[cfg(feature = "f-rar")]
    {
        acc = acc.wrapping_add(crate::exercise_features::rar());
    }
    #[cfg(feature = "f-dpop")]
    {
        acc = acc.wrapping_add(crate::exercise_features::dpop());
    }
    #[cfg(feature = "f-client_assertion")]
    {
        acc = acc.wrapping_add(crate::exercise_features::client_assertion());
    }
    #[cfg(feature = "f-consent")]
    {
        acc = acc.wrapping_add(crate::exercise_features::consent());
    }
    #[cfg(feature = "f-token-exchange")]
    {
        acc = acc.wrapping_add(crate::exercise_features::token_exchange());
    }
    #[cfg(feature = "f-resource-metadata")]
    {
        acc = acc.wrapping_add(crate::exercise_features::resource_metadata());
    }
    #[cfg(feature = "f-test-util")]
    {
        acc = acc.wrapping_add(crate::exercise_features::test_util());
    }

    std::hint::black_box(acc)
}

/// Everything a default (feature-free) build can do, driven end to end: the four grants, the
/// authorization endpoint, introspection, revocation, RFC 8414 metadata, RFC 7591 registration,
/// PKCE and scopes.
fn core_plane() -> u64 {
    let server = server();
    let mut acc: u64 = 0;

    // RFC 8414: the metadata document, derived and serialized, which is what a host publishes.
    let metadata = AuthorizationServerMetadata::from_config(server.config());
    acc = acc.wrapping_add(
        serde_json::to_string(&metadata)
            .map(|s| s.len() as u64)
            .unwrap_or(0),
    );

    // RFC 7636: the PKCE primitives, against the appendix B vector.
    acc = acc.wrapping_add(oauth_as::pkce::code_challenge_s256(VERIFIER).len() as u64);
    acc = acc.wrapping_add(u64::from(oauth_as::pkce::verify_s256(VERIFIER, CHALLENGE)));
    acc = acc.wrapping_add(u64::from(oauth_as::pkce::verifier_is_valid(VERIFIER)));
    acc = acc.wrapping_add(
        ScopeSet::parse("read write")
            .map(|s| s.len() as u64)
            .unwrap_or(0),
    );

    block_on(async {
        let confidential = ClientId::new(CONFIDENTIAL_CLIENT);
        let public = ClientId::new(PUBLIC_CLIENT);

        // RFC 8628: authorize, approve, redeem.
        let device = server
            .device_authorization(&public, None, None)
            .await
            .expect("seeded client may use the device grant");
        acc = acc.wrapping_add(device.user_code.len() as u64);
        // The DENIAL path first, on a second grant, so the error arm is linked too.
        let denied = server
            .device_authorization(&public, None, None)
            .await
            .expect("seeded client may use the device grant");
        let _ = server.deny_device(&denied.user_code).await;
        let _ = server
            .token(TokenRequest::DeviceCode {
                client_id: public.clone(),
                client_secret: None,
                device_code: denied.device_code.clone(),
            })
            .await;
        server
            .approve_device(&device.user_code, "probe-subject")
            .await
            .expect("a pending grant may be approved");
        let issued = server
            .token(TokenRequest::DeviceCode {
                client_id: public.clone(),
                client_secret: None,
                device_code: device.device_code,
            })
            .await
            .expect("an approved grant redeems");
        acc = acc.wrapping_add(issued.access_token.len() as u64);

        // RFC 6749 section 6: rotation.
        if let Some(refresh) = issued.refresh_token.clone() {
            let rotated = server
                .token(TokenRequest::RefreshToken {
                    client_id: public.clone(),
                    client_secret: None,
                    refresh_token: refresh.clone(),
                    scope: None,
                })
                .await
                .expect("a fresh refresh token rotates");
            acc = acc.wrapping_add(rotated.access_token.len() as u64);
            // REUSE, which is the detection path and a different arm of the state machine.
            let _ = server
                .token(TokenRequest::RefreshToken {
                    client_id: public.clone(),
                    client_secret: None,
                    refresh_token: refresh,
                    scope: None,
                })
                .await;
        }

        // RFC 6749 section 4.4.
        let cc = server
            .token(TokenRequest::ClientCredentials {
                client_id: confidential.clone(),
                client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
                scope: None,
            })
            .await
            .expect("a confidential client may use client_credentials");
        acc = acc.wrapping_add(cc.access_token.len() as u64);

        // RFC 6749 section 4.1: the authorization endpoint, then the code redemption.
        let request = oauth_as::authorization::AuthorizationRequest::from_pairs([
            ("response_type", "code"),
            ("client_id", PUBLIC_CLIENT),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "read"),
            ("state", "probe-state"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ]);
        match server.validate_authorization_request(&request).await {
            Ok(validated) => {
                let approval = oauth_as::server::UserApproval::granted(&validated, "probe-subject");
                if let Ok(response) = server.issue_authorization_code(approval).await {
                    acc = acc.wrapping_add(response.code.len() as u64);
                    if let Ok(redeemed) = server
                        .token(TokenRequest::AuthorizationCode {
                            client_id: public.clone(),
                            client_secret: None,
                            code: response.code.clone(),
                            redirect_uri: Some(REDIRECT_URI.to_string()),
                            code_verifier: Some(VERIFIER.to_string()),
                        })
                        .await
                    {
                        acc = acc.wrapping_add(redeemed.access_token.len() as u64);
                    }
                    // REPLAY: the second redemption is the revocation cascade, a distinct arm.
                    let _ = server
                        .token(TokenRequest::AuthorizationCode {
                            client_id: public.clone(),
                            client_secret: None,
                            code: response.code,
                            redirect_uri: Some(REDIRECT_URI.to_string()),
                            code_verifier: Some(VERIFIER.to_string()),
                        })
                        .await;
                }
            }
            Err(error) => acc = acc.wrapping_add(u64::from(error.http_status())),
        }
        // The DIRECT-error arm (an unregistered redirect URI, which must not redirect).
        let bad = oauth_as::authorization::AuthorizationRequest::from_pairs([
            ("response_type", "code"),
            ("client_id", PUBLIC_CLIENT),
            ("redirect_uri", "https://attacker.example/cb"),
        ]);
        if let Err(error) = server.validate_authorization_request(&bad).await {
            acc = acc.wrapping_add(u64::from(error.http_status()));
        }

        // RFC 7662 and RFC 7009, both arms: a live token and an unknown one.
        if let Ok(response) = server
            .introspection_response(
                &confidential,
                Some(CONFIDENTIAL_SECRET),
                cc.access_token.as_str(),
            )
            .await
        {
            acc = acc.wrapping_add(u64::from(response.active));
        }
        if let Ok(response) = server
            .introspection_response(&confidential, Some(CONFIDENTIAL_SECRET), "not-a-token")
            .await
        {
            acc = acc.wrapping_add(u64::from(response.active));
        }
        let _ = server
            .revoke(
                &confidential,
                Some(CONFIDENTIAL_SECRET),
                cc.access_token.as_str(),
                None,
            )
            .await;

        // RFC 7591 / RFC 7592: create, read, update, delete.
        let metadata = oauth_as::registration::ClientMetadata {
            redirect_uris: vec![REDIRECT_URI.to_string()],
            token_endpoint_auth_method: Some("client_secret_basic".to_string()),
            grant_types: Some(vec!["authorization_code".to_string()]),
            response_types: Some(vec!["code".to_string()]),
            client_name: Some("probe dynamic".to_string()),
            scope: None,
            software_statement: None,
        };
        if let Ok(info) = server
            .register_dynamic_client(&metadata, Some("probe-iat"))
            .await
        {
            acc = acc.wrapping_add(info.client_id.as_str().len() as u64);
            if let Some(token) = info.registration_access_token.clone() {
                let id = ClientId::new(info.client_id.as_str());
                if let Ok(read) = server.read_registration(&id, &token).await {
                    acc = acc.wrapping_add(read.client_id.as_str().len() as u64);
                }
                let _ = server.update_registration(&id, &token, &metadata).await;
                let _ = server.delete_registration(&id, &token).await;
            }
        }

        // The expiry sweep, which is the only thing that reclaims anything.
        if let Ok(swept) = server
            .store()
            .sweep_expired(std::time::SystemTime::now())
            .await
        {
            acc = acc.wrapping_add(swept);
        }
    });

    std::hint::black_box(acc)
}
