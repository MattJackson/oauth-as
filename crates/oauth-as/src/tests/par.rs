// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for RFC 9126 PAR and RFC 9101 JAR, at the level of the module's own internals.
//!
//! The JAR half lives here rather than in `tests/jar.rs` for one concrete reason: producing a
//! signed request object means acting as the CLIENT, and signing is something an authorization
//! server has no public API for and should not grow one for. Inside the library's own test build
//! the `p256` dependency the `jar` feature already pulls in is reachable, so these tests can mint
//! genuine ES256 signatures (and genuinely wrong ones) without adding a dependency to the crate.
//!
//! The attacks reproduced here are the JWS ones, and they are the reason RFC 9101 section 6.2
//! points at RFC 8725 sections 3.1 and 3.2:
//!
//! - [`an_object_signed_by_a_key_the_client_did_not_register_is_refused`]
//! - [`an_object_whose_header_claims_alg_none_is_refused`]
//! - [`an_object_whose_header_claims_an_algorithm_the_client_did_not_register_is_refused`]
//! - [`a_payload_edited_after_signing_is_refused`]
//! - [`an_object_naming_another_client_is_refused`]
//! - [`a_jwt_minted_for_another_purpose_is_not_a_request_object`]

use super::*;

// ------------------------------------------------------------------------------- RFC 9126

#[cfg(feature = "par")]
#[test]
fn the_par_endpoint_defaults_under_the_issuer_and_honours_an_override() {
    let default = ParConfig::new();
    assert_eq!(
        default.endpoint("https://as.example"),
        "https://as.example/par"
    );
    // A trailing slash on the issuer must not become a double slash in the advertised URL.
    assert_eq!(
        default.endpoint("https://as.example/"),
        "https://as.example/par"
    );

    let overridden = ParConfig {
        pushed_authorization_request_endpoint: Some("https://edge.example/push".to_string()),
        ..ParConfig::new()
    };
    assert_eq!(
        overridden.endpoint("https://as.example"),
        "https://edge.example/push"
    );
}

/// RFC 9126 s7.1 makes a live `request_uri` a capability URL: guessing one is impersonating the
/// client that pushed it. A host's `tracing::debug!(?record)` must therefore not print it, the
/// same rule `AuthorizationCodeRecord` follows for the code.
#[cfg(feature = "par")]
#[test]
fn a_stored_handle_is_not_printed_by_debug() {
    let record = PushedAuthorizationRequest {
        request_uri: "urn:ietf:params:oauth:request_uri:5ecre7".to_string(),
        client_id: ClientId::new("app"),
        response_type: Some("code".to_string()),
        redirect_uri: Some("https://app.example/cb".to_string()),
        scope: Some("read".to_string()),
        state: Some("opaque".to_string()),
        code_challenge: Some("challenge".to_string()),
        code_challenge_method: Some("S256".to_string()),
        #[cfg(feature = "rar")]
        authorization_details: None,
        #[cfg(feature = "consent")]
        acr_values: None,
        #[cfg(feature = "consent")]
        max_age: None,
        resource: vec!["https://rs.example".to_string()],
        expires_at: std::time::SystemTime::UNIX_EPOCH,
    };
    let rendered = format!("{record:?}");
    assert!(
        !rendered.contains("5ecre7"),
        "the request_uri must not reach a debug format: {rendered}"
    );
    // Everything that is NOT a credential stays visible, or the type stops being debuggable.
    assert!(rendered.contains("app"));
    assert!(rendered.contains("https://app.example/cb"));
}

/// The stored record and the authorization request it resolves to must agree parameter for
/// parameter: this is the join between the two endpoints, and a dropped field here is a parameter
/// that silently stops applying between the push and the redirect.
#[cfg(feature = "par")]
#[test]
fn a_stored_handle_resolves_to_exactly_the_parameters_that_were_pushed() {
    #[cfg(feature = "rar")]
    const RAR_DETAILS: &str = r#"[{"type":"payment_initiation","actions":["initiate"],"locations":["https://rs.example"]}]"#;

    let record = PushedAuthorizationRequest {
        request_uri: "urn:ietf:params:oauth:request_uri:abc".to_string(),
        client_id: ClientId::new("app"),
        response_type: Some("code".to_string()),
        redirect_uri: Some("https://app.example/cb".to_string()),
        scope: Some("read write".to_string()),
        state: Some("opaque".to_string()),
        code_challenge: Some("challenge".to_string()),
        code_challenge_method: Some("S256".to_string()),
        #[cfg(feature = "rar")]
        authorization_details: Some(RAR_DETAILS.to_string()),
        #[cfg(feature = "consent")]
        acr_values: Some("urn:acr:phr urn:acr:mfa".to_string()),
        #[cfg(feature = "consent")]
        max_age: Some("0".to_string()),
        resource: vec![
            "https://rs.example/a".to_string(),
            "https://rs.example/b".to_string(),
        ],
        expires_at: std::time::SystemTime::UNIX_EPOCH,
    };
    let request = record.as_request();
    assert_eq!(request.response_type.as_deref(), Some("code"));
    assert_eq!(request.client_id.as_deref(), Some("app"));
    assert_eq!(
        request.redirect_uri.as_deref(),
        Some("https://app.example/cb")
    );
    assert_eq!(request.scope.as_deref(), Some("read write"));
    assert_eq!(request.state.as_deref(), Some("opaque"));
    assert_eq!(request.code_challenge.as_deref(), Some("challenge"));
    assert_eq!(request.code_challenge_method.as_deref(), Some("S256"));
    assert_eq!(
        request.resource,
        vec![
            "https://rs.example/a".to_string(),
            "https://rs.example/b".to_string()
        ],
        "RFC 8707 s2 indicators are per-request, so both the count and the values have to survive"
    );
    // RFC 9396 s3: `authorization_details` is the request parameter that says WHAT the token may
    // do, so dropping it across the join downgrades a fine-grained request to whatever `scope`
    // alone means. This crate has already had RAR details silently dropped on one feature-gated
    // path, which is why it is asserted here rather than assumed to ride along.
    #[cfg(feature = "rar")]
    assert_eq!(
        request.authorization_details.as_deref(),
        Some(RAR_DETAILS),
        "the pushed authorization_details did not survive to the request the handle resolves to"
    );
    // RFC 9470 s4. These two are the join's whole reason for existing as a test: they were absent
    // from this record entirely, so every pushed request resolved to a request asking for no
    // step-up, whatever the client had pushed.
    #[cfg(feature = "consent")]
    {
        assert_eq!(
            request.acr_values.as_deref(),
            Some("urn:acr:phr urn:acr:mfa")
        );
        assert_eq!(request.max_age.as_deref(), Some("0"));
    }
}

// ------------------------------------------------------------------------------- RFC 9101

#[cfg(feature = "jar")]
// `jwt-p256`, the built-in ES256 backend: every test in here has to SIGN a request object, and
// after the `Es256Signer` seam landed `jar` implies the verification surface, not a curve.
#[cfg(feature = "jwt-p256")]
mod jar {
    use super::*;

    use crate::client::{Client, ClientAuth};
    use crate::grant::GrantType;
    use crate::scope::ScopeSet;
    use crate::server::{AuthorizationServer, ServerConfig};
    use crate::store::MemoryStorage;

    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::SigningKey;
    use serde_json::json;

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    /// A key source that answers for exactly one client, which is what a real host's registration
    /// table amounts to from this trait's point of view.
    struct OneClientsKey {
        client_id: ClientId,
        key: RegisteredRequestObjectKey,
    }

    impl RequestObjectKeys for OneClientsKey {
        fn registered_key(&self, client_id: &ClientId) -> Option<RegisteredRequestObjectKey> {
            if client_id == &self.client_id {
                Some(self.key.clone())
            } else {
                None
            }
        }
    }

    fn registered(key: &SigningKey, kid: Option<&str>) -> RegisteredRequestObjectKey {
        let point = key.verifying_key().to_encoded_point(false);
        RegisteredRequestObjectKey::es256_from_sec1(kid.map(str::to_string), point.as_bytes())
            .expect("a freshly generated P-256 public key is a point on P-256")
    }

    fn signing_key(seed: u8) -> SigningKey {
        // Deterministic, so a failure is reproducible: a fixed nonzero scalar well inside the
        // curve order. Nothing here is a real credential.
        let mut scalar = [0u8; 32];
        scalar[31] = seed;
        SigningKey::from_slice(&scalar).expect("a small nonzero scalar is a valid P-256 key")
    }

    fn sign(header: serde_json::Value, payload: serde_json::Value, key: &SigningKey) -> String {
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{header}.{payload}");
        let signature: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    fn header() -> serde_json::Value {
        json!({"alg": "ES256", "typ": REQUEST_OBJECT_TYP, "kid": "client-key-1"})
    }

    fn claims() -> serde_json::Value {
        json!({
            "iss": "app",
            "aud": "https://as.example",
            "client_id": "app",
            "response_type": "code",
            "redirect_uri": "https://app.example/cb",
            "scope": "read",
            "state": "opaque-state",
            "code_challenge": crate::pkce::code_challenge_s256(VERIFIER),
            "code_challenge_method": "S256",
        })
    }

    async fn server(key: &SigningKey) -> AuthorizationServer<MemoryStorage> {
        let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
        cfg.jar = Some(Box::new(JarConfig::new()));
        let server = AuthorizationServer::new(cfg, MemoryStorage::new()).with_request_object_keys(
            Box::new(OneClientsKey {
                client_id: ClientId::new("app"),
                key: registered(key, Some("client-key-1")),
            }),
        );
        let client = Client {
            client_id: ClientId::new("app"),
            auth: ClientAuth::Public,
            grant_types: vec![GrantType::AuthorizationCode],
            redirect_uris: vec!["https://app.example/cb".to_string()],
            allowed_scopes: ScopeSet::parse("read write").unwrap(),
            default_scopes: ScopeSet::parse("read").unwrap(),
            name: None,
            registration: None,
        };
        server.register_client(client).await.unwrap();
        server
    }

    #[tokio::test]
    async fn a_signed_request_object_authorizes_and_its_parameters_are_the_ones_used() {
        let key = signing_key(7);
        let server = server(&key).await;
        let object = sign(header(), claims(), &key);

        let validated = server
            .validate_signed_authorization_request("app", &object)
            .await
            .expect("a correctly signed request object is accepted");
        assert_eq!(validated.client_id, ClientId::new("app"));
        assert_eq!(validated.redirect_uri, "https://app.example/cb");
        assert_eq!(validated.scope, ScopeSet::parse("read").unwrap());
        assert_eq!(validated.state.as_deref(), Some("opaque-state"));
        assert_eq!(
            validated.code_challenge,
            crate::pkce::code_challenge_s256(VERIFIER)
        );
    }

    /// ATTACK, RFC 9101 s6.2: "the signature MUST be validated using a key associated with the
    /// client". An attacker signs a request object of their own choosing with their own key and
    /// sends it as the victim client; if the server verifies against whatever key verifies, the
    /// signature has proved nothing at all.
    #[tokio::test]
    async fn an_object_signed_by_a_key_the_client_did_not_register_is_refused() {
        let registered_key = signing_key(7);
        let attacker_key = signing_key(11);
        let server = server(&registered_key).await;

        let mut forged = claims();
        forged["redirect_uri"] = json!("https://app.example/cb");
        forged["scope"] = json!("read write");
        let object = sign(header(), forged, &attacker_key);

        let error = server
            .verified_request_object(&ClientId::new("app"), &object)
            .expect_err("a signature by an unregistered key must not verify");
        assert_eq!(error.error, ErrorCode::InvalidRequestObject);
    }

    /// ATTACK, RFC 9101 s10.5 and RFC 8725 s3.1: the classic. Strip the signature, set the header
    /// to `alg: none`, and see whether the server reads the claims anyway. Note that the object
    /// below is otherwise perfectly well formed, and would be accepted if the header were trusted.
    #[tokio::test]
    async fn an_object_whose_header_claims_alg_none_is_refused() {
        let key = signing_key(7);
        let server = server(&key).await;

        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"alg": "none"})).unwrap());
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims()).unwrap());
        let unsigned = format!("{header}.{payload}.");

        let error = server
            .verified_request_object(&ClientId::new("app"), &unsigned)
            .expect_err("alg=none must never be accepted");
        assert_eq!(error.error, ErrorCode::InvalidRequestObject);
    }

    /// ATTACK, RFC 8725 s3.2 (algorithm confusion). The header names an algorithm the client did
    /// not register. Even with a signature attached, the server must refuse rather than switch
    /// algorithms on the token's say-so: the registered algorithm decides.
    #[tokio::test]
    async fn an_object_whose_header_claims_an_algorithm_the_client_did_not_register_is_refused() {
        let key = signing_key(7);
        let server = server(&key).await;

        // Signed genuinely with the registered ES256 key, but the header says HS256; a server that
        // took the header's word would try to verify the ES256 signature as a MAC (and a server
        // that took the header's word AND used the public key as the MAC secret is the published
        // attack).
        let object = sign(
            json!({"alg": "HS256", "kid": "client-key-1"}),
            claims(),
            &key,
        );

        let error = server
            .verified_request_object(&ClientId::new("app"), &object)
            .expect_err("the registered algorithm decides, not the header");
        assert_eq!(error.error, ErrorCode::InvalidRequestObject);
        assert!(error
            .error_description
            .as_deref()
            .unwrap_or_default()
            .contains("alg"));
    }

    /// ATTACK: the request object is signed legitimately and then edited in flight, which is the
    /// exact thing JAR exists to detect, since the object travels through the browser.
    #[tokio::test]
    async fn a_payload_edited_after_signing_is_refused() {
        let key = signing_key(7);
        let server = server(&key).await;
        let object = sign(header(), claims(), &key);

        let mut parts = object.split('.');
        let header_b64 = parts.next().unwrap();
        let signature_b64 = parts.clone().nth(1).unwrap();
        let mut tampered_claims = claims();
        tampered_claims["scope"] = json!("read write");
        let tampered_payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&tampered_claims).unwrap());
        let tampered = format!("{header_b64}.{tampered_payload}.{signature_b64}");

        let error = server
            .verified_request_object(&ClientId::new("app"), &tampered)
            .expect_err("an edited payload must not verify");
        assert_eq!(error.error, ErrorCode::InvalidRequestObject);
    }

    /// ATTACK, RFC 9101 s6.3: the `client_id` claim and the `client_id` the request arrived as
    /// MUST be identical. Without the check, a client that legitimately holds a signing key can
    /// mint a request object naming a victim client and have it accepted under the victim's
    /// registration (its redirect URIs, its scopes).
    #[tokio::test]
    async fn an_object_naming_another_client_is_refused() {
        let key = signing_key(7);
        let server = server(&key).await;

        let mut impersonation = claims();
        impersonation["client_id"] = json!("victim");
        let object = sign(header(), impersonation, &key);

        let error = server
            .verified_request_object(&ClientId::new("app"), &object)
            .expect_err("the two client ids must match");
        assert_eq!(error.error, ErrorCode::InvalidRequestObject);

        // And the mirror image: presented AS the victim, it does not even reach a key.
        let object = sign(header(), claims(), &key);
        let error = server
            .verified_request_object(&ClientId::new("victim"), &object)
            .expect_err("a client with no registered key cannot use JAR");
        assert_eq!(error.error, ErrorCode::InvalidRequestObject);
    }

    /// ATTACK, RFC 9101 s10.8 (cross-JWT confusion), applying RFC 8725 s3.11. A JWT the client
    /// signed for some other purpose must not be replayable as an authorization request.
    #[tokio::test]
    async fn a_jwt_minted_for_another_purpose_is_not_a_request_object() {
        let key = signing_key(7);
        let server = server(&key).await;

        // Same key, same claims, but typed as something else: an RFC 7523 client assertion, say.
        let object = sign(
            json!({"alg": "ES256", "typ": "client-authentication+jwt", "kid": "client-key-1"}),
            claims(),
            &key,
        );
        let error = server
            .verified_request_object(&ClientId::new("app"), &object)
            .expect_err("a typ that names another kind of JWT must be refused");
        assert_eq!(error.error, ErrorCode::InvalidRequestObject);
    }

    /// RFC 9101 s6.2: a `kid` that is present must identify the client's key. A `kid` naming
    /// somebody else's key, with a signature that happens to verify under the registered one, is a
    /// request the server should not have to reason about.
    #[tokio::test]
    async fn a_kid_that_names_another_key_is_refused() {
        let key = signing_key(7);
        let server = server(&key).await;
        let object = sign(
            json!({"alg": "ES256", "typ": REQUEST_OBJECT_TYP, "kid": "some-other-key"}),
            claims(),
            &key,
        );
        let error = server
            .verified_request_object(&ClientId::new("app"), &object)
            .expect_err("a kid must name the client's registered key");
        assert_eq!(error.error, ErrorCode::InvalidRequestObject);
    }

    /// ATTACK, RFC 9101 s4: the object SHOULD name this server in `aud`, and when it does, an
    /// object addressed elsewhere and replayed here is refused. This is the same mix-up reasoning
    /// as RFC 9207's `iss` on the response, in the other direction.
    #[tokio::test]
    async fn an_object_addressed_to_another_authorization_server_is_refused() {
        let key = signing_key(7);
        let server = server(&key).await;

        let mut elsewhere = claims();
        elsewhere["aud"] = json!("https://other-as.example");
        let object = sign(header(), elsewhere, &key);

        let error = server
            .verified_request_object(&ClientId::new("app"), &object)
            .expect_err("an object addressed to another AS must not be honoured here");
        assert_eq!(error.error, ErrorCode::InvalidRequestObject);

        // An object with no `aud` at all is still accepted: RFC 9101 s4 says SHOULD, and refusing
        // a conforming client for exercising that would be this server inventing a requirement.
        let mut silent = claims();
        silent.as_object_mut().unwrap().remove("aud");
        let object = sign(header(), silent, &key);
        server
            .verified_request_object(&ClientId::new("app"), &object)
            .expect("aud is a SHOULD, not a MUST");
    }

    /// ATTACK: a captured request object replayed after its own stated lifetime.
    #[tokio::test]
    async fn an_expired_object_is_refused() {
        let key = signing_key(7);
        let server = server(&key).await;

        let mut expired = claims();
        expired["exp"] = json!(1_000_000u64);
        let object = sign(header(), expired, &key);

        let error = server
            .verified_request_object(&ClientId::new("app"), &object)
            .expect_err("an expired request object must be refused");
        assert_eq!(error.error, ErrorCode::InvalidRequestObject);
    }

    /// RFC 9101 s4: `request` and `request_uri` MUST NOT appear inside a request object. At the
    /// PAR endpoint this is also what stops a `request_uri` smuggled inside a signed object from
    /// bypassing the section 2.1 refusal of one in the form body.
    #[tokio::test]
    async fn an_object_carrying_a_nested_reference_is_refused() {
        let key = signing_key(7);
        let server = server(&key).await;

        for forbidden in ["request", "request_uri"] {
            let mut nested = claims();
            nested[forbidden] = json!("urn:ietf:params:oauth:request_uri:smuggled");
            let object = sign(header(), nested, &key);
            let error = server
                .verified_request_object(&ClientId::new("app"), &object)
                .expect_err("a nested reference must be refused");
            assert_eq!(error.error, ErrorCode::InvalidRequestObject);
        }
    }

    /// RFC 9101 s6.1 defines encrypted request objects; this server implements none, so a JWE must
    /// be refused by SHAPE rather than mistaken for an unsigned JWS.
    #[tokio::test]
    async fn an_encrypted_request_object_is_refused_rather_than_misread() {
        let key = signing_key(7);
        let server = server(&key).await;
        let jwe = "eyJhbGciOiJFQ0RILUVTIn0.encrypted_key.iv.ciphertext.tag";

        let error = server
            .verified_request_object(&ClientId::new("app"), jwe)
            .expect_err("a five part JWE is not something this server can read");
        assert_eq!(error.error, ErrorCode::InvalidRequestObject);
    }

    /// With no key source installed at all, a `request` parameter is refused rather than trusted:
    /// "the server cannot check this signature" must never read as "the signature checked out".
    #[tokio::test]
    async fn with_no_key_source_installed_every_request_object_is_refused() {
        let key = signing_key(7);
        let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
        cfg.jar = Some(Box::new(JarConfig::new()));
        let server = AuthorizationServer::new(cfg, MemoryStorage::new());
        let object = sign(header(), claims(), &key);

        let error = server
            .verified_request_object(&ClientId::new("app"), &object)
            .expect_err("no keys means no verification means no acceptance");
        assert_eq!(error.error, ErrorCode::InvalidRequestObject);
    }

    /// RFC 9101 s4: parameter values are JSON STRINGS. A number where a string belongs is not a
    /// parameter any query string could have carried, so coercing it would be the server inventing
    /// a request the client did not make.
    #[tokio::test]
    async fn a_non_string_parameter_claim_is_refused() {
        let key = signing_key(7);
        let server = server(&key).await;

        let mut odd = claims();
        odd["scope"] = json!(42);
        let object = sign(header(), odd, &key);

        let error = server
            .verified_request_object(&ClientId::new("app"), &object)
            .expect_err("a non-string parameter claim is refused");
        assert_eq!(error.error, ErrorCode::InvalidRequestObject);
    }

    /// The other half of what moved out of registration: a well formed pair of coordinates that
    /// is NOT a point on P-256 registers, and then verifies NOTHING. Fail closed is the property
    /// that matters; being told early is the convenience.
    #[tokio::test]
    async fn an_off_curve_key_registers_but_verifies_nothing() {
        let off_curve = RegisteredRequestObjectKey::es256_from_sec1(None, &[0x04; 65])
            .expect("well formed coordinates, which is all registration can now check");

        let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
        cfg.jar = Some(Box::new(JarConfig::new()));
        let server = AuthorizationServer::new(cfg, MemoryStorage::new()).with_request_object_keys(
            Box::new(OneClientsKey {
                client_id: ClientId::new("app"),
                key: off_curve,
            }),
        );
        server
            .register_client(Client {
                client_id: ClientId::new("app"),
                auth: ClientAuth::Public,
                grant_types: vec![GrantType::AuthorizationCode],
                redirect_uris: vec!["https://app.example/cb".to_string()],
                allowed_scopes: ScopeSet::parse("read write").unwrap(),
                default_scopes: ScopeSet::parse("read").unwrap(),
                name: None,
                registration: None,
            })
            .await
            .unwrap();

        // A genuinely signed request object, under a genuinely valid key. It is refused because
        // the REGISTERED key is unusable, which is the only safe reading of an unusable key.
        let object = sign(header(), claims(), &signing_key(7));
        let error = server
            .verified_request_object(&ClientId::new("app"), &object)
            .expect_err("a key that is not on the curve verifies nothing");
        assert_eq!(error.error, ErrorCode::InvalidRequestObject);
    }

    /// A registered key's ENCODING is checked when it is REGISTERED, so a host that pastes in a
    /// truncated coordinate finds out at configuration time rather than at request time.
    ///
    /// WHAT MOVED, and it moved for a reason worth stating: whether the point is actually ON P-256
    /// is no longer checked here. It cannot be, because `--features jar` no longer contains an
    /// elliptic curve at all (the ES256 arithmetic is behind the `Es256Verifier` seam, and the
    /// `jwt-p256` backend is one implementation of it). The check still happens, in the installed
    /// verifier, once per request, and it still FAILS CLOSED, which
    /// [`an_off_curve_key_registers_but_verifies_nothing`] is what proves. What is lost is only
    /// how early the host is told, and what is bought is that a host with its own backend does not
    /// carry a second curve implementation to be told slightly sooner.
    #[test]
    fn a_malformed_public_key_cannot_be_registered() {
        assert!(RegisteredRequestObjectKey::es256_from_sec1(None, &[0x04; 33]).is_err());
        // 65 bytes, but not the uncompressed SEC 1 form: the leading byte is what says which
        // encoding this is, so a buffer that does not begin 0x04 is not the point it looks like.
        assert!(RegisteredRequestObjectKey::es256_from_sec1(None, &[0x00; 65]).is_err());
        assert!(RegisteredRequestObjectKey::es256_from_jwk_coordinates(
            None,
            "not base64!",
            "AAAA"
        )
        .is_err());
        // A three byte coordinate: RFC 7518 s6.2.1.2 fixes P-256's at 32, leading zeros KEPT.
        assert!(
            RegisteredRequestObjectKey::es256_from_jwk_coordinates(None, "AAAA", "AAAA").is_err()
        );

        let key = signing_key(7);
        let point = key.verifying_key().to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
        let registered =
            RegisteredRequestObjectKey::es256_from_jwk_coordinates(Some("k".into()), &x, &y)
                .expect("a JWK's own coordinates register");
        assert_eq!(registered.alg(), RequestObjectAlg::Es256);
        assert_eq!(registered.kid(), Some("k"));
        // The public key is not a secret, but the Debug form is still only what an operator needs.
        assert!(format!("{registered:?}").contains("Es256"));
    }
}
