// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! One function per remaining cargo feature, each calling the surface that feature adds.
//!
//! Where a feature's happy path needs a credential only a client can produce (a signed request
//! object, a DPoP proof, an RFC 7523 assertion), the probe drives the REFUSAL path instead. That
//! is not a shortcut: the parser, the JWS reader, the algorithm check and the error type are the
//! same code either way, and they are the bulk of it. Where the happy path is reachable without a
//! counterparty (PAR, RAR, consent, token exchange, resource metadata) it is what runs.

/// The crate's built-in ES256 backend. Verification goes through the `Es256Verifier` seam, so a
/// verifier is a per-call argument; this is the one a consumer who enables `jwt-p256` gets.
#[cfg(any(feature = "f-dpop", feature = "f-client-assertion"))]
const VERIFIER: &oauth_as::jwt::P256Verifier = &oauth_as::jwt::P256Verifier;

#[cfg(feature = "f-mtls")]
pub fn mtls() -> u64 {
    use oauth_as::mtls::{CertificateThumbprint, ClientCertificate, MtlsClientRegistration};

    let der: Vec<u8> = (0u8..=255).cycle().take(512).collect();
    let certificate = ClientCertificate::from_der(&der)
        .with_subject_dn("CN=probe,O=probe")
        .with_san_dns(&["probe.example"]);
    let thumbprint = *certificate.thumbprint();
    let text = thumbprint.to_base64url();
    let mut acc = text.len() as u64;
    if let Ok(parsed) = CertificateThumbprint::from_base64url(&text) {
        acc = acc.wrapping_add(u64::from(parsed.as_bytes()[0]));
    }
    if let Ok(certificates) =
        oauth_as::mtls::RegisteredCertificates::from_thumbprints(vec![thumbprint])
    {
        let registration = MtlsClientRegistration::SelfSignedTlsClientAuth(certificates);
        acc = acc.wrapping_add(u64::from(registration.accepts(&certificate)));
        acc = acc.wrapping_add(registration.method_name().len() as u64);
    }
    // The OTHER RFC 8705 method, whose subject matching is separate code.
    if let Ok(subject) = oauth_as::mtls::ExpectedSubject::from_registration_parameters([(
        oauth_as::mtls::TLS_CLIENT_AUTH_SAN_DNS,
        "probe.example",
    )]) {
        let registration = MtlsClientRegistration::TlsClientAuth(subject);
        acc = acc.wrapping_add(u64::from(registration.accepts(&certificate)));
        acc = acc.wrapping_add(registration.method_name().len() as u64);
    }
    std::hint::black_box(acc)
}

#[cfg(feature = "f-par")]
pub fn par() -> u64 {
    use oauth_as::client::ClientId;

    use crate::blockon::block_on;

    let server = crate::exercise::server();
    let client = ClientId::new("probe-public");
    let mut acc: u64 = 0;
    block_on(async {
        let pushed = server
            .pushed_authorization_request(
                &client,
                None,
                &[
                    ("response_type", "code"),
                    ("client_id", "probe-public"),
                    ("redirect_uri", "https://client.probe.example/cb"),
                    ("scope", "read"),
                    (
                        "code_challenge",
                        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    ),
                    ("code_challenge_method", "S256"),
                ],
            )
            .await;
        if let Ok(response) = pushed {
            acc = acc.wrapping_add(u64::from(response.http_status()));
            let uri = response.request_uri.clone();
            if let Ok(validated) = server
                .validate_pushed_authorization_request("probe-public", &uri)
                .await
            {
                acc = acc.wrapping_add(validated.redirect_uri.len() as u64);
            }
            // SINGLE USE: the second read is the replay arm.
            let _ = server
                .validate_pushed_authorization_request("probe-public", &uri)
                .await;
        }
    });
    std::hint::black_box(acc)
}

#[cfg(feature = "f-jar")]
pub fn jar() -> u64 {
    use oauth_as::par::RegisteredRequestObjectKey;

    use crate::blockon::block_on;

    let mut acc: u64 = 0;
    // Key registration: the SEC 1 / JWK-coordinate import a host performs once per client.
    let key = oauth_as::jwt::EcdsaP256Key::generate("probe-jar-1");
    let jwk = key.public_jwk();
    if let Ok(value) = serde_json::to_value(&jwk) {
        let x = value["x"].as_str().unwrap_or_default().to_string();
        let y = value["y"].as_str().unwrap_or_default().to_string();
        if let Ok(registered) = RegisteredRequestObjectKey::es256_from_jwk_coordinates(
            Some("probe-jar-1".into()),
            &x,
            &y,
        ) {
            acc = acc.wrapping_add(registered.alg().as_str().len() as u64);
        }
    }
    // The verification entry point. No key source is installed, so this refuses, which is the arm
    // that carries the JWS parse, the header checks and the error mapping.
    let server = crate::exercise::server();
    block_on(async {
        let outcome = server
            .validate_signed_authorization_request("probe-public", "not.a.jws")
            .await;
        if let Err(error) = outcome {
            acc = acc.wrapping_add(u64::from(error.http_status()));
        }
    });
    std::hint::black_box(acc)
}

#[cfg(feature = "f-rar")]
pub fn rar() -> u64 {
    use oauth_as::rar::AuthorizationDetails;

    const RAW: &str = r#"[{"type":"probe_payment","actions":["read"],"locations":["https://rs.probe.example"],"datatypes":["account"]}]"#;
    let mut acc: u64 = 0;
    if let Ok(details) = AuthorizationDetails::parse(RAW) {
        acc = acc.wrapping_add(details.len() as u64);
        let types = ["probe_payment".to_string()];
        acc = acc.wrapping_add(u64::from(
            details.require_supported_types(Some(&types)).is_ok(),
        ));
        if let Ok(narrowed) = details.clone().narrow(&details) {
            acc = acc.wrapping_add(narrowed.len() as u64);
        }
        for detail in details.iter() {
            acc = acc.wrapping_add(u64::from(detail.is_narrowing_of(detail)));
        }
    }
    // The REFUSAL arms: unparseable, and over the element bound.
    let _ = AuthorizationDetails::parse("not json");
    let _ = AuthorizationDetails::parse("[]");
    std::hint::black_box(acc)
}

#[cfg(feature = "f-dpop")]
pub fn dpop() -> u64 {
    use oauth_as::dpop::{htu_of, verify_proof};

    let mut acc = htu_of("https://as.probe.example/token?x=1").len() as u64;
    // No client here to mint a real proof, so this is the refusal arm: it still runs the compact
    // JWS parse, the `typ` and `alg` checks and the failure mapping, which is most of the code.
    match verify_proof(
        VERIFIER,
        "not.a.proof",
        "POST",
        "https://as.probe.example/token",
        std::time::SystemTime::now(),
    ) {
        Ok(proof) => acc = acc.wrapping_add(proof.jkt.len() as u64),
        Err(failure) => acc = acc.wrapping_add(failure.to_string().len() as u64),
    }
    std::hint::black_box(acc)
}

#[cfg(feature = "f-client-assertion")]
pub fn client_assertion() -> u64 {
    use oauth_as::client_assertion::{
        unverified_subject, verify_assertion, AssertionKeys, ClientSecretKey,
    };

    let mut acc: u64 = 0;
    // Both key shapes, because HS256 and ES256 are separate verification bodies.
    if let Ok(secret) = ClientSecretKey::new("probe-secret-0123456789abcdefghij") {
        let keys = AssertionKeys::ClientSecret { secret };
        acc = acc.wrapping_add(keys.token_endpoint_auth_method().len() as u64);
        if let Err(failure) = verify_assertion(
            Some(VERIFIER as &dyn oauth_as::jwt::Es256Verifier),
            &keys,
            "not.an.assertion",
            "probe-confidential",
            &["https://as.probe.example/token"],
            std::time::SystemTime::now(),
        ) {
            acc = acc.wrapping_add(failure.to_string().len() as u64);
        }
    }
    let key = oauth_as::jwt::EcdsaP256Key::generate("probe-assertion-1");
    if let Ok(value) = serde_json::to_value(key.public_jwk()) {
        if let Ok(public) = oauth_as::jwt::PublicJwk::from_json(&value) {
            let keys = AssertionKeys::PublicKeys { keys: vec![public] };
            acc = acc.wrapping_add(keys.signing_alg().len() as u64);
            if let Err(failure) = verify_assertion(
                Some(VERIFIER as &dyn oauth_as::jwt::Es256Verifier),
                &keys,
                "not.an.assertion",
                "probe-confidential",
                &["https://as.probe.example/token"],
                std::time::SystemTime::now(),
            ) {
                acc = acc.wrapping_add(failure.to_string().len() as u64);
            }
        }
    }
    acc = acc.wrapping_add(unverified_subject("not.an.assertion").map_or(0, |s| s.len() as u64));
    std::hint::black_box(acc)
}

#[cfg(feature = "f-consent")]
pub fn consent() -> u64 {
    use oauth_as::client::ClientId;
    use oauth_as::consent::{
        step_up_challenge, Authentication, AuthenticationRequirement, RequestedDetails,
    };
    use oauth_as::scope::ScopeSet;

    use crate::blockon::block_on;

    let server = crate::exercise::server();
    let client = ClientId::new("probe-public");
    let scope = ScopeSet::from_tokens(["read"]).expect("static scopes are valid");
    let mut acc: u64 = 0;

    let requirement = AuthenticationRequirement::from_pairs([
        ("acr_values", "urn:probe:loa2 urn:probe:loa3"),
        ("max_age", "300"),
    ])
    .unwrap_or_else(|_| AuthenticationRequirement::none());
    let authentication =
        Authentication::at(std::time::SystemTime::now()).with_acr("urn:probe:loa3");
    acc = acc.wrapping_add(u64::from(
        requirement
            .satisfied_by(Some(&authentication), std::time::SystemTime::now())
            .is_ok(),
    ));
    // The REFUSAL arm and the RFC 9470 challenge it produces.
    acc = acc.wrapping_add(
        requirement
            .satisfied_by(None, std::time::SystemTime::now())
            .err()
            .map_or(0, |f| f.description().len() as u64),
    );
    acc = acc.wrapping_add(
        step_up_challenge(
            "Bearer",
            &["urn:probe:loa3".into()],
            Some(std::time::Duration::from_secs(300)),
        )
        .len() as u64,
    );

    block_on(async {
        if let Ok(record) = server
            .record_consent(
                &client,
                "probe-subject",
                &scope,
                &[],
                Some(authentication.clone()),
            )
            .await
        {
            acc = acc.wrapping_add(record.consent_id.len() as u64);
            acc = acc.wrapping_add(u64::from(record.covers(&scope, &[], RequestedDetails::none())));
            if let Ok(all) = server.consents_for_subject("probe-subject").await {
                acc = acc.wrapping_add(all.len() as u64);
            }
            if let Ok(Some(found)) = server.remembered_consent(&client, "probe-subject").await {
                acc = acc.wrapping_add(found.subject.len() as u64);
            }
            if let Ok(revoked) = server.withdraw_consent(&record.consent_id).await {
                acc = acc.wrapping_add(revoked);
            }
        }
    });
    std::hint::black_box(acc)
}

#[cfg(feature = "f-token-exchange")]
pub fn token_exchange() -> u64 {
    use oauth_as::client::ClientId;
    use oauth_as::token_exchange::{TokenExchange, TokenExchangeRequest, TokenTypeIdentifier};

    use crate::blockon::block_on;

    let server = crate::exercise::server();
    let client = ClientId::new("probe-confidential");
    let mut acc: u64 = 0;
    block_on(async {
        let mut request =
            TokenExchangeRequest::new(&client, "not-a-token", TokenTypeIdentifier::AccessToken);
        request.client_secret = Some("probe-secret-0123456789abcdefghij");
        // The seeded client is not registered for this grant, so this refuses. The request
        // parsing, the identifier table and the audit path all run either way.
        match server.exchange_token(&request).await {
            Ok(token) => acc = acc.wrapping_add(token.response.access_token.len() as u64),
            Err(error) => acc = acc.wrapping_add(error.error.as_str().len() as u64),
        }
    });
    acc = acc.wrapping_add(TokenTypeIdentifier::RefreshToken.as_str().len() as u64);
    acc = acc.wrapping_add(
        "urn:ietf:params:oauth:token-type:access_token"
            .parse::<TokenTypeIdentifier>()
            .map_or(0, |t| t.as_str().len() as u64),
    );
    std::hint::black_box(acc)
}

#[cfg(feature = "f-resource-metadata")]
pub fn resource_metadata() -> u64 {
    use oauth_as::resource_metadata::{ProtectedResourceConfig, ProtectedResourceMetadata};

    let config = ProtectedResourceConfig::new("https://rs.probe.example", crate::exercise::ISSUER);
    let document = ProtectedResourceMetadata::from_config(&config);
    let mut acc = document.well_known_path().len() as u64;
    acc = acc.wrapping_add(
        serde_json::to_string(&document)
            .map(|s| s.len() as u64)
            .unwrap_or(0),
    );
    std::hint::black_box(acc)
}

#[cfg(feature = "f-test-util")]
pub fn test_util() -> u64 {
    use oauth_as::storage_conformance::StorageConformance;
    use oauth_as::store::MemoryStorage;

    use crate::blockon::block_on;

    // RUN it, because that is what a host does with this feature: the checks are the code, and a
    // harness that is merely constructed is a harness LTO deletes. Threads rather than a runtime,
    // for the reason in blockon.rs: tokio is not this crate's cost.
    let harness = StorageConformance::new(|| async { MemoryStorage::new() })
        .with_spawn(|task| {
            std::thread::spawn(move || block_on(task));
        })
        .racers(2);
    let violations = block_on(harness.run());
    let mut acc = violations.len() as u64;
    acc = acc.wrapping_add(oauth_as::storage_conformance::CHECKS.len() as u64);
    std::hint::black_box(acc)
}
