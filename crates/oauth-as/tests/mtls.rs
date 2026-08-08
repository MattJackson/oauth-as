// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 8705 end to end, through the crate's PUBLIC API only: mutual-TLS client authentication at
//! the token endpoint (section 2) and certificate-bound access tokens (section 3).
//!
//! The whole file is behind the `mtls` feature, so without it this compiles to nothing. What it
//! tests that `src/tests/mtls.rs` cannot is the WIRING: that the certificate actually reaches
//! client authentication from every endpoint, that the binding actually reaches the persisted
//! record and comes back out of introspection, and that a client registered for mutual TLS cannot
//! get a token through the entry point that does not take a certificate.
//!
//! The attack tests are the point of the file, and each says what an attacker ends up holding.
#![cfg(feature = "mtls")]

mod support;

use std::sync::{Arc, Mutex};

use oauth_as::{
    AuthorizationServerMetadata, CertificateThumbprint, Client, ClientAuth, ClientCertificate,
    ClientId, ErrorCode, Event, EventSink, ExpectedSubject, GrantType, MtlsClientRegistration,
    RegisteredCertificates, ScopeSet, ServerConfig, TokenRequest, TokenTypeHint,
};
use support::{server_with, ManualClock};

/// Stand-in DER. Nothing in this crate parses a certificate (the host has already done that; see
/// the `mtls` module docs), so the only property these need is to be different byte strings.
const CLIENT_DER: &[u8] = b"\x30\x82\x02\x0a--the-payments-client-certificate";
const ATTACKER_DER: &[u8] = b"\x30\x82\x02\x0a--some-other-certificate-the-CA-signed";

const SAN: &str = "payments.example.com";
const PKI_REDIRECT: &str = "https://payments.example.com/cb";

/// Drive an authorization request through to a code. Written here rather than reached for from
/// `support`, because the point of these tests is the mutual-TLS leg and the code flow is only the
/// way to get a grant that HAS a refresh chain to rotate.
async fn issue_code<S: oauth_as::Storage>(
    srv: &oauth_as::AuthorizationServer<S, ManualClock>,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
) -> String {
    let challenge = oauth_as::pkce::code_challenge_s256(support::RFC7636_VERIFIER);
    let request = oauth_as::AuthorizationRequest {
        resource: Vec::new(),
        response_type: Some("code".to_string().into()),
        client_id: Some(client_id.to_string().into()),
        redirect_uri: Some(redirect_uri.to_string().into()),
        scope: Some(scope.to_string().into()),
        state: None,
        code_challenge: Some(challenge.into()),
        code_challenge_method: Some("S256".to_string().into()),
    };
    let validated = srv.validate_authorization_request(&request).await.unwrap();
    srv.issue_authorization_code(&validated, "user-1")
        .await
        .unwrap()
        .code
}

/// The client registered under RFC 8705 s2.1 (PKI method), identified by ONE SAN entry. It holds
/// no secret at all, which is the case this whole slice exists for: a deployment whose policy
/// forbids shared secrets.
fn pki_client() -> Client {
    Client {
        client_id: ClientId::new("payments"),
        auth: ClientAuth::Mtls {
            registration: MtlsClientRegistration::TlsClientAuth(ExpectedSubject::SanDns(
                SAN.to_string(),
            )),
        },
        grant_types: vec![
            GrantType::ClientCredentials,
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
        ],
        redirect_uris: vec![PKI_REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("api:read api:write").unwrap(),
        default_scopes: ScopeSet::parse("api:read").unwrap(),
        name: Some("Payments".into()),
        registration: None,
    }
}

/// The client registered under RFC 8705 s2.2 (self-signed method), identified by the thumbprint of
/// the certificate it registered itself.
fn self_signed_client() -> Client {
    Client {
        client_id: ClientId::new("selfie"),
        auth: ClientAuth::Mtls {
            registration: MtlsClientRegistration::SelfSignedTlsClientAuth(
                RegisteredCertificates::from_der_certificates([CLIENT_DER]),
            ),
        },
        grant_types: vec![GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("api:read").unwrap(),
        default_scopes: ScopeSet::parse("api:read").unwrap(),
        name: None,
        registration: None,
    }
}

fn genuine_certificate() -> ClientCertificate<'static> {
    const SANS: &[&str] = &[SAN];
    ClientCertificate::from_der(CLIENT_DER)
        .with_subject_dn("CN=payments,O=Example,C=GB")
        .with_san_dns(SANS)
}

/// A certificate the host verified just as thoroughly: same CA, same deployment, different client.
/// This is what an insider, or the holder of any other certificate the deployment trusts, has.
fn attacker_certificate() -> ClientCertificate<'static> {
    const SANS: &[&str] = &["intern-laptop.example.com"];
    ClientCertificate::from_der(ATTACKER_DER)
        .with_subject_dn("CN=intern-laptop,O=Example,C=GB")
        .with_san_dns(SANS)
}

fn cc_request(client_id: &str) -> TokenRequest {
    TokenRequest::ClientCredentials {
        client_id: ClientId::new(client_id),
        client_secret: None,
        scope: None,
    }
}

/// A sink that records the `ClientAuthFailure` reasons, so the "what does the host get told"
/// assertions can be made without the wire ever distinguishing them.
#[derive(Default)]
struct Failures(Arc<Mutex<Vec<String>>>);

impl EventSink for Failures {
    fn on_event(&self, event: Event<'_>) {
        if let Event::ClientAuthenticationFailed { failure, .. } = event {
            self.0.lock().unwrap().push(format!("{failure:?}"));
        }
    }
}

// ------------------------------------------------------------------- s2: it actually authenticates

/// RFC 8705 s2.1, the case that has to work: a client with NO secret authenticates with its
/// certificate and gets a token.
#[tokio::test]
async fn a_mutual_tls_client_authenticates_with_its_certificate() {
    let srv = server_with(ManualClock::at_epoch(), vec![pki_client()]).await;
    let token = srv
        .token_with_certificate(cc_request("payments"), &[], Some(&genuine_certificate()))
        .await
        .expect("the registered certificate must authenticate the client");
    assert_eq!(token.scope.as_deref(), Some("api:read"));
}

/// RFC 8705 s2.2, the same for the self-signed method.
#[tokio::test]
async fn a_self_signed_client_authenticates_with_the_certificate_it_registered() {
    let srv = server_with(ManualClock::at_epoch(), vec![self_signed_client()]).await;
    let certificate = ClientCertificate::from_der(CLIENT_DER);
    srv.token_with_certificate(cc_request("selfie"), &[], Some(&certificate))
        .await
        .expect("the registered certificate must authenticate the client");
}

// -------------------------------------------------------------------------------- s2: the attacks

/// ATTACK. The attacker holds a certificate this deployment's CA issued (to somebody else) and
/// names a client id, which RFC 6749 s2.2 says is not a secret. If the registered subject value
/// were not compared, this is a token for a client the caller is not.
#[tokio::test]
async fn a_certificate_issued_to_someone_else_gets_no_token() {
    let sink = Failures::default();
    let seen = sink.0.clone();
    let srv = server_with(ManualClock::at_epoch(), vec![pki_client()])
        .await
        .with_event_sink(Box::new(sink));

    let refused = srv
        .token_with_certificate(cc_request("payments"), &[], Some(&attacker_certificate()))
        .await
        .expect_err("a certificate issued to another subject must not authenticate this client");
    assert_eq!(refused.error, ErrorCode::InvalidClient);
    // The WIRE says only `invalid_client` (RFC 6749 s5.2), so nothing is learned about the
    // registration; the host's own channel says exactly what happened, because the host is not the
    // attacker and this is the shape of an attack rather than a misconfiguration.
    assert_eq!(seen.lock().unwrap().as_slice(), ["CertificateMismatch"]);
}

/// ATTACK, and the one a host is most likely to enable by accident: the mutual-TLS client is
/// reachable through the ORDINARY token endpoint, which takes no certificate. If "no certificate
/// registered secret" collapsed into "nothing to check", naming the client id would be enough.
#[tokio::test]
async fn a_mutual_tls_client_cannot_authenticate_without_a_certificate() {
    let sink = Failures::default();
    let seen = sink.0.clone();
    let srv = server_with(ManualClock::at_epoch(), vec![pki_client()])
        .await
        .with_event_sink(Box::new(sink));

    // The plain endpoint: no certificate can reach it at all.
    let refused = srv
        .token(cc_request("payments"))
        .await
        .expect_err("naming a client id is not authenticating as it");
    assert_eq!(refused.error, ErrorCode::InvalidClient);

    // The mutual-TLS endpoint, with the host passing None because its terminator forwarded
    // nothing. Same refusal: an absent certificate is not a satisfied one.
    let refused = srv
        .token_with_certificate(cc_request("payments"), &[], None)
        .await
        .expect_err("an absent certificate must not authenticate anybody");
    assert_eq!(refused.error, ErrorCode::InvalidClient);

    // A guessed secret, which the registration does not have and so cannot match.
    let refused = srv
        .token_with_certificate(
            TokenRequest::ClientCredentials {
                client_id: ClientId::new("payments"),
                client_secret: Some("hunter2".to_string()),
                scope: None,
            },
            &[],
            None,
        )
        .await
        .expect_err("a mutual-TLS registration has no secret, so no secret is the right one");
    assert_eq!(refused.error, ErrorCode::InvalidClient);

    assert_eq!(
        seen.lock().unwrap().as_slice(),
        [
            "NoCertificatePresented",
            "NoCertificatePresented",
            "SecretMismatch"
        ],
        "the host is told which of the three it was, even though the wire is not"
    );
}

/// ATTACK. A certificate is not a substitute for a secret the other way round either: whoever
/// holds any verified certificate must not be able to authenticate as a client that registered a
/// shared secret.
#[tokio::test]
async fn a_certificate_does_not_stand_in_for_a_clients_secret() {
    let secret_client = Client {
        client_id: ClientId::new("legacy"),
        auth: ClientAuth::ConfidentialSecret {
            secret: "s3cret".into(),
        },
        grant_types: vec![GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("api:read").unwrap(),
        default_scopes: ScopeSet::parse("api:read").unwrap(),
        name: None,
        registration: None,
    };
    let srv = server_with(ManualClock::at_epoch(), vec![secret_client]).await;

    let refused = srv
        .token_with_certificate(cc_request("legacy"), &[], Some(&genuine_certificate()))
        .await
        .expect_err("holding a certificate is not knowing the secret");
    assert_eq!(refused.error, ErrorCode::InvalidClient);
}

// ---------------------------------------------------------------------- s3: the binding is real

/// RFC 8705 s3 and s3.2 together: the token issued over a mutual-TLS connection is bound to that
/// certificate, the binding is PERSISTED (this crate's default token is opaque, so there is nowhere
/// else it could live), and introspection reports it in the `cnf` claim so a resource server can
/// check it.
#[tokio::test]
async fn an_access_token_issued_over_a_certificate_is_bound_to_it() {
    let srv = server_with(ManualClock::at_epoch(), vec![pki_client()]).await;
    let certificate = genuine_certificate();
    let token = srv
        .token_with_certificate(cc_request("payments"), &[], Some(&certificate))
        .await
        .unwrap();

    let record = srv
        .introspect(&token.access_token)
        .await
        .unwrap()
        .expect("the token was just issued");
    let cnf = record.cnf.as_deref().expect("RFC 8705 s3: the token is bound");
    assert_eq!(
        cnf.certificate_thumbprint(),
        Some(&CertificateThumbprint::from_der(CLIENT_DER))
    );

    // The resource server's half. This is the check that makes the binding worth anything.
    assert!(cnf.confirms_certificate(CLIENT_DER));
    assert!(
        !cnf.confirms_certificate(ATTACKER_DER),
        "a stolen bound token replayed over a different connection must not confirm"
    );

    // RFC 7662 s2.2 / RFC 8705 s3.2: the wire document a resource server actually reads.
    let wire = srv
        .introspection_response_with_certificate(
            &ClientId::new("payments"),
            None,
            &token.access_token,
            Some(&certificate),
        )
        .await
        .unwrap();
    let json = serde_json::to_value(&wire).unwrap();
    assert_eq!(json["active"], serde_json::json!(true));
    assert_eq!(
        json["cnf"],
        serde_json::json!({
            "x5t#S256": CertificateThumbprint::from_der(CLIENT_DER).to_base64url()
        }),
        "RFC 8705 s3.2 names the member `cnf` and s3.1 names the confirmation `x5t#S256`"
    );
}

/// ATTACK: a binding that can be IGNORED is not a binding. An ordinary bearer token must not come
/// back from introspection carrying a `cnf` (which would let a resource server believe an unbound
/// token was constrained), and a resource server asking "is this bound to my caller" about an
/// unbound token must hear no.
#[tokio::test]
async fn an_unbound_token_reports_no_binding_at_all() {
    let srv = server_with(ManualClock::at_epoch(), vec![support::client_credentials_client()])
        .await;
    let token = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("cc-app"),
            client_secret: Some(support::CC_SECRET.to_string()),
            scope: None,
        })
        .await
        .unwrap();

    let record = srv.introspect(&token.access_token).await.unwrap().unwrap();
    assert!(
        record.cnf.is_none(),
        "a token issued with no certificate is a plain bearer token and must say so"
    );

    let wire = srv
        .introspection_response(
            &ClientId::new("cc-app"),
            Some(support::CC_SECRET),
            &token.access_token,
        )
        .await
        .unwrap();
    let json = serde_json::to_value(&wire).unwrap();
    assert!(
        json.get("cnf").is_none(),
        "RFC 8705 s3.2: the member is absent, not an empty object: {json}"
    );
}

/// RFC 8705 s4: certificate binding is available to a client that does not authenticate with
/// mutual TLS at all, including a PUBLIC client. The certificate authenticates nobody here; it
/// still constrains the token, which is the entire value of section 4.
#[tokio::test]
async fn a_public_clients_token_is_still_bound_to_its_certificate() {
    let srv = server_with(ManualClock::at_epoch(), vec![support::public_client()]).await;
    let certificate = ClientCertificate::from_der(CLIENT_DER);

    let code = issue_code(&srv, "public-app", support::PUBLIC_REDIRECT, "read").await;
    let token = srv
        .token_with_certificate(
            TokenRequest::AuthorizationCode {
                client_id: ClientId::new("public-app"),
                client_secret: None,
                code,
                redirect_uri: Some(support::PUBLIC_REDIRECT.to_string()),
                code_verifier: Some(support::RFC7636_VERIFIER.to_string()),
            },
            &[],
            Some(&certificate),
        )
        .await
        .unwrap();

    let record = srv.introspect(&token.access_token).await.unwrap().unwrap();
    assert!(
        record
            .cnf
            .as_deref()
            .is_some_and(|c| c.confirms_certificate(CLIENT_DER)),
        "RFC 8705 s4: a public client's token binds to the certificate it presented"
    );
}

/// The binding has to survive the grant that mints tokens from tokens, or a client can launder a
/// bound token into an unbound one simply by refreshing. Each leg binds to the certificate THAT
/// leg presented, which is the right rule: the constraint describes the connection the token was
/// handed to, not the one before it.
#[tokio::test]
async fn a_refreshed_token_binds_to_the_certificate_of_the_refresh_request() {
    let srv = server_with(ManualClock::at_epoch(), vec![pki_client()]).await;
    let certificate = genuine_certificate();

    let code = issue_code(&srv, "payments", PKI_REDIRECT, "api:read").await;
    let first = srv
        .token_with_certificate(
            TokenRequest::AuthorizationCode {
                client_id: ClientId::new("payments"),
                client_secret: None,
                code,
                redirect_uri: Some(PKI_REDIRECT.to_string()),
                code_verifier: Some(support::RFC7636_VERIFIER.to_string()),
            },
            &[],
            Some(&certificate),
        )
        .await
        .expect("the certificate authenticates the code redemption too");
    let refresh = first.refresh_token.expect("this grant issues a refresh chain");

    let rotated = srv
        .token_with_certificate(
            TokenRequest::RefreshToken {
                client_id: ClientId::new("payments"),
                client_secret: None,
                refresh_token: refresh,
                scope: None,
            },
            &[],
            Some(&certificate),
        )
        .await
        .expect("the certificate authenticates the refresh leg too");

    for token in [&first.access_token, &rotated.access_token] {
        let record = srv.introspect(token).await.unwrap().unwrap();
        assert!(
            record
                .cnf
                .as_deref()
                .is_some_and(|c| c.confirms_certificate(CLIENT_DER)),
            "every leg of the chain must carry the binding, or refreshing launders it away"
        );
    }
}

// ------------------------------------------------------------------- the other protected endpoints

/// A client that can obtain a token and cannot revoke it has no answer to its own compromise, so
/// RFC 7009 and RFC 7662 have to accept the same credential the token endpoint does.
#[tokio::test]
async fn a_mutual_tls_client_can_introspect_and_revoke_its_own_tokens() {
    let srv = server_with(ManualClock::at_epoch(), vec![pki_client()]).await;
    let certificate = genuine_certificate();
    let token = srv
        .token_with_certificate(cc_request("payments"), &[], Some(&certificate))
        .await
        .unwrap();

    let seen = srv
        .introspection_response_with_certificate(
            &ClientId::new("payments"),
            None,
            &token.access_token,
            Some(&certificate),
        )
        .await
        .unwrap();
    assert!(seen.active);

    srv.revoke_with_certificate(
        &ClientId::new("payments"),
        None,
        &token.access_token,
        Some(TokenTypeHint::AccessToken),
        Some(&certificate),
    )
    .await
    .unwrap();
    assert!(srv.introspect(&token.access_token).await.unwrap().is_none());

    // ATTACK: the same two endpoints must refuse the attacker's certificate, or introspection
    // becomes the oracle RFC 7662 s4 warns about and revocation becomes a free kill switch.
    let refused = srv
        .revoke_with_certificate(
            &ClientId::new("payments"),
            None,
            "anything",
            None,
            Some(&attacker_certificate()),
        )
        .await
        .expect_err("the wrong certificate must not revoke this client's tokens");
    assert_eq!(refused.error, ErrorCode::InvalidClient);
}

/// The device grant authenticates its client too, so the certificate has to reach it.
#[tokio::test]
async fn the_device_authorization_endpoint_takes_a_certificate() {
    let mut client = pki_client();
    client.grant_types.push(GrantType::DeviceCode);
    let srv = server_with(ManualClock::at_epoch(), vec![client]).await;

    srv.device_authorization_with_certificate(
        &ClientId::new("payments"),
        None,
        None,
        Some(&genuine_certificate()),
    )
    .await
    .expect("the certificate authenticates the device authorization request");

    let refused = srv
        .device_authorization_with_certificate(
            &ClientId::new("payments"),
            None,
            None,
            Some(&attacker_certificate()),
        )
        .await
        .expect_err("and the wrong one does not");
    assert_eq!(refused.error, ErrorCode::InvalidClient);
}

// ------------------------------------------------------------------------------------ s2 / s3.3

/// RFC 8414 s2 with RFC 8705 s2.1.1, s2.2.1 and s3.3: a client learns that mutual TLS is available
/// here by reading the metadata document, not by probing. Advertising a method the endpoint
/// rejects is a lie a client cannot recover from, and staying silent about one it accepts is how a
/// client ends up sending a secret it did not need to have.
#[test]
fn the_metadata_document_advertises_both_methods_and_the_binding() {
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let doc = AuthorizationServerMetadata::from_config(&cfg);
    let json = serde_json::to_value(&doc).unwrap();

    let methods = json["token_endpoint_auth_methods_supported"]
        .as_array()
        .unwrap();
    assert!(methods.contains(&serde_json::json!("tls_client_auth")));
    assert!(methods.contains(&serde_json::json!("self_signed_tls_client_auth")));
    // The pre-existing three are still there: this feature ADDS methods, it does not replace them.
    assert!(methods.contains(&serde_json::json!("client_secret_basic")));
    assert!(methods.contains(&serde_json::json!("client_secret_post")));
    assert!(methods.contains(&serde_json::json!("none")));

    assert_eq!(
        json["tls_client_certificate_bound_access_tokens"],
        serde_json::json!(true),
        "RFC 8705 s3.3: this build binds every token issued over a certificate"
    );
}

// ------------------------------------------------------------------------------------------ s3.1

/// RFC 8705 s3.1: with the `jwt` feature the binding also travels INSIDE the signed access token,
/// so a resource server that validates the JWT itself never has to call introspection to discover
/// that the token is constrained.
#[cfg(feature = "jwt")]
#[tokio::test]
async fn a_signed_access_token_carries_the_cnf_claim() {
    use base64::Engine as _;
    use oauth_as::jwt::{AccessTokenFormat, EcdsaP256Key, JwtConfig};

    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.access_token_format = AccessTokenFormat::Jwt(Box::new(JwtConfig::new(
        EcdsaP256Key::generate("k1"),
        "https://rs.example",
    )));
    let srv = oauth_as::AuthorizationServer::with_clock(
        cfg,
        oauth_as::MemoryStorage::new(),
        ManualClock::at_epoch(),
    );
    srv.register_client(pki_client()).await.unwrap();

    let token = srv
        .token_with_certificate(cc_request("payments"), &[], Some(&genuine_certificate()))
        .await
        .unwrap();

    let payload = token.access_token.split('.').nth(1).expect("a JWS has three parts");
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        claims["cnf"],
        serde_json::json!({
            "x5t#S256": CertificateThumbprint::from_der(CLIENT_DER).to_base64url()
        }),
        "RFC 8705 s3.1 puts the thumbprint in the cnf claim of the access token"
    );
}
