// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for [`crate::mtls`], kept out of the implementation file. These reach private items
//! (`ClientCertificate::satisfies`, `verify_certificate`), so they live in the crate rather
//! than in `tests/`.
//!
//! The ATTACK tests here are the ones that matter, and each names the thing an attacker ends up
//! holding that they should not: a certificate that authenticates a client it was not issued to, a
//! registration whose credential is weaker than the operator asked for, and a secret that
//! authenticates a client which has none.

use super::*;

use crate::client::ClientId;
use crate::grant::GrantType;
use crate::scope::ScopeSet;
use crate::server::ClientCredential;

/// The credential a request presents: a certificate, a secret, or (the attack) neither.
fn cred<'a>(
    secret: Option<&'a str>,
    certificate: Option<&'a ClientCertificate<'a>>,
) -> ClientCredential<'a> {
    ClientCredential {
        certificate,
        ..ClientCredential::secret(secret)
    }
}

/// Two certificates that differ in one byte, so their thumbprints differ and nothing else about
/// the fixture does. Not real X.509: nothing in this crate parses the bytes (see the module docs on
/// why it does not), so the only property the fixture needs is that the DER of one client is not
/// the DER of another.
const CERT_A: &[u8] = b"\x30\x82\x01\x0a-client-a-certificate-der-bytes";
const CERT_B: &[u8] = b"\x30\x82\x01\x0a-client-b-certificate-der-bytes";

fn mtls_client(registration: MtlsClientRegistration) -> Client {
    Client {
        client_id: ClientId::new("mtls-client"),
        auth: ClientAuth::Mtls { registration },
        grant_types: vec![GrantType::ClientCredentials],
        redirect_uris: Vec::new(),
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

// ------------------------------------------------------------------------------ RFC 8705 s3.1

/// RFC 8705 section 3.1 defines the thumbprint as "the base64url-encoded SHA-256 hash of the DER
/// encoding of the X.509 certificate", and the encoding is the interoperability hazard: base64url
/// without padding, not standard base64, not hex, not padded. 32 bytes is exactly 43 base64url
/// characters with no `=`.
#[test]
fn the_thumbprint_is_unpadded_base64url_of_the_sha256_of_the_der() {
    let thumbprint = CertificateThumbprint::from_der(CERT_A);
    let text = thumbprint.to_base64url();
    assert_eq!(text.len(), 43, "{text}");
    assert!(
        !text.contains('='),
        "RFC 8705 s3.1 is base64url WITHOUT padding: {text}"
    );
    assert!(
        !text.contains('+') && !text.contains('/'),
        "the URL-safe alphabet has no + or /: {text}"
    );
    // The value itself, computed independently of the crate's own encoder.
    let expected = {
        use sha2::{Digest, Sha256};
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            Sha256::digest(CERT_A),
        )
    };
    assert_eq!(text, expected);
    // Round trip through the wire form.
    assert_eq!(
        CertificateThumbprint::from_base64url(&text).unwrap(),
        thumbprint
    );
}

/// A PEM certificate is base64 TEXT wrapping the DER, and hashing the text (or the armour lines)
/// produces a thumbprint that matches nothing. The helper exists precisely so a host cannot make
/// that mistake, so the test pins that it agrees with the DER form.
#[test]
fn the_pem_helper_hashes_the_der_and_not_the_armour() {
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, CERT_A);
    let pem = format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n");
    assert_eq!(
        CertificateThumbprint::from_pem(&pem).unwrap(),
        CertificateThumbprint::from_der(CERT_A)
    );
    assert_eq!(
        CertificateThumbprint::from_pem("not a pem file"),
        Err(MtlsRegistrationError::MalformedCertificate)
    );
}

/// An `x5t#S256` that is not 32 bytes was never produced by SHA-256, so it can never match a
/// certificate. Refusing it at parse time is what stops a typo becoming a client that authenticates
/// at registration and fails at the first token request.
#[test]
fn a_thumbprint_that_is_not_a_sha256_is_refused() {
    assert_eq!(
        CertificateThumbprint::from_base64url("c2hvcnQ"),
        Err(MtlsRegistrationError::MalformedThumbprint)
    );
    assert_eq!(
        CertificateThumbprint::from_base64url("not base64url!!"),
        Err(MtlsRegistrationError::MalformedThumbprint)
    );
}

// ------------------------------------------------------------- ATTACK: RFC 8705 s2.1.2, one only

/// ATTACK, RFC 8705 section 2.1.2. A registration document names TWO of the five subject
/// parameters. The five are alternatives, not a conjunction, so a server that accepts two has to
/// decide whether the client must satisfy both or either; "either" is a strictly weaker credential
/// than whoever wrote the registration asked for, and the client can then authenticate with a
/// certificate that satisfies only the parameter the operator considered the weaker one.
///
/// Here the operator meant "the certificate whose subject DN is CN=payments" and a second parameter
/// smuggles in "or anything with the SAN client.example.com", which is a name an attacker who can
/// get a certificate from the same CA may well be able to obtain. Section 2.1.2 settles it: the
/// registration is REFUSED, before the client exists.
#[test]
fn a_registration_naming_two_subject_parameters_is_refused() {
    let refused = ExpectedSubject::from_registration_parameters([
        (TLS_CLIENT_AUTH_SUBJECT_DN, "CN=payments,O=Example,C=GB"),
        (TLS_CLIENT_AUTH_SAN_DNS, "client.example.com"),
    ]);
    assert_eq!(refused, Err(MtlsRegistrationError::MoreThanOneSubjectValue));

    // Order must not decide it either: whichever came first, the answer is the same refusal.
    let refused = ExpectedSubject::from_registration_parameters([
        (TLS_CLIENT_AUTH_SAN_DNS, "client.example.com"),
        (TLS_CLIENT_AUTH_SUBJECT_DN, "CN=payments,O=Example,C=GB"),
    ]);
    assert_eq!(refused, Err(MtlsRegistrationError::MoreThanOneSubjectValue));

    // And two of the SAN flavours, which is the same mistake without a DN in sight.
    let refused = ExpectedSubject::from_registration_parameters([
        (TLS_CLIENT_AUTH_SAN_URI, "https://client.example.com/"),
        (TLS_CLIENT_AUTH_SAN_EMAIL, "ops@example.com"),
    ]);
    assert_eq!(refused, Err(MtlsRegistrationError::MoreThanOneSubjectValue));
}

/// The other two halves of the same rule: exactly one means not zero, and a parameter present with
/// an empty value is not a registration, it is a client that can never authenticate.
#[test]
fn a_registration_naming_no_subject_parameter_or_an_empty_one_is_refused() {
    assert_eq!(
        ExpectedSubject::from_registration_parameters([("client_name", "Payments")]),
        Err(MtlsRegistrationError::NoSubjectValue)
    );
    assert_eq!(
        ExpectedSubject::from_registration_parameters([(TLS_CLIENT_AUTH_SAN_DNS, "")]),
        Err(MtlsRegistrationError::EmptySubjectValue)
    );
}

/// Exactly one, with the other registration members alongside it, is what a real document looks
/// like and it has to work.
#[test]
fn a_registration_naming_exactly_one_subject_parameter_is_accepted() {
    let expected = ExpectedSubject::from_registration_parameters([
        ("client_name", "Payments"),
        (TLS_CLIENT_AUTH_SAN_DNS, "client.example.com"),
        ("grant_types", "client_credentials"),
    ])
    .unwrap();
    assert_eq!(
        expected,
        ExpectedSubject::SanDns("client.example.com".to_string())
    );
    assert_eq!(expected.parameter_name(), TLS_CLIENT_AUTH_SAN_DNS);
    assert_eq!(expected.value(), "client.example.com");
}

// --------------------------------------------------- ATTACK: RFC 8705 s2.1, the wrong certificate

/// ATTACK, RFC 8705 section 2.1. A caller holding a certificate the HOST verified, issued to some
/// other subject by the same CA, presents it as `mtls-client`. Every deployment that trusts a CA
/// for client certificates has more than one certificate under that CA, so "the chain validated"
/// is emphatically not "this is the client it claims to be"; the registered subject value is the
/// entire difference between the two, and a server that does not compare it authenticates any
/// holder of any certificate the deployment trusts.
#[test]
fn a_certificate_with_the_wrong_subject_does_not_authenticate() {
    let client = mtls_client(MtlsClientRegistration::TlsClientAuth(
        ExpectedSubject::SubjectDn("CN=payments,O=Example,C=GB".to_string()),
    ));
    let attacker = ClientCertificate::from_der(CERT_B)
        .with_subject_dn("CN=intern-laptop,O=Example,C=GB")
        .with_san_dns(&["intern.example.com"]);

    assert_eq!(
        verify_certificate(&client, &cred(None, Some(&attacker))),
        Err(ClientAuthFailure::CertificateMismatch),
        "a certificate issued to a different subject must not authenticate this client"
    );

    // The registered subject, and nothing else, is what authenticates.
    let genuine = ClientCertificate::from_der(CERT_A).with_subject_dn("CN=payments,O=Example,C=GB");
    assert_eq!(
        verify_certificate(&client, &cred(None, Some(&genuine))),
        Ok(())
    );
}

/// ATTACK, the same shape one level down: the registered value is a SAN entry, and the attacker's
/// certificate carries a DIFFERENT entry of the same kind, plus a matching entry of a kind that was
/// not registered. A server that searched all the SAN lists rather than the registered one would
/// accept it.
#[test]
fn a_san_match_of_the_wrong_kind_does_not_authenticate() {
    let client = mtls_client(MtlsClientRegistration::TlsClientAuth(
        ExpectedSubject::SanDns("client.example.com".to_string()),
    ));
    // The value the registration names, present as a URI SAN and as an email SAN, but NOT as the
    // dNSName the registration asked for.
    let attacker = ClientCertificate::from_der(CERT_B)
        .with_san_dns(&["attacker.example.com"])
        .with_san_uri(&["client.example.com"])
        .with_san_email(&["client.example.com"]);
    assert_eq!(
        verify_certificate(&client, &cred(None, Some(&attacker))),
        Err(ClientAuthFailure::CertificateMismatch)
    );

    let genuine = ClientCertificate::from_der(CERT_A)
        .with_san_dns(&["other.example.com", "client.example.com"]);
    assert_eq!(
        verify_certificate(&client, &cred(None, Some(&genuine))),
        Ok(())
    );
}

/// ATTACK: a wildcard SAN. `*.example.com` is a perfectly ordinary certificate to hold, and if it
/// matched a registration for `client.example.com` then anybody with a wildcard for the
/// organisation's domain could authenticate as every client in it. RFC 8705 section 2.1 compares
/// the registered value; it does not do name resolution, and neither does this crate.
#[test]
fn a_wildcard_san_matches_only_itself() {
    let client = mtls_client(MtlsClientRegistration::TlsClientAuth(
        ExpectedSubject::SanDns("client.example.com".to_string()),
    ));
    let wildcard = ClientCertificate::from_der(CERT_B).with_san_dns(&["*.example.com"]);
    assert_eq!(
        verify_certificate(&client, &cred(None, Some(&wildcard))),
        Err(ClientAuthFailure::CertificateMismatch)
    );
}

/// Case folding is not applied, even to DNS names where the protocol would tolerate it. A partial
/// normaliser is how two different subjects come to compare equal; the exact rule is stated in
/// `ClientCertificate::satisfies` and pinned here so nobody relaxes it as a convenience.
#[test]
fn matching_is_case_sensitive() {
    let client = mtls_client(MtlsClientRegistration::TlsClientAuth(
        ExpectedSubject::SanDns("client.example.com".to_string()),
    ));
    let shouty = ClientCertificate::from_der(CERT_A).with_san_dns(&["CLIENT.EXAMPLE.COM"]);
    assert_eq!(
        verify_certificate(&client, &cred(None, Some(&shouty))),
        Err(ClientAuthFailure::CertificateMismatch)
    );
}

// ------------------------------------------ ATTACK: RFC 8705 s2.2, a certificate nobody registered

/// ATTACK, RFC 8705 section 2.2. The self-signed method has no CA at all: the registration IS the
/// trust anchor. So a caller who presents a certificate they generated themselves five seconds ago
/// (which is exactly as "valid" as the registered one, since both are self-signed) must not
/// authenticate. The thumbprint comparison is the whole of the check.
#[test]
fn a_self_signed_certificate_nobody_registered_does_not_authenticate() {
    let client = mtls_client(MtlsClientRegistration::SelfSignedTlsClientAuth(
        RegisteredCertificates::from_der_certificates([CERT_A]).unwrap(),
    ));
    let forged = ClientCertificate::from_der(CERT_B);
    assert_eq!(
        verify_certificate(&client, &cred(None, Some(&forged))),
        Err(ClientAuthFailure::CertificateMismatch)
    );
    assert_eq!(
        verify_certificate(
            &client,
            &cred(None, Some(&ClientCertificate::from_der(CERT_A)))
        ),
        Ok(())
    );
}

/// A client re-keying registers both certificates for the overlap window, and BOTH must work: a
/// rotation a deployment cannot express is a flag day it takes instead.
#[test]
fn every_registered_self_signed_certificate_authenticates() {
    let client = mtls_client(MtlsClientRegistration::SelfSignedTlsClientAuth(
        RegisteredCertificates::from_der_certificates([CERT_A, CERT_B]).unwrap(),
    ));
    for der in [CERT_A, CERT_B] {
        assert_eq!(
            verify_certificate(
                &client,
                &cred(None, Some(&ClientCertificate::from_der(der)))
            ),
            Ok(())
        );
    }
}

/// The JWK Set is the form RFC 8705 section 2.2 defines the registration in, and `x5c` (RFC 7517
/// section 4.7) is STANDARD base64 with padding, not base64url. A host that decoded it as base64url
/// would register a thumbprint of nothing. Keys with no `x5c` are skipped rather than refused,
/// because a JWK Set legitimately carries keys for other purposes.
#[test]
fn a_registration_reads_certificates_out_of_the_clients_jwks() {
    let a = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, CERT_A);
    let jwks = format!(
        r#"{{"keys":[{{"kty":"RSA","n":"...","e":"AQAB"}},{{"kty":"EC","x5c":["{a}","aXNzdWVy"]}}]}}"#
    );
    let registered = RegisteredCertificates::from_jwks(&jwks).unwrap();
    assert_eq!(
        registered.thumbprints(),
        &[CertificateThumbprint::from_der(CERT_A)],
        "only the LEAF (first x5c entry) is the client's own certificate"
    );

    assert_eq!(
        RegisteredCertificates::from_jwks(r#"{"keys":[{"kty":"RSA"}]}"#),
        Err(MtlsRegistrationError::NoCertificateInJwks)
    );
    assert_eq!(
        RegisteredCertificates::from_jwks("{"),
        Err(MtlsRegistrationError::MalformedJwks)
    );
}

// ------------------------------------------------------ ATTACK: the credential families must not mix

/// ATTACK. A mutual-TLS registration holds NO secret, so there is no string a caller could present
/// that is the right one. The dangerous failure mode is a server that reads "no secret registered"
/// as "no secret required" and lets a caller through on the client id alone, which is a public
/// value RFC 6749 section 2.2 says is not a credential.
///
/// The check runs at two levels, and both are asserted here, because the second is what protects
/// every caller that is not `authenticate_client`: `ClientAuth::verify_with` itself answers `false`
/// for a mutual-TLS registration, so even a build with this feature compiled OUT (where nothing
/// exists to check a certificate) refuses the client rather than admitting it.
#[test]
fn no_secret_and_no_certificate_authenticates_a_mutual_tls_client() {
    let client = mtls_client(MtlsClientRegistration::TlsClientAuth(
        ExpectedSubject::SanDns("client.example.com".to_string()),
    ));

    // Nothing at all presented.
    assert_eq!(
        verify_certificate(&client, &cred(None, None)),
        Err(ClientAuthFailure::NoCertificatePresented),
        "naming a client id is not authenticating as it"
    );
    // A secret presented, with no certificate: there is nothing to compare it against, and
    // "nothing to compare against" must never read as "compared and matched".
    assert_eq!(
        verify_certificate(&client, &cred(Some("hunter2"), None)),
        Err(ClientAuthFailure::SecretMismatch)
    );
    // A secret presented ALONGSIDE the right certificate. OAuth 2.1 section 2.4 has a client use
    // exactly one authentication method; a request carrying two is a client that does not know
    // which credential it is relying on, and this crate refuses rather than silently picking.
    let genuine = ClientCertificate::from_der(CERT_A).with_san_dns(&["client.example.com"]);
    assert_eq!(
        verify_certificate(&client, &cred(Some("hunter2"), Some(&genuine))),
        Err(ClientAuthFailure::SecretMismatch)
    );

    // The lower level, which holds with or without this module compiled in.
    assert!(!client.auth.verify_with(None, None));
    assert!(!client.auth.verify_with(Some("hunter2"), None));
    assert!(!client.auth.verify_with(Some(""), None));
    // ... and it is still a CONFIDENTIAL client, so the endpoints that refuse public clients
    // (client_credentials, introspection, revocation) admit it.
    assert!(client.auth.is_confidential());
}

/// ATTACK, the converse. A certificate must never authenticate a client that registered some
/// OTHER credential. `verify_certificate` is reached only for a mutual-TLS registration, and this
/// pins that it fails closed for every other one rather than falling back to "well, a certificate
/// was presented": a caller who steals a client id and holds any certificate the deployment
/// verified still needs that client's actual credential.
///
/// The end-to-end half of this, where a secret client and a public client both present a
/// certificate and are judged on their own credential (and get an RFC 8705 section 4 BOUND token
/// out of it), is in `tests/mtls.rs`, which can reach the whole token endpoint.
#[test]
fn a_certificate_does_not_authenticate_a_client_registered_any_other_way() {
    let certificate = ClientCertificate::from_der(CERT_A).with_san_dns(&["client.example.com"]);
    let mut client = mtls_client(MtlsClientRegistration::TlsClientAuth(
        ExpectedSubject::SanDns("client.example.com".to_string()),
    ));

    for other in [
        ClientAuth::Public,
        ClientAuth::ConfidentialSecret {
            secret: "s3cret".to_string(),
        },
        ClientAuth::ConfidentialSecretHash {
            hash: crate::client::SecretHash::sha256("s3cret"),
        },
    ] {
        client.auth = other;
        assert_eq!(
            verify_certificate(&client, &cred(None, Some(&certificate))),
            Err(ClientAuthFailure::SecretMismatch),
            "a certificate is not this registration's credential: {:?}",
            client.auth
        );
    }
}

// -------------------------------------------------------------- the confirmation, and its coexistence

/// The resource server's half of RFC 8705 section 3: a token bound to one certificate must not be
/// confirmed by another. This is the check that makes the binding worth anything, and it fails
/// closed for a token that carries no binding at all.
#[test]
fn a_confirmation_confirms_only_the_certificate_it_was_built_from() {
    let certificate = ClientCertificate::from_der(CERT_A);
    let cnf = Confirmation::for_certificate(&certificate);
    assert!(cnf.confirms_certificate(CERT_A));
    assert!(
        !cnf.confirms_certificate(CERT_B),
        "a stolen bound token presented over a different connection must not confirm"
    );
    assert_eq!(
        cnf.certificate_thumbprint(),
        Some(&CertificateThumbprint::from_der(CERT_A))
    );

    let unbound = Confirmation::default();
    assert!(unbound.is_empty());
    assert!(
        !unbound.confirms_certificate(CERT_A),
        "an unbound token is not bound to the caller's certificate; false is the safe answer"
    );
}

/// RFC 7800 section 3.1 makes `cnf` an OBJECT of confirmation members, and RFC 8705 section 3.1's
/// `x5t#S256` is one member of it. The serialized shape is pinned here because it is what a
/// resource server parses, and because the member name contains a `#`, which is exactly the kind of
/// thing a rename typo silently changes.
#[test]
fn the_confirmation_serializes_as_the_rfc_7800_object() {
    let cnf = Confirmation::for_certificate(&ClientCertificate::from_der(CERT_A));
    let json = serde_json::to_value(&cnf).unwrap();
    assert_eq!(
        json,
        serde_json::json!({ "x5t#S256": CertificateThumbprint::from_der(CERT_A).to_base64url() })
    );
    // Round trips, because a host persists this inside `IssuedToken`.
    let back: Confirmation = serde_json::from_value(json).unwrap();
    assert_eq!(back, cnf);
    // An empty confirmation serializes to an empty object and is never emitted (the `cnf` members
    // on `IssuedToken` and `IntrospectionResponse` are `skip_serializing_if = "Option::is_none"`).
    assert_eq!(
        serde_json::to_value(Confirmation::default()).unwrap(),
        serde_json::json!({})
    );
    // COEXISTENCE with RFC 9449: an object carrying a DPoP `jkt` alongside is not an error, and
    // deserializing one must not lose the certificate binding. This is the assumption the DPoP
    // work is being held to: `jkt` is a SECOND member of this same struct, never a replacement.
    let both = serde_json::json!({
        "x5t#S256": CertificateThumbprint::from_der(CERT_A).to_base64url(),
        "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
    });
    let parsed: Confirmation = serde_json::from_value(both).unwrap();
    assert_eq!(
        parsed.certificate_thumbprint(),
        Some(&CertificateThumbprint::from_der(CERT_A))
    );
}

/// The method name is what the RFC 8414 document advertises and what a client registration records,
/// so the two spellings are pinned rather than left to a `Display`.
#[test]
fn the_registered_method_names_are_the_rfc_8705_spellings() {
    assert_eq!(TLS_CLIENT_AUTH, "tls_client_auth");
    assert_eq!(SELF_SIGNED_TLS_CLIENT_AUTH, "self_signed_tls_client_auth");
    assert_eq!(
        MtlsClientRegistration::TlsClientAuth(ExpectedSubject::SanDns("d".into())).method_name(),
        "tls_client_auth"
    );
    assert_eq!(
        MtlsClientRegistration::SelfSignedTlsClientAuth(
            RegisteredCertificates::from_der_certificates([CERT_A]).unwrap()
        )
        .method_name(),
        "self_signed_tls_client_auth"
    );
}

/// A certificate is a public document, so nothing here is redacted; but the `Debug` must still be
/// the base64url form an operator can compare against `openssl x509 -fingerprint`, not 32 decimal
/// numbers.
#[test]
fn the_thumbprint_debug_is_the_wire_form() {
    let printed = format!("{:?}", CertificateThumbprint::from_der(CERT_A));
    assert!(
        printed.contains(&CertificateThumbprint::from_der(CERT_A).to_base64url()),
        "{printed}"
    );
}
