// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Types that made the WRONG thing easy.
//!
//! Every test here pins a place where the crate's public shape let a host reach an unsafe state by
//! doing nothing in particular: a security-relevant parameter with a permissive default, a
//! guarantee stated in prose that a struct literal walked straight past, a registration that could
//! never authenticate anybody being accepted at the point it was written. The crate's established
//! answer to that shape is elsewhere in it already: an absent consent resolver REFUSES, an absent
//! registration policy REFUSES, and a `user_code_length` below the floor is CLAMPED UP rather than
//! honoured. These extend it.

/// RFC 8628 s5.4 (Remote Phishing) is the reason `verification_uri_complete` is risky: it removes
/// the one friction point, typing the code, that makes an attacker's "click here to finish setting
/// up your TV" mail hard to act on. A deployment gets that deep link only by asking for it.
#[test]
fn verification_uri_complete_is_off_until_a_host_asks_for_it() {
    let config = oauth_as::ServerConfig::new("https://as.example", "https://as.example/device");
    assert!(
        !config.include_verification_uri_complete,
        "RFC 8628 s5.4: the deep link must be opt in, not inherited"
    );
}

/// Every other error-shaped type in this crate implements `std::error::Error`, so a host can put
/// it in a `Box<dyn Error>` or behind `?`. `StepUpFailure` was the one that could not.
#[cfg(feature = "consent")]
#[test]
fn step_up_failure_is_a_std_error() {
    fn assert_error<E: std::error::Error + 'static>(e: E) -> Box<dyn std::error::Error> {
        Box::new(e)
    }

    let boxed = assert_error(oauth_as::StepUpFailure::Stale);
    assert_eq!(boxed.to_string(), "authentication older than max_age");
}

/// The same gap, in the same shape, one type over. `ClientAuthFailure` is the `Err` payload of
/// `mtls.rs`'s `authenticate_via_mtls` exactly as `AssertionFailure`, `DpopFailure`,
/// `StepUpFailure`, `RegistrationFailure` and `MtlsRegistrationError` are the payloads of theirs,
/// and it was the only one of the six a host could not put behind `?` or in a `Box<dyn Error>`.
#[test]
fn client_auth_failure_is_a_std_error() {
    fn assert_error<E: std::error::Error + 'static>(e: E) -> Box<dyn std::error::Error> {
        Box::new(e)
    }

    let boxed = assert_error(oauth_as::ClientAuthFailure::UnknownClient);
    assert_eq!(boxed.to_string(), "no registration for that client_id");
    // The audit channel separates these deliberately (see the type's docs), so the DISPLAY forms
    // have to separate them too: a host that logs the message must not be told the same sentence
    // for "no such client" and "wrong secret".
    // `mut` only when a feature below pushes onto it; a default build compares three.
    #[allow(unused_mut)]
    let mut seen: Vec<String> = vec![
        oauth_as::ClientAuthFailure::UnknownClient.to_string(),
        oauth_as::ClientAuthFailure::SecretMismatch.to_string(),
        oauth_as::ClientAuthFailure::RateLimited.to_string(),
        oauth_as::ClientAuthFailure::SecretExpired.to_string(),
    ];
    #[cfg(feature = "mtls")]
    {
        seen.push(oauth_as::ClientAuthFailure::NoCertificatePresented.to_string());
        seen.push(oauth_as::ClientAuthFailure::CertificateMismatch.to_string());
    }
    #[cfg(feature = "client_assertion")]
    seen.push(oauth_as::ClientAuthFailure::AssertionInvalid.to_string());
    let distinct = seen.iter().collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        distinct.len(),
        seen.len(),
        "two ClientAuthFailure variants render the same message: {seen:?}"
    );
}

/// `from_jwks` refuses a key set that yields no certificate, because such a registration can never
/// authenticate anybody. `from_thumbprints` accepted the identical empty state in silence, and
/// `from_der_certificates` accepted an empty iterator, so the same misconfiguration was a refusal
/// or a live-but-useless registration depending only on which constructor the host reached for.
#[cfg(feature = "mtls")]
#[test]
fn an_empty_certificate_registration_is_refused_by_every_constructor() {
    use oauth_as::mtls::{MtlsRegistrationError, RegisteredCertificates};

    assert_eq!(
        RegisteredCertificates::from_thumbprints(Vec::new()),
        Err(MtlsRegistrationError::NoCertificates),
    );
    assert_eq!(
        RegisteredCertificates::from_der_certificates(std::iter::empty()),
        Err(MtlsRegistrationError::NoCertificates),
    );
    assert_eq!(
        RegisteredCertificates::from_jwks(r#"{"keys":[]}"#),
        Err(MtlsRegistrationError::NoCertificateInJwks),
    );
    // A registration that names one certificate is still built.
    let one = RegisteredCertificates::from_der_certificates([b"a certificate".as_slice()])
        .expect("one certificate is a usable registration");
    assert_eq!(one.thumbprints().len(), 1);
}

/// An 8 character `client_secret_jwt` HMAC key is offline-crackable: the assertion carries its own
/// MAC, so an attacker who sees one assertion can grind the key without ever talking to this
/// server again. RFC 6749 s10.10 sets the bar at 128 bits of entropy for a server-generated
/// credential, which is 22 characters at base64url's 6 bits per character.
#[cfg(feature = "client_assertion")]
#[test]
fn a_client_secret_jwt_key_below_the_entropy_floor_is_refused() {
    use oauth_as::client_assertion::{
        AssertionKeys, ClientSecretKey, WeakClientSecret, MIN_CLIENT_SECRET_JWT_KEY_LENGTH,
    };

    assert_eq!(MIN_CLIENT_SECRET_JWT_KEY_LENGTH, 22);
    assert_eq!(ClientSecretKey::new("s3cr3t!!"), Err(WeakClientSecret));
    let long_enough = "0123456789012345678901";
    assert_eq!(long_enough.len(), MIN_CLIENT_SECRET_JWT_KEY_LENGTH);
    let key = ClientSecretKey::new(long_enough).expect("22 characters clears the floor");
    let _keys = AssertionKeys::ClientSecret { secret: key };
}

/// The floor holds on the way back OUT of a host's store too. `AssertionKeys` is `Deserialize`, so
/// a registration written before the floor existed (or by hand) would otherwise walk straight past
/// it, exactly the route `PublicJwk`'s hand-written `Deserialize` exists to close.
#[cfg(feature = "client_assertion")]
#[test]
fn a_weak_client_secret_does_not_survive_deserialization() {
    use oauth_as::client_assertion::AssertionKeys;

    let weak = serde_json::json!({ "ClientSecret": { "secret": "short" } });
    assert!(
        serde_json::from_value::<AssertionKeys>(weak).is_err(),
        "a stored registration must not reintroduce a key the constructor refuses"
    );
}

/// `PublicJwk` documents that "there is no route into this type that skips the private-parameter
/// rejection". Every field was `pub`, so a struct literal was exactly that route, and
/// `PublicJwk::thumbprint` would then emit a `cnf.jkt` over whatever the host wrote. The sentence
/// is the useful thing, so the fields are sealed and the only ways in validate.
#[cfg(feature = "jwt")]
#[test]
fn public_jwk_is_reachable_only_through_a_validating_constructor() {
    use oauth_as::jwt::PublicJwk;

    // RFC 7515 Appendix A.3.1's P-256 public key.
    const X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    const Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

    let key = PublicJwk::from_coordinates(X, Y).expect("a well formed P-256 point");
    assert_eq!(key.kty(), "EC");
    assert_eq!(key.crv(), "P-256");
    assert_eq!(key.x(), X);
    assert_eq!(key.y(), Y);
    assert_eq!(key.kid(), None);
    assert_eq!(key.clone().with_kid("2026-08").kid(), Some("2026-08"));

    // The width check RFC 7518 s6.2.1.2 requires, on the constructor and not only on the parser.
    assert!(PublicJwk::from_coordinates("AAAA", Y).is_err());
    assert!(PublicJwk::from_coordinates(X, "not base64url!!").is_err());
}

/// `subject_token_type` is what stops RFC 8693's type parameter being decorative: the exchange
/// refuses a subject token whose declared type is not an access token. `new` invented the value,
/// so a host that built the request in code and forgot to copy the form field turned that refusal
/// into a pass. It is an argument now.
#[cfg(feature = "token-exchange")]
#[test]
fn a_token_exchange_request_cannot_be_built_without_naming_the_subject_token_type() {
    use oauth_as::token_exchange::{TokenExchangeRequest, TokenTypeIdentifier};
    use oauth_as::ClientId;

    let client = ClientId::new("svc");
    let request = TokenExchangeRequest::new(&client, "tok", TokenTypeIdentifier::RefreshToken);
    assert_eq!(
        request.subject_token_type,
        TokenTypeIdentifier::RefreshToken,
        "the declared type is the caller's, never the constructor's"
    );
}

/// Two rejection types with one payload each, and opposite exposure rules: one published its
/// `String` as a tuple field a host could construct, the other kept it entirely. Both are sealed
/// and both are readable now, so which one a host is holding does not change what it can do.
#[cfg(feature = "token-exchange")]
#[test]
fn a_rejected_token_type_identifier_is_readable_but_not_forgeable() {
    use oauth_as::token_exchange::TokenTypeIdentifier;

    let rejected = "urn:example:not-registered"
        .parse::<TokenTypeIdentifier>()
        .expect_err("not RFC 8693 s3");
    assert_eq!(rejected.identifier(), "urn:example:not-registered");
}

#[cfg(feature = "jar")]
#[test]
fn a_rejected_request_object_key_is_readable_but_not_forgeable() {
    use oauth_as::par::RegisteredRequestObjectKey;

    let rejected = RegisteredRequestObjectKey::es256_from_jwk_coordinates(None, "AAAA", "AAAA")
        .expect_err("a 3 byte coordinate is not a P-256 point");
    assert!(
        !rejected.detail().is_empty(),
        "the reason is readable without parsing the Display string"
    );
}
