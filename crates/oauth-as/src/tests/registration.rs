// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for the private halves of RFC 7591 registration: the metadata validator and the
//! redirect URI rule. These need private access, which is why they are here rather than in
//! `tests/registration.rs`; everything reachable through the public API is tested from there.

use super::*;

fn config() -> RegistrationConfig {
    let mut cfg = RegistrationConfig::new();
    cfg.allowed_scopes = ScopeSet::parse("read write").unwrap();
    cfg
}

fn code_grant_metadata() -> ClientMetadata {
    ClientMetadata {
        redirect_uris: vec!["https://app.example/cb".to_string()],
        ..ClientMetadata::default()
    }
}

fn error_code(failure: RegistrationFailure) -> RegistrationErrorCode {
    match failure {
        RegistrationFailure::Invalid(e) => e.error,
        other => panic!("expected an RFC 7591 s3.2.2 error, got {other:?}"),
    }
}

/// RFC 6749 s3.1.2: a redirection endpoint URI MUST be an absolute URI and MUST NOT include a
/// fragment component. The authorization endpoint compares registered URIs by exact string match
/// (OAuth 2.1 s4.1.3), so a registration this rule lets through and that rule can never match
/// would be a client permanently unable to complete a flow.
#[test]
fn a_redirect_uri_must_be_absolute_and_carry_no_fragment() {
    assert!(redirect_uri_is_registerable("https://app.example/cb"));
    assert!(redirect_uri_is_registerable("https://app.example/cb?x=1"));
    // A private-use scheme, which RFC 8252 s7.1 makes the native-app norm.
    assert!(redirect_uri_is_registerable("com.example.app:/oauth"));

    assert!(
        !redirect_uri_is_registerable("/cb"),
        "a relative reference is not an absolute URI (RFC 6749 s3.1.2)"
    );
    assert!(
        !redirect_uri_is_registerable("https://app.example/cb#frag"),
        "RFC 6749 s3.1.2 forbids a fragment component"
    );
    assert!(
        !redirect_uri_is_registerable(""),
        "an empty string names nowhere"
    );
    assert!(
        !redirect_uri_is_registerable("1https://app.example/cb"),
        "a scheme must start with an ALPHA (RFC 3986 s3.1)"
    );
}

/// RFC 7591 s2: `grant_types` defaults to `["authorization_code"]` and `response_types` to
/// `["code"]` when the registration omits them.
#[test]
fn omitted_grant_and_response_types_take_the_rfc_defaults() {
    let registered = validate(&code_grant_metadata(), &config()).expect("valid");
    assert_eq!(registered.grant_types, vec![GrantType::AuthorizationCode]);
    assert_eq!(registered.response_types, vec!["code".to_string()]);
}

/// RFC 7591 s2 states the correspondence between `grant_types` and `response_types`: the
/// `authorization_code` grant goes with the `code` response type. A registration that asks for one
/// without the other is incoherent, and s3.2.2's `invalid_client_metadata` is the answer.
#[test]
fn grant_types_and_response_types_must_correspond() {
    let mut m = code_grant_metadata();
    m.grant_types = Some(vec!["authorization_code".to_string()]);
    m.response_types = Some(vec![]);
    assert_eq!(
        error_code(validate(&m, &config()).unwrap_err()),
        RegistrationErrorCode::InvalidClientMetadata,
        "authorization_code without the code response type"
    );

    let mut m = code_grant_metadata();
    m.grant_types = Some(vec!["refresh_token".to_string()]);
    m.response_types = Some(vec!["code".to_string()]);
    assert_eq!(
        error_code(validate(&m, &config()).unwrap_err()),
        RegistrationErrorCode::InvalidClientMetadata,
        "the code response type without the authorization_code grant"
    );
}

/// OAuth 2.1 removes the implicit grant, so `token` is not merely unsupported here, it is gone
/// from the protocol. RFC 7591 s3.2.2 `invalid_client_metadata`.
#[test]
fn the_implicit_response_type_is_refused() {
    let mut m = code_grant_metadata();
    m.grant_types = Some(vec!["implicit".to_string()]);
    m.response_types = Some(vec!["token".to_string()]);
    assert_eq!(
        error_code(validate(&m, &config()).unwrap_err()),
        RegistrationErrorCode::InvalidClientMetadata
    );
}

/// RFC 7591 s2 makes `redirect_uris` required for a client using a redirection-based flow. Without
/// one the authorization endpoint has nowhere to deliver a code, so the registration would be
/// unusable the moment it was made. RFC 7591 s3.2.2 `invalid_redirect_uri`.
#[test]
fn the_authorization_code_grant_requires_a_redirect_uri() {
    let m = ClientMetadata::default();
    assert_eq!(
        error_code(validate(&m, &config()).unwrap_err()),
        RegistrationErrorCode::InvalidRedirectUri
    );
}

/// RFC 7591 s3.2.2: a redirect URI value that is invalid is `invalid_redirect_uri`, NOT the
/// generic `invalid_client_metadata`. See `a_redirect_uri_must_be_absolute_and_carry_no_fragment`
/// for the rule itself.
#[test]
fn a_malformed_redirect_uri_is_its_own_error_code() {
    let mut m = code_grant_metadata();
    m.redirect_uris = vec!["https://app.example/cb#frag".to_string()];
    assert_eq!(
        error_code(validate(&m, &config()).unwrap_err()),
        RegistrationErrorCode::InvalidRedirectUri
    );
}

/// A grant outside `RegistrationConfig::allowed_grant_types` is refused. The default list carries
/// neither `client_credentials` (which mints tokens with no resource owner at all) nor the RFC
/// 8628 device grant, so an open endpoint cannot hand either out.
#[test]
fn a_grant_the_deployment_does_not_offer_registrants_is_refused() {
    let mut m = code_grant_metadata();
    m.grant_types = Some(vec!["client_credentials".to_string()]);
    m.response_types = Some(vec![]);
    assert_eq!(
        error_code(validate(&m, &config()).unwrap_err()),
        RegistrationErrorCode::InvalidClientMetadata
    );

    let mut cfg = config();
    cfg.allowed_grant_types = vec![GrantType::ClientCredentials];
    let registered = validate(&m, &cfg).expect("permitted once the host says so");
    assert_eq!(registered.grant_types, vec![GrantType::ClientCredentials]);
}

/// An unknown `grant_types` value is metadata this server cannot honour. RFC 7591 s2 tells a
/// server to ignore metadata it does not UNDERSTAND, but a grant type is not decoration: silently
/// dropping it would register a client that cannot do the one thing it asked for.
#[test]
fn an_unknown_grant_type_is_refused_rather_than_ignored() {
    let mut m = code_grant_metadata();
    m.grant_types = Some(vec!["urn:example:invented".to_string()]);
    m.response_types = Some(vec![]);
    assert_eq!(
        error_code(validate(&m, &config()).unwrap_err()),
        RegistrationErrorCode::InvalidClientMetadata
    );
}

/// RFC 7591 s2: `token_endpoint_auth_method` defaults to `client_secret_basic`, and a value this
/// server does not implement is `invalid_client_metadata`.
///
/// The containment that must hold is ONE WAY, and this test pins that direction rather than the
/// equality an earlier version of this comment claimed. Everything dynamic registration ACCEPTS
/// must appear in the RFC 8414 `token_endpoint_auth_methods_supported` member, because a
/// registration recorded under a method the token endpoint does not offer is a client that can
/// never authenticate. The reverse does not hold, and deliberately: see
/// [`a_method_the_metadata_advertises_may_still_be_unregisterable`].
#[test]
fn every_registerable_auth_method_is_one_the_metadata_advertises() {
    let registered = validate(&code_grant_metadata(), &config()).expect("valid");
    assert_eq!(registered.token_endpoint_auth_method, "client_secret_basic");

    let advertised = crate::metadata::AuthorizationServerMetadata::from_config(&ServerConfig::new(
        "https://as.example",
        "https://as.example/device",
    ))
    .token_endpoint_auth_methods_supported;

    for method in ["none", "client_secret_basic", "client_secret_post"] {
        let mut m = code_grant_metadata();
        m.token_endpoint_auth_method = Some(method.to_string());
        let accepted = validate(&m, &config()).expect("this server registers this method");
        assert_eq!(accepted.token_endpoint_auth_method, method);
        assert!(
            advertised.iter().any(|m| m == method),
            "registration accepts {method} but RFC 8414 \
             token_endpoint_auth_methods_supported does not advertise it, so a client registered \
             this way can never authenticate at the token endpoint"
        );
    }

    let mut m = code_grant_metadata();
    m.token_endpoint_auth_method = Some("urn:example:invented".to_string());
    assert_eq!(
        error_code(validate(&m, &config()).unwrap_err()),
        RegistrationErrorCode::InvalidClientMetadata
    );
}

/// The other direction of the same question, pinned SEPARATELY because it is an asymmetry a reader
/// will otherwise assume is a bug.
///
/// RFC 8414 s2's `token_endpoint_auth_methods_supported` describes the TOKEN ENDPOINT. Under
/// `client-assertion` it advertises `private_key_jwt` and `client_secret_jwt`, and under `mtls`
/// the two RFC 8705 methods, and all four of those are genuinely accepted there for a client the
/// HOST provisioned out of band. None of the four can be reached through RFC 7591 dynamic
/// registration, because a registration cannot carry what they need: [`ClientMetadata`] models no
/// `jwks`/`jwks_uri` (RFC 7591 s2) and none of the RFC 8705 s2.1.1 subject parameters, and
/// `client_secret_jwt` needs the secret in the CLEAR (see
/// [`crate::client_assertion::AssertionKeys::ClientSecret`]) while registration keeps a one-way
/// [`crate::client::SecretHash`] only. Accepting any of them here would mint the exact trap the
/// redirect-URI rule above refuses to mint: a registration the token endpoint can never honour.
///
/// So the refusal is right and the advertisement is right. What is NOT right is the wording of the
/// refusal, `"token_endpoint_auth_method is not one this server advertises"`, which under either
/// feature is factually false and sends the registrant looking for a metadata document that says
/// what they were just told it says.
#[test]
fn a_method_the_metadata_advertises_may_still_be_unregisterable() {
    let mut m = code_grant_metadata();
    m.token_endpoint_auth_method = Some("private_key_jwt".to_string());
    assert_eq!(
        error_code(validate(&m, &config()).unwrap_err()),
        RegistrationErrorCode::InvalidClientMetadata
    );

    // Gated on `jwt-p256` as well as `client-assertion`, because since the signing seam landed the
    // two are no longer the same claim. `private_key_jwt` is ES256, and `client-assertion = ["jwt"]`
    // buys the surface without a backend, so a build can have the feature and no way to check an
    // ES256 signature at all. `from_config` states only what the config alone establishes and
    // therefore omits the method in that build, which is the fail-safe direction: under-advertising
    // costs a client one unnecessary fallback, over-advertising sends it down a path that always
    // refuses. This test asserts the ADVERTISEMENT is honest, so it belongs in the build where the
    // advertisement is made.
    #[cfg(all(feature = "client-assertion", feature = "jwt-p256"))]
    {
        let advertised = crate::metadata::AuthorizationServerMetadata::from_config(
            &ServerConfig::new("https://as.example", "https://as.example/device"),
        )
        .token_endpoint_auth_methods_supported;
        assert!(
            advertised
                .iter()
                .any(|m| m == crate::client_assertion::PRIVATE_KEY_JWT),
            "this build verifies RFC 7523 assertions, so the token endpoint really does offer \
             private_key_jwt even though registration cannot record the key it would need"
        );
    }
}

/// RFC 6749 s4.4 gives the client credentials grant to CONFIDENTIAL clients only, so registering
/// it with `token_endpoint_auth_method: none` produces a client whose only grant the token
/// endpoint will always refuse. Same reasoning as the redirect URI rule: a registration that can
/// never be used is a trap, not a leniency.
#[test]
fn a_public_client_may_not_register_the_client_credentials_grant() {
    let mut cfg = config();
    cfg.allowed_grant_types = vec![GrantType::ClientCredentials];
    let mut m = ClientMetadata {
        token_endpoint_auth_method: Some("none".to_string()),
        grant_types: Some(vec!["client_credentials".to_string()]),
        ..ClientMetadata::default()
    };
    m.response_types = Some(vec![]);
    assert_eq!(
        error_code(validate(&m, &cfg).unwrap_err()),
        RegistrationErrorCode::InvalidClientMetadata
    );
}

/// The registered `scope` is bounded by `RegistrationConfig::allowed_scopes`. Widening it is the
/// whole point of the ceiling: an anonymous registrant must not be able to name a scope the
/// deployment reserves for clients it provisioned itself.
#[test]
fn scope_is_bounded_by_what_the_deployment_offers_registrants() {
    let mut m = code_grant_metadata();
    m.scope = Some("read".to_string());
    let registered = validate(&m, &config()).expect("inside the ceiling");
    assert_eq!(registered.scope, ScopeSet::parse("read").unwrap());

    m.scope = Some("read admin".to_string());
    assert_eq!(
        error_code(validate(&m, &config()).unwrap_err()),
        RegistrationErrorCode::InvalidClientMetadata,
        "admin is outside the deployment's registration ceiling"
    );

    // The DEFAULT ceiling is empty, so a host that enabled registration without saying which
    // scopes a registrant may reach hands out none.
    m.scope = Some("read".to_string());
    assert_eq!(
        error_code(validate(&m, &RegistrationConfig::new()).unwrap_err()),
        RegistrationErrorCode::InvalidClientMetadata
    );
}

/// A malformed `scope` is a value error, not a parameter error: RFC 6749 s3.3 defines the token
/// syntax and RFC 7591 s3.2.2 has one code for a bad metadata value.
#[test]
fn a_malformed_scope_is_invalid_client_metadata() {
    let mut m = code_grant_metadata();
    m.scope = Some("read \"write\"".to_string());
    assert_eq!(
        error_code(validate(&m, &config()).unwrap_err()),
        RegistrationErrorCode::InvalidClientMetadata
    );
}

/// RFC 7591 s2.3 software statements are not evaluated here (no trust anchor is a thing this
/// library can invent), and s3.2.2 has a code for exactly that. Refused rather than ignored: a
/// software statement is an assertion the client believes is being honoured, so dropping it
/// silently would register a client on terms nobody agreed to.
#[test]
fn a_software_statement_is_refused_rather_than_silently_dropped() {
    let mut m = code_grant_metadata();
    m.software_statement = Some("eyJhbGciOiJub25lIn0.e30.".to_string());
    assert_eq!(
        error_code(validate(&m, &config()).unwrap_err()),
        RegistrationErrorCode::InvalidSoftwareStatement
    );
}

/// RFC 7591 s2 requires a server to IGNORE client metadata it does not understand, so a member
/// this crate does not model must not make the registration fail.
#[test]
fn unmodelled_metadata_members_are_ignored() {
    let json = r#"{
        "redirect_uris": ["https://app.example/cb"],
        "logo_uri": "https://app.example/logo.png",
        "contacts": ["ops@app.example"],
        "tos_uri": "https://app.example/tos"
    }"#;
    let m: ClientMetadata = serde_json::from_str(json).expect("unknown members are ignored");
    assert!(validate(&m, &config()).is_ok());
}
