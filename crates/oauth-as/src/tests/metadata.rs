// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for [`crate::metadata`], kept out of the implementation file. These reach
//! private items, so they live in the crate rather than in `tests/`.

use super::*;

#[test]
fn issuer_join_never_doubles_the_slash() {
    assert_eq!(
        under_issuer("https://as.example.com/", "/token"),
        "https://as.example.com/token"
    );
    assert_eq!(
        under_issuer("https://as.example.com", "/token"),
        "https://as.example.com/token"
    );
}

/// RFC 8414 s3.1: the well-known string goes BETWEEN the host and the issuer's path, so an
/// issuer with a path publishes at `/.well-known/oauth-authorization-server/tenant1` and not at
/// the bare path (which every tenant would share) nor under the tenant prefix.
#[test]
fn the_well_known_path_follows_rfc_8414_section_3_1() {
    assert_eq!(
        well_known_path("https://as.example"),
        "/.well-known/oauth-authorization-server"
    );
    assert_eq!(
        well_known_path("https://as.example/"),
        "/.well-known/oauth-authorization-server"
    );
    assert_eq!(
        well_known_path("https://as.example/tenant1"),
        "/.well-known/oauth-authorization-server/tenant1"
    );
    assert_eq!(
        well_known_path("https://as.example/tenant1/"),
        "/.well-known/oauth-authorization-server/tenant1"
    );
    assert_eq!(
        well_known_path("https://as.example:8443/a/b"),
        "/.well-known/oauth-authorization-server/a/b"
    );
}

#[test]
fn the_issuer_path_is_only_what_follows_the_authority() {
    // A port, a userinfo-free authority, and an issuer with no path at all: none of these may
    // contribute a path component.
    assert_eq!(issuer_path("https://as.example"), "");
    assert_eq!(issuer_path("https://as.example:8443"), "");
    assert_eq!(issuer_path("https://as.example:8443/tenant1"), "/tenant1");
    // A scheme-less string is not an issuer RFC 8414 s2 admits; it is read as authority plus
    // path rather than rejected here.
    assert_eq!(issuer_path("as.example/tenant1"), "/tenant1");

    // SHORT authorities, which is where an arithmetic slip in "skip past the scheme" stops being
    // invisible. With a long host name a wrong offset still lands before the first `/`, so the
    // path that comes back is accidentally right; with a short one it lands after it and the
    // whole tenant path silently disappears. That would put every derived route, and the RFC 8414
    // s3.1 well-known path with it, at the wrong place for exactly the deployments least likely
    // to notice.
    assert_eq!(issuer_path("https://a.io/tenant"), "/tenant");
    assert_eq!(issuer_path("http://a.io/t"), "/t");
    assert_eq!(issuer_path("https://a.io"), "");
}

/// RFC 8414 s2 with RFC 9068 s4: `jwks_uri` is advertised exactly when this server signs its
/// access tokens. Both directions are load-bearing. Advertising keys for an AS whose tokens are
/// opaque points every resource server at a key set that verifies nothing; signing without
/// advertising leaves them unable to verify at all.
#[cfg(feature = "jwt-p256")]
#[test]
fn jwks_uri_is_advertised_exactly_when_the_server_signs() {
    use crate::jwt::{AccessTokenFormat, EcdsaP256Key, JwtConfig};

    let mut config = ServerConfig::new("https://as.example", "https://as.example/device");
    // Opaque tokens: no keys, whatever the host wrote in the `jwks_uri` field.
    config.jwks_uri = Some("https://as.example/jwks".to_string());
    assert_eq!(
        AuthorizationServerMetadata::from_config(&config).jwks_uri,
        None
    );

    // Signing, with the URI declared where the signing is declared.
    config.jwks_uri = None;
    config.access_token_format = AccessTokenFormat::Jwt(Box::new(
        JwtConfig::new(EcdsaP256Key::generate("k1"), "https://rs.example")
            .with_jwks_uri("https://as.example/jwks"),
    ));
    assert_eq!(
        AuthorizationServerMetadata::from_config(&config).jwks_uri,
        Some("https://as.example/jwks".to_string())
    );

    // Signing with no URI anywhere: nothing to advertise, and inventing a path the host does not
    // serve would be the same lie in the other direction.
    config.access_token_format = AccessTokenFormat::Jwt(Box::new(JwtConfig::new(
        EcdsaP256Key::generate("k1"),
        "https://rs.example",
    )));
    assert_eq!(
        AuthorizationServerMetadata::from_config(&config).jwks_uri,
        None
    );
}

/// Without the `jwt` feature this crate signs nothing, so the only source is the host's own
/// declaration that some other component publishes keys.
#[cfg(not(feature = "jwt"))]
#[test]
fn without_the_jwt_feature_jwks_uri_is_whatever_the_host_declared() {
    let mut config = ServerConfig::new("https://as.example", "https://as.example/device");
    assert_eq!(
        AuthorizationServerMetadata::from_config(&config).jwks_uri,
        None
    );
    config.jwks_uri = Some("https://keys.example/jwks".to_string());
    assert_eq!(
        AuthorizationServerMetadata::from_config(&config).jwks_uri,
        Some("https://keys.example/jwks".to_string())
    );
}

/// KILLS the 0.9.1 survivor `replace AuthorizationServerMetadata::es256_verification_is_available
/// with ()`.
///
/// The method tells the RFC 8414 document that ES256 verification exists, in a build where this
/// crate has no ES256 BACKEND and the host installed a verifier itself. Under `--all-features`
/// `jwt-p256` is on and `from_config` has already added everything, so emptying the method changes
/// nothing there and the mutant survived. It is NOT equivalent: the whole reason the method is
/// documented as idempotent is that it also runs in the configuration where `from_config` did not
/// add these, and that configuration is the one no test was building.
#[cfg(feature = "client-assertion")]
#[test]
fn announcing_es256_verification_adds_what_the_document_was_missing() {
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let mut doc = AuthorizationServerMetadata::from_config(&cfg);

    // Strip what a `jwt-p256` build would already have put there, so what follows is about THIS
    // method rather than about `from_config`.
    doc.token_endpoint_auth_methods_supported
        .retain(|m| m != "private_key_jwt");
    doc.token_endpoint_auth_signing_alg_values_supported = None;

    doc.es256_verification_is_available();

    assert!(
        doc.token_endpoint_auth_methods_supported
            .iter()
            .any(|m| m == "private_key_jwt"),
        "a deployment whose host installed an ES256 verifier must advertise private_key_jwt, or an \
         RFC 7523 client reading the document concludes it cannot authenticate that way: {:?}",
        doc.token_endpoint_auth_methods_supported
    );
    assert!(
        doc.token_endpoint_auth_signing_alg_values_supported
            .as_ref()
            .is_some_and(|algs| algs.iter().any(|a| a == "ES256")),
        "and it must name ES256 among the algorithms it accepts"
    );

    // IDEMPOTENT, which is what lets it run in a build where `from_config` already added these.
    // A document naming private_key_jwt twice would be a defect of its own.
    doc.es256_verification_is_available();
    assert_eq!(
        doc.token_endpoint_auth_methods_supported
            .iter()
            .filter(|m| *m == "private_key_jwt")
            .count(),
        1,
        "calling it twice must not duplicate the entry"
    );
}
