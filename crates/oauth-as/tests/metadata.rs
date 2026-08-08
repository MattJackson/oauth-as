// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 8414 authorization server metadata: the discovery document is the contract every other
//! party reads before it talks to us, so its required members, its OAuth 2.1 constraints, and its
//! omission behavior are pinned here rather than left to the serializer's defaults.

use oauth_as::{AuthorizationServerMetadata, ServerConfig};
use serde_json::{json, Value};

fn config() -> ServerConfig {
    ServerConfig::new("https://as.example.com", "https://as.example.com/device")
}

fn document() -> Value {
    serde_json::to_value(AuthorizationServerMetadata::from_config(&config())).unwrap()
}

/// RFC 8414 section 2 marks these REQUIRED, and RFC 8628 section 4 adds the device endpoint for
/// any AS that supports the device grant.
#[test]
fn required_members_are_present() {
    let doc = document();
    for key in [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "device_authorization_endpoint",
        "response_types_supported",
    ] {
        assert!(
            doc.get(key).is_some(),
            "RFC 8414 s2 / RFC 8628 s4 require {key}"
        );
    }
}

/// RFC 8414 section 3.3: the issuer in the document must equal the issuer the document was
/// fetched from, and section 2 forbids a query or fragment on it.
#[test]
fn issuer_is_the_configured_issuer_with_no_query_or_fragment() {
    let doc = document();
    assert_eq!(doc["issuer"], json!("https://as.example.com"));
    let iss = doc["issuer"].as_str().unwrap();
    assert!(!iss.contains('?') && !iss.contains('#'), "RFC 8414 s2");
}

/// OAuth 2.1 removes the implicit grant, so `token` must never be advertised.
#[test]
fn response_types_are_code_only() {
    let doc = document();
    assert_eq!(doc["response_types_supported"], json!(["code"]));
}

/// OAuth 2.1 makes S256 the baseline and this crate does not implement `plain`; advertising
/// `plain` would invite a downgrade the server cannot honor anyway.
#[test]
fn only_s256_pkce_is_advertised() {
    let doc = document();
    assert_eq!(doc["code_challenge_methods_supported"], json!(["S256"]));
}

/// RFC 8628 registers the grant type as a URN; a shortened spelling is a different grant type.
#[test]
fn device_grant_is_advertised_by_its_registered_urn() {
    let doc = document();
    let grants = doc["grant_types_supported"].as_array().unwrap();
    assert!(grants.contains(&json!("urn:ietf:params:oauth:grant-type:device_code")));
    assert!(grants.contains(&json!("authorization_code")));
    assert!(grants.contains(&json!("refresh_token")));
}

/// Endpoints default to conventional paths under the issuer so a host that sets only the issuer
/// still publishes a coherent document.
#[test]
fn endpoints_default_under_the_issuer() {
    let doc = document();
    assert_eq!(
        doc["authorization_endpoint"],
        json!("https://as.example.com/authorize")
    );
    assert_eq!(doc["token_endpoint"], json!("https://as.example.com/token"));
    assert_eq!(
        doc["device_authorization_endpoint"],
        json!("https://as.example.com/device_authorization")
    );
}

/// A trailing slash on the issuer must not produce a double slash in derived endpoints.
#[test]
fn trailing_slash_on_the_issuer_does_not_double_up() {
    let cfg = ServerConfig::new("https://as.example.com/", "https://as.example.com/device");
    let doc = serde_json::to_value(AuthorizationServerMetadata::from_config(&cfg)).unwrap();
    assert_eq!(
        doc["token_endpoint"],
        json!("https://as.example.com/token"),
        "derived endpoints must not contain \"//\""
    );
}

/// A host that overrides an endpoint gets its own value, not the derived one.
#[test]
fn hosts_can_override_any_endpoint() {
    let mut cfg = config();
    cfg.token_endpoint = Some("https://tokens.example.net/oauth/token".into());
    let doc = serde_json::to_value(AuthorizationServerMetadata::from_config(&cfg)).unwrap();
    assert_eq!(
        doc["token_endpoint"],
        json!("https://tokens.example.net/oauth/token")
    );
}

/// Absent optional members must be omitted entirely. A `null` is not "unsupported"; it is a
/// member of the wrong type, and strict consumers are entitled to reject it.
#[test]
fn absent_optional_members_are_omitted_not_null() {
    let doc = document();
    assert!(doc.get("jwks_uri").is_none(), "opaque tokens: no JWKS");
    for (key, value) in doc.as_object().unwrap() {
        assert!(!value.is_null(), "member {key} serialized as null");
    }
}

/// The document must advertise the client authentication methods the token endpoint actually
/// accepts; advertising one we reject is a lie a client cannot recover from.
#[test]
fn advertised_client_auth_methods_are_the_ones_we_accept() {
    let doc = document();
    let methods = doc["token_endpoint_auth_methods_supported"]
        .as_array()
        .unwrap();
    assert!(methods.contains(&json!("client_secret_basic")));
    assert!(methods.contains(&json!("client_secret_post")));
    assert!(
        methods.contains(&json!("none")),
        "public clients authenticate with no secret (RFC 8414 s2 \"none\")"
    );
}
