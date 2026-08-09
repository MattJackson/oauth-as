// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9728 protected resource metadata: the document a RESOURCE server publishes, and the one
//! member RFC 9728 adds to the AUTHORIZATION SERVER's own RFC 8414 document.
//!
//! Keeping the two halves in one file is deliberate, because the boundary between them is the
//! thing most likely to be got wrong by a reader who assumes this crate is a resource server. It
//! is not. Section 3.1 places the resource's document under the RESOURCE's identifier, and this
//! crate only produces the type; section 4 is the only part an authorization server publishes.
#![cfg(feature = "resource-metadata")]

use oauth_as::{
    AuthorizationServerMetadata, BearerMethod, ProtectedResourceConfig, ProtectedResourceMetadata,
    ServerConfig, PROTECTED_RESOURCE_WELL_KNOWN_PATH,
};
use serde_json::{json, Value};

const RESOURCE: &str = "https://rs.example/api";
const ISSUER: &str = "https://as.example";

fn config() -> ProtectedResourceConfig {
    ProtectedResourceConfig::new(RESOURCE, ISSUER)
}

fn document(config: &ProtectedResourceConfig) -> Value {
    serde_json::to_value(ProtectedResourceMetadata::from_config(config)).unwrap()
}

/// RFC 9728 s2 makes exactly one member REQUIRED, and s3.3 makes it the one a client checks: the
/// `resource` value MUST be identical to the identifier the well-known suffix was inserted into,
/// or the document MUST NOT be used.
#[test]
fn the_resource_member_is_required_and_is_the_configured_identifier() {
    let doc = document(&config());
    assert_eq!(doc["resource"], json!(RESOURCE));
    let value = doc["resource"].as_str().unwrap();
    assert!(!value.contains('#'), "RFC 9728 s2: no fragment");
}

/// The registered suffix, verbatim. A near-miss spelling means every client looks in a place the
/// resource does not publish, which reads to them as "this is not a protected resource at all".
#[test]
fn the_well_known_suffix_is_the_registered_one() {
    assert_eq!(
        PROTECTED_RESOURCE_WELL_KNOWN_PATH,
        "/.well-known/oauth-protected-resource"
    );
    assert_eq!(
        ProtectedResourceMetadata::from_config(&config()).well_known_path(),
        "/.well-known/oauth-protected-resource/api"
    );
}

/// The point of the document: a client that has only a resource identifier learns which
/// authorization server to go to. s7.6 is why the member is a claim to be cross-checked rather
/// than followed blindly, which is what the AS-side `protected_resources` member below is for.
#[test]
fn the_authorization_server_is_advertised_by_its_issuer_identifier() {
    let doc = document(&config());
    assert_eq!(doc["authorization_servers"], json!([ISSUER]));
}

/// RFC 6750 s2.1 is the only presentation method OAuth 2.1 keeps, so it is the only one a default
/// configuration claims. A resource that also accepts the query form (s2.3, SHOULD NOT) has to say
/// so on purpose.
#[test]
fn bearer_methods_default_to_the_header_form_and_use_the_registered_spellings() {
    let doc = document(&config());
    assert_eq!(doc["bearer_methods_supported"], json!(["header"]));

    let mut cfg = config();
    cfg.bearer_methods_supported = vec![
        BearerMethod::Header,
        BearerMethod::Body,
        BearerMethod::Query,
    ];
    let doc = document(&cfg);
    assert_eq!(
        doc["bearer_methods_supported"],
        json!(["header", "body", "query"])
    );
}

/// Every optional member the host did not declare is OMITTED, never serialized as `null`. RFC 9728
/// s2 defines member types and `null` is not one of them; the AS metadata tests pin the same rule
/// for the RFC 8414 document and this document is read by the same clients.
#[test]
fn undeclared_optional_members_are_omitted_and_never_null() {
    let doc = document(&config());
    for absent in [
        "jwks_uri",
        "scopes_supported",
        "resource_signing_alg_values_supported",
        "resource_name",
        "resource_documentation",
        "resource_policy_uri",
        "resource_tos_uri",
        "tls_client_certificate_bound_access_tokens",
        "authorization_details_types_supported",
        "dpop_signing_alg_values_supported",
        "dpop_bound_access_tokens_required",
        "signed_metadata",
    ] {
        assert!(
            doc.get(absent).is_none(),
            "{absent} must be omitted rather than null when it was not declared"
        );
    }
    let text = serde_json::to_string(&ProtectedResourceMetadata::from_config(&config())).unwrap();
    assert!(!text.contains("null"), "no member serializes as null");
}

/// A declared capability appears; an empty declaration does NOT become an empty array. `[]` says
/// "I support none of these", which is a different sentence from silence, and for the two boolean
/// members s2 already supplies `false` as the default when they are absent.
#[test]
fn a_declared_capability_appears_and_an_empty_one_stays_absent() {
    let mut cfg = config();
    cfg.scopes_supported = Some(vec!["read".into(), "write".into()]);
    cfg.resource_name = Some("Example API".into());
    cfg.resource_documentation = Some("https://rs.example/docs".into());
    cfg.resource_signing_alg_values_supported = vec!["ES256".into()];
    cfg.dpop_bound_access_tokens_required = true;
    cfg.dpop_signing_alg_values_supported = vec!["ES256".into()];
    let doc = document(&cfg);
    assert_eq!(doc["scopes_supported"], json!(["read", "write"]));
    assert_eq!(doc["resource_name"], json!("Example API"));
    assert_eq!(
        doc["resource_documentation"],
        json!("https://rs.example/docs")
    );
    assert_eq!(
        doc["resource_signing_alg_values_supported"],
        json!(["ES256"])
    );
    assert_eq!(doc["dpop_bound_access_tokens_required"], json!(true));
    assert_eq!(doc["dpop_signing_alg_values_supported"], json!(["ES256"]));
    // Still off, still absent rather than false.
    assert!(doc
        .get("tls_client_certificate_bound_access_tokens")
        .is_none());

    let mut empty = config();
    empty.authorization_servers = Vec::new();
    empty.bearer_methods_supported = Vec::new();
    let doc = document(&empty);
    assert!(doc.get("authorization_servers").is_none());
    assert!(doc.get("bearer_methods_supported").is_none());
}

/// s2.2 signed metadata is passed through and never manufactured: signing it needs the RESOURCE's
/// key, which an authorization server does not hold, and s7.9 makes the signed and unsigned
/// documents carry different trust.
#[test]
fn signed_metadata_is_passed_through_and_never_invented() {
    assert!(document(&config()).get("signed_metadata").is_none());
    let mut cfg = config();
    cfg.signed_metadata = Some("eyJhbGciOiJFUzI1NiJ9.e30.sig".into());
    assert_eq!(
        document(&cfg)["signed_metadata"],
        json!("eyJhbGciOiJFUzI1NiJ9.e30.sig")
    );
}

/// The document is DERIVED from configuration for the same reason the RFC 8414 one is: an
/// advertised capability the resource does not have is a lie the client cannot recover from. A
/// round trip is what proves the type is the whole document rather than a lossy view of it.
#[test]
fn the_document_round_trips_through_its_own_wire_form() {
    let mut cfg = config();
    cfg.scopes_supported = Some(vec!["read".into()]);
    cfg.jwks_uri = Some("https://rs.example/jwks".into());
    cfg.tls_client_certificate_bound_access_tokens = true;
    let original = ProtectedResourceMetadata::from_config(&cfg);
    let text = serde_json::to_string(&original).unwrap();
    let parsed: ProtectedResourceMetadata = serde_json::from_str(&text).unwrap();
    assert_eq!(original, parsed);
}

// --------------------------------------------------------- the AUTHORIZATION SERVER half (s4)

/// RFC 9728 s4 is the ONLY part of RFC 9728 an authorization server publishes: the resources it
/// issues tokens for, so a client can cross-check the `authorization_servers` claim it read from a
/// resource's document against the AS's own answer (s7.6).
#[test]
fn the_authorization_server_document_can_name_its_protected_resources() {
    let mut cfg = ServerConfig::new(ISSUER, "https://as.example/device");
    assert!(
        serde_json::to_value(AuthorizationServerMetadata::from_config(&cfg))
            .unwrap()
            .get("protected_resources")
            .is_none(),
        "omitted rather than empty when the host declared none: an empty array would say this AS \
         protects nothing, which is a different claim from silence"
    );

    cfg.protected_resources = Some(vec![RESOURCE.to_string()]);
    let doc = serde_json::to_value(AuthorizationServerMetadata::from_config(&cfg)).unwrap();
    assert_eq!(doc["protected_resources"], json!([RESOURCE]));
}
