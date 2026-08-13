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

/// A grant the CONFIGURATION cannot serve must not be advertised, which is the same rule that
/// keeps an unserved endpoint out of the document.
///
/// `ServerConfig::issue_refresh_tokens` decides whether this server ever mints a refresh token.
/// With it off no client can ever hold one, so RFC 6749 section 6 is unreachable: a client that
/// read `refresh_token` here would build a refresh loop it can never enter, and would discover it
/// only by never being given a `refresh_token` in a token response — which reads as a bug in the
/// client, not as a deliberate server policy.
#[test]
fn refresh_token_is_advertised_only_when_the_server_issues_one() {
    let doc = document();
    let grants = doc["grant_types_supported"].as_array().unwrap();
    assert!(
        grants.contains(&json!("refresh_token")),
        "the default configuration does issue refresh tokens"
    );

    let mut cfg = config();
    cfg.issue_refresh_tokens = false;
    let doc = serde_json::to_value(AuthorizationServerMetadata::from_config(&cfg)).unwrap();
    let grants = doc["grant_types_supported"].as_array().unwrap();
    assert!(
        !grants.contains(&json!("refresh_token")),
        "a server configured never to issue a refresh token must not advertise the grant that \
         redeems one: {grants:?}"
    );
    // The rest of the list is untouched: this is one member coming out, not the list being
    // rebuilt differently.
    assert!(grants.contains(&json!("authorization_code")));
    assert!(grants.contains(&json!("client_credentials")));
    assert!(grants.contains(&json!("urn:ietf:params:oauth:grant-type:device_code")));
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

/// A document that OMITS the two boolean members must still parse.
///
/// Both are `bool` rather than `Option<bool>` on this type, and both are OPTIONAL on the wire with
/// a specified absent-means-false default: RFC 9207 section 3 for
/// `authorization_response_iss_parameter_supported`, RFC 8705 section 3.3 for
/// `tls_client_certificate_bound_access_tokens`. Without `#[serde(default)]` a missing member is a
/// hard parse error, so this type could not read a document from any other authorization server,
/// nor the document THIS crate emits from a build with a different feature set: a non-`mtls` build
/// omits the second member entirely, and the `mtls` build's own type then refuses to read it.
///
/// The type doc claims "`Deserialize` is derived here and is unaffected, so a client-side or
/// test-side consumer parsing one still works". That is the claim under test.
#[test]
fn a_document_omitting_the_optional_booleans_still_parses() {
    let mut doc = document();
    let object = doc.as_object_mut().expect("the document is a JSON object");
    object.remove("authorization_response_iss_parameter_supported");
    object.remove("tls_client_certificate_bound_access_tokens");

    let parsed: Result<AuthorizationServerMetadata, _> = serde_json::from_value(doc);
    let parsed = match parsed {
        Ok(m) => m,
        Err(e) => panic!(
            "RFC 9207 s3 and RFC 8705 s3.3 both make their member OPTIONAL with a default of \
             false, so a document that omits it is not malformed: {e}"
        ),
    };
    assert!(
        !parsed.authorization_response_iss_parameter_supported,
        "RFC 9207 s3: absent means false, not true"
    );
    #[cfg(feature = "mtls")]
    assert!(
        !parsed.tls_client_certificate_bound_access_tokens,
        "RFC 8705 s3.3: absent means false, not true"
    );
}

/// `introspection_endpoint` is advertised only where the host asked for it.
///
/// RFC 7662's primary consumer is a RESOURCE SERVER, and this server has no resource-server
/// channel: `AuthorizationServer::introspection_response_with_credential` answers
/// `{"active":false}` to every authenticated caller that is not the token's own client. Publishing
/// the member unconditionally therefore told every deployment's resource servers that a facility
/// exists which cannot answer them, and this module's opening rule is that an advertised
/// capability the server rejects is a lie the client cannot recover from.
///
/// The opt-in is `ServerConfig::introspection_endpoint`: a host that names the URL is a host that
/// has decided to publish the endpoint. The bundled router still SERVES the path either way (a
/// client introspecting its own token is the case that does work); it just stops promising it.
#[test]
fn introspection_is_advertised_only_when_the_host_named_the_endpoint() {
    assert!(
        document().get("introspection_endpoint").is_none(),
        "RFC 7662 s2: this server answers only the token's own client, so the member is not \
         published until a host opts in"
    );

    let mut cfg = config();
    cfg.introspection_endpoint = Some("https://as.example.com/introspect".to_string());
    let doc = serde_json::to_value(AuthorizationServerMetadata::from_config(&cfg)).unwrap();
    assert_eq!(
        doc["introspection_endpoint"],
        json!("https://as.example.com/introspect"),
        "a host that named the endpoint gets it advertised verbatim"
    );
}
