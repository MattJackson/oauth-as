// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 8414 authorization server metadata: the discovery document served at
//! `{issuer}/.well-known/oauth-authorization-server`.
//!
//! This document is the only thing a client is required to fetch before it can talk to us, so
//! everything in it is load-bearing: an advertised endpoint that does not answer, or an
//! advertised capability the server rejects, is a lie the client cannot recover from. The
//! document is therefore DERIVED from [`ServerConfig`] rather than hand-written, and the
//! capability lists are derived from what this crate actually implements.
//!
//! The type is pure data with a `serde` shape. Serving it is the host's job (or the optional
//! `http` feature's); the library forces no HTTP stack on anyone.

use serde::{Deserialize, Serialize};

use crate::grant::DEVICE_CODE_GRANT_URN;
use crate::server::ServerConfig;

/// The well-known URI suffix RFC 8414 section 3 registers for this document.
///
/// This is the BARE form, correct only for an issuer with no path component. Use
/// [`well_known_path`] to place the document for a given issuer: section 3.1 does not append the
/// issuer's path to this string, it inserts this string between the host and that path.
pub const WELL_KNOWN_PATH: &str = "/.well-known/oauth-authorization-server";

/// The path component of an issuer identifier: `""` for `https://as.example`, `"/tenant1"` for
/// `https://as.example/tenant1`.
///
/// Parsed by hand rather than with a URL crate because the whole shape needed is "everything from
/// the first `/` after the authority", and this crate's dependency policy does not admit a URL
/// parser for one line of string handling. A trailing slash is trimmed so
/// `https://as.example/tenant1/` and `https://as.example/tenant1` agree.
pub fn issuer_path(issuer: &str) -> &str {
    let authority = match issuer.find("://") {
        Some(i) => &issuer[i + 3..],
        // A scheme-less string is not a shape RFC 8414 admits (section 2 requires an https URL),
        // so it is read as a bare authority plus path rather than rejected here: the router is
        // what refuses to serve an incoherent configuration.
        None => issuer,
    };
    match authority.find('/') {
        Some(i) => authority[i..].trim_end_matches('/'),
        None => "",
    }
}

/// Where this document lives for `issuer`, as an absolute path from the origin's root.
///
/// RFC 8414 section 3.1 is explicit and frequently got wrong: the well-known string is inserted
/// BETWEEN the host and the issuer's path component. For issuer `https://as.example/tenant1` the
/// document is at `https://as.example/.well-known/oauth-authorization-server/tenant1`, NOT at
/// `https://as.example/tenant1/.well-known/...` and NOT at the bare well-known path.
///
/// Getting this wrong is a security matter and not only a routing one. Section 3.3 requires the
/// client to check that the `issuer` member equals the URL the document was retrieved from, and
/// that check is a mix-up countermeasure (RFC 9700 section 4.14). A document served where the
/// check cannot pass teaches clients to skip it. In a multi-tenant deployment it is also a
/// correctness bug outright: every tenant would collide on the one bare path.
pub fn well_known_path(issuer: &str) -> String {
    let path = issuer_path(issuer);
    let mut out = String::with_capacity(WELL_KNOWN_PATH.len() + path.len());
    out.push_str(WELL_KNOWN_PATH);
    out.push_str(path);
    out
}

/// An RFC 8414 authorization server metadata document.
///
/// Optional members are `Option` and are OMITTED when absent, never serialized as `null`: RFC
/// 8414 defines member types, and `null` is not one of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    /// REQUIRED (section 2). The AS's issuer identifier; must equal the URL this document was
    /// retrieved from, minus the well-known path (section 3.3), and carries no query or fragment.
    pub issuer: String,
    /// REQUIRED for an AS supporting the authorization code grant (section 2).
    pub authorization_endpoint: String,
    /// REQUIRED unless only the implicit grant is supported, which OAuth 2.1 removes (section 2).
    pub token_endpoint: String,
    /// RFC 8628 section 4: how an AS advertises device grant support.
    pub device_authorization_endpoint: String,
    /// RFC 7662 section 2. Present when this server serves introspection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
    /// RFC 7009 section 2. Present when this server serves revocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    /// RFC 8414 section 2. Present only when the server issues signed (JWT) access tokens; an
    /// AS with opaque tokens has no keys to publish and must not pretend otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// OPTIONAL (section 2). Omitted when the host has not declared a scope catalogue, since an
    /// empty array would claim the server supports no scopes at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    /// REQUIRED (section 2). Always exactly `["code"]`: OAuth 2.1 removes the implicit grant.
    pub response_types_supported: Vec<String>,
    /// OPTIONAL (section 2). This server returns the code in the query string.
    pub response_modes_supported: Vec<String>,
    /// OPTIONAL (section 2), and worth stating: it is how a client learns the device grant is
    /// available without probing.
    pub grant_types_supported: Vec<String>,
    /// OPTIONAL (section 2). Exactly the methods the token endpoint accepts.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// RFC 7636 / RFC 8414 section 2. Always exactly `["S256"]`: `plain` is not implemented, and
    /// advertising it would invite a downgrade this server cannot honor.
    pub code_challenge_methods_supported: Vec<String>,
    /// OPTIONAL (section 2). A page of human-readable developer documentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_documentation: Option<String>,
}

/// Join an issuer and an absolute path without producing a double slash.
fn under_issuer(issuer: &str, path: &str) -> String {
    format!("{}{}", issuer.trim_end_matches('/'), path)
}

/// The `jwks_uri` to advertise, which RFC 8414 section 2 ties to keys this server actually signs
/// with.
///
/// With the `jwt` feature the truth about whether anything is signed lives in
/// [`ServerConfig::access_token_format`], so it, and not the bare `jwks_uri` field, decides. Both
/// halves of that matter: advertising a key set for an AS whose tokens are opaque points every
/// resource server at keys that verify nothing, and signing without advertising leaves them no way
/// to verify at all (RFC 9068 section 4 expects the key to be discoverable).
#[cfg(feature = "jwt")]
fn advertised_jwks_uri(config: &ServerConfig) -> Option<String> {
    match &config.access_token_format {
        crate::jwt::AccessTokenFormat::Opaque => None,
        // `JwtConfig::with_jwks_uri` is the specific statement, so it wins; the `jwks_uri` field
        // remains the fallback for a host that configured it there before enabling signing.
        crate::jwt::AccessTokenFormat::Jwt(jwt) => jwt
            .jwks_uri()
            .map(str::to_string)
            .or_else(|| config.jwks_uri.clone()),
    }
}

/// Without the `jwt` feature this crate signs nothing, so the only possible source is the host's
/// own declaration: it is publishing keys some other component holds, and serving that document
/// is entirely its own affair.
#[cfg(not(feature = "jwt"))]
fn advertised_jwks_uri(config: &ServerConfig) -> Option<String> {
    config.jwks_uri.clone()
}

impl AuthorizationServerMetadata {
    /// Derive the document from the server's configuration.
    ///
    /// Endpoints the host did not override default to conventional paths under the issuer, so a
    /// host that configures only an issuer still publishes a coherent, self-consistent document.
    pub fn from_config(config: &ServerConfig) -> Self {
        let iss = config.issuer.trim_end_matches('/').to_string();
        let endpoint = |override_: &Option<String>, path: &str| {
            override_
                .clone()
                .unwrap_or_else(|| under_issuer(&iss, path))
        };
        AuthorizationServerMetadata {
            authorization_endpoint: endpoint(&config.authorization_endpoint, "/authorize"),
            token_endpoint: endpoint(&config.token_endpoint, "/token"),
            device_authorization_endpoint: endpoint(
                &config.device_authorization_endpoint,
                "/device_authorization",
            ),
            introspection_endpoint: Some(endpoint(&config.introspection_endpoint, "/introspect")),
            revocation_endpoint: Some(endpoint(&config.revocation_endpoint, "/revoke")),
            jwks_uri: advertised_jwks_uri(config),
            scopes_supported: config.scopes_supported.clone(),
            issuer: iss,
            response_types_supported: vec!["code".to_string()],
            response_modes_supported: vec!["query".to_string()],
            // Exactly the grants AuthorizationServer::token will honor.
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
                "client_credentials".to_string(),
                DEVICE_CODE_GRANT_URN.to_string(),
            ],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
                // RFC 8414 s2: the registered value a public client uses. This server accepts
                // public clients, so omitting it would understate what it does.
                "none".to_string(),
            ],
            code_challenge_methods_supported: vec!["S256".to_string()],
            service_documentation: config.service_documentation.clone(),
        }
    }
}

#[cfg(test)]
#[path = "tests/metadata.rs"]
mod tests;
