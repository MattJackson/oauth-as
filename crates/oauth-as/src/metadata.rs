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
    /// RFC 7591 section 3 / RFC 8414 section 2. Present ONLY when the host enabled dynamic client
    /// registration, and absent otherwise.
    ///
    /// The conditional is the whole point of the member. RFC 8414 section 2 makes it optional, and
    /// a client reads its presence as "I may register here"; advertising it on a server that
    /// refuses every registration would be an endpoint that 404s or 401s for reasons a client
    /// cannot act on. The reverse is worse: RFC 7591 section 5 makes an unadvertised open endpoint
    /// no safer than an advertised one, so this must not become the thing a host relies on to keep
    /// registration private. It reports the configuration; it does not enforce it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    /// RFC 8414 section 2. Present only when the server issues signed (JWT) access tokens; an
    /// AS with opaque tokens has no keys to publish and must not pretend otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// OPTIONAL (section 2). Omitted when the host has not declared a scope catalogue, since an
    /// empty array would claim the server supports no scopes at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    /// RFC 9126 section 5. Present ONLY when the host enabled PAR
    /// ([`crate::server::ServerConfig::par`]): section 5 says its presence is sufficient for a
    /// client to decide it may use PAR, so advertising an endpoint that is not served would be a
    /// promise this server cannot keep.
    #[cfg(feature = "par")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<String>,
    /// RFC 9126 section 5. `Some(false)` states the default explicitly when PAR is offered;
    /// omitted entirely when PAR is off, since section 5 gives an absent member the meaning
    /// `false` and a server with no PAR endpoint has nothing to require.
    #[cfg(feature = "par")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_pushed_authorization_requests: Option<bool>,
    /// RFC 9101 section 4: the `alg` values this server will verify a request object with.
    /// Present only when signed request objects are enabled.
    #[cfg(feature = "jar")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    /// RFC 9101 section 10.5, registered by its section 9.2. Present only when signed request
    /// objects are enabled; `true` means a plain RFC 6749 authorization request is refused, which
    /// is the downgrade that section describes.
    #[cfg(feature = "jar")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_signed_request_object: Option<bool>,
    /// REQUIRED (section 2). Always exactly `["code"]`: OAuth 2.1 removes the implicit grant.
    pub response_types_supported: Vec<String>,
    /// OPTIONAL (section 2). This server returns the code in the query string.
    pub response_modes_supported: Vec<String>,
    /// OPTIONAL (section 2), and worth stating: it is how a client learns the device grant is
    /// available without probing.
    pub grant_types_supported: Vec<String>,
    /// OPTIONAL (section 2). Exactly the methods the token endpoint accepts.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// RFC 8414 section 2. The signing algorithms the token endpoint accepts on an RFC 7523
    /// client assertion.
    ///
    /// Section 2 makes this REQUIRED whenever `token_endpoint_auth_methods_supported` contains
    /// `client_secret_jwt` or `private_key_jwt`, and the requirement is not bureaucratic: a client
    /// cannot construct an assertion at all without knowing which algorithm the server will accept,
    /// and guessing wrong is indistinguishable from a wrong key. Absent when this build does not
    /// have the `client_assertion` feature, in which case neither method is advertised either.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// RFC 9449 section 5.1: the JWS algorithms this server will verify a DPoP proof under.
    ///
    /// Its PRESENCE is how a client learns DPoP is available here at all, so it appears only when
    /// this build can actually verify a proof. Advertising it on a server that would refuse every
    /// proof is worse than omitting it, because a client that acts on it has no way to discover the
    /// mistake except by failing to get a token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    /// RFC 7636 / RFC 8414 section 2. Always exactly `["S256"]`: `plain` is not implemented, and
    /// advertising it would invite a downgrade this server cannot honor.
    pub code_challenge_methods_supported: Vec<String>,
    /// OPTIONAL (section 2). A page of human-readable developer documentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_documentation: Option<String>,
    /// RFC 9728 section 4. The resource identifiers of the protected resources this AS
    /// issues tokens for, so a client that fetched a resource's own RFC 9728 document can
    /// cross-check that the AS agrees the relationship exists (section 7.6: an
    /// `authorization_servers` entry is a claim made by the RESOURCE, and believing it
    /// unchecked is how a resource points clients at an AS that never heard of it).
    ///
    /// OPTIONAL, and omitted rather than empty when the host declared none: an empty array
    /// would state that this AS protects nothing, which is a different claim from silence.
    #[cfg(feature = "resource-metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_resources: Option<Vec<String>>,
    /// RFC 9396 section 10. The authorization details TYPES this server will accept, so a
    /// client learns what it may ask for rather than discovering it from a refusal.
    ///
    /// Omitted rather than empty when the host declared none, exactly as `scopes_supported`
    /// is: an empty array claims the server supports no types at all, which is a different
    /// statement from silence and would be read as one. Note that the SERVER's behaviour for
    /// the two is not different: an undeclared catalogue refuses every type (section 5), so
    /// this member never overstates what the server will do.
    #[cfg(feature = "rar")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details_types_supported: Option<Vec<String>>,
    /// RFC 9207 section 3. Always `true` from this server, and NOT an `Option`.
    ///
    /// The member exists so a client can decide whether it is allowed to REQUIRE the `iss`
    /// authorization response parameter, which is the mix-up countermeasure RFC 9700 section 4.4
    /// names. RFC 9207 section 3 says its default when absent is `false`, so omitting it would tell
    /// every client that the countermeasure is unavailable here even though this server always
    /// sends the parameter. Publishing a constant `true` is only honest because
    /// [`crate::authorization::AuthorizationResponse`] and
    /// [`crate::authorization::AuthorizationErrorRedirect`] both carry `iss` unconditionally: the
    /// claim and the behaviour cannot drift apart, because neither type can express its absence.
    ///
    /// RFC 8707 (resource indicators), which this server also implements, registers NO metadata
    /// member of its own, so there is deliberately nothing here to advertise it.
    pub authorization_response_iss_parameter_supported: bool,
    /// RFC 8705 section 3.3. Always `true` in a build with the `mtls` feature, and absent
    /// entirely without it, which is the same honesty rule `jwks_uri` follows.
    ///
    /// Constant rather than configurable because the behaviour is: with the feature compiled
    /// in, an access token issued over a connection whose certificate the host passed in is
    /// ALWAYS bound to it (RFC 8705 section 3), so there is no configuration under which the
    /// claim could be false. Section 3.3's default when the member is absent is `false`, so a
    /// build without the feature says nothing and means nothing, which is correct.
    #[cfg(feature = "mtls")]
    pub tls_client_certificate_bound_access_tokens: bool,
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
        // Exactly the grants AuthorizationServer::token will honor. `mut` only when the
        // optional exchange grant is compiled in, which is what the allow below is for:
        // advertising a grant this build does not implement is the lie this document exists
        // to avoid, so the list is built rather than written out once for each feature set.
        #[allow(unused_mut)]
        let mut grant_types_supported = vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
            "client_credentials".to_string(),
            DEVICE_CODE_GRANT_URN.to_string(),
        ];
        // RFC 8693 s2.1 registers the URN; RFC 8414 s2 is what makes advertising it the way a
        // client learns the grant is available without probing.
        #[cfg(feature = "token-exchange")]
        grant_types_supported.push(crate::grant::TOKEN_EXCHANGE_GRANT_URN.to_string());
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
            registration_endpoint: config
                .registration
                .as_ref()
                .map(|r| endpoint(&r.registration_endpoint, "/register")),
            jwks_uri: advertised_jwks_uri(config),
            scopes_supported: config.scopes_supported.clone(),
            #[cfg(feature = "par")]
            pushed_authorization_request_endpoint: config
                .par
                .as_ref()
                .map(|par| par.endpoint(&iss)),
            #[cfg(feature = "par")]
            require_pushed_authorization_requests: config
                .par
                .as_ref()
                .map(|par| par.require_pushed_authorization_requests),
            #[cfg(feature = "jar")]
            request_object_signing_alg_values_supported: config.jar.as_ref().map(|_| {
                crate::par::REQUEST_OBJECT_SIGNING_ALGS
                    .iter()
                    .map(|alg| alg.to_string())
                    .collect()
            }),
            #[cfg(feature = "jar")]
            require_signed_request_object: config
                .jar
                .as_ref()
                .map(|jar| jar.require_signed_request_object),
            issuer: iss,
            response_types_supported: vec!["code".to_string()],
            response_modes_supported: vec!["query".to_string()],
            // Exactly the grants AuthorizationServer::token will honor.
            grant_types_supported,
            token_endpoint_auth_methods_supported: {
                // `mut` only matters under `client_assertion`, which is what the allow is for. The
                // alternative is two copies of the list, which is how two lists drift apart.
                #[allow(unused_mut)]
                let mut methods = vec![
                    "client_secret_basic".to_string(),
                    "client_secret_post".to_string(),
                    // RFC 8414 s2: the registered value a public client uses. This server accepts
                    // public clients, so omitting it would understate what it does.
                    "none".to_string(),
                ];
                // RFC 7523 s2.2, advertised exactly when this build can verify an assertion. The
                // list and the verifier are derived from the same feature, so they cannot drift.
                #[cfg(feature = "client_assertion")]
                {
                    methods.push(crate::client_assertion::CLIENT_SECRET_JWT.to_string());
                    methods.push(crate::client_assertion::PRIVATE_KEY_JWT.to_string());
                }
                // RFC 8705 s2.1.1 and s2.2.1 register these two, advertised exactly when this
                // build can actually check a certificate. Both halves matter: advertising a
                // method the endpoint rejects is a lie a client cannot recover from, and staying
                // silent about one it accepts is how a client ends up sending a shared secret it
                // did not need to have.
                #[cfg(feature = "mtls")]
                {
                    methods.push(crate::mtls::TLS_CLIENT_AUTH.to_string());
                    methods.push(crate::mtls::SELF_SIGNED_TLS_CLIENT_AUTH.to_string());
                }
                methods
            },
            #[cfg(feature = "client_assertion")]
            token_endpoint_auth_signing_alg_values_supported: Some(
                crate::client_assertion::ASSERTION_SIGNING_ALGS
                    .iter()
                    .map(|a| a.to_string())
                    .collect(),
            ),
            #[cfg(not(feature = "client_assertion"))]
            token_endpoint_auth_signing_alg_values_supported: None,
            #[cfg(feature = "dpop")]
            dpop_signing_alg_values_supported: Some(
                crate::dpop::DPOP_SIGNING_ALG_VALUES_SUPPORTED
                    .iter()
                    .map(|a| a.to_string())
                    .collect(),
            ),
            #[cfg(not(feature = "dpop"))]
            dpop_signing_alg_values_supported: None,
            code_challenge_methods_supported: vec!["S256".to_string()],
            service_documentation: config.service_documentation.clone(),
            #[cfg(feature = "resource-metadata")]
            protected_resources: config.protected_resources.clone(),
            #[cfg(feature = "rar")]
            authorization_details_types_supported: config
                .authorization_details_types_supported
                .clone(),
            authorization_response_iss_parameter_supported: true,
            #[cfg(feature = "mtls")]
            tls_client_certificate_bound_access_tokens: true,
        }
    }
}

#[cfg(test)]
#[path = "tests/metadata.rs"]
mod tests;
