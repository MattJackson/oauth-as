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
/// `#[non_exhaustive]`: five features (`par`, `jar`, `rar`, `mtls`, `resource-metadata`) each add a
/// member, which is what an RFC 8414 document IS: the list of what this build can do. A host builds
/// this with [`AuthorizationServerMetadata::from_config`], which is the only way to get a document
/// that agrees with the server that will answer the requests it advertises; a literal written by
/// hand is a document that describes a server nobody has to match. `Deserialize` is derived here
/// and is unaffected, so a client-side or test-side consumer parsing one still works.
#[non_exhaustive]
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
    /// RFC 7662 section 2. Present ONLY when the host named
    /// [`ServerConfig::introspection_endpoint`], and absent otherwise.
    ///
    /// # Why this one is opt-in and the others are not
    ///
    /// RFC 7662's primary consumer is a PROTECTED RESOURCE (section 1: "a protected resource to
    /// query an authorization server"), and through 0.9.1 this server has no channel for one.
    /// [`crate::AuthorizationServer::introspection_response_with_credential`] authenticates the
    /// caller as a registered CLIENT and then answers from a single arm,
    /// `Some(t) if t.client_id == client.client_id`; every other authenticated caller falls to
    /// `{"active": false}`, which section 2.2 defines as "the token is not active". So a resource
    /// server that did what the document told it to do is told, indistinguishably from the truth,
    /// that every live token it holds is dead.
    ///
    /// Advertising it unconditionally was therefore the exact thing this module's opening rule
    /// forbids: an advertised capability the server rejects. The client-facing half is real (a
    /// client may introspect its OWN token, and RFC 7662 section 2.1 permits that), and the
    /// bundled `http` router still ROUTES the endpoint in every build, so nothing that worked
    /// stops working. What changes is the PROMISE: it is now made only by a host that named the
    /// URL, which is a host that has read this and decided what its deployment means by it.
    ///
    /// The resource-server channel is 0.9.2 work. When it lands this member becomes unconditional
    /// again, and that is an addition to the document rather than a withdrawal.
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
    /// RFC 8414 section 2. With the `jwt` feature, present only when the server issues signed (JWT)
    /// access tokens; an AS with opaque tokens has no keys to publish and must not pretend
    /// otherwise.
    ///
    /// WITHOUT that feature this crate signs nothing, so the member says only what
    /// [`crate::server::ServerConfig::jwks_uri`] said: some other component holds the keys and
    /// publishes them. Nothing in this crate serves that document, which is why the bundled `http`
    /// service refuses to build when such a value points UNDER the issuer, where its own router
    /// would answer the request with a 404.
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
    /// have the `client-assertion` feature, in which case neither method is advertised either.
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
    ///
    /// `#[serde(default)]` on the way IN, and it is not a contradiction of the constant `true` on
    /// the way out. Serialization is this server describing itself; deserialization is this type
    /// reading someone else's document, and section 3 makes the member OPTIONAL there with a
    /// default of `false`. Without the attribute a `bool` field is a REQUIRED member to serde, so
    /// this type could not parse the document of any AS that omits it, which is every AS that does
    /// not implement RFC 9207. `false` is also the fail-closed reading: a client that cannot see
    /// the promise must not require the parameter.
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
    /// RFC 8705 section 3.3. Always `true` in a build with the `mtls` feature, and absent
    /// entirely without it, which is the same honesty rule `jwks_uri` follows.
    ///
    /// Constant rather than configurable because the CODE PATH is: with the feature compiled in,
    /// an access token issued for a request whose certificate the host passed in through
    /// [`crate::server::ClientCredential::certificate`] is ALWAYS bound to it (RFC 8705 section 3).
    /// There is no `ServerConfig` field that turns that off. Section 3.3's default when the member
    /// is absent is `false`, so a build without the feature says nothing and means nothing, which
    /// is correct.
    ///
    /// READ WHAT THE MEMBER THEREFORE MEANS, because it is narrower than it looks and the gap is
    /// reachable. It says this server BINDS a certificate it is given; it does not and cannot say
    /// that every token this deployment issues is bound, because whether a certificate arrives at
    /// all is the host's affair. This crate never terminates TLS. In particular the bundled `http`
    /// feature's router is handed an already-parsed request and passes `certificate: None` on every
    /// credential it builds (see the comment on `Credentials::credential` in `crate::http`), so a
    /// deployment whose only front door is that router publishes `true` here and binds nothing. A
    /// host offering RFC 8705 has to reach the server through its own handler with the certificate
    /// its terminator verified; a host that is not doing that should not compile the `mtls` feature
    /// in, because this member is the promise a client acts on when it decides to present one.
    ///
    /// `#[serde(default)]` for the reason its neighbour above carries one, and the case is not
    /// hypothetical here: a build WITHOUT this feature omits the member entirely, so an `mtls`
    /// build reading a non-`mtls` build's own document failed outright with `missing field
    /// "tls_client_certificate_bound_access_tokens"` until 0.9.1. Section 3.3's absent-means-false
    /// is both the RFC's answer and the fail-closed one: a client that cannot see the promise must
    /// not assume its token is bound.
    #[cfg(feature = "mtls")]
    #[serde(default)]
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
///
/// "Its own affair" has a boundary, and the 0.9.1 audit found it: a host on the bundled `http`
/// service does NOT serve this path, because every branch that routes a key set there is behind
/// the `jwt` feature. So a value under the issuer in such a build advertises an endpoint that
/// router can only 404, and `crate::http::ServiceBuilder::build` refuses it
/// (`ServiceError::JwksNotServable`) rather than publishing the promise. A host serving its own
/// listener is unaffected: this function reports the configuration and routes nothing.
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
        // Exactly the grants AuthorizationServer::token will honor: advertising a grant this
        // build does not implement, or this CONFIGURATION cannot serve, is the lie this document
        // exists to avoid, so the list is built rather than written out once for each feature set.
        let mut grant_types_supported = vec!["authorization_code".to_string()];
        // RFC 6749 s6 is only reachable for a client that HOLDS a refresh token, and
        // `ServerConfig::issue_refresh_tokens` decides whether this server ever mints one: with it
        // off, `issue` refuses the refresh half of every issuance, so no client can ever arrive at
        // the token endpoint with something to redeem. Advertising the grant there would be the
        // same defect as advertising an endpoint that 404s — a capability a client reads as
        // available, plans an implementation around, and can only discover is absent by failing.
        // Conditional for exactly the reason `token-exchange` is conditional three lines below.
        if config.issue_refresh_tokens {
            grant_types_supported.push("refresh_token".to_string());
        }
        grant_types_supported.push("client_credentials".to_string());
        grant_types_supported.push(DEVICE_CODE_GRANT_URN.to_string());
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
            // NOT `endpoint(...)`: the host's own value or nothing at all. See the field's doc for
            // why this member alone is opt-in, and `crate::http::ServiceBuilder::build` for why
            // the ROUTE is not.
            introspection_endpoint: config.introspection_endpoint.clone(),
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
            // Every algorithm on this list is ES256, so the list is honest only where an ES256
            // signature can be checked. Without the built-in backend that is not something a
            // `&ServerConfig` can answer, so the member is omitted here and
            // `es256_verification_is_available` puts it back when the server resolves a verifier.
            // `require_signed_request_object` below stays the signal that RFC 9101 is configured
            // at all, which is what that method keys off.
            #[cfg(all(feature = "jar", feature = "jwt-p256"))]
            request_object_signing_alg_values_supported: config.jar.as_ref().map(|_| {
                crate::par::REQUEST_OBJECT_SIGNING_ALGS
                    .iter()
                    .map(|alg| alg.to_string())
                    .collect()
            }),
            #[cfg(all(feature = "jar", not(feature = "jwt-p256")))]
            request_object_signing_alg_values_supported: None,
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
                // `mut` only matters under `client-assertion`, which is what the allow is for. The
                // alternative is two copies of the list, which is how two lists drift apart.
                #[allow(unused_mut)]
                let mut methods = vec![
                    "client_secret_basic".to_string(),
                    "client_secret_post".to_string(),
                    // RFC 8414 s2: the registered value a public client uses. This server accepts
                    // public clients, so omitting it would understate what it does.
                    "none".to_string(),
                ];
                // RFC 7523 s2.2, and the two methods do NOT have the same requirements.
                // `client_secret_jwt` is HS256 over the secret the registration already holds, so
                // the feature alone makes it true. `private_key_jwt` is ES256, and since the
                // signing seam landed a build can have this feature and no way to check an ES256
                // signature at all (`client-assertion = ["jwt"]`, which does not pull `jwt-p256`),
                // in which case every such assertion is refused. So it is advertised here only
                // with the built-in backend, and `es256_verification_is_available` adds it when
                // the host installed a verifier of its own.
                #[cfg(feature = "client-assertion")]
                {
                    methods.push(crate::client_assertion::CLIENT_SECRET_JWT.to_string());
                    #[cfg(feature = "jwt-p256")]
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
            // The same split, one member along: HS256 is checkable in every build with the
            // feature, ES256 only where there is a backend to check it with.
            #[cfg(all(feature = "client-assertion", feature = "jwt-p256"))]
            token_endpoint_auth_signing_alg_values_supported: Some(
                crate::client_assertion::ASSERTION_SIGNING_ALGS
                    .iter()
                    .map(|a| a.to_string())
                    .collect(),
            ),
            #[cfg(all(feature = "client-assertion", not(feature = "jwt-p256")))]
            token_endpoint_auth_signing_alg_values_supported: Some(vec!["HS256".to_string()]),
            #[cfg(not(feature = "client-assertion"))]
            token_endpoint_auth_signing_alg_values_supported: None,
            // RFC 9449 s5.1: a proof is an ES256 JWS this server VERIFIES, so with no backend
            // there is no algorithm a client could send one under.
            #[cfg(all(feature = "dpop", feature = "jwt-p256"))]
            dpop_signing_alg_values_supported: Some(
                crate::dpop::DPOP_SIGNING_ALG_VALUES_SUPPORTED
                    .iter()
                    .map(|a| a.to_string())
                    .collect(),
            ),
            #[cfg(all(feature = "dpop", not(feature = "jwt-p256")))]
            dpop_signing_alg_values_supported: None,
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

    /// Add back every advertisement that is honest only when an ES256 VERIFIER exists.
    ///
    /// [`AuthorizationServerMetadata::from_config`] cannot see one: `jwt-p256` compiles the
    /// built-in backend in, and a host may install its own with
    /// [`crate::AuthorizationServer::with_es256_verifier`], and neither is reachable from a
    /// `&ServerConfig`. So `from_config` advertises the ES256-dependent members only when the
    /// built-in backend is compiled in, and [`crate::AuthorizationServer::metadata`] calls this
    /// when the server resolves a verifier.
    ///
    /// IDEMPOTENT, and it has to be: with `jwt-p256` on, `from_config` has already added all of
    /// this, and a document that named `private_key_jwt` twice would be a defect of its own.
    #[cfg(any(feature = "client-assertion", feature = "jar", feature = "dpop"))]
    pub(crate) fn es256_verification_is_available(&mut self) {
        #[cfg(feature = "client-assertion")]
        {
            let method = crate::client_assertion::PRIVATE_KEY_JWT.to_string();
            if !self.token_endpoint_auth_methods_supported.contains(&method) {
                self.token_endpoint_auth_methods_supported.push(method);
            }
            let algs = self
                .token_endpoint_auth_signing_alg_values_supported
                .get_or_insert_with(Vec::new);
            if !algs.iter().any(|a| a == "ES256") {
                algs.push("ES256".to_string());
            }
        }
        #[cfg(feature = "jar")]
        {
            // Only for a server that HAS signed request objects enabled. `from_config` derives
            // `require_signed_request_object` from `config.jar` and nothing else, so its presence
            // is the one signal here for "RFC 9101 is configured" that does not depend on the
            // very thing this method is adjusting.
            if self.require_signed_request_object.is_some() {
                self.request_object_signing_alg_values_supported = Some(
                    crate::par::REQUEST_OBJECT_SIGNING_ALGS
                        .iter()
                        .map(|alg| alg.to_string())
                        .collect(),
                );
            }
        }
        #[cfg(feature = "dpop")]
        {
            self.dpop_signing_alg_values_supported = Some(
                crate::dpop::DPOP_SIGNING_ALG_VALUES_SUPPORTED
                    .iter()
                    .map(|a| a.to_string())
                    .collect(),
            );
        }
    }
}

#[cfg(test)]
#[path = "tests/metadata.rs"]
mod tests;
