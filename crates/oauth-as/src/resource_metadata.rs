// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9728 protected resource metadata: the document served at
//! `{resource}/.well-known/oauth-protected-resource`.
//!
//! # Read this before using the module: whose document is this
//!
//! THIS CRATE IS AN AUTHORIZATION SERVER. RFC 9728 defines a document a PROTECTED RESOURCE (a
//! resource server) publishes about itself, and section 3.1 places it under the RESOURCE's own
//! identifier, not under the AS's issuer. So the boundary this module draws is deliberate and it
//! is not a limitation to be papered over later:
//!
//! - [`ProtectedResourceMetadata`] is the TYPE. A host that runs a resource server (very often the
//!   same process that embeds this AS, which is why the type lives here at all) fills it in from
//!   [`ProtectedResourceConfig`] and serves it from its own resource origin. This crate does not
//!   serve it, does not route it, and does not validate incoming access tokens: none of those is
//!   an authorization server's job, and pretending otherwise would be the "true but substantively
//!   misleading" trap that this project already refuses for OIDC bolt-ons.
//! - The AUTHORIZATION SERVER half of RFC 9728 is section 4 alone: the `protected_resources`
//!   member on the RFC 8414 document, which this crate does derive, from
//!   [`crate::server::ServerConfig::protected_resources`]. That member is the AS's own statement
//!   about which resources it issues tokens for, and section 7.6 is why it is worth publishing: an
//!   `authorization_servers` entry in a resource's document is a claim made BY THE RESOURCE, and a
//!   client that believes it unchecked can be pointed at an AS that never heard of that resource.
//!
//! # Why the type is derived from config rather than hand-written
//!
//! Exactly the reasoning [`crate::metadata::AuthorizationServerMetadata::from_config`] gives: this
//! document is read by clients before they talk to the resource, so an advertised capability the
//! resource does not have is a lie the client cannot recover from. Every member below is either
//! REQUIRED by section 2 or derived from something the host actually declared, and an optional
//! member the host did not declare is OMITTED rather than serialized as `null`. Section 2 defines
//! member types and `null` is not one of them.

use serde::{Deserialize, Serialize};

/// The well-known URI suffix RFC 9728 section 3.1 registers for this document.
///
/// This is the BARE form, correct only for a resource identifier with no path or query. Use
/// [`well_known_path`] to place the document for a given resource: as in RFC 8414 section 3.1, the
/// suffix is INSERTED between the host and the rest of the identifier rather than appended to it.
pub const PROTECTED_RESOURCE_WELL_KNOWN_PATH: &str = "/.well-known/oauth-protected-resource";

/// The part of a resource identifier that RFC 9728 section 3.1 places AFTER the well-known suffix:
/// `""` for `https://rs.example`, `"/api"` for `https://rs.example/api`.
///
/// The path case is delegated to [`crate::metadata::issuer_path`] rather than parsed again here.
/// RFC 9728 section 3.1 is the same insertion rule RFC 8414 section 3.1 states, and two
/// hand-rolled parsers for one rule is exactly how the AS document and the resource document end
/// up disagreeing about where a tenant lives.
///
/// One shape is handled on top of it, because it is a shape an RFC 8414 issuer cannot have:
/// section 3.1 says "path and/or query components", so a resource identifier MAY carry a query
/// with no path at all (`https://rs.example?tenant=1`). `issuer_path` splits at the first `/`, so
/// it reports nothing for that, and the query would otherwise be silently dropped from the URL a
/// client is told to fetch.
pub fn resource_path(resource: &str) -> &str {
    let path = crate::metadata::issuer_path(resource);
    if !path.is_empty() {
        // "any terminating slash (/) following the host component MUST be removed" (section 3.1).
        // `issuer_path` already trims a trailing one; this is the same slash carrying a query, as
        // in `https://rs.example/?tenant=1`, which would otherwise place the document at
        // `/.well-known/oauth-protected-resource/?tenant=1`.
        if path.starts_with("/?") {
            return &path[1..];
        }
        return path;
    }
    // A `?` cannot appear in a scheme or an authority, so the first one in the whole string is the
    // start of the query and no second authority scan is needed.
    match resource.find('?') {
        Some(i) => &resource[i..],
        None => "",
    }
}

/// Where this document lives for `resource`, as an absolute path from the origin's root.
///
/// RFC 9728 section 3.1: the well-known string goes BETWEEN the host and the rest of the resource
/// identifier. For resource `https://rs.example/api` the document is at
/// `https://rs.example/.well-known/oauth-protected-resource/api`, NOT at
/// `https://rs.example/api/.well-known/...` and NOT at the bare well-known path.
///
/// This is the same trap RFC 8414 section 3.1 sets for the AS document, and it matters for the
/// same two reasons: section 3.3 makes the client compare the `resource` member against the
/// identifier it inserted the suffix into, so a document served where that check cannot pass
/// teaches clients to skip a check that exists to stop a resource impersonating another; and a
/// deployment with several resources on one origin would otherwise collide on one bare path.
pub fn well_known_path(resource: &str) -> String {
    let path = resource_path(resource);
    let mut out = String::with_capacity(PROTECTED_RESOURCE_WELL_KNOWN_PATH.len() + path.len());
    out.push_str(PROTECTED_RESOURCE_WELL_KNOWN_PATH);
    out.push_str(path);
    out
}

/// How a client may present a bearer token to this resource (RFC 6750 sections 2.1, 2.2 and 2.3),
/// which RFC 9728 section 2 publishes as `bearer_methods_supported`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BearerMethod {
    /// RFC 6750 section 2.1, the `Authorization: Bearer` request header field. The only method
    /// OAuth 2.1 keeps, and the only one [`ProtectedResourceConfig::new`] advertises by default.
    Header,
    /// RFC 6750 section 2.2, the `access_token` form-encoded body parameter.
    Body,
    /// RFC 6750 section 2.3, the `access_token` query parameter. RFC 6750 itself says SHOULD NOT,
    /// because a URI carrying a credential is logged by every proxy on the path and leaks through
    /// `Referer`. A host that advertises this is stating a fact about its own resource, not being
    /// given a recommendation.
    Query,
}

/// What a host declares about its own protected resource, from which
/// [`ProtectedResourceMetadata::from_config`] derives the document.
///
/// Only two things have no sane default and are therefore arguments to
/// [`ProtectedResourceConfig::new`]: the resource identifier (section 2 makes `resource`
/// REQUIRED), and the issuer identifier of at least one authorization server, without which the
/// document tells a client nothing it can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
/// `#[non_exhaustive]`: RFC 9728 section 7.1 registers these members in an IANA registry that takes
/// new entries, and this type gains a field for each one this crate learns to publish. A host that
/// wrote a full struct literal would have a build that breaks on a PATCH release that only added a
/// member. Construct with `new()` and assign the fields you want. This is the one attribute on this
/// type that cannot be added after publication, because by then somebody's struct literal is in
/// production.
///
/// Note that the justification is NOT the one
/// [`crate::metadata::AuthorizationServerMetadata`] carries: that type's field set genuinely varies
/// with cargo features, and this one's does not — there is no `#[cfg]` on any field here, because
/// RFC 9728 is the whole of the `resource-metadata` feature and nothing else gates a member of it.
/// Both types want the attribute; they want it for different reasons, and stating the wrong one
/// invites somebody to remove the attribute on discovering the reason is untrue.
#[non_exhaustive]
pub struct ProtectedResourceConfig {
    /// Section 2 `resource`: the resource identifier, an absolute URI with no fragment. This is
    /// the SAME string a client sends as an RFC 8707 `resource` indicator to get a token for this
    /// resource, and the same string section 3.3 requires the served document to echo.
    pub resource: String,
    /// Section 2 `authorization_servers`: the issuer identifiers of the ASes that can issue tokens
    /// for this resource. Empty omits the member rather than publishing an empty array, which
    /// would say "no authorization server can issue for me".
    pub authorization_servers: Vec<String>,
    /// Section 2 `jwks_uri`: the RESOURCE's own key set, for signed resource responses. This is
    /// NOT the authorization server's `jwks_uri` and must not be set to it: section 2 defines it
    /// as the keys a client uses to validate signatures FROM this resource, and pointing it at the
    /// AS would tell clients to validate resource responses with token-signing keys.
    pub jwks_uri: Option<String>,
    /// Section 2 `scopes_supported` (RECOMMENDED): the scope values used with this resource.
    /// `None` omits the member; an empty catalogue and an undeclared one are different claims.
    pub scopes_supported: Option<Vec<String>>,
    /// Section 2 `bearer_methods_supported`. Empty omits the member, which section 2 leaves as
    /// "unspecified" rather than "none".
    pub bearer_methods_supported: Vec<BearerMethod>,
    /// Section 2 `resource_signing_alg_values_supported`: JWS `alg` values this resource signs its
    /// RESPONSES with. Empty omits the member. `none` is not a value this crate will emit, for the
    /// reason RFC 7518 section 3.6 gives.
    pub resource_signing_alg_values_supported: Vec<String>,
    /// Section 2.1 `resource_name` (RECOMMENDED): a human-readable name for display to end users.
    pub resource_name: Option<String>,
    /// Section 2 `resource_documentation`: a page of developer documentation.
    pub resource_documentation: Option<String>,
    /// Section 2 `resource_policy_uri`: how the resource's data is used.
    pub resource_policy_uri: Option<String>,
    /// Section 2 `resource_tos_uri`: terms of service.
    pub resource_tos_uri: Option<String>,
    /// Section 2 `tls_client_certificate_bound_access_tokens` (RFC 8705): whether this resource
    /// supports mutual-TLS certificate-bound access tokens. `false` OMITS the member rather than
    /// publishing `false`, because section 2 gives `false` as the default when absent and a host
    /// that never thought about mTLS should not be made to publish a sentence about it.
    pub tls_client_certificate_bound_access_tokens: bool,
    /// Section 2 `dpop_bound_access_tokens_required` (RFC 9449): whether this resource ALWAYS
    /// requires DPoP-bound tokens. Same omit-on-false rule and same reason.
    pub dpop_bound_access_tokens_required: bool,
    /// Section 2 `dpop_signing_alg_values_supported`: JWS `alg` values accepted in a DPoP proof.
    /// Empty omits the member.
    pub dpop_signing_alg_values_supported: Vec<String>,
    /// Section 2 `authorization_details_types_supported` (RFC 9396): the RAR type values this
    /// resource understands. Empty omits the member.
    pub authorization_details_types_supported: Vec<String>,
    /// Section 2.2 `signed_metadata`: a JWT whose claims are these same members, signed by the
    /// resource.
    ///
    /// This crate does NOT produce it, and will not silently: signing requires a key this crate
    /// does not hold (the RESOURCE's key, not the AS's), and section 7.9 makes the signed and
    /// unsigned documents carry different trust, so manufacturing one here would be the AS
    /// asserting something about a resource on the resource's behalf. A host that signs its own
    /// document sets the compact serialization here and this crate passes it through unread.
    pub signed_metadata: Option<String>,
}

impl ProtectedResourceConfig {
    /// A config for `resource`, protected by the authorization server at issuer identifier
    /// `authorization_server`.
    ///
    /// Defaults chosen so that the document a host publishes without touching anything else is
    /// both minimal and true: header-only bearer presentation (RFC 6750 section 2.1, the one form
    /// OAuth 2.1 keeps), and no capability claimed that the host has not stated.
    pub fn new(resource: impl Into<String>, authorization_server: impl Into<String>) -> Self {
        ProtectedResourceConfig {
            resource: resource.into(),
            authorization_servers: vec![authorization_server.into()],
            jwks_uri: None,
            scopes_supported: None,
            bearer_methods_supported: vec![BearerMethod::Header],
            resource_signing_alg_values_supported: Vec::new(),
            resource_name: None,
            resource_documentation: None,
            resource_policy_uri: None,
            resource_tos_uri: None,
            tls_client_certificate_bound_access_tokens: false,
            dpop_bound_access_tokens_required: false,
            dpop_signing_alg_values_supported: Vec::new(),
            authorization_details_types_supported: Vec::new(),
            signed_metadata: None,
        }
    }
}

/// An RFC 9728 protected resource metadata document.
///
/// Published by the RESOURCE, at [`well_known_path`] under the resource's own origin. See the
/// module docs for why this crate carries the type but does not serve it.
///
/// Optional members are `Option` and are OMITTED when absent, never serialized as `null`, exactly
/// as [`crate::metadata::AuthorizationServerMetadata`] does and for the same reason: section 2
/// defines member types, and `null` is not one of them.
///
/// `#[non_exhaustive]` for the same reason [`ProtectedResourceConfig`] is, and it is the DOCUMENT
/// that the reason is really about: RFC 9728 section 7.1 registers its members in an IANA registry
/// that takes new entries, so this type gains a field whenever the crate learns to publish one, and
/// a member added to a wire format is not a breaking change to anybody except a host who wrote the
/// struct out by hand. The supported way to build one is
/// [`ProtectedResourceMetadata::from_config`], which is also the only way to get a document that
/// agrees with the [`ProtectedResourceConfig`] the host actually declared. `Deserialize` is derived
/// and is unaffected, so a client-side or test-side consumer parsing a served document still works,
/// and so does reading or matching on any field.
///
/// Added in 0.9.1, which is the last release it can be added in: 0.9.0 was an alpha published so
/// the crate could be built against, and after a release meant for real use the attribute can never
/// go on, because by then somebody's struct literal is in production.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ProtectedResourceMetadata {
    /// REQUIRED (section 2). Section 3.3 makes this the member a client checks: it MUST be
    /// identical to the resource identifier the well-known suffix was inserted into, or the
    /// document MUST NOT be used.
    pub resource: String,
    /// OPTIONAL (section 2). Issuer identifiers, each of which a client then discovers through RFC
    /// 8414. Section 7.6: this is the RESOURCE's claim, so a client is expected to be suspicious
    /// of it rather than to follow it blindly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_servers: Option<Vec<String>>,
    /// OPTIONAL (section 2). The RESOURCE's key set, not the AS's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// RECOMMENDED (section 2). Section 7.2: publishing scopes is what lets a client ask for the
    /// least it needs rather than the most it can.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    /// OPTIONAL (section 2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bearer_methods_supported: Option<Vec<BearerMethod>>,
    /// OPTIONAL (section 2). JWS `alg` values for signed responses FROM this resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_signing_alg_values_supported: Option<Vec<String>>,
    /// RECOMMENDED (section 2.1). Human-readable, for display to end users.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
    /// OPTIONAL (section 2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_documentation: Option<String>,
    /// OPTIONAL (section 2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_policy_uri: Option<String>,
    /// OPTIONAL (section 2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_tos_uri: Option<String>,
    /// OPTIONAL (section 2), RFC 8705. Omitted rather than `false`, since section 2 already gives
    /// `false` as the default when the member is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_certificate_bound_access_tokens: Option<bool>,
    /// OPTIONAL (section 2), RFC 9396.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details_types_supported: Option<Vec<String>>,
    /// OPTIONAL (section 2), RFC 9449.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    /// OPTIONAL (section 2), RFC 9449. Omitted rather than `false`, as above.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_bound_access_tokens_required: Option<bool>,
    /// OPTIONAL (section 2.2). Passed through from the host; never produced by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_metadata: Option<String>,
}

/// `None` for an empty list, so an undeclared capability is an omitted member rather than an empty
/// array. The distinction is the whole of the omission rule: `[]` is a claim ("I support none of
/// these"), absence is silence, and section 2 gives a default for several of these members that
/// only applies when they are absent.
fn some_unless_empty<T>(values: Vec<T>) -> Option<Vec<T>> {
    (!values.is_empty()).then_some(values)
}

impl ProtectedResourceMetadata {
    /// Derive the document from the resource's configuration.
    pub fn from_config(config: &ProtectedResourceConfig) -> Self {
        ProtectedResourceMetadata {
            // Section 3.3 compares this for equality against the identifier the client built the
            // request URL from, so a trailing slash is trimmed here exactly as
            // `AuthorizationServerMetadata::from_config` trims the issuer's: a host that wrote
            // `https://rs.example/api/` must not end up with two spellings of one identity, and
            // `well_known_path` trims the same slash when placing the document.
            resource: config.resource.trim_end_matches('/').to_string(),
            authorization_servers: some_unless_empty(config.authorization_servers.clone()),
            jwks_uri: config.jwks_uri.clone(),
            scopes_supported: config.scopes_supported.clone(),
            bearer_methods_supported: some_unless_empty(config.bearer_methods_supported.clone()),
            resource_signing_alg_values_supported: some_unless_empty(
                config.resource_signing_alg_values_supported.clone(),
            ),
            resource_name: config.resource_name.clone(),
            resource_documentation: config.resource_documentation.clone(),
            resource_policy_uri: config.resource_policy_uri.clone(),
            resource_tos_uri: config.resource_tos_uri.clone(),
            tls_client_certificate_bound_access_tokens: config
                .tls_client_certificate_bound_access_tokens
                .then_some(true),
            authorization_details_types_supported: some_unless_empty(
                config.authorization_details_types_supported.clone(),
            ),
            dpop_signing_alg_values_supported: some_unless_empty(
                config.dpop_signing_alg_values_supported.clone(),
            ),
            dpop_bound_access_tokens_required: config
                .dpop_bound_access_tokens_required
                .then_some(true),
            signed_metadata: config.signed_metadata.clone(),
        }
    }

    /// Where this document belongs, as an absolute path from the resource origin's root. See
    /// [`well_known_path`], which this defers to so the served location and the `resource` member
    /// cannot drift apart.
    pub fn well_known_path(&self) -> String {
        well_known_path(&self.resource)
    }
}

#[cfg(test)]
#[path = "tests/resource_metadata.rs"]
mod tests;
