// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 7591 dynamic client registration and RFC 7592 registration management.
//!
//! # Read this before you turn it on (RFC 7591 section 5)
//!
//! Dynamic registration lets a caller CREATE A CLIENT. Section 5 of RFC 7591 says so plainly: an
//! open registration endpoint is available to anyone on the internet, and the authorization server
//! "MUST" treat what it is handed as untrusted, because a registration is an attacker-chosen
//! `client_name` on a consent screen, an attacker-chosen redirect URI, and an identity that every
//! later threat model quietly assumes is scarce. This crate's own security review made the same
//! point from the other side: several residual risks here are bounded by "the attacker must
//! control a registered client", and dynamic registration turns that from an assumption into a
//! form submission.
//!
//! So the shape of this module is decided by that, not by convenience:
//!
//! - It is OFF unless [`crate::server::ServerConfig::registration`] is `Some`. There is no
//!   "enabled by default", no environment variable, and no way to reach it by accident. A host
//!   that does not set that field cannot be dynamically registered against, and pays 8 bytes and
//!   no allocation for the privilege.
//! - Enabling it is not enough. A [`RegistrationPolicy`] must also be installed (see
//!   [`crate::server::AuthorizationServer::with_registration_policy`]), and with none installed
//!   every registration is REFUSED. That is the opposite default to the rate limiter, and the
//!   reasoning is in [`crate::events::Hooks::registration_policy`].
//! - What a registrant may ask for is bounded by [`RegistrationConfig`]: which grants, which
//!   scopes. The defaults are the narrow ones (no `client_credentials`, no device grant, no
//!   scopes), because the widening should be a sentence the host wrote.
//! - Every registration, update and deletion is an audit event
//!   ([`crate::events::Event::ClientRegistered`] and friends), carrying no credential.
//!
//! # The registration access token (RFC 7592 section 2)
//!
//! Management is authenticated by a bearer token minted at registration. It reads, REWRITES and
//! DELETES a registration, so it is at least as powerful as the client secret it sits next to, and
//! it is stored exactly the same way: as a one-way [`crate::client::SecretHash`], compared in
//! constant time, never in plaintext and never with `==`.
//!
//! That has one visible consequence, and it is a deliberate deviation worth stating rather than
//! burying. RFC 7592 section 3 lists `registration_access_token` (and, for a confidential client,
//! `client_secret`) as members of the client information response, which the read and update
//! responses of sections 2.1 and 2.2 also use. This server cannot return either on a read or an
//! update, because it does not have them: it kept a verifier, not the credential. Both are
//! returned exactly once, by the registration that minted them, and after that the client holds
//! the only copy. The alternative is storing two live bearer credentials in plaintext for the
//! lifetime of every registration, which is the thing [`crate::client::SecretHash`] exists to stop.
//!
//! # What is NOT implemented, and why
//!
//! - `software_statement` and `software_id` (RFC 7591 sections 2.3 and 3.1.1). A software
//!   statement is a JWT that has to be verified against a trust anchor the HOST owns, and there is
//!   no honest default for "which issuers do you trust to vouch for a client". A request carrying
//!   one is REFUSED with `invalid_software_statement` rather than ignored: RFC 7591 section 2
//!   tells a server to ignore metadata it does not understand, but a software statement is an
//!   assertion the client believes is being HONOURED, and silently dropping it would register a
//!   client on terms nobody agreed to.
//! - The optional human-readable metadata of RFC 7591 section 2 (`client_uri`, `logo_uri`,
//!   `contacts`, `tos_uri`, `policy_uri`, `jwks`, `jwks_uri`). They are ignored, as section 2
//!   permits, because this server has nothing to do with them: it renders no branded consent
//!   screen and does not yet do RFC 7523 client assertions, so storing them would be storing
//!   attacker-supplied strings for no purpose.

use serde::{Deserialize, Serialize};

use crate::client::{Client, ClientAuth, ClientId, DynamicRegistration, SecretHash};
use crate::grant::GrantType;
use crate::scope::ScopeSet;
use crate::server::{AuthorizationServer, Clock, ServerConfig};
use crate::store::{Storage, StorageError};

/// RFC 7591 section 2 client metadata: the registration request body, and the echoed half of the
/// section 3.2.1 client information response.
///
/// Only the members this server actually acts on are modelled. RFC 7591 section 2 requires a
/// server to IGNORE metadata it does not understand, which is what `serde`'s default handling of
/// unknown fields does here, so a client that sends `logo_uri` is not refused for it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientMetadata {
    /// Redirection URIs (RFC 6749 section 3.1.2). REQUIRED for a client registering the
    /// authorization code grant, since that grant has nowhere to deliver a code without one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<String>,
    /// How the client will authenticate at the token endpoint. Omitted means
    /// `client_secret_basic`, which is the default RFC 7591 section 2 states.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
    /// The grants this client will use. OMITTED (`None`) means `["authorization_code"]`
    /// (section 2), which is why this is an `Option` rather than a `Vec` that is empty when
    /// absent: section 2 gives omission a meaning, and an explicitly empty list means the opposite
    /// of that meaning. Collapsing the two would make `{"grant_types": []}` silently register the
    /// authorization code grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<String>>,
    /// The authorization response types this client will use. Omitted (`None`) means `["code"]`
    /// (section 2); see [`ClientMetadata::grant_types`] for why this is an `Option`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_types: Option<Vec<String>>,
    /// Human-readable name, shown to a resource owner. ATTACKER-CHOSEN when registration is open:
    /// it is echoed into this crate's device verification page, which escapes it, and any host
    /// consent screen must do the same.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// The space-delimited scope list (RFC 6749 section 3.3) this client may request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// RFC 7591 section 2.3. NOT evaluated by this server, and its presence is a refusal rather
    /// than an omission: see the module docs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software_statement: Option<String>,
}

/// The RFC 7591 section 3.2.1 client information response, which RFC 7592 section 3 reuses for
/// read and update.
///
/// `Debug` is hand-written (below) because two of these fields are live bearer credentials at the
/// moment this value exists, and this is the value a host is most likely to log: it is what it is
/// about to serialize.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientInformation {
    /// REQUIRED (section 3.2.1). The identifier this server minted.
    pub client_id: String,
    /// Present only for a confidential registration, and only on the response that MINTED it: see
    /// the module docs on why a read cannot return it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Seconds since the Unix epoch (section 3.2.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id_issued_at: Option<u64>,
    /// REQUIRED when a `client_secret` is issued (section 3.2.1). `0` means it never expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<u64>,
    /// RFC 7592 section 3. Present only on the response that minted it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_access_token: Option<String>,
    /// RFC 7592 section 3: where this registration is read, updated and deleted. Absent when the
    /// host did not enable management.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_client_uri: Option<String>,
    /// The registered metadata, echoed as section 3.2.1 requires, INCLUDING any value this server
    /// substituted for what was asked (section 3.2.1: the response reflects what was registered,
    /// not what was requested).
    #[serde(flatten)]
    pub metadata: ClientMetadata,
}

/// Hand-written so neither credential reaches a debug format, on the same reasoning as
/// [`crate::client::ClientAuth`]'s and [`crate::server::TokenRequest`]'s. The Some/None
/// distinction is kept: "a secret was issued" is registration shape, not a secret.
impl std::fmt::Debug for ClientInformation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn redact_opt<T>(value: &Option<T>) -> Option<&'static str> {
            value.as_ref().map(|_| "[redacted]")
        }
        f.debug_struct("ClientInformation")
            .field("client_id", &self.client_id)
            .field("client_secret", &redact_opt(&self.client_secret))
            .field("client_id_issued_at", &self.client_id_issued_at)
            .field("client_secret_expires_at", &self.client_secret_expires_at)
            .field(
                "registration_access_token",
                &redact_opt(&self.registration_access_token),
            )
            .field("registration_client_uri", &self.registration_client_uri)
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// The RFC 7591 section 3.2.2 error codes.
///
/// A SEPARATE registry from RFC 6749 section 5.2, and modelled separately for that reason: the two
/// share no value, they are returned by different endpoints, and collapsing them into
/// [`crate::error::ErrorCode`] would let a token-endpoint code be emitted here (or the reverse)
/// with nothing to catch it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RegistrationErrorCode {
    /// One or more `redirect_uris` is invalid: not an absolute URI, or carrying a fragment, or
    /// absent for a grant that needs one.
    InvalidRedirectUri,
    /// Some other submitted metadata value is invalid, or names something this server will not
    /// register.
    InvalidClientMetadata,
    /// The software statement presented is invalid. This server evaluates none, so any is: see
    /// the module docs.
    InvalidSoftwareStatement,
}

impl RegistrationErrorCode {
    /// The registered wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            RegistrationErrorCode::InvalidRedirectUri => "invalid_redirect_uri",
            RegistrationErrorCode::InvalidClientMetadata => "invalid_client_metadata",
            RegistrationErrorCode::InvalidSoftwareStatement => "invalid_software_statement",
        }
    }
}

impl std::fmt::Display for RegistrationErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The RFC 7591 section 3.2.2 error response body: a 400 with `error` and an optional
/// `error_description`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationErrorResponse {
    /// The registered code.
    pub error: RegistrationErrorCode,
    /// Human-readable detail for the developer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

impl RegistrationErrorResponse {
    /// An error with a description attached.
    pub fn new(error: RegistrationErrorCode, description: impl Into<String>) -> Self {
        RegistrationErrorResponse {
            error,
            error_description: Some(description.into()),
        }
    }
}

impl std::fmt::Display for RegistrationErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.error_description {
            Some(d) => write!(f, "{}: {d}", self.error),
            None => f.write_str(self.error.as_str()),
        }
    }
}

/// Why a registration or management request was refused.
///
/// One enum for RFC 7591 and RFC 7592 because the two endpoints share every failure mode they have
/// in common, and splitting them would make a host match twice on the same four cases.
#[derive(Debug)]
#[non_exhaustive]
pub enum RegistrationFailure {
    /// This server does not offer the endpoint: the host set no
    /// [`crate::server::ServerConfig::registration`], or set one with management turned off. A 404
    /// on the wire, because the honest answer to "is there a registration endpoint here" is no.
    Disabled,
    /// The RFC 7591 section 1.2 initial access token, or the RFC 7592 section 2 registration
    /// access token, was missing, wrong, or refused by the host's [`RegistrationPolicy`]. 401,
    /// with an RFC 6750 section 3 `Bearer` challenge.
    ///
    /// Deliberately ONE answer for all of those, including "no such registration": distinguishing
    /// them would turn this endpoint into an oracle for which client ids exist, exactly as
    /// `invalid_client` collapses the same two cases at the token endpoint.
    Unauthorized,
    /// The metadata is not acceptable (RFC 7591 section 3.2.2). 400.
    Invalid(RegistrationErrorResponse),
    /// The storage seam failed. 500, and the wire learns nothing else.
    Storage(StorageError),
}

impl RegistrationFailure {
    /// The HTTP status this refusal takes.
    pub fn http_status(&self) -> u16 {
        match self {
            RegistrationFailure::Disabled => 404,
            RegistrationFailure::Unauthorized => 401,
            RegistrationFailure::Invalid(_) => 400,
            RegistrationFailure::Storage(_) => 500,
        }
    }
}

impl std::fmt::Display for RegistrationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistrationFailure::Disabled => f.write_str("dynamic client registration is disabled"),
            RegistrationFailure::Unauthorized => f.write_str("not authorized to register"),
            RegistrationFailure::Invalid(e) => write!(f, "{e}"),
            RegistrationFailure::Storage(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RegistrationFailure {}

/// What the host's [`RegistrationPolicy`] is told about one attempt.
///
/// Everything borrows: the policy is called inside the request the host is already driving.
/// `#[non_exhaustive]` because later releases will have more to say about the caller.
#[non_exhaustive]
pub struct RegistrationAttempt<'a> {
    /// The RFC 7591 section 1.2 initial access token the request presented, if any. This crate
    /// does not interpret it: the host decides what an acceptable one is, because it is the host
    /// that issued it (or that recognises an allowlisted API key, or a signed invite, or nothing
    /// at all).
    pub initial_access_token: Option<&'a str>,
    /// The metadata being registered, parsed but NOT yet validated, so a policy can refuse on
    /// content (a `client_name` impersonating the deployment, a redirect URI on a domain the host
    /// will not serve) before this server ever writes it down.
    pub metadata: &'a ClientMetadata,
}

/// Hand-written: the initial access token is a bearer credential, and this struct exists only
/// inside a request path, which is precisely where a host is most likely to debug-print it.
impl std::fmt::Debug for RegistrationAttempt<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationAttempt")
            .field(
                "initial_access_token",
                &self.initial_access_token.map(|_| "[redacted]"),
            )
            .field("metadata", self.metadata)
            .finish()
    }
}

/// What a [`RegistrationPolicy`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegistrationDecision {
    /// Register the client, subject to the metadata being valid.
    Allow,
    /// Refuse. The wire gets 401 and nothing else; the host knows why and this crate does not
    /// need to.
    Deny,
}

/// Who may create a client here. THIS LIBRARY HAS NO OPINION, and cannot have one: it never sees
/// a request, so it has no caller, no IP, no tenant and no invite list.
///
/// With NO policy installed, every registration is denied. That is not a safe default chosen for
/// tidiness, it is the only reading of RFC 7591 section 5 that does not leave an anonymous
/// client-minting endpoint on the internet because somebody set a config field and moved on. A
/// host that genuinely wants an open endpoint writes a two-line policy that returns
/// [`RegistrationDecision::Allow`], and that line is then something a reviewer can find.
pub trait RegistrationPolicy: Send + Sync {
    /// Decide whether this attempt may create a client. Called BEFORE the metadata is validated
    /// and before anything is written, so a refusal costs one call and touches no storage.
    fn authorize(&self, attempt: &RegistrationAttempt<'_>) -> RegistrationDecision;
}

/// What dynamic registration is allowed to produce here. Held behind
/// [`crate::server::ServerConfig::registration`], which is `None` (registration off) by default.
///
/// Every bound below is a CEILING on what an anonymous, or merely policy-approved, registrant can
/// obtain. The defaults are the narrow ones on purpose; see [`RegistrationConfig::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationConfig {
    /// RFC 8414 section 2 `registration_endpoint`. `None` derives `{issuer}/register`.
    pub registration_endpoint: Option<String>,
    /// The grants a registration may ask for. Anything outside this list is
    /// `invalid_client_metadata`.
    pub allowed_grant_types: Vec<GrantType>,
    /// The ceiling on a registration's `scope`. A request outside it is `invalid_client_metadata`;
    /// the default is EMPTY, so a host must say what a registrant may reach.
    pub allowed_scopes: ScopeSet,
    /// How long an issued client secret lives. `None` (the default) means it never expires, which
    /// is what `client_secret_expires_at: 0` says on the wire (RFC 7591 section 3.2.1).
    pub client_secret_ttl: Option<std::time::Duration>,
    /// Whether RFC 7592 read, update and delete are offered at all. `true` by default: a client
    /// that can be created and never corrected or deleted leaves the host doing registration
    /// lifecycle by hand.
    pub management_enabled: bool,
}

impl Default for RegistrationConfig {
    fn default() -> Self {
        RegistrationConfig::new()
    }
}

impl RegistrationConfig {
    /// The narrow defaults: the authorization code grant with refresh, no scopes, management on.
    ///
    /// `client_credentials` and the device grant are deliberately absent. A `client_credentials`
    /// registration mints tokens with NO resource owner anywhere in the picture, so an open
    /// registration endpoint that grants it is an open token endpoint; the device grant makes the
    /// registrant able to allocate user codes, which RFC 8628 section 5.1 says are only adequate
    /// in combination with rate limiting. Both are one line for a host to add, with its eyes open.
    pub fn new() -> Self {
        RegistrationConfig {
            registration_endpoint: None,
            allowed_grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            allowed_scopes: ScopeSet::default(),
            client_secret_ttl: None,
            management_enabled: true,
        }
    }

    /// The advertised registration endpoint for `issuer`.
    pub fn endpoint(&self, issuer: &str) -> String {
        match &self.registration_endpoint {
            Some(url) => url.clone(),
            None => format!("{}/register", issuer.trim_end_matches('/')),
        }
    }
}

/// The registered `token_endpoint_auth_method` values this server implements, which are exactly
/// the ones its RFC 8414 `token_endpoint_auth_methods_supported` advertises.
const AUTH_METHOD_NONE: &str = "none";
const AUTH_METHOD_BASIC: &str = "client_secret_basic";
const AUTH_METHOD_POST: &str = "client_secret_post";

/// RFC 7591 section 2: the `response_type` that corresponds to the authorization code grant. It is
/// also the only one OAuth 2.1 keeps, the implicit grant's `token` having been removed.
const RESPONSE_TYPE_CODE: &str = "code";

/// Whether a redirect URI is one this server can ever match.
///
/// The strictness here is set by what the AUTHORIZATION endpoint does with it, not by what looks
/// tidy. `AuthorizationServer::validate_authorization_request` compares the requested
/// `redirect_uri` against the registered one by EXACT STRING MATCH (OAuth 2.1 section 4.1.3), so a
/// registration this server accepts but can never match is not a lenient registration, it is a
/// client that will be told `invalid_request` forever with no way to find out why. RFC 6749
/// section 3.1.2 settles both halves: the URI MUST be absolute, and it MUST NOT carry a fragment.
///
/// Delegated to the RFC 8707 resource-indicator check rather than restated, because that function
/// already implements exactly this rule (absolute URI, no fragment, nothing outside printable
/// ASCII, which RFC 3986 requires of a URI anyway) and two copies of one rule drift.
fn redirect_uri_is_registerable(value: &str) -> bool {
    crate::authorization::is_valid_resource_indicator(value)
}

/// The metadata as this server will actually record it.
#[derive(Debug)]
struct Registered {
    redirect_uris: Vec<String>,
    grant_types: Vec<GrantType>,
    response_types: Vec<String>,
    token_endpoint_auth_method: String,
    scope: ScopeSet,
    client_name: Option<String>,
}

fn invalid(code: RegistrationErrorCode, why: &str) -> RegistrationFailure {
    RegistrationFailure::Invalid(RegistrationErrorResponse::new(code, why))
}

/// Validate one RFC 7591 section 2 metadata document against what this deployment will register.
///
/// Every refusal here is a registration this server would otherwise have written down and then
/// been unable to honour. That is the standard the rules are set to: not "is this plausible" but
/// "will the endpoints that later read this record be able to act on it".
fn validate(
    metadata: &ClientMetadata,
    config: &RegistrationConfig,
) -> Result<Registered, RegistrationFailure> {
    // RFC 7591 s2.3 / s3.2.2. First, because a client that sent one is asking to be registered on
    // terms this server has not read, and nothing after this point would be the registration it
    // asked for. See the module docs for why this is a refusal and not an ignored member.
    if metadata.software_statement.is_some() {
        return Err(invalid(
            RegistrationErrorCode::InvalidSoftwareStatement,
            "this server does not evaluate software statements (RFC 7591 s2.3)",
        ));
    }

    // RFC 7591 s2: absent `grant_types` defaults to `["authorization_code"]`.
    let grant_types: Vec<GrantType> = match metadata.grant_types.as_deref() {
        None => vec![GrantType::AuthorizationCode],
        Some(values) => {
            let mut out = Vec::with_capacity(values.len());
            for value in values {
                // An unknown grant type is refused rather than dropped: see the test in
                // `src/tests/registration.rs`. `implicit` and `password` land here too, which is
                // right, because OAuth 2.1 removes both.
                let grant: GrantType = value.parse().map_err(|_| {
                    invalid(
                        RegistrationErrorCode::InvalidClientMetadata,
                        "grant_types names a grant this server does not implement",
                    )
                })?;
                if !config.allowed_grant_types.contains(&grant) {
                    return Err(invalid(
                        RegistrationErrorCode::InvalidClientMetadata,
                        "grant_types names a grant this deployment does not offer registrants",
                    ));
                }
                if !out.contains(&grant) {
                    out.push(grant);
                }
            }
            out
        }
    };
    let uses_code = grant_types.contains(&GrantType::AuthorizationCode);

    // RFC 7591 s2 spells out the correspondence between the two lists (`authorization_code` with
    // `code`, `implicit` with `token`). It permits a server to reject OR to substitute; rejecting
    // is the choice here, because substituting registers a client that asked for something else
    // and tells it so only in the echoed response it may not re-read.
    //
    // OAuth 2.1 has exactly one response type left, so the whole correspondence reduces to: the
    // list is `["code"]` if and only if the authorization code grant is registered.
    let response_types: Vec<String> = match metadata.response_types.as_deref() {
        // s2: absent defaults to `["code"]`, which is only coherent when the code grant is there.
        None => match uses_code {
            true => vec![RESPONSE_TYPE_CODE.to_string()],
            false => Vec::new(),
        },
        // An EXPLICIT empty list falls through here and is caught by the correspondence check
        // below when the code grant is registered: the client said it uses no response type while
        // asking for the one grant that has one.
        Some(values) => {
            for value in values {
                if value != RESPONSE_TYPE_CODE {
                    return Err(invalid(
                        RegistrationErrorCode::InvalidClientMetadata,
                        "this server issues authorization codes only; OAuth 2.1 removes the \
                         implicit grant",
                    ));
                }
            }
            let asks_for_code = !values.is_empty();
            // The correspondence, in both directions: `code` without `authorization_code` is a
            // response type nothing will produce, and `authorization_code` without `code` is a
            // grant with no way to start.
            if asks_for_code != uses_code {
                return Err(invalid(
                    RegistrationErrorCode::InvalidClientMetadata,
                    "grant_types and response_types must correspond: authorization_code with \
                     code (RFC 7591 s2)",
                ));
            }
            match asks_for_code {
                true => vec![RESPONSE_TYPE_CODE.to_string()],
                false => Vec::new(),
            }
        }
    };

    // RFC 7591 s2 makes `redirect_uris` required for a redirection-based flow, and s3.2.2 gives
    // the missing case and the malformed case the same code, because both say the same thing: this
    // client has no address a code can be delivered to.
    if uses_code && metadata.redirect_uris.is_empty() {
        return Err(invalid(
            RegistrationErrorCode::InvalidRedirectUri,
            "the authorization_code grant requires at least one redirect_uri",
        ));
    }
    for uri in &metadata.redirect_uris {
        if !redirect_uri_is_registerable(uri) {
            // The offending value is NOT echoed: it is attacker-supplied and this description
            // goes into an error body and quite possibly a log line.
            return Err(invalid(
                RegistrationErrorCode::InvalidRedirectUri,
                "each redirect_uri must be an absolute URI with no fragment (RFC 6749 s3.1.2)",
            ));
        }
    }

    // RFC 7591 s2: absent `token_endpoint_auth_method` defaults to `client_secret_basic`.
    let token_endpoint_auth_method = metadata
        .token_endpoint_auth_method
        .clone()
        .unwrap_or_else(|| AUTH_METHOD_BASIC.to_string());
    if !matches!(
        token_endpoint_auth_method.as_str(),
        AUTH_METHOD_NONE | AUTH_METHOD_BASIC | AUTH_METHOD_POST
    ) {
        return Err(invalid(
            RegistrationErrorCode::InvalidClientMetadata,
            "token_endpoint_auth_method is not one this server advertises",
        ));
    }
    // RFC 6749 s4.4 gives client credentials to confidential clients only, so this pair produces a
    // registration whose only grant the token endpoint will refuse every time. Same argument as
    // the redirect URI rule above.
    if token_endpoint_auth_method == AUTH_METHOD_NONE
        && grant_types.contains(&GrantType::ClientCredentials)
    {
        return Err(invalid(
            RegistrationErrorCode::InvalidClientMetadata,
            "client_credentials requires a confidential client (RFC 6749 s4.4)",
        ));
    }

    // RFC 6749 s3.3 syntax, then the deployment's ceiling. Both are `invalid_client_metadata`:
    // s3.2.2 has one code for a metadata value this server will not accept.
    let scope = match metadata.scope.as_deref() {
        None => ScopeSet::empty(),
        Some(s) => {
            let requested = ScopeSet::parse(s).map_err(|_| {
                invalid(
                    RegistrationErrorCode::InvalidClientMetadata,
                    "scope is not a space-delimited RFC 6749 s3.3 token list",
                )
            })?;
            if !requested.is_subset(&config.allowed_scopes) {
                return Err(invalid(
                    RegistrationErrorCode::InvalidClientMetadata,
                    "scope exceeds what this deployment offers dynamically registered clients",
                ));
            }
            requested
        }
    };

    Ok(Registered {
        redirect_uris: metadata.redirect_uris.clone(),
        grant_types,
        response_types,
        token_endpoint_auth_method,
        scope,
        client_name: metadata.client_name.clone(),
    })
}

/// Rebuild the RFC 7591 section 2 view of a stored registration, for the section 3.2.1 echo.
fn registered_metadata(client: &Client, registration: &DynamicRegistration) -> ClientMetadata {
    ClientMetadata {
        redirect_uris: client.redirect_uris.clone(),
        token_endpoint_auth_method: Some(registration.token_endpoint_auth_method.clone()),
        grant_types: Some(client.grant_types.iter().map(|g| g.to_string()).collect()),
        // Derived rather than stored: `validate` enforces the RFC 7591 section 2 correspondence
        // between the two lists, so the response types are a function of the grant types and
        // storing them separately would only create a second place for them to disagree.
        response_types: Some(match client.allows_grant(GrantType::AuthorizationCode) {
            true => vec![RESPONSE_TYPE_CODE.to_string()],
            false => Vec::new(),
        }),
        client_name: client.name.clone(),
        scope: (!client.allowed_scopes.is_empty()).then(|| client.allowed_scopes.to_string()),
        // Never echoed: none was accepted, so echoing one would say it had been.
        software_statement: None,
    }
}

impl<S: Storage, C: Clock> AuthorizationServer<S, C> {
    /// The registration configuration, when the host enabled it.
    fn registration_config(&self) -> Result<&RegistrationConfig, RegistrationFailure> {
        self.config()
            .registration
            .as_deref()
            .ok_or(RegistrationFailure::Disabled)
    }

    /// RFC 7591 section 3.1: register a client.
    ///
    /// `initial_access_token` is whatever the request presented as an RFC 6750 bearer token, and
    /// is passed straight to the host's [`RegistrationPolicy`]; this crate does not interpret it.
    ///
    /// On success the returned [`ClientInformation`] carries the ONLY copy of the client secret
    /// (for a confidential registration) and of the RFC 7592 registration access token. Neither is
    /// recoverable afterwards, by the client or by the host: see the module docs.
    pub async fn register_dynamic_client(
        &self,
        metadata: &ClientMetadata,
        initial_access_token: Option<&str>,
    ) -> Result<ClientInformation, RegistrationFailure> {
        let config = self.registration_config()?;

        // The host decides, FIRST, before anything is validated or written. With no policy
        // installed the answer is no: see [`RegistrationPolicy`] and RFC 7591 section 5. The
        // refusal is deliberately indistinguishable from a bad initial access token, because a
        // policy that refuses on content should not confirm what content it dislikes.
        let attempt = RegistrationAttempt {
            initial_access_token,
            metadata,
        };
        match self.hooks().registration_policy() {
            Some(policy) if policy.authorize(&attempt) == RegistrationDecision::Allow => {}
            _ => return Err(RegistrationFailure::Unauthorized),
        }

        let registered = validate(metadata, config)?;

        let now = crate::server::unix_seconds(self.now());
        let client_id = ClientId::new(crate::server::random_hex(16));
        let secret = (registered.token_endpoint_auth_method != AUTH_METHOD_NONE)
            .then(|| crate::server::random_hex(32));
        let secret_expires_at = secret.as_ref().map(|_| match config.client_secret_ttl {
            // RFC 7591 section 3.2.1: 0 means the secret never expires.
            None => 0,
            Some(ttl) => now.unwrap_or_default() + ttl.as_secs(),
        });
        let registration_access_token = crate::server::random_hex(32);

        let client = Client {
            client_id: client_id.clone(),
            auth: match &secret {
                None => ClientAuth::Public,
                Some(s) => ClientAuth::ConfidentialSecretHash {
                    hash: SecretHash::sha256(s),
                },
            },
            grant_types: registered.grant_types.clone(),
            redirect_uris: registered.redirect_uris.clone(),
            allowed_scopes: registered.scope.clone(),
            default_scopes: registered.scope.clone(),
            name: registered.client_name.clone(),
            registration: Some(Box::new(DynamicRegistration {
                registration_access_token_hash: SecretHash::sha256(&registration_access_token),
                client_id_issued_at: now,
                client_secret_expires_at: secret_expires_at,
                token_endpoint_auth_method: registered.token_endpoint_auth_method.clone(),
            })),
        };
        self.store()
            .put_client(client)
            .await
            .map_err(RegistrationFailure::Storage)?;

        // Emitted AFTER the write: a registration that failed to persist did not happen.
        self.hooks()
            .emit(|| crate::events::Event::ClientRegistered {
                client_id: client_id.as_str(),
            });

        Ok(ClientInformation {
            client_id: client_id.as_str().to_string(),
            client_secret: secret,
            client_id_issued_at: now,
            client_secret_expires_at: secret_expires_at,
            registration_access_token: config
                .management_enabled
                .then_some(registration_access_token),
            registration_client_uri: config
                .management_enabled
                .then(|| registration_client_uri(config, self.config(), client_id.as_str())),
            metadata: ClientMetadata {
                redirect_uris: registered.redirect_uris,
                token_endpoint_auth_method: Some(registered.token_endpoint_auth_method),
                grant_types: Some(
                    registered
                        .grant_types
                        .iter()
                        .map(|g| g.to_string())
                        .collect(),
                ),
                response_types: Some(registered.response_types),
                client_name: registered.client_name,
                scope: (!registered.scope.is_empty()).then(|| registered.scope.to_string()),
                software_statement: None,
            },
        })
    }

    /// Authenticate an RFC 7592 section 2 management request.
    ///
    /// Every failure is [`RegistrationFailure::Unauthorized`]: an unknown client, a statically
    /// provisioned client that has no registration access token, and a wrong token are one answer
    /// on the wire, because telling them apart is an enumeration oracle over the client table.
    ///
    /// The same timing caveat that `AuthorizationServer::authenticate_client` documents applies:
    /// this returns before any hashing when the client is unknown, so an unknown client and a
    /// known client with the wrong token are distinguishable by wall time. The comparison itself
    /// leaks nothing (see [`SecretHash::verify`]); equalising the two paths is the host's business,
    /// and this is a management endpoint the host is expected to throttle anyway.
    async fn authenticate_registration(
        &self,
        client_id: &ClientId,
        registration_access_token: &str,
    ) -> Result<(Client, DynamicRegistration), RegistrationFailure> {
        let config = self.registration_config()?;
        if !config.management_enabled {
            return Err(RegistrationFailure::Disabled);
        }
        let client = self
            .store()
            .get_client(client_id)
            .await
            .map_err(RegistrationFailure::Storage)?
            .ok_or(RegistrationFailure::Unauthorized)?;
        let registration = client
            .registration
            .as_deref()
            .cloned()
            .ok_or(RegistrationFailure::Unauthorized)?;
        if !registration
            .registration_access_token_hash
            .verify(registration_access_token, self.hooks().secret_verifier())
        {
            return Err(RegistrationFailure::Unauthorized);
        }
        Ok((client, registration))
    }

    /// RFC 7592 section 2.1: read a registration.
    ///
    /// The response carries no `client_secret` and no `registration_access_token`, because this
    /// server stores neither: see the module docs.
    pub async fn read_registration(
        &self,
        client_id: &ClientId,
        registration_access_token: &str,
    ) -> Result<ClientInformation, RegistrationFailure> {
        let (client, registration) = self
            .authenticate_registration(client_id, registration_access_token)
            .await?;
        let config = self.registration_config()?;
        Ok(ClientInformation {
            client_id: client.client_id.as_str().to_string(),
            client_secret: None,
            client_id_issued_at: registration.client_id_issued_at,
            client_secret_expires_at: registration.client_secret_expires_at,
            registration_access_token: None,
            registration_client_uri: Some(registration_client_uri(
                config,
                self.config(),
                client.client_id.as_str(),
            )),
            metadata: registered_metadata(&client, &registration),
        })
    }

    /// RFC 7592 section 2.2: replace a registration's metadata.
    ///
    /// The whole document is replaced, not merged: section 2.2 says the client sends its full
    /// metadata and that any omitted member is treated as absent. Merging would make a client that
    /// dropped a redirect URI keep it, which is precisely backwards for the one member that
    /// decides where a code may be delivered.
    ///
    /// `client_id` cannot be changed (section 2.2), and the grant and scope ceilings of
    /// [`RegistrationConfig`] apply again, so an update cannot reach anything a fresh registration
    /// could not.
    pub async fn update_registration(
        &self,
        client_id: &ClientId,
        registration_access_token: &str,
        metadata: &ClientMetadata,
    ) -> Result<ClientInformation, RegistrationFailure> {
        let (client, registration) = self
            .authenticate_registration(client_id, registration_access_token)
            .await?;
        let config = self.registration_config()?;

        // The host decides on an UPDATE too, and this is not a formality. RFC 7592 section 2.2
        // has the client send a complete replacement metadata document, so every content control
        // a policy applied at registration (a `client_name` impersonating the deployment, a
        // `redirect_uris` entry on a domain the host will not serve) is exactly what this call can
        // rewrite. Consulting the policy only on the way in would leave every one of those
        // controls one PUT away from being void, and the registration access token is long lived
        // where an initial access token is typically single use.
        //
        // `initial_access_token` is None because there is no second one to present: RFC 7592
        // section 2 authenticates this request with the registration access token, which
        // `authenticate_registration` above has already verified.
        let attempt = RegistrationAttempt {
            initial_access_token: None,
            metadata,
        };
        match self.hooks().registration_policy() {
            Some(policy) if policy.authorize(&attempt) == RegistrationDecision::Allow => {}
            _ => return Err(RegistrationFailure::Unauthorized),
        }

        let registered = validate(metadata, config)?;

        // A change of authentication method that needs a secret the registration does not have
        // mints one; this is the only path other than registration itself that can produce one.
        let wants_secret = registered.token_endpoint_auth_method != AUTH_METHOD_NONE;
        let had_secret = client.auth.is_confidential();
        let new_secret = (wants_secret && !had_secret).then(|| crate::server::random_hex(32));
        let auth = match (&new_secret, wants_secret) {
            (Some(s), _) => ClientAuth::ConfidentialSecretHash {
                hash: SecretHash::sha256(s),
            },
            // Keeps the existing verifier: this server cannot re-issue a secret it does not hold,
            // and silently rotating one on every metadata edit would log the client out of the
            // token endpoint for changing its name.
            (None, true) => client.auth.clone(),
            (None, false) => ClientAuth::Public,
        };
        let client_secret_expires_at = match (&new_secret, wants_secret) {
            (Some(_), _) => Some(match config.client_secret_ttl {
                None => 0,
                Some(ttl) => {
                    crate::server::unix_seconds(self.now()).unwrap_or_default() + ttl.as_secs()
                }
            }),
            (None, true) => registration.client_secret_expires_at,
            (None, false) => None,
        };

        let updated_registration = DynamicRegistration {
            registration_access_token_hash: registration.registration_access_token_hash.clone(),
            client_id_issued_at: registration.client_id_issued_at,
            client_secret_expires_at,
            token_endpoint_auth_method: registered.token_endpoint_auth_method.clone(),
        };
        let updated = Client {
            client_id: client.client_id.clone(),
            auth,
            grant_types: registered.grant_types.clone(),
            redirect_uris: registered.redirect_uris.clone(),
            allowed_scopes: registered.scope.clone(),
            default_scopes: registered.scope.clone(),
            name: registered.client_name.clone(),
            registration: Some(Box::new(updated_registration.clone())),
        };
        self.store()
            .put_client(updated.clone())
            .await
            .map_err(RegistrationFailure::Storage)?;
        self.hooks()
            .emit(|| crate::events::Event::ClientRegistrationUpdated {
                client_id: client_id.as_str(),
            });

        Ok(ClientInformation {
            client_id: client_id.as_str().to_string(),
            client_secret: new_secret,
            client_id_issued_at: updated_registration.client_id_issued_at,
            client_secret_expires_at: updated_registration.client_secret_expires_at,
            registration_access_token: None,
            registration_client_uri: Some(registration_client_uri(
                config,
                self.config(),
                client_id.as_str(),
            )),
            metadata: registered_metadata(&updated, &updated_registration),
        })
    }

    /// RFC 7592 section 2.3: delete a registration.
    ///
    /// Deletion takes everything the registration was issued with it, through
    /// [`Storage::delete_client`]: a client that no longer exists must not still have live access
    /// tokens, refresh chains or outstanding authorization codes. Section 2.3 requires exactly
    /// that, and it is the half of deletion that is easy to skip and impossible to notice.
    pub async fn delete_registration(
        &self,
        client_id: &ClientId,
        registration_access_token: &str,
    ) -> Result<(), RegistrationFailure> {
        self.authenticate_registration(client_id, registration_access_token)
            .await?;
        self.store()
            .delete_client(client_id)
            .await
            .map_err(RegistrationFailure::Storage)?;
        self.hooks()
            .emit(|| crate::events::Event::ClientRegistrationDeleted {
                client_id: client_id.as_str(),
            });
        Ok(())
    }
}

/// RFC 7592 section 3 `registration_client_uri`: `{registration_endpoint}/{client_id}`.
///
/// The client id is a 32-character hex string this server minted, so it carries nothing that needs
/// percent-encoding here.
fn registration_client_uri(
    config: &RegistrationConfig,
    server: &ServerConfig,
    client_id: &str,
) -> String {
    format!("{}/{client_id}", config.endpoint(&server.issuer))
}

#[cfg(test)]
#[path = "tests/registration.rs"]
mod tests;
