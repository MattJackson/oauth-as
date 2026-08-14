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
//! responses of sections 2.1 and 2.2 also use. This server cannot ECHO either one, because it does
//! not have them: it kept a verifier, not the credential. A credential appears in a response
//! exactly once, in the response that MINTED it, and after that the client holds the only copy. The
//! alternative is storing two live bearer credentials in plaintext for the lifetime of every
//! registration, which is the thing [`crate::client::SecretHash`] exists to stop.
//!
//! So a read (section 2.1) returns neither, and an update (section 2.2) returns no
//! `registration_access_token` — this server never rotates that one, so there is never a new one to
//! hand back. An update DOES return a `client_secret` in one case, and only that case: when the
//! updated metadata moves the client from `token_endpoint_auth_method: none` to a method that needs
//! a secret, [`AuthorizationServer::update_registration`] mints one, because a client that has just
//! become confidential and was told nothing would be a client that can no longer authenticate at
//! all. That is a mint, not an echo, and it obeys the same once-only rule as the rest.
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
//!   `contacts`, `tos_uri`, `policy_uri`). They are ignored, as section 2 permits, because this
//!   server renders no branded consent screen, so storing them would be storing
//!   attacker-supplied strings for no purpose.
//! - `jwks` and `jwks_uri` (RFC 7591 section 2), and this one is a GAP rather than a decision.
//!   The crate does RFC 7523 client assertions under the `client-assertion` feature, so a key
//!   registered here would be a key the token endpoint could use; modelling these two members is
//!   most of what it would take to make `private_key_jwt` registrable, and it is not done. Until
//!   it is, a `private_key_jwt` client is one the HOST provisions out of band, and asking to
//!   register one is refused rather than accepted-and-ignored (see the note on the
//!   `AUTH_METHOD_*` constants below).

use serde::{Deserialize, Serialize};

use crate::client::{Client, ClientAuth, ClientId, DynamicRegistration, SecretHash};
use crate::events::ClientAuthFailure;
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
    ///
    /// `Cow<'static, str>` for the same reason [`crate::error::ErrorResponse`] uses one: every
    /// refusal `validate` can produce describes a RULE rather than a value, so the description is
    /// always a string constant, and RFC 7591 section 1.2 makes the initial access token optional,
    /// which means a host may expose this endpoint to unauthenticated callers who then choose its
    /// refusal rate. Size neutral: `Option<Cow<'static, str>>` is 24 bytes, exactly what
    /// `Option<String>` was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<std::borrow::Cow<'static, str>>,
}

impl RegistrationErrorResponse {
    /// An error with a description attached.
    pub fn new(
        error: RegistrationErrorCode,
        description: impl Into<std::borrow::Cow<'static, str>>,
    ) -> Self {
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

/// For the reason [`crate::error::ErrorResponse`] is one: this is the value a host is handed when
/// a registration is refused, and a host that propagates it with `?` into a `Box<dyn Error>`
/// should not have to care which of the two sibling refusal bodies it is holding. There is no
/// `source`: the refusal describes a rule this server applied, not a failure underneath it.
impl std::error::Error for RegistrationErrorResponse {}

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

/// The refusal a randomness failure becomes on these two endpoints.
///
/// RFC 7591 registration and RFC 7592 management are ORDINARY ROUTES (`POST /register`,
/// `PUT /register/{id}`), so a `getrandom` that will not answer — an exhausted descriptor table, a
/// seccomp policy, a container without the syscall — has to become a refusal here exactly as it
/// does at the token and authorization endpoints. Through 0.9.0 these four draws used the
/// panicking `random_hex`, on the strength of a comment asserting they were "outside the request
/// path"; they never were.
///
/// [`RegistrationFailure::Storage`] is the crate's 500, and it is the honest answer for the same
/// reason `crate::server::randomness_error` collapses onto RFC 6749 section 5.2 `server_error`: the
/// caller must learn only that this server could not fulfil the request and that retrying later is
/// the right response. The message says which internal condition it was, for the host's own logs.
fn randomness_failure() -> RegistrationFailure {
    RegistrationFailure::Storage(StorageError::new(
        "the OS would not provide randomness for a registration artifact",
    ))
}

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
/// `#[non_exhaustive]`: this struct's field set VARIES WITH CARGO FEATURES, so a host that writes a
/// full struct literal has a build that breaks the day anything in their dependency graph enables a
/// feature they did not ask for. Construct with `new()` and assign the fields you want. This is the
/// one attribute on this type that cannot be added after publication, because by then somebody's
/// struct literal is in production.
#[non_exhaustive]
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

/// The largest number of `redirect_uris` one dynamic registration may declare.
///
/// # Why there is a cap at all
///
/// RFC 7591 section 2 sets none, and the list is not read here: it is read on EVERY authorization
/// request for the registered client, as a linear scan with exact string comparison, because
/// OAuth 2.1 section 4.1.3 forbids anything cheaper than exact matching. So an unbounded list is a
/// cost bought once, at an endpoint whose [`RegistrationPolicy`] a host may well have opened to
/// anonymous callers, and then paid per request for as long as the registration exists. That
/// durability is what makes this worth a constant rather than a shrug.
///
/// # Why 16
///
/// It is counted from what a real client needs: one redirect URI per deployment environment
/// (production, staging, a review app or two) times one per platform that needs its own
/// (web, a native custom scheme, a loopback range for a desktop app). That is a handful, and
/// sixteen is several times a handful. A registrant that genuinely needs more has one client
/// standing in for several, which is a modelling problem this cap makes visible rather than a
/// limit it imposes; separate clients also give the deployment separate secrets and separate
/// revocation, which is the better shape anyway.
///
/// # Why the scan stays linear
///
/// At sixteen it is faster than hashing, and it is the same argument as
/// [`crate::server::MAX_RESOURCE_INDICATORS`]. The defect was the missing bound, not the loop.
pub const MAX_REGISTERED_REDIRECT_URIS: usize = 16;

// The `token_endpoint_auth_method` values one may REGISTER here, which are a strict SUBSET of the
// ones RFC 8414 `token_endpoint_auth_methods_supported` advertises, and deliberately so. That
// document describes the TOKEN ENDPOINT (RFC 8414 s2), which really does accept
// `client_secret_jwt`, `private_key_jwt`, `tls_client_auth` and `self_signed_tls_client_auth` for
// a client the host provisioned out of band; narrowing it to this list would lie to every
// statically configured client that uses one.
//
// The other four are out of reach of REGISTRATION, not of the server:
//
// - `private_key_jwt` and `client_secret_jwt` need a key. [`ClientMetadata`] models neither `jwks`
//   nor `jwks_uri` (RFC 7591 s2), so there is nowhere for a registrant to put one, and
//   `client_secret_jwt` additionally needs the shared secret IN THE CLEAR at verification time
//   while a registration keeps only a one-way [`SecretHash`].
// - `tls_client_auth` and `self_signed_tls_client_auth` need the RFC 8705 s2.1.1 subject
//   parameters (`tls_client_auth_subject_dn` and the four SAN forms), which are likewise not
//   modelled.
//
// Accepting any of the four would mint a registration the token endpoint could never honour,
// which is worse than refusing it: RFC 7591 s3.2.2 gives `invalid_client_metadata` for exactly
// this, a value the server will not register. Closing the gap means modelling `jwks`/`jwks_uri`
// and the RFC 8705 subject parameters, and that is the change to make, not a wider list here.
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
///
/// `pub(crate)` rather than private because [`crate::cimd`] validates a
/// draft-ietf-oauth-client-id-metadata-document-01 client with THIS function rather than a second
/// copy of it. The members of a client identifier metadata document come from the same OAuth
/// Dynamic Client Registration Metadata registry (-01 section 4.1), so the rules are the same
/// rules, and this crate has already paid once for a rule that existed twice and drifted.
///
/// `Clone`, `PartialEq` and `Eq` exist for [`crate::cimd::ValidatedClientIdDocument`], which is the
/// only thing that holds one of these beyond the call that produced it. They are NOT feature gated,
/// and that was checked rather than assumed: `scripts/size-report.sh`'s `default` row is byte for
/// byte identical with and without them, because LTO deletes three impls a default build never
/// reaches. Gating them would have been noise for a measured zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Registered {
    pub(crate) redirect_uris: Vec<String>,
    pub(crate) grant_types: Vec<GrantType>,
    pub(crate) response_types: Vec<String>,
    pub(crate) token_endpoint_auth_method: String,
    pub(crate) scope: ScopeSet,
    pub(crate) client_name: Option<String>,
}

/// Validate one RFC 7591 section 2 metadata document against what this deployment will register.
///
/// Every refusal here is a registration this server would otherwise have written down and then
/// been unable to honour. That is the standard the rules are set to: not "is this plausible" but
/// "will the endpoints that later read this record be able to act on it".
pub(crate) fn validate(
    metadata: &ClientMetadata,
    config: &RegistrationConfig,
) -> Result<Registered, RegistrationFailure> {
    // RFC 7591 s2.3 / s3.2.2. First, because a client that sent one is asking to be registered on
    // terms this server has not read, and nothing after this point would be the registration it
    // asked for. See the module docs for why this is a refusal and not an ignored member.
    if metadata.software_statement.is_some() {
        return Err(RegistrationFailure::Invalid(
            RegistrationErrorResponse::new(
                RegistrationErrorCode::InvalidSoftwareStatement,
                "this server does not evaluate software statements (RFC 7591 s2.3)",
            ),
        ));
    }

    // RFC 7591 s2: absent `grant_types` defaults to `["authorization_code"]`.
    let grant_types: Vec<GrantType> =
        match metadata.grant_types.as_deref() {
            None => vec![GrantType::AuthorizationCode],
            Some(values) => {
                let mut out = Vec::with_capacity(values.len());
                for value in values {
                    // An unknown grant type is refused rather than dropped: see the test in
                    // `src/tests/registration.rs`. `implicit` and `password` land here too, which is
                    // right, because OAuth 2.1 removes both.
                    // `GrantType::parse` and not `value.parse()`: the refusal below discards the
                    // value, and `FromStr`'s error would first copy the caller's string onto the
                    // heap to carry it there. The registration document is caller-supplied text of
                    // the caller's chosen length, same as `grant_type` at the token endpoint.
                    let grant: GrantType = GrantType::parse(value).ok_or_else(|| {
                        RegistrationFailure::Invalid(RegistrationErrorResponse::new(
                            RegistrationErrorCode::InvalidClientMetadata,
                            "grant_types names a grant this server does not implement",
                        ))
                    })?;
                    if !config.allowed_grant_types.contains(&grant) {
                        return Err(RegistrationFailure::Invalid(RegistrationErrorResponse::new(
                        RegistrationErrorCode::InvalidClientMetadata,
                        "grant_types names a grant this deployment does not offer registrants",
                    )));
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
    let response_types: Vec<String> =
        match metadata.response_types.as_deref() {
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
                        return Err(RegistrationFailure::Invalid(RegistrationErrorResponse::new(
                        RegistrationErrorCode::InvalidClientMetadata,
                        "this server issues authorization codes only; OAuth 2.1 removes the \
                         implicit grant",
                    )));
                    }
                }
                let asks_for_code = !values.is_empty();
                // The correspondence, in both directions: `code` without `authorization_code` is a
                // response type nothing will produce, and `authorization_code` without `code` is a
                // grant with no way to start.
                if asks_for_code != uses_code {
                    return Err(RegistrationFailure::Invalid(RegistrationErrorResponse::new(
                    RegistrationErrorCode::InvalidClientMetadata,
                    "grant_types and response_types must correspond: authorization_code with \
                     code (RFC 7591 s2)",
                )));
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
        return Err(RegistrationFailure::Invalid(
            RegistrationErrorResponse::new(
                RegistrationErrorCode::InvalidRedirectUri,
                "the authorization_code grant requires at least one redirect_uri",
            ),
        ));
    }
    // A CAP, because a registration is durable and the cost it imposes is not paid here. Every
    // authorization request for this client scans `redirect_uris` linearly with exact string
    // comparison (OAuth 2.1 section 4.1.3 allows nothing cheaper), so an unbounded list bought
    // once at an endpoint a policy may well have opened to anonymous callers is a per-request cost
    // that lasts as long as the registration does. RFC 7591 section 2 sets no bound of its own.
    if metadata.redirect_uris.len() > MAX_REGISTERED_REDIRECT_URIS {
        return Err(RegistrationFailure::Invalid(
            RegistrationErrorResponse::new(
                RegistrationErrorCode::InvalidRedirectUri,
                "too many redirect_uris",
            ),
        ));
    }
    for uri in &metadata.redirect_uris {
        if !redirect_uri_is_registerable(uri) {
            // The offending value is NOT echoed: it is attacker-supplied and this description
            // goes into an error body and quite possibly a log line.
            return Err(RegistrationFailure::Invalid(
                RegistrationErrorResponse::new(
                    RegistrationErrorCode::InvalidRedirectUri,
                    "each redirect_uri must be an absolute URI with no fragment (RFC 6749 s3.1.2)",
                ),
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
        return Err(RegistrationFailure::Invalid(
            RegistrationErrorResponse::new(
                RegistrationErrorCode::InvalidClientMetadata,
                "token_endpoint_auth_method is not one this server can REGISTER; RFC 8414 \
                 token_endpoint_auth_methods_supported describes the token endpoint, which \
                 accepts more",
            ),
        ));
    }
    // RFC 6749 s4.4 gives client credentials to confidential clients only, so this pair produces a
    // registration whose only grant the token endpoint will refuse every time. Same argument as
    // the redirect URI rule above.
    if token_endpoint_auth_method == AUTH_METHOD_NONE
        && grant_types.contains(&GrantType::ClientCredentials)
    {
        return Err(RegistrationFailure::Invalid(
            RegistrationErrorResponse::new(
                RegistrationErrorCode::InvalidClientMetadata,
                "client_credentials requires a confidential client (RFC 6749 s4.4)",
            ),
        ));
    }

    // RFC 6749 s3.3 syntax, then the deployment's ceiling. Both are `invalid_client_metadata`:
    // s3.2.2 has one code for a metadata value this server will not accept.
    let scope =
        match metadata.scope.as_deref() {
            None => ScopeSet::empty(),
            Some(s) => {
                let requested = ScopeSet::parse(s).map_err(|_| {
                    RegistrationFailure::Invalid(RegistrationErrorResponse::new(
                        RegistrationErrorCode::InvalidClientMetadata,
                        "scope is not a space-delimited RFC 6749 s3.3 token list",
                    ))
                })?;
                if !requested.is_subset(&config.allowed_scopes) {
                    return Err(RegistrationFailure::Invalid(RegistrationErrorResponse::new(
                    RegistrationErrorCode::InvalidClientMetadata,
                    "scope exceeds what this deployment offers dynamically registered clients",
                )));
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
    ///
    /// # THIS FUTURE IS NOT CANCELLATION SAFE, and what a drop costs
    ///
    /// A dropped future stops at whatever `await` it was suspended in and never resumes, and this
    /// crate cannot make it finish: there is no destructor that can run an `async` store call. The
    /// token plane states this contract on [`AuthorizationServer::token`] and
    /// [`AuthorizationServer::revoke`]. The management plane pays something different for a drop,
    /// and until 0.9.2 said nothing at all about it.
    ///
    /// What it costs here follows from the once-only rule above: the credentials are minted
    /// BEFORE [`crate::store::Storage::put_client`] and handed back only in the return value after
    /// it. A drop at or after that write leaves a row this server will honour whose registration
    /// access token — and, for a confidential registration, whose client secret — existed only in
    /// the dropped frame. Nothing recovers either one: this server kept verifiers, not
    /// credentials, so there is nothing to re-send; RFC 7592
    /// management of that registration needs the access token that is gone, so section 2.3 cannot
    /// delete it either; and a [`crate::client::Client`] has no expiry and is never reclaimed by
    /// [`crate::store::Storage::sweep_expired`]. The caller sees a request that did not answer and
    /// retries, which registers a SECOND client. The first is permanent litter that only a host
    /// deleting it out of band removes.
    ///
    /// The order is not the defect and reversing it would be worse: returning the credentials
    /// before the write would hand a caller a live-looking secret for a registration that then
    /// failed to persist.
    ///
    /// WHAT A HOST MUST DO, exactly as on the token plane: drive this from a task the connection
    /// cannot cancel — spawn the call and await the join handle — so a disconnecting client aborts
    /// the response and not the work. This crate's axum adapter already does that for every route,
    /// this one included, because it spawns inside a single `fallback`; see [`crate::http`]. A
    /// host that mounts [`crate::http::AuthorizationService::handle`] itself, or calls this method
    /// directly, owns it.
    pub async fn register_dynamic_client(
        &self,
        metadata: &ClientMetadata,
        initial_access_token: Option<&str>,
    ) -> Result<ClientInformation, RegistrationFailure> {
        self.admit_registration()?;
        self.register_admitted_client(metadata, initial_access_token)
            .await
    }

    /// THE HOST'S THROTTLE, before the host's policy and before anything is read or written — and,
    /// for an HTTP caller, before the request BODY is parsed.
    ///
    /// This endpoint is the one place in the crate where a caller's request becomes a PERMANENT
    /// row: a `Client` has no expiry and `Storage::sweep_expired` never reclaims one, so an
    /// unthrottled registration endpoint is not a burst a deployment rides out, it is growth that
    /// does not come back. RFC 7591 section 5 says the same thing in prose — an open registration
    /// endpoint is available to anyone on the internet — and a [`RegistrationPolicy`] is a decision
    /// about CONTENT, which is the wrong instrument for volume.
    ///
    /// The refusal is `Unauthorized`, the same answer the policy refusal gives, and deliberately
    /// so: those two must not be distinguishable, or a caller learns from the wire whether it was
    /// the content or the rate that stopped them. No event is emitted, because there is no
    /// `client_id` to name and the audit vocabulary here is about credentials.
    ///
    /// `pub(crate)` for ONE caller and one reason, exactly as
    /// [`AuthorizationServer::authenticate_registration`] is: `crate::http`'s RFC 7591 `POST`
    /// handler runs it before it parses the request body, so an anonymous caller cannot buy a
    /// `MAX_BODY_BYTES` JSON parse per request. RFC 7591 s3.1 registration MAY be anonymous, so
    /// unlike the RFC 7592 management plane there is no credential to look at first — but the
    /// throttle is not a credential, it is keyed on nothing at all, and nothing stopped it being
    /// asked first. That it was not is the whole of the defect.
    ///
    /// [`AuthorizationServer::register_dynamic_client`] still runs it for itself, so a host calling
    /// that method directly is throttled on the same terms. It is NOT re-run underneath the HTTP
    /// handler, which is the difference from the management plane's arrangement: this budget is
    /// GLOBAL and its shipped default is 60 per window, so a second charge for one request would
    /// quietly halve a host's configured ceiling. The split into
    /// `register_admitted_client` is what keeps the count at one, and
    /// `tests/http_refusal_honesty.rs` counts it.
    ///
    /// The `registration_config` check comes FIRST and is repeated below, so that a deployment with
    /// registration disabled answers `Disabled` exactly as it did before rather than spending a
    /// throttle budget on an endpoint it does not serve.
    pub(crate) fn admit_registration(&self) -> Result<(), RegistrationFailure> {
        self.registration_config()?;
        if self
            .hooks()
            .check(crate::events::Attempt::ClientRegistration)
            == crate::events::RateLimitDecision::Deny
        {
            return Err(RegistrationFailure::Unauthorized);
        }
        Ok(())
    }

    /// RFC 7591 section 3.1 from the policy check onwards, for a caller
    /// [`AuthorizationServer::admit_registration`] has already admitted.
    ///
    /// Split out so the throttle can be asked before an HTTP body is parsed and asked ONCE; see
    /// that method. Every branch here is the one it was when this was the back half of
    /// `register_dynamic_client`.
    pub(crate) async fn register_admitted_client(
        &self,
        metadata: &ClientMetadata,
        initial_access_token: Option<&str>,
    ) -> Result<ClientInformation, RegistrationFailure> {
        let config = self.registration_config()?;
        let limited = crate::events::Attempt::ClientRegistration;

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
            _ => {
                // `None`: no client id has been minted yet, and none is minted for a refusal.
                self.hooks()
                    .emit(|| crate::events::Event::ClientRegistrationRefusedByPolicy {
                        client_id: None,
                    });
                self.hooks()
                    .record(limited, crate::events::AttemptOutcome::Failed);
                return Err(RegistrationFailure::Unauthorized);
            }
        }

        // Reported as a FAILURE, which is what a limiter counting abuse rather than traffic wants:
        // a caller submitting documents this server refuses is the shape of somebody probing for
        // what the policy and the validator will accept.
        let registered = match validate(metadata, config) {
            Ok(registered) => registered,
            Err(refusal) => {
                self.hooks()
                    .record(limited, crate::events::AttemptOutcome::Failed);
                return Err(refusal);
            }
        };

        let now = crate::server::unix_seconds(self.now());
        // `?` rather than a panic, for the reason `randomness_failure` gives: this is an
        // unauthenticated HTTP route, and a library that aborts its host's request handler because
        // the OS would not hand over sixteen bytes is worse than one that answers 500.
        let client_id =
            ClientId::new(crate::server::try_random_hex(16).ok_or_else(randomness_failure)?);
        let secret = if registered.token_endpoint_auth_method != AUTH_METHOD_NONE {
            Some(crate::server::try_random_hex(32).ok_or_else(randomness_failure)?)
        } else {
            None
        };
        let secret_expires_at = secret.as_ref().map(|_| match config.client_secret_ttl {
            // RFC 7591 section 3.2.1: 0 means the secret never expires.
            None => 0,
            // `saturating_add`: plain `+` panics in debug and, worse, WRAPS in release, which
            // would report a freshly minted secret as already expired. A host-set TTL is not
            // validated anywhere, so the ceiling is the honest answer.
            Some(ttl) => now.unwrap_or_default().saturating_add(ttl.as_secs()),
        });
        let registration_access_token =
            crate::server::try_random_hex(32).ok_or_else(randomness_failure)?;

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

        // Emitted AFTER the write: a registration that failed to persist did not happen. The
        // outcome is reported on the same terms, and for the same reason: the row exists now.
        self.hooks()
            .emit(|| crate::events::Event::ClientRegistered {
                client_id: client_id.as_str(),
            });
        self.hooks()
            .record(limited, crate::events::AttemptOutcome::Succeeded);

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
    /// Every failure is [`RegistrationFailure::Unauthorized`]: an attempt the host's rate limiter
    /// denied, an unknown client, a statically provisioned client that has no registration access
    /// token, and a wrong token are one answer on the wire, because telling them apart is an
    /// enumeration oracle over the client table — and, for the limiter's own refusal, because a
    /// distinct answer would tell an attacker they had found a live registration and merely hit
    /// the ceiling.
    ///
    /// The same timing caveat that `AuthorizationServer::authenticate_client` documents applies:
    /// this returns before any hashing when the client is unknown, so an unknown client and a
    /// known client with the wrong token are distinguishable by wall time. The comparison itself
    /// leaks nothing (see [`SecretHash::verify`]); equalising the two paths is the host's
    /// business.
    ///
    /// THE HOST'S [`crate::events::RateLimiter`] IS ASKED FIRST, before the store is touched, and
    /// the attempt is [`crate::events::Attempt::ClientAuthentication`] keyed on this `client_id`:
    /// the same budget the token endpoint spends, because this is the same client's other
    /// credential and the more powerful one. Until 0.9.2 this said the host "is expected to
    /// throttle anyway", which was advice the host could not take through this crate: no `Attempt`
    /// reached the seam from any of the three management verbs. See the body for why the budget is
    /// shared rather than new.
    ///
    /// What the WIRE will not say, the AUDIT CHANNEL does. Each of the four refusals emits
    /// [`crate::events::Event::ClientRegistrationAuthenticationFailed`] naming which one it was,
    /// for the same reason the token plane separates its refusals: the host is not the attacker,
    /// and it cannot notice somebody guessing registration access tokens if the only record of the
    /// guess is a `401` that looks like every other `401`. That matters more here than on the token
    /// plane, because RFC 7592 section 2.2 lets a landed guess rewrite `redirect_uris`.
    /// `pub(crate)` for ONE caller and one reason: `crate::http`'s RFC 7592 `PUT` handler runs it
    /// before it parses the request body, so an unauthenticated caller cannot buy a
    /// `MAX_BODY_BYTES` JSON parse per request. `update_registration` below still authenticates for
    /// itself, because a check performed by a caller is not a check the method may assume — so an
    /// HTTP `PUT` spends TWO units of the throttle's budget rather than one. That is stated rather
    /// than tuned away: at the shipped default of 6000 per client per minute it is not a ceiling
    /// any real management traffic reaches, and removing the second check to save a unit would
    /// trade a bound for an assumption.
    pub(crate) async fn authenticate_registration(
        &self,
        client_id: &ClientId,
        registration_access_token: &str,
    ) -> Result<(std::sync::Arc<Client>, DynamicRegistration), RegistrationFailure> {
        let config = self.registration_config()?;
        if !config.management_enabled {
            return Err(RegistrationFailure::Disabled);
        }
        // THE HOST'S THROTTLE, before the store is touched, exactly as
        // `AuthorizationServer::authenticate_client` asks before it looks a client up.
        //
        // This is a bearer credential being GUESSED AT, which is the thing RFC 9700 section 4.13
        // is about, and the credential here is the more powerful of the two a dynamic registration
        // holds: the client secret authenticates as the client, while this one REWRITES (RFC 7592
        // s2.2) and DELETES (s2.3) the registration, cascading through every token and refresh
        // chain it was issued. Through 0.9.1 the three management verbs took no `Attempt` at all,
        // so a host that installed a limiter had this plane open while believing otherwise, and
        // the note on this function told that host it "is expected to throttle anyway" without
        // giving it anywhere to do so through this crate's own seam.
        //
        // `Attempt::ClientAuthentication` rather than a variant of its own, and rather than
        // `Attempt::ClientRegistration` (which names RFC 7591 and the permanent row it writes).
        // Two reasons. It is the same question — may this caller keep presenting credentials as
        // this `client_id` — and one client's two credentials sharing one budget is the answer
        // that cannot be walked around by moving from one endpoint to the other. And it adds NO
        // new denial of service: the budget is already keyed on a `client_id` RFC 6749 s2.2 makes
        // public, so anybody who could exhaust it here could already exhaust it by spraying wrong
        // secrets at the token endpoint.
        let attempt = crate::events::Attempt::ClientAuthentication {
            client_id: client_id.as_str(),
        };
        if self.hooks().check(attempt) == crate::events::RateLimitDecision::Deny {
            // No `record`: the attempt never happened, so there is no outcome to report. The
            // refusal is the SAME `Unauthorized` a wrong token gets (see below), because a
            // distinct answer would tell an attacker they had found a live registration and
            // merely hit the ceiling.
            return Err(self.registration_auth_failed(
                client_id,
                ClientAuthFailure::RateLimited,
                false,
            ));
        }
        let found = self
            .store()
            .get_client(client_id)
            .await
            .map_err(RegistrationFailure::Storage)?;
        let client = match found {
            Some(client) => client,
            None => {
                return Err(self.registration_auth_failed(
                    client_id,
                    ClientAuthFailure::UnknownClient,
                    true,
                ))
            }
        };
        let registration = match client.registration.as_deref() {
            Some(registration) => registration.clone(),
            // A client the host provisioned itself. Reported apart from an unknown id because it
            // says the id was real, which is what an operator needs to see the probe for.
            None => {
                return Err(self.registration_auth_failed(
                    client_id,
                    ClientAuthFailure::NoDynamicRegistration,
                    true,
                ))
            }
        };
        if !registration
            .registration_access_token_hash
            .verify(registration_access_token, self.hooks().secret_verifier())
        {
            return Err(self.registration_auth_failed(
                client_id,
                ClientAuthFailure::SecretMismatch,
                true,
            ));
        }
        // The limiter counts FAILURES rather than traffic (see `crate::rate_limit`), so a
        // management call that authenticated has to say so or a legitimate client's own polling
        // would be charged at the rate a guessing attack is.
        self.hooks()
            .record(attempt, crate::events::AttemptOutcome::Succeeded);
        Ok((client, registration))
    }

    /// Report one refused management authentication and answer with the single wire failure all
    /// four share.
    ///
    /// The presented token is NOT a parameter, and that is deliberate rather than incidental: it
    /// cannot be logged by a later edit to this function because it is not here to log. See the
    /// rule in the [`crate::events`] module docs.
    ///
    /// `attempted` says whether the limiter ALLOWED this attempt and it then failed, which is the
    /// only case there is an outcome to report: a refusal by the limiter itself never happened, so
    /// reporting it would charge the caller twice for one attempt and, on a failure-weighted
    /// budget like [`crate::rate_limit::FixedWindowRateLimiter`], charge the heavier of the two
    /// prices for work nobody did.
    fn registration_auth_failed(
        &self,
        client_id: &ClientId,
        failure: ClientAuthFailure,
        attempted: bool,
    ) -> RegistrationFailure {
        self.hooks().emit(
            || crate::events::Event::ClientRegistrationAuthenticationFailed {
                client_id: client_id.as_str(),
                failure,
            },
        );
        if attempted {
            self.hooks().record(
                crate::events::Attempt::ClientAuthentication {
                    client_id: client_id.as_str(),
                },
                crate::events::AttemptOutcome::Failed,
            );
        }
        RegistrationFailure::Unauthorized
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
    ///
    /// The response carries a `client_secret` in exactly one case: an update that moves the client
    /// from `token_endpoint_auth_method: none` to a method that needs one MINTS a secret, and this
    /// is the only response other than the original registration that ever carries a live
    /// credential. It is never an ECHO of an existing secret, which this server does not hold; see
    /// the module docs.
    ///
    /// # THIS FUTURE IS NOT CANCELLATION SAFE, and this is the drop a client cannot retry around
    ///
    /// See [`AuthorizationServer::register_dynamic_client`] for why a dropped future cannot be
    /// finished by this crate. The expensive drop point here is the one case above: the mint.
    ///
    /// When this call mints a secret it writes the [`crate::client::SecretHash`] of it through
    /// [`crate::store::Storage::compare_and_swap_client`], and returns the secret itself only in
    /// the value at the end of this function. A drop after that swap RESOLVES and before the
    /// response reaches the client leaves the store holding a verifier for a string that exists
    /// nowhere. The client's retry does not repair it and cannot: the stored registration is now
    /// confidential, so on the second pass `had_secret` is true and the arm that KEEPS THE
    /// EXISTING VERIFIER is taken rather than the mint. That arm is right for what it was written
    /// for — a metadata edit must not log a client out of the token endpoint — and nothing on the
    /// wire distinguishes that case from this one. The registration can never authenticate at the
    /// token endpoint again.
    ///
    /// The way out is RFC 7592 section 2.3, and it is the only one: this call never rotates the
    /// registration access token, so the client still holds it and can DELETE the registration and
    /// register afresh. A host whose [`RegistrationPolicy`] admits an initial access token only
    /// once has to provision the client again itself.
    ///
    /// Reversing the order would be worse rather than better: handing the secret back before the
    /// swap would give a client a credential for a write that a concurrent section 2.3 delete is
    /// entitled to refuse — which is exactly what the compare-and-swap exists to allow. So the
    /// order stands and the contract is stated instead.
    ///
    /// The cheaper drop points, for completeness: anywhere before the swap costs nothing, because
    /// nothing has been written; between the swap and the return, an update with no mint loses
    /// only the [`crate::events::Event::ClientRegistrationUpdated`], so an audit trail can miss an
    /// update that did happen.
    ///
    /// WHAT A HOST MUST DO is what [`AuthorizationServer::register_dynamic_client`] says: spawn
    /// this and await the join handle. The axum adapter does. A host driving this future from the
    /// connection is choosing the cost above, at whatever rate its clients disconnect.
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
            _ => {
                // The caller HAS authenticated here, with a registration access token this server
                // just verified, and is being refused anyway. See the event's own docs on why that
                // is a different thing from a failed authentication.
                self.hooks()
                    .emit(|| crate::events::Event::ClientRegistrationRefusedByPolicy {
                        client_id: Some(client_id.as_str()),
                    });
                return Err(RegistrationFailure::Unauthorized);
            }
        }

        let registered = validate(metadata, config)?;

        // A change of authentication method that needs a secret the registration does not have
        // mints one; this is the only path other than registration itself that can produce one.
        let wants_secret = registered.token_endpoint_auth_method != AUTH_METHOD_NONE;
        let had_secret = client.auth.is_confidential();
        // `?` for the reason `randomness_failure` gives; RFC 7592 s2.2 is a routed `PUT` and this
        // is the only path other than registration itself that mints a secret.
        let new_secret = if wants_secret && !had_secret {
            Some(crate::server::try_random_hex(32).ok_or_else(randomness_failure)?)
        } else {
            None
        };
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
                    // Same saturating add as the mint path above, for the same reason.
                    crate::server::unix_seconds(self.now())
                        .unwrap_or_default()
                        .saturating_add(ttl.as_secs())
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
        // COMPARE-AND-SWAP, not a blind put. This function read the registration at its top, then
        // awaited a policy decision and a validation pass before arriving here, and a concurrent
        // RFC 7592 section 2.3 delete anywhere in that window used to be UNDONE by this write: the
        // client came back with its old credential and its old `registration_access_token_hash`,
        // which makes deleting a compromised registration defeatable by whoever holds the stolen
        // token. `client` is exactly what was read, so it is the expectation; a store that no
        // longer holds it refuses, and the deletion stands.
        //
        // The refusal is `Unauthorized` rather than a storage error, because by the time this
        // returns false the caller's registration access token names a registration that no
        // longer exists. That is the same answer `authenticate_registration` gives for an unknown
        // client, which is what this now is.
        //
        // NO AUDIT EVENT, and the absence is the fix rather than an omission. This used to report
        // `ClientAuthFailure::UnknownClient` on the management plane, which is a claim that an
        // AUTHENTICATION FAILED — and the authentication did not fail: reaching this line requires
        // `authenticate_registration` above to have SUCCEEDED, so the caller presented a
        // registration access token this server verified. The only ways here are a concurrent
        // section 2.3 delete and a second concurrent update, neither of which is a credential
        // guess. `Event::ClientRegistrationAuthenticationFailed` is the one signal a host has for
        // somebody guessing registration access tokens (see its docs on what a landed guess buys an
        // attacker), and a deployment whose own racing clients emit it is a deployment that has
        // learned to ignore it. What an operator sees instead is exactly what happened: a
        // `ClientRegistrationDeleted` (or another `ClientRegistrationUpdated`) from the request that
        // won, and no `ClientRegistrationUpdated` from this one.
        let applied = self
            .store()
            .compare_and_swap_client(&client, updated.clone())
            .await
            .map_err(RegistrationFailure::Storage)?;
        if !applied {
            return Err(RegistrationFailure::Unauthorized);
        }
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
    ///
    /// # THIS FUTURE IS NOT CANCELLATION SAFE, and what a drop costs
    ///
    /// This is the cheap one of the three; see [`AuthorizationServer::register_dynamic_client`]
    /// for the contract and [`AuthorizationServer::update_registration`] for the expensive one. A
    /// drop before [`crate::store::Storage::delete_client`] leaves the registration standing, and
    /// the client still holds the registration access token, so the request is simply repeatable.
    /// A drop after it loses the [`crate::events::Event::ClientRegistrationDeleted`], so a host
    /// can find a registration gone with no audit record of who removed it. A retry after that
    /// answers `Unauthorized`, because the token now names a registration that does not exist —
    /// and pays what an unknown id pays: a
    /// [`crate::events::Event::ClientRegistrationAuthenticationFailed`] carrying
    /// [`crate::events::ClientAuthFailure::UnknownClient`], charged to the limiter as a failure.
    /// So a client retrying a deletion that in fact completed reads, to an operator, exactly like
    /// somebody guessing at a registration access token. That is the audit cost of a drop here,
    /// and it is the whole of it: nothing is left half-written.
    pub async fn delete_registration(
        &self,
        client_id: &ClientId,
        registration_access_token: &str,
    ) -> Result<(), RegistrationFailure> {
        self.authenticate_registration(client_id, registration_access_token)
            .await?;
        // The barrier deadline comes from the server's own token lifetimes: a deletion has to
        // refuse not just the records that exist now but anything an issuance already in flight
        // for this client is about to write. See `revocation_window`.
        self.store()
            .delete_client(client_id, self.revocation_window())
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
/// THE ID IS ESCAPED, and until the 0.9.1 audit this was a bare `format!` justified by the ids this
/// server MINTS being 32 hex characters. That justification only ever covered the dynamic path:
/// `read_registration` and `update_registration` mint this URL for whatever client the caller
/// authenticated as, and a host that provisioned a client through `register_client` chose its own
/// id. A space, a `?` or a `#` in one produced a `registration_client_uri` that is not a URL, and a
/// slash produced one that names a different resource; the client uses the value verbatim, so the
/// escaping has to happen where the URL is built.
///
/// RFC 3986 section 3.3: everything outside `unreserved` is percent-encoded, which is stricter than
/// `pchar` allows and is the safe direction. `crate::http`'s `decode_path_segment` decodes the
/// segment on the way back in, so the round trip is exact.
fn registration_client_uri(
    config: &RegistrationConfig,
    server: &ServerConfig,
    client_id: &str,
) -> String {
    let endpoint = config.endpoint(&server.issuer);
    let mut url = String::with_capacity(endpoint.len() + 1 + client_id.len());
    url.push_str(&endpoint);
    url.push('/');
    for byte in client_id.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                url.push(byte as char)
            }
            other => url.push_str(&format!("%{other:02X}")),
        }
    }
    url
}

#[cfg(test)]
#[path = "tests/registration.rs"]
mod tests;
