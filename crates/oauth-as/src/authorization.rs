// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The authorization endpoint (RFC 6749 section 4.1) under the OAuth 2.1 constraints: `code` is
//! the only response type (the implicit grant is removed), PKCE is REQUIRED, only `S256` is
//! offered, and registered redirect URIs match exactly.
//!
//! # Why the request type is lenient
//!
//! [`AuthorizationRequest`] holds raw, optional text rather than parsed enums. A server cannot
//! reject what it cannot represent, and rejecting correctly is most of what this endpoint does:
//! a request with no `code_challenge`, or with `response_type=token`, has to reach the state
//! machine so the machine can answer it the way the RFC prescribes. Parsing into
//! [`ValidatedAuthorizationRequest`] is what validation MEANS here, and only the validated form
//! can mint a code. [`ValidatedAuthorizationRequest`] carries a private witness field so that,
//! within this crate, `ValidatedAuthorizationRequest::new` (private) is the only way to produce one; a
//! host consuming this crate cannot construct one for itself. See that type's doc comment for
//! exactly what is and is not proven by this.
//!
//! # Why the two error shapes are different
//!
//! RFC 6749 section 4.1.2.1 splits authorization errors in two, and the split is a security
//! boundary rather than a stylistic one. If the client or the redirect URI cannot be validated,
//! the AS MUST NOT redirect: the redirect target is precisely what an attacker would be trying to
//! choose, so reporting the error to it would hand over the thing being protected. Every other
//! error goes back to the (already validated) redirect URI as query parameters.
//!
//! # Allocation
//!
//! Request fields are [`Cow`], so a host parsing a query string that needs no percent-decoding
//! borrows it and allocates nothing. Only the validated form, which outlives the request while a
//! consent screen is shown, owns its data.

use std::borrow::Cow;
use std::fmt;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::client::ClientId;
use crate::error::{ErrorCode, ErrorResponse};
use crate::scope::ScopeSet;

/// `response_type` values this server will ever accept. OAuth 2.1 removes `token` (implicit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseType {
    /// The authorization-code response type.
    #[serde(rename = "code")]
    Code,
}

/// PKCE challenge methods this server offers (RFC 7636). OAuth 2.1 requires `S256`; `plain` is
/// deliberately not implemented, and is not advertised, because accepting it is a downgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeChallengeMethod {
    /// `code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))`, no padding.
    S256,
}

/// The raw authorization request as it arrives on the wire (RFC 6749 section 4.1.1 plus the RFC
/// 7636 PKCE parameters). The host parses its query string into this; every member is optional
/// because every member can be absent in a real (invalid) request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthorizationRequest<'a> {
    /// Must be `code`.
    pub response_type: Option<Cow<'a, str>>,
    /// The requesting client.
    pub client_id: Option<Cow<'a, str>>,
    /// Requested redirect target; must exact-match a registered URI when present.
    pub redirect_uri: Option<Cow<'a, str>>,
    /// Requested scope, space delimited; absent means the client's registered default.
    pub scope: Option<Cow<'a, str>>,
    /// Opaque client state, echoed back verbatim.
    pub state: Option<Cow<'a, str>>,
    /// The PKCE challenge (REQUIRED in OAuth 2.1 for the authorization code grant).
    pub code_challenge: Option<Cow<'a, str>>,
    /// The PKCE method; only `S256`.
    pub code_challenge_method: Option<Cow<'a, str>>,
    /// RFC 8707 resource indicators: the resource server(s) the client intends the issued token to
    /// be used at.
    ///
    /// A `Vec` rather than an `Option<Cow>` because RFC 8707 section 2 says the parameter MAY be
    /// repeated, and a client naming two resource servers means both, not the last one. An empty
    /// `Vec` allocates nothing, so a request that carries no `resource` still costs what it did
    /// before this parameter existed.
    pub resource: Vec<Cow<'a, str>>,
    /// RFC 9396 section 2 `authorization_details`: a JSON array of objects, each naming a
    /// `type` that defines the rest of it.
    ///
    /// RAW TEXT, not a parsed structure, for the reason the rest of this type is raw text:
    /// a server cannot reject what it cannot represent, and this parameter's failure modes
    /// (unparseable, oversized, an unknown type) all have to reach the state machine so it
    /// can answer them the way RFC 9396 section 5 prescribes. Parsing happens in
    /// [`crate::rar::AuthorizationDetails::parse`], under this crate's bounds, and only the
    /// validated form carries the result.
    #[cfg(feature = "rar")]
    pub authorization_details: Option<Cow<'a, str>>,
    /// RFC 9470 section 4 / OpenID Connect Core section 3.1.2.1 `acr_values`: the authentication
    /// context classes the client will accept, space delimited, in order of preference.
    ///
    /// ON THIS TYPE rather than parsed straight off the query, and that is the whole of the fix
    /// for a real gap. Every way into the authorization endpoint (a plain query, an RFC 9126
    /// pushed request, an RFC 9101 signed request object) funnels through this struct, so a
    /// parameter that lives here is a parameter every path must carry; a parameter parsed
    /// separately from the query is a parameter the other two paths silently drop. That is exactly
    /// what happened to these two: PAR and JAR requests disabled step-up entirely, and for JAR the
    /// server was reading intermediary-rewritable query text on a request whose only purpose is
    /// that it cannot be rewritten (RFC 9101 section 6.3).
    ///
    /// RAW TEXT for the same reason as the rest of this type, and parsed into
    /// [`crate::consent::AuthenticationRequirement`] by validation.
    #[cfg(feature = "consent")]
    pub acr_values: Option<Cow<'a, str>>,
    /// RFC 9470 section 4 / OpenID Connect Core section 3.1.2.1 `max_age`: how old the user's
    /// authentication may be, in seconds. See [`AuthorizationRequest::acr_values`] for why it is
    /// a field here rather than something read off the query.
    #[cfg(feature = "consent")]
    pub max_age: Option<Cow<'a, str>>,
}

impl<'a> AuthorizationRequest<'a> {
    /// Collect a request from already-decoded `(name, value)` query pairs.
    ///
    /// Unknown parameters are ignored, which RFC 6749 section 3.1 requires. A repeated parameter
    /// keeps the FIRST occurrence: section 3.1 says a parameter MUST NOT appear more than once,
    /// and last-wins is the smuggling-friendly choice when two intermediaries disagree about
    /// which copy counts.
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: Into<Cow<'a, str>>,
    {
        let mut req = AuthorizationRequest::default();
        for (k, v) in pairs {
            // RFC 8707 section 2 is the one exception to the first-wins rule below: `resource` MAY
            // legitimately appear more than once, and every occurrence is part of the request.
            if k.as_ref() == "resource" {
                req.resource.push(v.into());
                continue;
            }
            let slot = match k.as_ref() {
                "response_type" => &mut req.response_type,
                "client_id" => &mut req.client_id,
                "redirect_uri" => &mut req.redirect_uri,
                "scope" => &mut req.scope,
                "state" => &mut req.state,
                "code_challenge" => &mut req.code_challenge,
                "code_challenge_method" => &mut req.code_challenge_method,
                #[cfg(feature = "rar")]
                "authorization_details" => &mut req.authorization_details,
                #[cfg(feature = "consent")]
                "acr_values" => &mut req.acr_values,
                #[cfg(feature = "consent")]
                "max_age" => &mut req.max_age,
                _ => continue,
            };
            if slot.is_none() {
                *slot = Some(v.into());
            }
        }
        req
    }
}

/// Whether one RFC 8707 `resource` value is a resource indicator this server will accept.
///
/// RFC 8707 section 2 states the rule in three parts, and all three are checked here:
///
/// 1. the value MUST be an absolute URI as defined by RFC 3986 section 4.3, so it carries a scheme
///    (`scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`) followed by `:`. A relative reference
///    names nothing an audience restriction could be built from, since what it resolves against is
///    the client's business and not the server's;
/// 2. it MAY include a query component, so `?` is explicitly NOT a reason to refuse. That is worth
///    stating because the obvious "strip everything after the first delimiter" implementation gets
///    it wrong;
/// 3. it MUST NOT include a fragment. A fragment is never transmitted to a server (RFC 3986
///    section 3.5), so two indicators differing only in their fragment name the SAME resource while
///    comparing unequal, which turns any later audience check into a string game.
///
/// Anything outside printable ASCII is refused as well: RFC 3986 section 2 requires characters
/// outside its own grammar to be percent-encoded, so a raw space or control byte here is not a URI
/// at all, and accepting one would let a value that cannot round-trip through a query string reach
/// the token's audience.
pub(crate) fn is_valid_resource_indicator(value: &str) -> bool {
    let bytes = value.as_bytes();
    // Scheme: at least one character, the first alphabetic, terminated by the first `:`.
    let colon = match value.find(':') {
        Some(0) | None => return false,
        Some(i) => i,
    };
    if !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    if !bytes[1..colon]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return false;
    }
    // No fragment, and nothing that is not a legal URI character in the first place.
    bytes
        .iter()
        .all(|&b| b != b'#' && (0x21..=0x7e).contains(&b))
}

/// A request that has passed validation: the client exists, is allowed this grant, the redirect
/// URI is one of its registrations, and the PKCE parameters are well formed.
///
/// The data fields stay `pub` for read access (state, ergonomics, and the smallest diff over the
/// existing call sites in `tests/authorization_code.rs`, none of which construct this type by
/// hand). What actually enforces "only a validated request can mint a code" is the private
/// `_sealed` field below: because it is not `pub`, no struct-literal expression written outside
/// this module (that includes every downstream host, since this module is the only one with
/// access to `Sealed`) can name every field of this struct, so a `ValidatedAuthorizationRequest`
/// can only come from the crate-private `ValidatedAuthorizationRequest::new`, which only
/// `AuthorizationServer::validate_authorization_request` (in `server.rs`, within this crate)
/// calls. That is what "cannot be spelled" now actually means: not "the fields are private" (they
/// are not), but "the value cannot be produced without going through validation first."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAuthorizationRequest {
    /// The validated client.
    pub client_id: ClientId,
    /// The exact registered redirect URI this request resolved to.
    pub redirect_uri: String,
    /// The scope that will be granted on approval.
    pub scope: ScopeSet,
    /// The request's `state`, to be echoed on either outcome.
    pub state: Option<String>,
    /// The PKCE challenge to record against the issued code.
    pub code_challenge: String,
    /// The PKCE method (only `S256`).
    pub code_challenge_method: CodeChallengeMethod,
    /// This server's issuer identifier, carried so that the authorization response can name its
    /// author (RFC 9207 section 2).
    ///
    /// It is on the VALIDATED request rather than looked up at response time because
    /// [`ValidatedAuthorizationRequest::denied`] is also an authorization response and has no
    /// access to the server's configuration: a refusal that could not say who refused would be
    /// exactly the gap RFC 9207 section 2.2 closes.
    pub issuer: String,
    /// The RFC 8707 resource indicators this request asked for, already validated. Empty when the
    /// client named none, which means the issued token carries no audience restriction from this
    /// mechanism.
    pub resource: Vec<String>,
    /// The RFC 9396 authorization details this request asked for, already parsed and
    /// already checked against the server's supported types (section 5). Empty when the
    /// client named none.
    ///
    /// A host's consent screen MAY replace this before the code is issued: RFC 9396 section
    /// 7.1 is explicit that the details attached to the token may differ from the request,
    /// which is how an AS records the account the user actually picked.
    #[cfg(feature = "rar")]
    pub authorization_details: crate::rar::AuthorizationDetails,
    /// The RFC 9470 step-up requirement this request carried, already parsed.
    ///
    /// It rides on the VALIDATED request so that there is exactly ONE source of it per path, and
    /// that source is the request that was actually resolved: the pushed record for a PAR request,
    /// the signed claim set for a JAR request, the query for a plain one. Anything that reads the
    /// query separately is reading the wrong thing for two of the three (RFC 9126 section 4, RFC
    /// 9101 section 6.3).
    ///
    /// Empty means the client asked for no step-up, which is what an ordinary request carries.
    #[cfg(feature = "consent")]
    pub authentication_requirement: crate::consent::AuthenticationRequirement,
    /// Zero-sized witness, private to this module. Its only purpose is that it cannot be named
    /// (let alone constructed) outside `authorization.rs`, so a struct-literal expression cannot
    /// build a whole `ValidatedAuthorizationRequest` from anywhere else, in this crate or out of
    /// it. See the struct doc comment.
    _sealed: Sealed,
}

/// The witness type behind [`ValidatedAuthorizationRequest`]'s sealed field. Deliberately
/// private and zero-sized: it carries no data and exists only to make the containing struct
/// unconstructible by struct-literal syntax from outside this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sealed;

impl ValidatedAuthorizationRequest {
    /// The only constructor. `pub(crate)` rather than private: `AuthorizationServer::
    /// validate_authorization_request` lives in `server.rs`, a sibling module, and is the sole
    /// intended caller. `pub(crate)` is strictly narrower than the old fully-`pub` struct
    /// literal: no code outside this crate can reach this function, so no host can hand
    /// [`crate::server::AuthorizationServer::issue_authorization_code`] a request it invented
    /// itself. (Within the crate, `pub(crate)` cannot stop a different in-crate module from also
    /// calling this constructor honestly; the guarantee this seals is against a host of the
    /// library, not against other code inside it.)
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        client_id: ClientId,
        redirect_uri: String,
        scope: ScopeSet,
        state: Option<String>,
        code_challenge: String,
        code_challenge_method: CodeChallengeMethod,
        issuer: String,
        resource: Vec<String>,
    ) -> Self {
        ValidatedAuthorizationRequest {
            client_id,
            redirect_uri,
            scope,
            state,
            code_challenge,
            code_challenge_method,
            issuer,
            resource,
            #[cfg(feature = "rar")]
            authorization_details: crate::rar::AuthorizationDetails::none(),
            #[cfg(feature = "consent")]
            authentication_requirement: crate::consent::AuthenticationRequirement::none(),
            _sealed: Sealed,
        }
    }

    /// Record the RFC 9470 step-up requirement this request was validated as carrying.
    ///
    /// `pub(crate)` for the reason [`ValidatedAuthorizationRequest::set_authorization_details`]
    /// is: a public setter for the field that decides whether a code may be minted at all would
    /// hand back exactly what the sealed field exists to keep.
    #[cfg(feature = "consent")]
    pub(crate) fn set_authentication_requirement(
        &mut self,
        requirement: crate::consent::AuthenticationRequirement,
    ) {
        self.authentication_requirement = requirement;
    }

    /// Record the RFC 9396 authorization details this request was validated as carrying.
    ///
    /// `pub(crate)`, like [`ValidatedAuthorizationRequest::new`] itself: the sealed field on
    /// this type exists so that only validation can produce one, and a public setter for a
    /// field that decides what a token authorizes would hand that back.
    #[cfg(feature = "rar")]
    pub(crate) fn set_authorization_details(&mut self, details: crate::rar::AuthorizationDetails) {
        self.authorization_details = details;
    }

    /// The redirect describing the user refusing consent (RFC 6749 section 4.1.2.1
    /// `access_denied`). A refusal is an answer the client is entitled to receive, not an error
    /// page.
    pub fn denied(&self) -> AuthorizationErrorRedirect {
        AuthorizationErrorRedirect {
            redirect_uri: self.redirect_uri.clone(),
            error: ErrorResponse::new(ErrorCode::AccessDenied),
            state: self.state.clone(),
            // RFC 9207 section 2: the parameter belongs on the authorization response whatever the
            // outcome, and a refusal is an outcome the client is entitled to attribute.
            iss: self.issuer.clone(),
        }
    }
}

/// The success redirect parameters (RFC 6749 section 4.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    /// The single-use authorization code.
    pub code: String,
    /// The request's `state`, echoed verbatim; REQUIRED iff the request carried one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// RFC 9207 section 2: this server's issuer identifier, so a client talking to several
    /// authorization servers can tell WHICH one answered.
    ///
    /// Not an `Option`: this server always supports RFC 9207 and its metadata says so
    /// (`authorization_response_iss_parameter_supported`), and section 2 makes the parameter
    /// mandatory for a server that does. A response that could omit it would be a response a
    /// client cannot rely on, which defeats the mix-up countermeasure RFC 9700 section 4.4 is
    /// asking for.
    pub iss: String,
}

impl AuthorizationResponse {
    /// The `Location` header value for the success redirect.
    ///
    /// Parameter ORDER is not constrained by any RFC (RFC 6749 section 4.1.2 and RFC 9207
    /// section 2 both describe an unordered set of query parameters), so `iss` is appended last
    /// purely to keep the existing prefix of the URL unchanged.
    pub fn location(&self, redirect_uri: &str) -> String {
        let mut out = String::with_capacity(redirect_uri.len() + self.encoded_len());
        out.push_str(redirect_uri);
        let mut sep = query_separator(redirect_uri);
        append_param(&mut out, &mut sep, "code", &self.code);
        if let Some(state) = &self.state {
            append_param(&mut out, &mut sep, "state", state);
        }
        append_param(&mut out, &mut sep, "iss", &self.iss);
        out
    }

    /// A worst-case size for the appended query, so `location` allocates exactly once.
    fn encoded_len(&self) -> usize {
        6 + self.code.len() * 3
            + self.state.as_ref().map_or(0, |s| 7 + s.len() * 3)
            // "&iss=" is 5 characters, and the issuer is percent-encoded like everything else.
            + 5
            + self.iss.len() * 3
    }
}

/// An authorization error delivered by redirecting the user agent back to the client (RFC 6749
/// section 4.1.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationErrorRedirect {
    /// The VALIDATED redirect URI. Never a URI supplied by an unvalidated request.
    pub redirect_uri: String,
    /// The error to report.
    pub error: ErrorResponse,
    /// The request's `state`, echoed so the client can correlate the failure.
    pub state: Option<String>,
    /// RFC 9207 section 2: the issuer identifier, present on error responses exactly as on
    /// successful ones. A client that cannot attribute a failure cannot tell a genuine refusal by
    /// its own AS from one manufactured by an attacker's.
    pub iss: String,
}

impl AuthorizationErrorRedirect {
    /// The `Location` header value for the error redirect.
    pub fn location(&self) -> String {
        // 96 covers the error code, the separators, and a short description; the issuer is sized
        // properly because a host may run under a long issuer identifier and RFC 9207 section 2
        // puts it on every one of these.
        let mut out = String::with_capacity(self.redirect_uri.len() + 96 + self.iss.len() * 3);
        out.push_str(&self.redirect_uri);
        let mut sep = query_separator(&self.redirect_uri);
        append_param(&mut out, &mut sep, "error", self.error.error.as_str());
        if let Some(d) = &self.error.error_description {
            append_param(&mut out, &mut sep, "error_description", d);
        }
        if let Some(u) = &self.error.error_uri {
            append_param(&mut out, &mut sep, "error_uri", u);
        }
        if let Some(state) = &self.state {
            append_param(&mut out, &mut sep, "state", state);
        }
        append_param(&mut out, &mut sep, "iss", &self.iss);
        out
    }
}

/// How an authorization request failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationError {
    /// RFC 6749 section 4.1.2.1: the client or the redirect URI could not be validated, so the AS
    /// MUST NOT redirect. The host renders this to the user directly; 400 is the conventional
    /// status.
    Direct(ErrorResponse),
    /// The error is reported to the client by redirecting to its validated redirect URI.
    Redirect(AuthorizationErrorRedirect),
}

impl AuthorizationError {
    /// The HTTP status the host should use: 302 for the redirect form, otherwise a direct status.
    pub fn http_status(&self) -> u16 {
        match self {
            // invalid_client's 401 belongs to the token endpoint's WWW-Authenticate exchange; at
            // the authorization endpoint there is no client authentication to challenge, so a
            // refused request is a plain 400.
            AuthorizationError::Direct(e) if e.error == ErrorCode::ServerError => 500,
            AuthorizationError::Direct(_) => 400,
            AuthorizationError::Redirect(_) => 302,
        }
    }
}

impl std::fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorizationError::Direct(e) => write!(f, "{e}"),
            AuthorizationError::Redirect(r) => write!(f, "{}", r.error),
        }
    }
}

impl std::error::Error for AuthorizationError {}

/// What an issued authorization code became, once redeemed.
///
/// Consumed codes are RETAINED until their expiry rather than deleted, because RFC 6749 section
/// 4.1.2 and RFC 9700 section 4.1.1 want a replayed code to revoke the tokens it already minted.
/// Deleting the record on redemption would make a replay indistinguishable from a typo, and the
/// stolen access token would stay live.
/// `Debug` is hand-written (see below), for the same reason as [`crate::client::ClientAuth`]: the
/// `Consumed` variant carries the access and refresh tokens this code minted, and those are bearer
/// credentials that a host's `tracing::debug!(?record)` must not write to a log in plaintext.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorizationCodeState {
    /// Issued and not yet redeemed.
    Issued,
    /// Already redeemed, recording what it minted so a replay can revoke it.
    Consumed {
        /// The access token issued.
        access_token: String,
        /// The refresh token issued, if any.
        refresh_token: Option<String>,
    },
}

impl fmt::Debug for AuthorizationCodeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthorizationCodeState::Issued => f.write_str("Issued"),
            AuthorizationCodeState::Consumed {
                access_token: _,
                refresh_token,
            } => f
                .debug_struct("Consumed")
                .field("access_token", &"[redacted]")
                .field(
                    "refresh_token",
                    // Presence/absence is worth keeping visible (it distinguishes an
                    // authorization-code-only grant from one that also minted a refresh token);
                    // the value itself is not.
                    &refresh_token.as_ref().map(|_| "[redacted]"),
                )
                .finish(),
        }
    }
}

/// A persisted authorization code (RFC 6749 section 4.1.2).
///
/// `Debug` is hand-written (see below): `code` is itself a bearer credential (RFC 6749 section
/// 4.1.2 treats a leaked code as equivalent to a leaked token for as long as it is live, which is
/// why replay revokes what it minted, see [`AuthorizationCodeState`]'s doc comment), so it must
/// not appear in a debug format either.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationCodeRecord {
    /// The code string (the storage key).
    pub code: String,
    /// The client the code was issued to; presentation by any other client is `invalid_grant`.
    pub client_id: ClientId,
    /// The redirect URI the authorization request used; the token request must present the same.
    pub redirect_uri: String,
    /// The scope the user approved.
    pub scope: ScopeSet,
    /// The authenticated resource owner.
    pub subject: String,
    /// The recorded PKCE challenge (RFC 7636 section 4.4).
    pub code_challenge: String,
    /// The recorded PKCE method.
    pub code_challenge_method: CodeChallengeMethod,
    /// The RFC 8707 resource indicators the authorization request named.
    ///
    /// Recorded on the code because the token request that redeems it MAY narrow this set but MUST
    /// NOT widen it (RFC 8707 section 2), and "what was granted" is not knowable at the token
    /// endpoint any other way. Empty means the client asked for no audience restriction.
    pub resource: Vec<String>,
    /// The RFC 9396 authorization details the user approved.
    ///
    /// Recorded on the code for exactly the reason `resource` above is: section 6 lets the
    /// token request that redeems it NARROW this set and never widen it, and "what was
    /// granted" is not knowable at the token endpoint any other way. Empty means the client
    /// asked for no rich authorization detail.
    #[cfg(feature = "rar")]
    pub authorization_details: crate::rar::AuthorizationDetails,
    /// Expiry instant; the code is dead at and after this instant.
    pub expires_at: SystemTime,
    /// Whether the code has been redeemed, and what it produced.
    pub state: AuthorizationCodeState,
    /// What the host reported about the resource owner's authentication when this code was
    /// approved (the consent-0.8.0 slice; see [`crate::consent::Authentication`]).
    ///
    /// Recorded on the CODE because that is the only path by which the authentication the user
    /// actually performed can reach the token the code mints: the token endpoint has no user in
    /// front of it and cannot ask. Without it, RFC 9470 section 5's `auth_time` and `acr` could
    /// only ever be guessed at.
    #[cfg(feature = "consent")]
    pub authentication: Option<Box<crate::consent::Authentication>>,
}

impl fmt::Debug for AuthorizationCodeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = f.debug_struct("AuthorizationCodeRecord");
        out.field("code", &"[redacted]")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("scope", &self.scope)
            .field("subject", &self.subject)
            .field("code_challenge", &self.code_challenge)
            .field("code_challenge_method", &self.code_challenge_method)
            .field("resource", &self.resource);
        // Not a credential: it describes what was authorized, which is precisely what an
        // operator investigating a grant needs to see.
        #[cfg(feature = "rar")]
        out.field("authorization_details", &self.authorization_details);
        out.field("expires_at", &self.expires_at)
            .field("state", &self.state)
            .finish()
    }
}

/// `?` if the URI has no query yet, `&` if it does.
fn query_separator(uri: &str) -> char {
    if uri.contains('?') {
        '&'
    } else {
        '?'
    }
}

/// Append `name=value` with `value` percent-encoded, advancing the separator after first use.
fn append_param(out: &mut String, sep: &mut char, name: &str, value: &str) {
    out.push(*sep);
    *sep = '&';
    out.push_str(name);
    out.push('=');
    percent_encode_into(out, value);
}

/// Percent-encode everything outside the RFC 3986 unreserved set.
///
/// Deliberately conservative: encoding a character that did not strictly require it is harmless,
/// while failing to encode `&`, `=` or `#` lets a value forge or truncate the query. That is a
/// parameter-injection bug in the one place it must never happen.
fn percent_encode_into(out: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
}

#[cfg(test)]
#[path = "tests/authorization.rs"]
mod tests;
