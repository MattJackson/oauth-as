// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The OAuth error response object, mirrored from RFC 6749 section 5.2 (token endpoint), section
//! 4.1.2.1 (authorization endpoint), and the RFC 8628 section 3.5 device-grant extension codes.
//! One enum, one struct, owned here: never a third party's generated types.

use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Registered `error` codes this server can emit.
///
/// The wire spelling is the exact registered token (`snake_case`), which the `serde` rename below
/// pins; `tests/conformance_schema.rs` locks the full emitted set against a schema transcribed
/// from the RFCs.
///
/// `#[non_exhaustive]`, and for this enum that is not the usual forward-compatibility hedge. The
/// VARIANT SET here depends on cargo features: `consent`, `dpop`, `par` and `jar` each add one
/// (`rar` used to, and no longer does: see `InvalidAuthorizationDetails`). Without the attribute,
/// a host's exhaustive `match` compiles or fails depending on which features something ELSE in
/// its dependency graph turned on, which is a build break with no release behind it. This is also the most widely matched type this crate publishes, so a host
/// that wants a total match should write one with a `_` arm and decide what an unknown code means
/// to it (`ErrorCode::as_str` still gives it the wire spelling).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    // RFC 6749 section 5.2 (token endpoint).
    /// RFC 6749 section 5.2 `invalid_request`: the request is missing a required parameter,
    /// repeats one, or is otherwise malformed. It says "you sent the wrong bytes", so a client
    /// that retries the identical request cannot succeed.
    InvalidRequest,
    /// RFC 6749 section 5.2 `invalid_client`: client authentication failed. Every reason collapses
    /// into this one code deliberately, unknown client and wrong secret alike, because
    /// distinguishing them tells an attacker which client ids exist. Carries HTTP 401 when the
    /// client authenticated with a scheme that requires a `WWW-Authenticate` challenge.
    InvalidClient,
    /// RFC 6749 section 5.2 `invalid_grant`: the authorization code, device code or refresh token
    /// is invalid, expired, revoked, was issued to another client, or does not match the
    /// redirect URI. Also the answer to a failed PKCE verification (RFC 7636 section 4.6), and to
    /// a REPLAY, which additionally revokes the whole issued family.
    InvalidGrant,
    /// RFC 6749 section 5.2 `unauthorized_client`: the client is authenticated but is not
    /// registered for this grant type. Distinct from `invalid_client`, which is about identity,
    /// and from `access_denied`, which is about the user.
    UnauthorizedClient,
    /// RFC 6749 section 5.2 `unsupported_grant_type`: this server does not implement the requested
    /// `grant_type` at all, as opposed to declining it for this client.
    UnsupportedGrantType,
    /// RFC 6749 section 5.2 `invalid_scope`: the requested scope is unknown, malformed, or exceeds
    /// what the grant being presented was issued with. A refresh that widens scope lands here
    /// (section 6), because narrowing is allowed and widening never is.
    InvalidScope,
    // RFC 6749 section 4.1.2.1 (authorization endpoint; `access_denied` is also an RFC 8628
    // section 3.5 device-grant terminal code).
    /// RFC 6749 section 4.1.2.1 `access_denied`: the resource owner, or this server's own policy,
    /// refused the request. Also the RFC 8628 section 3.5 terminal answer for a device grant the
    /// user rejected at the verification page.
    AccessDenied,
    /// RFC 6749 section 4.1.2.1 `unsupported_response_type`: this server will not issue an
    /// authorization code by this method. `response_type=token`, the implicit grant, is refused
    /// with this code: OAuth 2.1 removes it.
    UnsupportedResponseType,
    /// RFC 6749 section 4.1.2.1 `server_error`: the server hit a condition it could not recover
    /// from and that is nobody's fault but its own. It is what a storage failure becomes, so it
    /// never carries a detail that would describe the host's internals to a caller.
    ServerError,
    /// RFC 6749 section 4.1.2.1 `temporarily_unavailable`: the server is overloaded or under
    /// maintenance. Distinct from `server_error` because it tells the client that retrying LATER
    /// is the right response, where `server_error` does not.
    TemporarilyUnavailable,
    // RFC 8628 section 3.5 (device access token request).
    /// RFC 8628 section 3.5 `authorization_pending`: the device grant exists and the user has not
    /// finished with it yet. The client keeps polling at the interval it was given. Not an error
    /// in any useful sense: it is the normal answer for most of a device flow's life.
    AuthorizationPending,
    /// RFC 8628 section 3.5 `slow_down`: the client polled faster than the interval it was given.
    /// Emitting this obliges the server to increase that interval by 5 seconds, which this crate
    /// does; a server that emitted the code without raising the interval would be asking the
    /// client to guess by how much.
    SlowDown,
    /// RFC 8628 section 3.5 `expired_token`: the `device_code` has passed its lifetime. Terminal.
    /// The client must start a new device authorization request rather than keep polling.
    ExpiredToken,
    /// RFC 9396 section 5: the `authorization_details` parameter is unparseable, exceeds
    /// what this server will accept, names a `type` this server does not support, or asks
    /// for more than the underlying grant allows (section 6). Section 5 makes refusing a
    /// MUST rather than a choice: an AS that ignored an authorization detail it did not
    /// understand would issue a token that says nothing about a permission the client
    /// believes it obtained, and the client cannot tell the difference.
    ///
    /// Distinct from `invalid_request` for the reason `invalid_target` is: the parameter was
    /// well formed AS A PARAMETER, so a client conflating the two would retry unchanged.
    ///
    /// NOT FEATURE GATED, for the same reason `invalid_target` is not: the build that has the
    /// most to refuse is the build WITHOUT `rar`, which supports no authorization detail type
    /// whatsoever and therefore meets section 5's condition on every request that carries the
    /// parameter. Gating the code on `rar` left exactly that build with nothing to answer with,
    /// so the parameter was accepted and ignored, which is the one outcome section 5 forbids.
    InvalidAuthorizationDetails,
    /// RFC 8707 section 2: the `resource` parameter names a target this server will not issue a
    /// token for, because the value is malformed, is not an absolute URI, or was never granted.
    /// The code itself is registered by RFC 8693 section 2.2.2 and RFC 8707 section 2 is what
    /// directs an authorization server to use it for resource indicators specifically. It is a
    /// distinct code from `invalid_request` on purpose: the parameter was well formed AS A
    /// PARAMETER, so a client that conflated the two would retry the same request.
    InvalidTarget,
    /// RFC 9470 section 3: the authentication the user performed is not enough for what is
    /// being asked. Registered by RFC 9470 for the RESOURCE server's challenge; this server
    /// emits it from the AUTHORIZATION endpoint when the host's reported authentication
    /// cannot satisfy the request's `acr_values` or `max_age`.
    ///
    /// Reusing the resource server's code is deliberate. It is the code the client was just
    /// handed, so re-sending it says the true thing: the authentication is STILL not
    /// sufficient. `invalid_request` would say the parameters were malformed and invite the
    /// client to retry the identical request, which is the one thing that cannot help.
    #[cfg(feature = "consent")]
    InsufficientUserAuthentication,
    /// RFC 9449 section 5: the DPoP proof on this request is missing, malformed, does not bind to
    /// this request, or has already been used. Registered by RFC 9449 section 12.3.
    ///
    /// A DISTINCT code from `invalid_client` on purpose, and the distinction is actionable: the
    /// client's credential may be perfectly good and only its proof wrong, and a client told
    /// `invalid_client` would go and check the wrong thing. Feature gated, so a build without
    /// `dpop` has exactly the code set it had before.
    #[cfg(feature = "dpop")]
    InvalidDpopProof,
    /// RFC 9101 section 7: the `request_uri` in the authorization request returns an error or
    /// contains invalid data. This server mints its own `request_uri` values at its RFC 9126
    /// endpoint and fetches nothing, so "invalid data" here means unknown, already used, expired,
    /// or issued to a different client.
    #[cfg(feature = "par")]
    InvalidRequestUri,
    /// RFC 9101 section 7: the `request` parameter contains an invalid Request Object. Sections
    /// 6.1 and 6.2 make this the REQUIRED answer for a request object that fails to decrypt, fails
    /// signature validation, or is signed with a key that is not the client's.
    #[cfg(feature = "jar")]
    InvalidRequestObject,
    /// RFC 9101 section 7: this server does not support the `request` parameter. Emitted when the
    /// host has not enabled signed request objects at all, which is distinct from a request object
    /// that was offered and refused.
    #[cfg(feature = "jar")]
    RequestNotSupported,
}

impl ErrorCode {
    /// The registered wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidRequest => "invalid_request",
            ErrorCode::InvalidClient => "invalid_client",
            ErrorCode::InvalidGrant => "invalid_grant",
            ErrorCode::UnauthorizedClient => "unauthorized_client",
            ErrorCode::UnsupportedGrantType => "unsupported_grant_type",
            ErrorCode::InvalidScope => "invalid_scope",
            ErrorCode::AccessDenied => "access_denied",
            ErrorCode::UnsupportedResponseType => "unsupported_response_type",
            ErrorCode::ServerError => "server_error",
            ErrorCode::TemporarilyUnavailable => "temporarily_unavailable",
            ErrorCode::AuthorizationPending => "authorization_pending",
            ErrorCode::SlowDown => "slow_down",
            ErrorCode::ExpiredToken => "expired_token",
            ErrorCode::InvalidAuthorizationDetails => "invalid_authorization_details",
            ErrorCode::InvalidTarget => "invalid_target",
            #[cfg(feature = "consent")]
            ErrorCode::InsufficientUserAuthentication => "insufficient_user_authentication",
            #[cfg(feature = "dpop")]
            ErrorCode::InvalidDpopProof => "invalid_dpop_proof",
            #[cfg(feature = "par")]
            ErrorCode::InvalidRequestUri => "invalid_request_uri",
            #[cfg(feature = "jar")]
            ErrorCode::InvalidRequestObject => "invalid_request_object",
            #[cfg(feature = "jar")]
            ErrorCode::RequestNotSupported => "request_not_supported",
        }
    }

    /// The HTTP status a token-endpoint response carrying this code takes, per RFC 6749
    /// section 5.2: 400 unless the code is `invalid_client` (401, and the host should attach a
    /// `WWW-Authenticate` header when the client attempted header-based authentication), plus the
    /// conventional 500/503 for the two server-side codes.
    ///
    /// EVERY variant is listed, exactly as in [`ErrorCode::as_str`] above, and there is no
    /// catch-all. A `_ => 400` arm compiles for a variant nobody thought about, and 400 is a
    /// plausible enough answer that nothing would ever notice: the status is part of the wire
    /// contract, so adding a code should require choosing one rather than inheriting one.
    pub fn http_status(self) -> u16 {
        match self {
            // 401, because RFC 6749 section 5.2 says so: client authentication failed, and the
            // response participates in the `WWW-Authenticate` challenge exchange.
            ErrorCode::InvalidClient => 401,
            // The two server-side codes take the conventional statuses for what they describe.
            ErrorCode::ServerError => 500,
            ErrorCode::TemporarilyUnavailable => 503,
            // Everything below is 400: RFC 6749 section 5.2's default for a request this server
            // will not act on, and RFC 8628 section 3.5 keeps the device grant's three polling
            // codes there too (they are answers about the REQUEST, not about the server).
            ErrorCode::InvalidRequest => 400,
            ErrorCode::InvalidGrant => 400,
            ErrorCode::UnauthorizedClient => 400,
            ErrorCode::UnsupportedGrantType => 400,
            ErrorCode::InvalidScope => 400,
            ErrorCode::AccessDenied => 400,
            ErrorCode::UnsupportedResponseType => 400,
            ErrorCode::AuthorizationPending => 400,
            ErrorCode::SlowDown => 400,
            ErrorCode::ExpiredToken => 400,
            ErrorCode::InvalidTarget => 400,
            ErrorCode::InvalidAuthorizationDetails => 400,
            // RFC 9470 section 3 gives 401 to the RESOURCE server's challenge; this is the
            // AUTHORIZATION server's token-endpoint refusal of a grant whose authentication was
            // too old or too weak, which is an RFC 6749 section 5.2 error response like the rest.
            #[cfg(feature = "consent")]
            ErrorCode::InsufficientUserAuthentication => 400,
            // RFC 9449 section 5: the token endpoint answers a bad proof with 400 and this code,
            // not with 401, because the client's CREDENTIAL was fine and its proof was not.
            #[cfg(feature = "dpop")]
            ErrorCode::InvalidDpopProof => 400,
            #[cfg(feature = "par")]
            ErrorCode::InvalidRequestUri => 400,
            #[cfg(feature = "jar")]
            ErrorCode::InvalidRequestObject => 400,
            #[cfg(feature = "jar")]
            ErrorCode::RequestNotSupported => 400,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The RFC 6749 section 5.2 error response body: `error` required, `error_description` and
/// `error_uri` optional and omitted (never `null`) when absent.
///
/// # Why the two optional fields are `Cow<'static, str>` and not `String`
///
/// This is the type every REFUSAL in this crate is built out of, and a refusal is the one response
/// an attacker chooses the rate of: an unauthenticated caller can ask for as many `invalid_request`
/// bodies as it can open sockets for, and asks for none of the successful ones. Roughly 50 of the
/// crate's 57 description sites pass a string constant, so an owned `String` meant one heap copy
/// of a `&'static str` per refused request, bought for nothing.
///
/// It is free in memory as well as in allocations: `Option<Cow<'static, str>>` is 24 bytes, the
/// SAME as `Option<String>`, because `Cow`'s discriminant lives in the niche the pointer already
/// has. MEASURED, not assumed: `ErrorResponse` is 56 bytes before and after, and
/// `tests/allocation.rs` pins both that size and the zero-allocation claim.
///
/// A host that needs a description it computed still passes a `String`: `Cow` owns that case, and
/// [`ErrorResponse::with_description`] takes `impl Into<Cow<'static, str>>` so both spellings
/// compile unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// The registered error code.
    pub error: ErrorCode,
    /// Human-readable ASCII detail for the developer (not the end user), per section 5.2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<Cow<'static, str>>,
    /// A URI identifying a human-readable page with more information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<Cow<'static, str>>,
}

impl ErrorResponse {
    /// A bare error with no description.
    pub fn new(error: ErrorCode) -> Self {
        ErrorResponse {
            error,
            error_description: None,
            error_uri: None,
        }
    }

    /// Attach a developer-facing description.
    ///
    /// `impl Into<Cow<'static, str>>`, so a `&'static str` borrows and a `String` moves: the
    /// overwhelmingly common caller passes a literal and pays nothing, and a caller that genuinely
    /// computed the text keeps working with no change at the call site.
    pub fn with_description(mut self, description: impl Into<Cow<'static, str>>) -> Self {
        self.error_description = Some(description.into());
        self
    }

    /// Attach an `error_uri` (RFC 6749 section 5.2), the same way and for the same reason.
    pub fn with_uri(mut self, uri: impl Into<Cow<'static, str>>) -> Self {
        self.error_uri = Some(uri.into());
        self
    }

    /// The HTTP status for this response; see [`ErrorCode::http_status`].
    pub fn http_status(&self) -> u16 {
        self.error.http_status()
    }
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.error_description {
            Some(d) => write!(f, "{}: {}", self.error, d),
            None => f.write_str(self.error.as_str()),
        }
    }
}

impl std::error::Error for ErrorResponse {}

#[cfg(test)]
#[path = "tests/error.rs"]
mod tests;
