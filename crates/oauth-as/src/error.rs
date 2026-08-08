// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The OAuth error response object, mirrored from RFC 6749 section 5.2 (token endpoint), section
//! 4.1.2.1 (authorization endpoint), and the RFC 8628 section 3.5 device-grant extension codes.
//! One enum, one struct, owned here: never a third party's generated types.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Registered `error` codes this server can emit.
///
/// The wire spelling is the exact registered token (`snake_case`), which the `serde` rename below
/// pins; `tests/conformance_schema.rs` locks the full emitted set against a schema transcribed
/// from the RFCs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    // RFC 6749 section 5.2 (token endpoint).
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    // RFC 6749 section 4.1.2.1 (authorization endpoint; `access_denied` is also an RFC 8628
    // section 3.5 device-grant terminal code).
    AccessDenied,
    UnsupportedResponseType,
    ServerError,
    TemporarilyUnavailable,
    // RFC 8628 section 3.5 (device access token request).
    AuthorizationPending,
    SlowDown,
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
    #[cfg(feature = "rar")]
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
            #[cfg(feature = "rar")]
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
    pub fn http_status(self) -> u16 {
        match self {
            ErrorCode::InvalidClient => 401,
            ErrorCode::ServerError => 500,
            ErrorCode::TemporarilyUnavailable => 503,
            _ => 400,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// The registered error code.
    pub error: ErrorCode,
    /// Human-readable ASCII detail for the developer (not the end user), per section 5.2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    /// A URI identifying a human-readable page with more information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
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
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.error_description = Some(description.into());
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
