// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Token wire and storage shapes: the RFC 6749 section 5.1 success response, plus the records the
//! server persists through [`crate::store::Storage`]. Access and refresh tokens here are OPAQUE
//! random strings; structured (JWT) access tokens are a possible later addition and would slot in
//! at issuance without changing these shapes.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::client::ClientId;
use crate::scope::ScopeSet;

/// `token_type` values this server issues. Only `Bearer` (RFC 6750); the registered value is
/// case-insensitive on the wire but conventionally spelled `Bearer`, which the rename pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    /// RFC 6750 bearer token.
    #[serde(rename = "Bearer")]
    Bearer,
}

/// The RFC 6749 section 5.1 successful token response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The opaque access token.
    pub access_token: String,
    /// Always `Bearer` from this server.
    pub token_type: TokenType,
    /// Lifetime in seconds (RECOMMENDED by the RFC; this server always includes it).
    pub expires_in: u64,
    /// The rotating refresh token, when the grant and server config produce one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Space-delimited granted scope. This server always includes it when non-empty, which also
    /// satisfies the section 3.3 requirement to report a scope differing from the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// The RFC 7009 section 2.1 `token_type_hint`. A hint the server disagrees with is not an error:
/// section 2.1 requires it to keep looking, so this only chooses which lookup runs first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenTypeHint {
    /// The caller believes this is an access token.
    AccessToken,
    /// The caller believes this is a refresh token.
    RefreshToken,
}

impl std::str::FromStr for TokenTypeHint {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "access_token" => Ok(TokenTypeHint::AccessToken),
            "refresh_token" => Ok(TokenTypeHint::RefreshToken),
            _ => Err(()),
        }
    }
}

/// The RFC 7662 section 2.2 introspection response.
///
/// `active` is the only REQUIRED member, and for an inactive token it is the ONLY member: section
/// 2.2 is explicit that the server should not describe a token the caller has not proven it
/// holds, and section 4 explains why (the endpoint would otherwise answer questions about tokens
/// an attacker merely guessed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    /// Whether the token is currently active.
    pub active: bool,
    /// Space-delimited granted scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The client the token was issued to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// The resource owner the token acts for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// The token type (RFC 6750 `Bearer`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<TokenType>,
    /// Expiry, as seconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// Issuance, as seconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    /// The issuer of the token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
}

impl IntrospectionResponse {
    /// The one-member answer for a token that is unknown, expired, or not the caller's.
    pub fn inactive() -> Self {
        IntrospectionResponse {
            active: false,
            scope: None,
            client_id: None,
            sub: None,
            token_type: None,
            exp: None,
            iat: None,
            iss: None,
        }
    }
}

/// A persisted access token: what introspection needs to answer for an opaque token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedToken {
    /// The opaque access token string (the storage key).
    pub access_token: String,
    /// The client the token was issued to.
    pub client_id: ClientId,
    /// The resource owner the token acts for; `None` for client-only grants.
    pub subject: Option<String>,
    /// The granted scope.
    pub scope: ScopeSet,
    /// Issuance instant.
    pub issued_at: SystemTime,
    /// Expiry instant; the token is dead at and after this instant.
    pub expires_at: SystemTime,
}

/// A persisted refresh token. Single use: redemption goes through
/// [`crate::store::Storage::take_refresh_token`], and rotation issues a replacement carrying the
/// SAME `expires_at`, so a chain has an absolute lifetime rather than a sliding one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshTokenRecord {
    /// The opaque refresh token string (the storage key).
    pub refresh_token: String,
    /// The client the token was issued to; presentation by any other client consumes it.
    pub client_id: ClientId,
    /// The resource owner the chain acts for.
    pub subject: Option<String>,
    /// The scope originally granted; refreshes may narrow, never widen.
    pub scope: ScopeSet,
    /// Absolute chain expiry; `None` means the chain does not expire by time.
    pub expires_at: Option<SystemTime>,
}

#[cfg(test)]
#[path = "tests/token.rs"]
mod tests;
