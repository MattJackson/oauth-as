// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Grant types, mirrored from RFC 6749 section 4 plus the RFC 8628 device-grant URN. The wire
//! spelling of the device grant is the full URN, exactly as registered.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The RFC 8628 `grant_type` URN, verbatim.
pub const DEVICE_CODE_GRANT_URN: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// The RFC 8693 section 2.1 `grant_type` URN, verbatim.
#[cfg(feature = "token-exchange")]
pub const TOKEN_EXCHANGE_GRANT_URN: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// A grant type a client may be allowed to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GrantType {
    /// RFC 6749 section 4.1 (OAuth 2.1: PKCE required; types in [`crate::authorization`]).
    #[serde(rename = "authorization_code")]
    AuthorizationCode,
    /// RFC 6749 section 6, with OAuth 2.1 single-use rotation as implemented by
    /// [`crate::server::AuthorizationServer`].
    #[serde(rename = "refresh_token")]
    RefreshToken,
    /// RFC 6749 section 4.4.
    #[serde(rename = "client_credentials")]
    ClientCredentials,
    /// RFC 8628.
    #[serde(rename = "urn:ietf:params:oauth:grant-type:device_code")]
    DeviceCode,
    /// RFC 8693 token exchange. A registration carries this exactly when the deployment has
    /// decided this client may exchange a token it holds for another one; see
    /// [`crate::token_exchange`], and note that the grant can only ever NARROW what the
    /// subject token already carries.
    #[cfg(feature = "token-exchange")]
    #[serde(rename = "urn:ietf:params:oauth:grant-type:token-exchange")]
    TokenExchange,
}

impl GrantType {
    /// Resolve a wire `grant_type` value WITHOUT allocating, returning `None` for anything this
    /// server does not implement.
    ///
    /// This is the parse the HTTP surface uses, and it exists because [`FromStr`]'s error type
    /// cannot be built without a heap copy of the caller's value. `grant_type` is resolved BEFORE
    /// client authentication (deliberately, so an unimplemented grant is answered
    /// `unsupported_grant_type` rather than with a client-auth error about a parameter it never
    /// reached), and the router does NOT echo the value back: RFC 6749 s5.2 restricts
    /// `error_description` to a charset an attacker-supplied value need not respect. So the
    /// `String` [`UnknownGrantType`] carries was allocated, copied into and dropped unread on every
    /// refused request. `MAX_BODY_BYTES` is 64 KiB and `MAX_FORM_PARAMETERS` is 64, so one
    /// parameter can be nearly the whole body: an unauthenticated caller sized that allocation, and
    /// a refusal is work the attacker buys.
    ///
    /// [`FromStr`] is kept unchanged, and still carries the value, because a HOST parsing its own
    /// configuration or a registration document wants to know which spelling it got wrong. The two
    /// differ in what they can afford, not in what they accept: `from_str` is this function plus
    /// the copy.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "authorization_code" => Some(GrantType::AuthorizationCode),
            "refresh_token" => Some(GrantType::RefreshToken),
            "client_credentials" => Some(GrantType::ClientCredentials),
            DEVICE_CODE_GRANT_URN => Some(GrantType::DeviceCode),
            #[cfg(feature = "token-exchange")]
            TOKEN_EXCHANGE_GRANT_URN => Some(GrantType::TokenExchange),
            _ => None,
        }
    }

    /// The registered wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            GrantType::AuthorizationCode => "authorization_code",
            GrantType::RefreshToken => "refresh_token",
            GrantType::ClientCredentials => "client_credentials",
            GrantType::DeviceCode => DEVICE_CODE_GRANT_URN,
            #[cfg(feature = "token-exchange")]
            GrantType::TokenExchange => TOKEN_EXCHANGE_GRANT_URN,
        }
    }
}

impl fmt::Display for GrantType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The rejection for an unknown `grant_type` parameter value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownGrantType(pub String);

impl fmt::Display for UnknownGrantType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown grant_type {:?}", self.0)
    }
}

impl std::error::Error for UnknownGrantType {}

impl FromStr for GrantType {
    type Err = UnknownGrantType;

    /// The value IS carried here, and that is the difference from [`GrantType::parse`]: a host
    /// calling `"...".parse()` on its own configuration is not a path an attacker sets the rate of,
    /// and it is a path where knowing which spelling was wrong is the whole point of the error.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        GrantType::parse(s).ok_or_else(|| UnknownGrantType(s.to_string()))
    }
}

#[cfg(test)]
#[path = "tests/grant.rs"]
mod tests;
