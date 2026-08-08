// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Grant types, mirrored from RFC 6749 section 4 plus the RFC 8628 device-grant URN. The wire
//! spelling of the device grant is the full URN, exactly as registered.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The RFC 8628 `grant_type` URN, verbatim.
pub const DEVICE_CODE_GRANT_URN: &str = "urn:ietf:params:oauth:grant-type:device_code";

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
}

impl GrantType {
    /// The registered wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            GrantType::AuthorizationCode => "authorization_code",
            GrantType::RefreshToken => "refresh_token",
            GrantType::ClientCredentials => "client_credentials",
            GrantType::DeviceCode => DEVICE_CODE_GRANT_URN,
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

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "authorization_code" => Ok(GrantType::AuthorizationCode),
            "refresh_token" => Ok(GrantType::RefreshToken),
            "client_credentials" => Ok(GrantType::ClientCredentials),
            DEVICE_CODE_GRANT_URN => Ok(GrantType::DeviceCode),
            other => Err(UnknownGrantType(other.to_string())),
        }
    }
}

#[cfg(test)]
#[path = "tests/grant.rs"]
mod tests;
