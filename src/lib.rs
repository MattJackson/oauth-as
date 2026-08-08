// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Placeholder release. This crate contains NO implementation.
//!
//! An embeddable OAuth 2.1 Authorization Server library is in development. It is intended to cover
//! the authorization code grant with PKCE, the RFC 8628 device authorization grant, and RFC 8414
//! authorization server metadata, with storage supplied by the host through a trait rather than
//! chosen by the library.
//!
//! Nothing is published here yet because nothing is ready to be depended on. The first release
//! carrying an implementation will be 0.1.0. Until then this version exists only to reserve the
//! name, and depending on it buys you nothing.
//!
//! Source and progress: <https://github.com/MattJackson/oauth-as>

/// Returns the crate version. Present only so this placeholder compiles and documents itself.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_placeholder_reports_its_own_version() {
        assert_eq!(super::version(), "0.0.1");
    }
}
