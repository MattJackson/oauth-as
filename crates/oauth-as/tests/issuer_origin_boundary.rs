// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A CONSTRUCTOR THAT REPORTS AN ERROR MUST NOT PANIC INSTEAD.
//!
//! [`oauth_as::http::ServiceBuilder::build`] answers a configuration it cannot serve with a
//! [`oauth_as::http::ServiceError`]. That is the designed answer, and it is the whole reason
//! `build` returns a `Result` rather than a service: a library does not abort its host's process
//! over a value in its host's configuration file.
//!
//! The origin of the issuer is derived on that path (RFC 6454 s6.1 scheme, host and port, which
//! is what the device verification form compares an `Origin` header against). Deriving it by
//! subtracting the length of a TRIMMED path from an UNTRIMMED issuer puts the split point inside
//! a multi-byte character as soon as the issuer carries both a non-ASCII path and a trailing
//! slash, and slicing a `str` there panics.
//!
//! `\u{e9}` is spelled as an escape rather than written literally because this repository is
//! ASCII-only, source included.

#![cfg(feature = "http")]

use oauth_as::http::ServiceBuilder;
use oauth_as::server::{AuthorizationServer, ServerConfig};
use oauth_as::store::MemoryStorage;

/// Build a service for `issuer` and return whether it came back at all. A panic here fails the
/// test by unwinding out of it, which is exactly the defect under examination.
fn builds(issuer: &str) -> bool {
    let server = AuthorizationServer::new(
        ServerConfig::new(issuer, "https://as.example/device"),
        MemoryStorage::new(),
    );
    ServiceBuilder::new(std::sync::Arc::new(server))
        .build()
        .is_ok()
}

/// The reported case: a two-byte character in the issuer's path, and two trailing slashes, so the
/// trimmed path is two bytes shorter than the untrimmed one and the subtraction lands inside the
/// character.
#[test]
fn an_issuer_with_a_multi_byte_path_and_trailing_slashes_does_not_panic() {
    assert!(
        builds("https://as.example/\u{e9}//"),
        "a configuration this service can serve must build"
    );
}

/// The neighbours, so the fix is not a special case for one string: every combination of a
/// multi-byte path component with and without trailing slashes, and the ASCII path that already
/// worked.
#[test]
fn the_neighbouring_issuer_shapes_all_build() {
    for issuer in [
        "https://as.example/\u{e9}",
        "https://as.example/\u{e9}/",
        "https://as.example/tenant\u{e9}1//",
        "https://as.example/\u{1f600}//",
        "https://as.example/tenant1//",
        "https://as.example//",
        "https://as.example",
    ] {
        assert!(builds(issuer), "{issuer} must build rather than panic");
    }
}
