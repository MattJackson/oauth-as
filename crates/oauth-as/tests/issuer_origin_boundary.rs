// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A CONSTRUCTOR THAT REPORTS AN ERROR MUST NOT PANIC INSTEAD.
//!
//! [`oauth_as::http::ServiceBuilder::build`] answers a configuration it cannot serve with a
//! [`oauth_as::http::ServiceError`]. That is the designed answer, and it is the whole reason
//! `build` returns a `Result` rather than a service: a library does not abort its host's process
//! over a value in its host's configuration file. What this file pins is that every issuer shape
//! below — non-ASCII path components, one trailing slash, two, none — reaches that `Result` at all,
//! for a whole `build`, which is the only thing a host can observe and the only thing an
//! integration test is placed to check.
//!
//! # WHAT THIS FILE DOES NOT PIN, and where that is pinned instead
//!
//! The origin of the issuer is derived on this path (RFC 6454 s6.1 scheme, host and port, which is
//! what the device verification form compares an `Origin` header against), and the reported defect
//! was in that derivation: subtracting the length of a TRIMMED path from an UNTRIMMED issuer puts
//! the split point inside a multi-byte character and slicing a `str` there panics.
//!
//! THAT DEFECT IS NOT REACHABLE FROM HERE and this file cannot reproduce it. `build` goes through
//! `AuthorizationServerMetadata::from_config`, which trims the issuer's trailing slashes before
//! `issuer_origin` is ever handed one, so by the time the subtraction happened there was nothing
//! left to shift the index. Restoring the subtraction leaves every test below green. The guard
//! that does reproduce it calls `issuer_origin` directly and can only live inside the crate:
//! `the_issuer_origin_does_not_slice_inside_a_character` in `src/tests/http.rs`, whose own doc
//! says the same thing from the other side. This file is kept as the outer half — the shapes
//! really do build — with its claim cut back to that.
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

/// The shape the report named: a two-byte character in the issuer's path, and two trailing
/// slashes. Whether the panic is REACHABLE through `build` is settled in this file's module docs
/// (it is not); what is asserted here is only that this configuration builds.
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
