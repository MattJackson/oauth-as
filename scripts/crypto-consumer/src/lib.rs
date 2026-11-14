// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson
//! Independent consumer: workspace dev dependencies cannot contaminate this graph.
pub use oauth_as::*;

#[test]
fn no_backend_requires_an_explicit_provider() {
    assert!(matches!(
        crypto::default_provider(),
        Err(crypto::CryptoError::MissingProvider)
    ));
    let server = AuthorizationServer::try_new(
        ServerConfig::new("https://as.example", "https://as.example/verify"),
        MemoryStorage::default(),
    );
    assert!(matches!(server, Err(crypto::CryptoError::MissingProvider)));
}
