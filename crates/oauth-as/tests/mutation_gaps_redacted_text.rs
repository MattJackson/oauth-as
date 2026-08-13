// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! THREE HAND-WRITTEN `Debug` AND `Display` IMPLEMENTATIONS THAT NOTHING READ.
//!
//! Survivors of the `--all-features` mutation sweep at commit `42fa851`:
//!
//! ```text
//! client_assertion.rs replace <impl fmt::Debug for ClientSecretKey>::fmt -> fmt::Result with Ok(Default::default())
//! client_assertion.rs replace <impl fmt::Display for WeakClientSecret>::fmt -> fmt::Result with Ok(Default::default())
//! http.rs replace <impl std::fmt::Debug for AuthorizationService<S, C>>::fmt -> std::fmt::Result with Ok(Default::default())
//! ```
//!
//! Each is hand written rather than derived, and each carries a comment saying why. A mutant that
//! empties the body proves the reason was never checked. That matters most for the first:
//! `ClientSecretKey`'s `Debug` is hand written precisely because "this type exists to sit inside a
//! registration that gets logged, and a derived one would print the key". An implementation
//! nothing reads is one nobody would notice being replaced by a derive, and a derive here writes a
//! client's HMAC key into the host's log.
//!
//! `tests/wire_text.rs` covers the `Display` impls across nine modules and this crate's other
//! `Debug` redactions; these three are the ones it does not reach.

/// RFC 7523 `client_secret_jwt` key material.
#[cfg(feature = "client-assertion")]
mod assertion_keys {
    use oauth_as::client_assertion::{
        ClientSecretKey, WeakClientSecret, MIN_CLIENT_SECRET_JWT_KEY_LENGTH,
    };

    /// The secret must not appear, and the redaction must.
    ///
    /// Two assertions rather than one: "does not contain the secret" alone is satisfied by an
    /// empty string, which is exactly the mutant, and a reader who finds a field with nothing
    /// after it cannot tell a redaction from a missing value.
    #[test]
    fn a_registered_client_secret_jwt_key_is_redacted_rather_than_printed() {
        let secret = "a-registered-hmac-key-well-over-the-floor";
        let key = ClientSecretKey::new(secret).expect("well over the character floor");

        let printed = format!("{key:?}");
        assert!(
            !printed.contains(secret),
            "a registration that gets logged must not carry the key into the log: {printed:?}"
        );
        assert!(
            printed.contains("[redacted]"),
            "and the reader has to be told that is what happened: {printed:?}"
        );
    }

    /// The refusal names the floor it enforces.
    ///
    /// `WeakClientSecret` carries no payload on purpose, so its `Display` IS the whole error.
    /// Emptied, a host registering a client is told nothing about why the registration was
    /// refused, and the one number that would let them fix it goes missing with it.
    #[test]
    fn the_weak_secret_refusal_says_what_the_floor_is() {
        let refused =
            ClientSecretKey::new("too-short").expect_err("nine characters is under the floor");
        assert_eq!(refused, WeakClientSecret);

        let printed = refused.to_string();
        assert!(
            printed.contains(&MIN_CLIENT_SECRET_JWT_KEY_LENGTH.to_string()),
            "the floor is the actionable part of this refusal: {printed:?}"
        );
        assert!(
            printed.contains("client_secret_jwt"),
            "and it has to say which credential it is about: {printed:?}"
        );
    }
}

/// The HTTP service's route table.
#[cfg(feature = "http")]
mod service {
    use oauth_as::http::ServiceBuilder;
    use oauth_as::{AuthorizationServer, MemoryStorage, ServerConfig};

    /// The `Debug` shows the route table, which is the one thing a host debugging a 404 wants and
    /// the whole reason the impl is hand written rather than derived (a derive "would print the
    /// whole metadata document").
    #[test]
    fn the_http_service_debug_prints_its_route_table() {
        let server = AuthorizationServer::new(
            ServerConfig::new("https://as.example", "https://as.example/device"),
            MemoryStorage::new(),
        );
        let builder = ServiceBuilder::new(std::sync::Arc::new(server));
        #[cfg(feature = "consent")]
        let builder =
            builder.with_approval_resolver(|_req| oauth_as::http::ApprovalDecision::Approve);
        let service = builder.build().expect("a default service builds");

        let printed = format!("{service:?}");
        assert!(
            printed.contains("AuthorizationService"),
            "the type has to name itself: {printed:?}"
        );
        assert!(
            printed.contains("routes"),
            "the route table is the whole reason this impl is hand written: {printed:?}"
        );
        assert!(
            printed.contains('/'),
            "and it has to contain the route paths themselves: {printed:?}"
        );
    }
}
