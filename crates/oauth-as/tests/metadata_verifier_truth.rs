// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! THE DOCUMENT MUST NOT NAME A METHOD THIS SERVER REFUSES UNCONDITIONALLY.
//!
//! RFC 8414 s2's `token_endpoint_auth_methods_supported` is what a client reads to decide how to
//! authenticate. A method it names that the endpoint refuses every single time is not a bug the
//! client can recover from: it did what the server told it to do.
//!
//! The two RFC 7523 methods do NOT have the same requirements, which is the whole of this file:
//!
//! - `client_secret_jwt` is HS256 over the registered secret. It needs no elliptic curve, so it
//!   is honest in every build that has the `client_assertion` feature.
//! - `private_key_jwt` is ES256. It needs a verifier, and since the signing seam landed there are
//!   builds that have `client_assertion` and no verifier at all (`client_assertion = ["jwt"]`,
//!   which does not pull `jwt-p256`, and no host verifier installed).
//!
//! So there are three states and the document has to be right in each:
//!
//! | state                                | `client_secret_jwt` | `private_key_jwt` |
//! |--------------------------------------|---------------------|-------------------|
//! | `jwt-p256` compiled in               | advertised          | advertised        |
//! | host verifier installed              | advertised          | advertised        |
//! | neither                              | advertised          | NOT advertised    |
//!
//! `tests/wire_reachability.rs` is the other half: it proves every value the document DOES name
//! works over HTTP. This file is what stops the answer to that being "advertise nothing".

#![cfg(feature = "client_assertion")]

use oauth_as::client_assertion::{CLIENT_SECRET_JWT, PRIVATE_KEY_JWT};
use oauth_as::{AuthorizationServer, MemoryStorage, ServerConfig};

fn server() -> AuthorizationServer<MemoryStorage> {
    AuthorizationServer::new(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        MemoryStorage::new(),
    )
}

/// True in every build with the feature: the HMAC method needs nothing this build might lack.
#[test]
fn client_secret_jwt_is_advertised_whenever_the_feature_is_on() {
    let meta = server().metadata();
    assert!(
        meta.token_endpoint_auth_methods_supported
            .iter()
            .any(|m| m == CLIENT_SECRET_JWT),
        "client_secret_jwt is an HMAC over the registered secret and works in every \
         client_assertion build: {:?}",
        meta.token_endpoint_auth_methods_supported
    );
    let algs = meta
        .token_endpoint_auth_signing_alg_values_supported
        .clone()
        .expect("a client cannot build an assertion without knowing the algorithm");
    assert!(algs.iter().any(|a| a == "HS256"), "{algs:?}");
}

/// State one: the built-in backend is compiled in, so a verifier always exists.
#[cfg(feature = "jwt-p256")]
mod with_the_built_in_backend {
    use super::*;

    #[test]
    fn private_key_jwt_is_advertised() {
        let meta = server().metadata();
        assert!(
            meta.token_endpoint_auth_methods_supported
                .iter()
                .any(|m| m == PRIVATE_KEY_JWT),
            "jwt-p256 installs P256Verifier, so ES256 assertions are checkable: {:?}",
            meta.token_endpoint_auth_methods_supported
        );
        let algs = meta
            .token_endpoint_auth_signing_alg_values_supported
            .expect("present under client_assertion");
        assert!(algs.iter().any(|a| a == "ES256"), "{algs:?}");
    }
}

/// States two and three, which only a build WITHOUT the built-in backend can tell apart.
#[cfg(not(feature = "jwt-p256"))]
mod without_the_built_in_backend {
    use super::*;

    use std::sync::Arc;

    use oauth_as::jwt::{Es256Verifier, PublicJwk};

    /// Says yes to everything, exactly as `tests/verifier_refusal.rs` does and for the same
    /// reason: the question here is whether the SEAM is wired, not whether the arithmetic is
    /// right, which is `signer_conformance`'s job.
    struct AlwaysVerifies;

    impl Es256Verifier for AlwaysVerifies {
        fn verify(&self, _key: &PublicJwk, _input: &[u8], _signature: &[u8]) -> bool {
            true
        }
    }

    /// State three: no backend of any kind. Every ES256 assertion is refused, so naming the
    /// method would be an instruction a client cannot follow.
    #[test]
    fn private_key_jwt_is_not_advertised_with_no_verifier() {
        let meta = server().metadata();
        assert!(
            !meta
                .token_endpoint_auth_methods_supported
                .iter()
                .any(|m| m == PRIVATE_KEY_JWT),
            "with no ES256 backend every private_key_jwt assertion is refused, so the document \
             must not name it: {:?}",
            meta.token_endpoint_auth_methods_supported
        );
        let algs = meta
            .token_endpoint_auth_signing_alg_values_supported
            .expect("client_secret_jwt still works, so the member is still present");
        assert!(
            !algs.iter().any(|a| a == "ES256"),
            "nothing in this build can check an ES256 signature: {algs:?}"
        );
        assert!(algs.iter().any(|a| a == "HS256"), "{algs:?}");
    }

    /// State two: the host installed a verifier, so the method works and the document says so.
    #[test]
    fn private_key_jwt_is_advertised_once_a_verifier_is_installed() {
        let meta = server()
            .with_es256_verifier(Arc::new(AlwaysVerifies))
            .metadata();
        assert!(
            meta.token_endpoint_auth_methods_supported
                .iter()
                .any(|m| m == PRIVATE_KEY_JWT),
            "an installed verifier is what makes an ES256 assertion checkable: {:?}",
            meta.token_endpoint_auth_methods_supported
        );
        let algs = meta
            .token_endpoint_auth_signing_alg_values_supported
            .expect("present under client_assertion");
        assert!(algs.iter().any(|a| a == "ES256"), "{algs:?}");
    }
}
