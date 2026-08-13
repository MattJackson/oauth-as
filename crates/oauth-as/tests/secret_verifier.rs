// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The client secret verifier seam (`crates/oauth-as/src/client.rs`), from outside the crate.
//!
//! WHY THIS SEAM EXISTS. Before 0.2.0 the only confidential registration this crate could express
//! was `ClientAuth::ConfidentialSecret { secret }`, which is the secret ITSELF, so the host was
//! pushed toward keeping plaintext credentials in whatever it persists a `Client` into. A library
//! that makes the insecure thing the easy thing is doing harm, so 0.2.0 added this seam: hosts can
//! store a hash rather than a secret, and the plaintext variant is no longer the only way in.
//!
//! Two paths are pinned here:
//!
//! - The BUILT IN one, `SecretHash::sha256`, which needs no host code and no new dependency (the
//!   crate already carries `sha2` for RFC 7636 PKCE). Registering a hash is a one-line change for
//!   a host and the token endpoint keeps working unchanged.
//! - The HOST one, [`oauth_as::SecretVerifier`], for a host whose policy names a specific KDF
//!   (argon2id, scrypt, bcrypt) or whose verification lives in an HSM. This crate will not grow
//!   those dependencies, and it does not have to: it hands the stored [`oauth_as::SecretHash`] and
//!   the presented secret to the host and believes the answer.

mod support;

use oauth_as::{
    Client, ClientAuth, ClientId, ErrorCode, GrantType, ScopeSet, SecretHash, SecretVerifier,
    TokenRequest,
};
use support::{server_with, ManualClock};

const SECRET: &str = "a-high-entropy-host-generated-secret";

/// The verifier is READ through `Hooks` and INSTALLED through the server's builder, which as of
/// 0.9.1 is the crate's one installation verb. These tests exercise the seam rather than an
/// endpoint, so they build a server only to borrow its `&Hooks`.
async fn server_with_verifier(
    verifier: Box<dyn SecretVerifier>,
) -> oauth_as::AuthorizationServer<oauth_as::MemoryStorage, ManualClock> {
    server_with(ManualClock::at_epoch(), Vec::new())
        .await
        .with_secret_verifier(verifier)
}

fn hashed_client(auth: ClientAuth) -> Client {
    Client {
        client_id: ClientId::new("hashed-app"),
        auth,
        grant_types: vec![GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("api:read").unwrap(),
        default_scopes: ScopeSet::parse("api:read").unwrap(),
        name: None,
        registration: None,
    }
}

/// The point of the whole seam: a registration that stores a HASH still authenticates, so a host
/// never has to persist the secret. RFC 6749 section 2.3.1 treats the client secret as a password,
/// and passwords at rest belong in a one-way form.
#[tokio::test]
async fn a_client_registered_with_a_hash_authenticates_with_its_secret() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(
        clock,
        vec![hashed_client(ClientAuth::ConfidentialSecretHash {
            hash: SecretHash::sha256(SECRET),
        })],
    )
    .await;

    let issued = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("hashed-app"),
            client_secret: Some(SECRET.to_string()),
            scope: None,
        })
        .await
        .expect("a hash-registered client must authenticate with its secret");
    assert!(!issued.access_token.is_empty());
}

/// The other half: a wrong secret is still `invalid_client` (RFC 6749 section 5.2), and so is no
/// secret at all. A hashed registration must not become a way to authenticate with nothing.
#[tokio::test]
async fn a_wrong_or_absent_secret_is_still_invalid_client() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(
        clock,
        vec![hashed_client(ClientAuth::ConfidentialSecretHash {
            hash: SecretHash::sha256(SECRET),
        })],
    )
    .await;

    for presented in [Some("wrong".to_string()), Some(String::new()), None] {
        let err = srv
            .token(TokenRequest::ClientCredentials {
                client_id: ClientId::new("hashed-app"),
                client_secret: presented.clone(),
                scope: None,
            })
            .await
            .expect_err("a wrong secret must not authenticate");
        assert_eq!(
            err.error,
            ErrorCode::InvalidClient,
            "presented {presented:?}"
        );
    }
}

/// A hash-registered client is still a CONFIDENTIAL client. `client_credentials`, introspection
/// and revocation all refuse public clients, and that refusal keys off the variant, so a new
/// variant that read as public would silently open three endpoints.
#[tokio::test]
async fn a_hashed_registration_counts_as_confidential() {
    let auth = ClientAuth::ConfidentialSecretHash {
        hash: SecretHash::sha256(SECRET),
    };
    assert!(auth.is_confidential());
    assert!(!ClientAuth::Public.is_confidential());
}

/// The stored value must not be the secret, and must not print as one either: security finding
/// C13 redacted `Debug` on every credential-bearing type, and a verifier is offline-attackable if
/// it leaks, so it is redacted the same way. The scheme stays visible, because knowing WHICH
/// scheme a registration uses is what an operator needs when rotating.
#[tokio::test]
async fn the_stored_hash_is_neither_the_secret_nor_printable() {
    let hash = SecretHash::sha256(SECRET);
    assert_ne!(hash.encoded(), SECRET);
    assert!(!hash.encoded().contains(SECRET));
    assert_eq!(hash.scheme(), SecretHash::SHA256_HEX);

    let printed = format!("{hash:?}");
    assert!(
        !printed.contains(SECRET),
        "Debug leaked the secret: {printed}"
    );
    assert!(
        !printed.contains(hash.encoded()),
        "Debug leaked the stored verifier: {printed}"
    );
    assert!(printed.contains(SecretHash::SHA256_HEX));

    let auth = ClientAuth::ConfidentialSecretHash { hash };
    let printed = format!("{auth:?}");
    assert!(
        !printed.contains(SECRET),
        "Debug leaked the secret: {printed}"
    );
    assert!(printed.contains("[redacted]"));
}

/// A host scheme this crate cannot compute FAILS CLOSED when no verifier is installed. The
/// alternative, treating an unverifiable registration as a public client or as a match, would turn
/// a misconfiguration into an authentication bypass.
#[tokio::test]
async fn an_unknown_scheme_without_a_verifier_never_authenticates() {
    let auth = ClientAuth::ConfidentialSecretHash {
        hash: SecretHash::custom("argon2id", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"),
    };
    assert!(!auth.verify(Some(SECRET)));
    assert!(!auth.verify(None));
    assert!(!auth.verify_with(Some(SECRET), None));
}

/// With a host verifier installed, the same registration authenticates: the crate hands over the
/// stored hash and the presented secret and takes the host's answer.
#[tokio::test]
async fn an_installed_verifier_decides_a_host_scheme() {
    struct FakeArgon;
    impl SecretVerifier for FakeArgon {
        fn verify(&self, stored: &SecretHash, presented: &str) -> bool {
            stored.scheme() == "argon2id" && presented == SECRET
        }
    }

    let server = server_with_verifier(Box::new(FakeArgon)).await;
    let hooks = server.hooks();

    let auth = ClientAuth::ConfidentialSecretHash {
        hash: SecretHash::custom("argon2id", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"),
    };
    assert!(auth.verify_with(Some(SECRET), hooks.secret_verifier()));
    assert!(!auth.verify_with(Some("wrong"), hooks.secret_verifier()));
    // No secret presented is a refusal that never reaches the host: there is nothing to verify.
    assert!(!auth.verify_with(None, hooks.secret_verifier()));
}

/// The built-in scheme is verified BY THIS CRATE even when a host verifier is installed. A host
/// verifier is an addition, not an override: a buggy or permissive one must not be able to weaken
/// a registration whose scheme the crate can check itself.
#[tokio::test]
async fn an_installed_verifier_cannot_weaken_the_built_in_scheme() {
    struct AlwaysYes;
    impl SecretVerifier for AlwaysYes {
        fn verify(&self, _stored: &SecretHash, _presented: &str) -> bool {
            true
        }
    }

    let server = server_with_verifier(Box::new(AlwaysYes)).await;
    let hooks = server.hooks();

    let auth = ClientAuth::ConfidentialSecretHash {
        hash: SecretHash::sha256(SECRET),
    };
    assert!(
        !auth.verify_with(Some("wrong"), hooks.secret_verifier()),
        "the built-in sha256-hex scheme must be checked by the crate, not delegated"
    );
    assert!(auth.verify_with(Some(SECRET), hooks.secret_verifier()));
}

/// The plaintext variant keeps working: hosts that hold their secrets in a vault and hand this
/// crate the resolved value are not broken by the new path, they are merely no longer the only
/// option. `ClientAuth::ConfidentialSecret` remains supported and documented as the second choice.
#[tokio::test]
async fn the_plaintext_variant_still_works() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(
        clock,
        vec![hashed_client(ClientAuth::ConfidentialSecret {
            secret: SECRET.to_string(),
        })],
    )
    .await;
    assert!(srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("hashed-app"),
            client_secret: Some(SECRET.to_string()),
            scope: None,
        })
        .await
        .is_ok());
}

// ------------------------------------------------------------------ end to end
//
// The tests above pin the SEAM. This one pins the WIRING: that the token endpoint consults the
// installed verifier, so a host whose policy names argon2id can actually run this crate.

/// A host scheme, verified end to end through the token endpoint. `FakeArgon` stands in for a real
/// KDF (this crate will not grow that dependency, and does not need to in order to prove the seam
/// is reached): what is being pinned is that `AuthorizationServer` asks the host about a scheme it
/// cannot compute, rather than refusing the client outright.
#[tokio::test]
async fn a_host_scheme_authenticates_through_the_token_endpoint() {
    struct FakeArgon;
    impl SecretVerifier for FakeArgon {
        fn verify(&self, stored: &SecretHash, presented: &str) -> bool {
            // A real implementation calls its KDF here, in constant time.
            stored.scheme() == "argon2id" && stored.encoded() == format!("kdf-of:{presented}")
        }
    }

    let cfg = oauth_as::ServerConfig::new("https://as.example", "https://as.example/device");
    let srv = oauth_as::AuthorizationServer::with_clock(
        cfg,
        oauth_as::MemoryStorage::new(),
        ManualClock::at_epoch(),
    )
    .with_secret_verifier(Box::new(FakeArgon));
    srv.register_client(hashed_client(ClientAuth::ConfidentialSecretHash {
        hash: SecretHash::custom("argon2id", format!("kdf-of:{SECRET}")),
    }))
    .await
    .unwrap();

    assert!(srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("hashed-app"),
            client_secret: Some(SECRET.to_string()),
            scope: None,
        })
        .await
        .is_ok());

    let err = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("hashed-app"),
            client_secret: Some("wrong".to_string()),
            scope: None,
        })
        .await
        .expect_err("the host verifier must be able to say no");
    assert_eq!(err.error, ErrorCode::InvalidClient);
}

/// Without the verifier installed, the same registration authenticates NOBODY. This is the
/// fail-closed property from the seam tests, observed at the endpoint a client actually calls.
#[tokio::test]
async fn the_same_registration_authenticates_nobody_without_the_verifier() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(
        clock,
        vec![hashed_client(ClientAuth::ConfidentialSecretHash {
            hash: SecretHash::custom("argon2id", format!("kdf-of:{SECRET}")),
        })],
    )
    .await;
    let err = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("hashed-app"),
            client_secret: Some(SECRET.to_string()),
            scope: None,
        })
        .await
        .expect_err("a scheme nobody can verify must not authenticate");
    assert_eq!(err.error, ErrorCode::InvalidClient);
}

/// THE COLLAPSE IS A TIMING PROPERTY TOO, and this is the seam half of it.
///
/// RFC 6749 section 5.2 has an unknown `client_id` and a wrong secret answer the same
/// `invalid_client`, and `AuthorizationServer::authenticate_client` says in as many words that this
/// is so "an attacker cannot probe which ids exist". A server that cannot verify a secret for a
/// registration it did not find answers in the time of one store read, while a real id additionally
/// pays a whole verification — which for the argon2id-shaped registration this very seam exists to
/// support is roughly two milliseconds against two hundred. That is a single-request oracle over
/// the entire client registry, and per-`client_id` throttling cannot see it, because the attacker
/// sends exactly one request per candidate and never repeats one.
///
/// So the unknown-id path performs a DUMMY verification through this seam. What is asserted is that
/// the host's verifier is CALLED, with the dummy it supplied, on a request naming a client that
/// does not exist — and that the wire answer is unchanged. A wall-clock assertion would be the
/// property itself and would also be flaky on shared CI; the call is what the wall clock is made
/// of.
#[tokio::test]
async fn an_unknown_client_id_still_costs_a_verification_through_the_host_seam() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Default)]
    struct Counting {
        calls: AtomicUsize,
        schemes: std::sync::Mutex<Vec<String>>,
    }
    struct Installed(Arc<Counting>);
    impl SecretVerifier for Installed {
        fn verify(&self, stored: &SecretHash, presented: &str) -> bool {
            self.0.calls.fetch_add(1, Ordering::SeqCst);
            self.0
                .schemes
                .lock()
                .unwrap()
                .push(stored.scheme().to_string());
            // The dummy must never AUTHENTICATE anything, whatever is presented: no registration
            // names it, and a verifier that said yes would be answering about nobody.
            stored.encoded() == "the-real-registration" && presented == SECRET
        }

        /// The half only the host can write: a stored verifier in ITS scheme, over a secret nobody
        /// holds. A real implementation would use its own KDF parameters so the dummy costs what a
        /// real registration costs.
        fn dummy_hash(&self) -> Option<SecretHash> {
            Some(SecretHash::custom(
                "argon2id",
                "a-dummy-nobody-holds-the-secret-for",
            ))
        }
    }

    let seen = Arc::new(Counting::default());
    let srv = server_with(ManualClock::at_epoch(), Vec::new())
        .await
        .with_secret_verifier(Box::new(Installed(seen.clone())));
    srv.register_client(hashed_client(ClientAuth::ConfidentialSecretHash {
        hash: SecretHash::custom("argon2id", "the-real-registration"),
    }))
    .await
    .unwrap();

    // A KNOWN id: one verification, and it succeeds. This is the cost the unknown path has to
    // match, and pinning it is what makes the comparison below mean something.
    srv.token(TokenRequest::ClientCredentials {
        client_id: ClientId::new("hashed-app"),
        client_secret: Some(SECRET.to_string()),
        scope: None,
    })
    .await
    .expect("the registered client authenticates through the host seam");
    assert_eq!(seen.calls.load(Ordering::SeqCst), 1);

    // AN UNKNOWN id, with a secret presented. Same wire answer, and the same one verification.
    let refused = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("no-such-client-was-ever-registered"),
            client_secret: Some(SECRET.to_string()),
            scope: None,
        })
        .await
        .expect_err("an unknown client is invalid_client, as RFC 6749 s5.2 requires");
    assert_eq!(refused.error, ErrorCode::InvalidClient);
    assert_eq!(
        seen.calls.load(Ordering::SeqCst),
        2,
        "an unknown client_id must cost a verification through the same seam, or the wire's \
         collapse is undone by the wall clock"
    );
    let schemes = seen.schemes.lock().unwrap().clone();
    assert_eq!(
        schemes,
        vec!["argon2id".to_string(), "argon2id".to_string()],
        "the dummy has to be in the HOST's scheme; one in a scheme the verifier does not \
         recognise is rejected on inspection, in microseconds, which is the leak again"
    );
}

/// The half only the host can supply, and what happens when it does not. `dummy_hash` defaults to
/// `None` because a required method would break every existing implementation of this trait; the
/// crate then falls back to its own `sha256-hex`, which prices the BUILT-IN scheme exactly and a
/// host scheme not at all. That residual is documented on `authenticate_client`, and it is pinned
/// here so that a later change to the default is a deliberate one.
#[tokio::test]
async fn without_a_dummy_the_fallback_never_reaches_the_host_verifier() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct NoDummy(Arc<AtomicUsize>);
    impl SecretVerifier for NoDummy {
        fn verify(&self, _stored: &SecretHash, _presented: &str) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst);
            false
        }
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let srv = server_with(ManualClock::at_epoch(), Vec::new())
        .await
        .with_secret_verifier(Box::new(NoDummy(calls.clone())));

    let refused = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("no-such-client-was-ever-registered"),
            client_secret: Some(SECRET.to_string()),
            scope: None,
        })
        .await
        .expect_err("still invalid_client");
    assert_eq!(refused.error, ErrorCode::InvalidClient);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the crate's own sha256-hex dummy is decided by the crate, so a verifier offering no \
         dummy is never consulted: that is the stated limitation, not a silent one"
    );
}
