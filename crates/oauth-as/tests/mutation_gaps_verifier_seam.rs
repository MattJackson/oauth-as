// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! THE HOST'S ES256 VERIFIER IS THE ONE THAT DECIDES, EVEN WHEN THE BUILT-IN BACKEND IS PRESENT.
//!
//! Written for three survivors of the `--all-features` mutation sweep at commit `42fa851`:
//!
//! ```text
//! events.rs replace Hooks::install_es256_verifier with ()
//! events.rs replace Hooks::es256_verifier -> Option<&Arc<dyn Es256Verifier>> with None
//! jwt.rs replace <impl fmt::Display for SignerError>::fmt -> fmt::Result with Ok(Default::default())
//! ```
//!
//! # Why the first two survived, which is the interesting part
//!
//! `tests/verifier_refusal.rs` is the file that tests this seam, and it is gated
//! `#![cfg(not(feature = "jwt-p256"))]`, because it asks what happens when there is NO backend at
//! all. An `--all-features` run does not compile it. So in the configuration the sweep measures,
//! nothing at all read the installed verifier, and `Hooks::es256_verifier` could return `None`
//! unconditionally with every test still green: `AuthorizationServer::es256_verifier` would fall
//! back to the built-in `P256Verifier`, which gives the same answers as every verifier the suite
//! installs, so the substitution is invisible.
//!
//! That is a hole rather than a `cfg` artifact, and the difference matters. A `cfg` artifact is a
//! mutant that survives only because the code it changes is compiled out of the configuration the
//! sweep ran in; the behaviour is still pinned SOMEWHERE, in the configuration where the code
//! exists. This one was pinned NOWHERE: the precedence rule ("a verifier installed here
//! WINS over the built-in one, because it was installed", `server.rs`) has a configuration in
//! which it is meaningful only when BOTH exist, and that is exactly the configuration no test
//! covered. A host that installs a stricter verifier and gets the permissive built-in one instead
//! is the failure this closes, and it would be silent.
//!
//! Both directions are asserted, against the same seam, because either alone is weak. A verifier
//! that refuses proves only that SOMETHING refused; a verifier that accepts what the built-in
//! backend would refuse proves the installed one is the one being asked.
//!
//! The always-accepting verifier here is a test fixture and nothing else. A deployment that
//! installed it would have no signature checking at all, which is what `signer_conformance` exists
//! to catch.

#![cfg(all(feature = "dpop", feature = "jwt-p256"))]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use oauth_as::jwt::{compact_jws, EcdsaP256Key, Es256Verifier, PublicJwk, SignerError};
use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientId, ErrorCode, GrantType, MemoryStorage,
    ScopeSet, ServerConfig, TokenRequest, TokenRequestContext,
};

const ISSUER: &str = "https://as.example";
const TOKEN_ENDPOINT: &str = "https://as.example/token";
const SECRET: &str = "confidential-client-secret";

/// Counts how many times it was asked, and answers whatever it was built with.
///
/// The COUNT is what separates "the seam is wired" from "something else happened to agree": a
/// verifier that is never called cannot be the one that decided.
struct FixedAnswer {
    answer: bool,
    calls: AtomicUsize,
}

impl FixedAnswer {
    fn new(answer: bool) -> Arc<Self> {
        Arc::new(FixedAnswer {
            answer,
            calls: AtomicUsize::new(0),
        })
    }
}

impl Es256Verifier for FixedAnswer {
    fn verify(&self, _key: &PublicJwk, _signing_input: &[u8], _signature: &[u8]) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.answer
    }
}

fn config() -> ServerConfig {
    ServerConfig::new(ISSUER, "https://as.example/device")
}

fn confidential_client() -> Client {
    Client {
        client_id: ClientId::new("app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: SECRET.to_string(),
        },
        grant_types: vec![GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// One RFC 9449 section 4.2 proof for `POST {TOKEN_ENDPOINT}`.
///
/// `well_signed` chooses between a real ES256 signature and sixty-four bytes of nothing. The
/// second is what makes the accepting case a proof about the SEAM: the built-in backend refuses
/// it, so a token issued over it can only have come from the installed verifier.
fn proof(key: &EcdsaP256Key, jti: &str, well_signed: bool) -> String {
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": serde_json::to_value(key.to_public_jwk()).unwrap(),
    });
    let claims = serde_json::json!({
        "jti": jti,
        "htm": "POST",
        "htu": TOKEN_ENDPOINT,
        "iat": now_secs(),
    });
    compact_jws(
        &serde_json::to_vec(&header).unwrap(),
        &serde_json::to_vec(&claims).unwrap(),
        |input| {
            if well_signed {
                key.sign_signing_input(input).unwrap()
            } else {
                vec![0u8; 64]
            }
        },
    )
}

fn request() -> TokenRequest {
    TokenRequest::ClientCredentials {
        client_id: ClientId::new("app"),
        client_secret: Some(SECRET.to_string()),
        scope: None,
    }
}

fn with_proof(proof: &str) -> TokenRequestContext<'_> {
    TokenRequestContext::default().with_dpop_proof(proof)
}

/// The host installed a verifier that REFUSES, and a proof the built-in backend would have
/// accepted is refused.
///
/// Kills `Hooks::install_es256_verifier -> ()` and `Hooks::es256_verifier -> None`: under either,
/// `AuthorizationServer::es256_verifier` falls through to the built-in `P256Verifier`, the proof is
/// well formed and correctly signed, and the request SUCCEEDS.
#[tokio::test]
async fn an_installed_verifier_that_refuses_beats_the_built_in_backend() {
    let verifier = FixedAnswer::new(false);
    let srv = AuthorizationServer::new(config(), MemoryStorage::new())
        .with_es256_verifier(verifier.clone() as Arc<dyn Es256Verifier>);
    srv.register_client(confidential_client()).await.unwrap();

    let key = EcdsaP256Key::generate("device");
    let refused = srv
        .token_with_context(request(), with_proof(&proof(&key, "seam-1", true)))
        .await
        .expect_err("the installed verifier said no, so the proof is not valid");
    assert_eq!(refused.error, ErrorCode::InvalidDpopProof);

    assert!(
        verifier.calls.load(Ordering::SeqCst) > 0,
        "the installed verifier must be the thing that was asked, not merely present"
    );
}

/// The host installed a verifier that ACCEPTS, and a proof carrying sixty-four zero bytes where
/// its signature belongs is accepted.
///
/// The other direction of the same rule, and the one that cannot pass by coincidence: the built-in
/// `P256Verifier` refuses this proof, so a token at all proves the installed verifier decided.
#[tokio::test]
async fn an_installed_verifier_that_accepts_beats_the_built_in_backend() {
    let verifier = FixedAnswer::new(true);
    let srv = AuthorizationServer::new(config(), MemoryStorage::new())
        .with_es256_verifier(verifier.clone() as Arc<dyn Es256Verifier>);
    srv.register_client(confidential_client()).await.unwrap();

    let key = EcdsaP256Key::generate("device");
    srv.token_with_context(request(), with_proof(&proof(&key, "seam-2", false)))
        .await
        .expect("the installed verifier said yes, so this unsigned proof is accepted");

    assert!(
        verifier.calls.load(Ordering::SeqCst) > 0,
        "the installed verifier must be the thing that was asked"
    );
}

/// The same proof, with NO verifier installed, is refused by the built-in backend.
///
/// The control for the test above: without it, "an unsigned proof was accepted" could be a
/// statement about this crate rather than about the seam.
#[tokio::test]
async fn with_no_verifier_installed_the_built_in_backend_refuses_an_unsigned_proof() {
    let srv = AuthorizationServer::new(config(), MemoryStorage::new());
    srv.register_client(confidential_client()).await.unwrap();

    let key = EcdsaP256Key::generate("device");
    let refused = srv
        .token_with_context(request(), with_proof(&proof(&key, "seam-3", false)))
        .await
        .expect_err("sixty-four zero bytes are not an ES256 signature");
    assert_eq!(refused.error, ErrorCode::InvalidDpopProof);
}

/// `Hooks::es256_verifier` reports what the host installed, in a build where the built-in backend
/// also exists.
///
/// The accessor is public API and its own documentation says it "reports only what the HOST
/// installed", separately from the `jwt-p256` fallback. Read directly, so that
/// `Hooks::es256_verifier -> None` is killed by a test that names it rather than only through a
/// grant flow.
#[tokio::test]
async fn the_hooks_accessor_reports_the_installed_verifier_rather_than_the_fallback() {
    let plain = AuthorizationServer::new(config(), MemoryStorage::new());
    assert!(
        plain.hooks().es256_verifier().is_none(),
        "nothing was installed, and the built-in backend is not something the host installed"
    );

    let srv = AuthorizationServer::new(config(), MemoryStorage::new())
        .with_es256_verifier(FixedAnswer::new(true) as Arc<dyn Es256Verifier>);
    assert!(
        srv.hooks().es256_verifier().is_some(),
        "a verifier the host installed must be readable back"
    );
}

/// `SignerError`'s `Display` says what it is.
///
/// Kills `<impl fmt::Display for SignerError>::fmt -> Ok(Default::default())`, which prints
/// NOTHING. This is the error a host's KMS-backed signer returns, and it reaches a host's log
/// through `signer_conformance`'s `signer/signs` violation, which formats it with `{e}`. An empty
/// `Display` turns "the signer refused to sign: the key service refused" into "the signer refused
/// to sign: ", which is the one place a deployment finds out why its tokens stopped.
#[test]
fn a_signer_error_prints_its_message() {
    let e = SignerError::new("the key service refused");
    let printed = e.to_string();
    assert!(
        printed.contains("the key service refused"),
        "the host's own detail must survive: {printed:?}"
    );
    assert!(
        printed.contains("ES256 signer error"),
        "and it must say what kind of failure it is: {printed:?}"
    );
}
