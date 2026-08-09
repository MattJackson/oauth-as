// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The ES256 SIGNING SEAM, exercised with NO elliptic-curve implementation anywhere in the build.
//!
//! This file is compiled under `--features jwt`, which after 0.9.0 pulls in no crypto crate at
//! all: `p256` moved behind `jwt-p256`. So every signer here returns bytes it made up, and that is
//! the point. What is being proved is that [`oauth_as::jwt::JwtConfig`] needs NOTHING from a
//! signer but the trait: it decides the RFC 7515 section 3.1 compact serialization, the RFC 9068
//! section 2.1 protected header and the `kid`, and it hands the signer exactly the JWS Signing
//! Input of RFC 7515 section 5.1 step 5 and puts back exactly the 64 bytes it returns.
//!
//! A host whose key is in a cloud KMS or an HSM is in precisely this position: it can produce a
//! signature and a public JWK and nothing else. If these tests need a curve, the seam is not a
//! seam.

#![cfg(feature = "jwt")]

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use oauth_as::jwt::{AccessTokenClaims, Audience, Es256Signer, Jwk, JwtConfig, SignerError};

/// A signer that records what it was asked to sign and answers with a fixed 64 bytes.
///
/// NOT a valid ES256 signature, and it does not need to be: nothing in `JwtConfig` inspects the
/// signature, which is the property under test. `crates/oauth-as/src/signer_conformance.rs` is
/// where a signature is required to be real, and it is the harness a host runs against its OWN
/// signer for exactly that reason.
struct RecordingSigner {
    kid: &'static str,
    fill: u8,
    /// Every signing input handed to [`Es256Signer::sign`], in order.
    seen: Mutex<Vec<String>>,
    calls: AtomicUsize,
}

impl RecordingSigner {
    fn new(kid: &'static str, fill: u8) -> Arc<Self> {
        Arc::new(RecordingSigner {
            kid,
            fill,
            seen: Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
        })
    }

    fn seen(&self) -> Vec<String> {
        self.seen
            .lock()
            .expect("no test panics under this lock")
            .clone()
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Es256Signer for RecordingSigner {
    fn sign(
        &self,
        signing_input: &[u8],
    ) -> impl Future<Output = Result<[u8; 64], SignerError>> + Send {
        // Recorded BEFORE the await point, so the order in `seen` is call order and not
        // completion order.
        self.seen
            .lock()
            .expect("no test panics under this lock")
            .push(String::from_utf8(signing_input.to_vec()).expect("a JWS signing input is ASCII"));
        self.calls.fetch_add(1, Ordering::SeqCst);
        let fill = self.fill;
        async move { Ok([fill; 64]) }
    }

    fn public_jwk(&self) -> Jwk {
        // The coordinates are arbitrary but WELL FORMED: 32 bytes each, base64url unpadded, which
        // is what RFC 7518 section 6.2.1.2 fixes and what a resource server will parse.
        Jwk {
            kty: "EC",
            crv: "P-256",
            x: URL_SAFE_NO_PAD.encode([0x11u8; 32]),
            y: URL_SAFE_NO_PAD.encode([0x22u8; 32]),
            kid: self.kid.to_string(),
            use_: "sig",
            alg: "ES256",
        }
    }
}

/// A signer that cannot sign, which is what a KMS looks like when it is unreachable or when the
/// deployment's IAM policy has been tightened under it.
struct BrokenSigner;

impl Es256Signer for BrokenSigner {
    // Written in the `-> impl Future + Send` form the TRAIT declares rather than as `async fn`,
    // which clippy suggests. The explicit form keeps the `Send` bound visible at the impl, and a
    // host writing a real KMS signer will copy this shape: a signer whose future is not `Send`
    // cannot be used from a multi-threaded runtime, and discovering that from a trait-solver error
    // is much worse than reading it here.
    #[allow(clippy::manual_async_fn)]
    fn sign(
        &self,
        _signing_input: &[u8],
    ) -> impl Future<Output = Result<[u8; 64], SignerError>> + Send {
        async { Err(SignerError::new("the key service refused")) }
    }

    fn public_jwk(&self) -> Jwk {
        Jwk {
            kty: "EC",
            crv: "P-256",
            x: URL_SAFE_NO_PAD.encode([0x33u8; 32]),
            y: URL_SAFE_NO_PAD.encode([0x44u8; 32]),
            kid: "broken".to_string(),
            use_: "sig",
            alg: "ES256",
        }
    }
}

fn claims(jti: &str) -> AccessTokenClaims {
    AccessTokenClaims {
        iss: "https://as.example".to_string(),
        exp: 4_000_000_000,
        aud: Audience::One("https://rs.example".to_string()),
        sub: "alice".to_string(),
        client_id: "app".to_string(),
        iat: 1_700_000_000,
        jti: jti.to_string(),
        scope: Some("read".to_string()),
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        #[cfg(any(feature = "dpop", feature = "mtls"))]
        cnf: None,
    }
}

/// The seam's whole contract, in one token: the signer sees the JWS Signing Input and nothing
/// else, and its 64 bytes come back as the third segment.
#[tokio::test]
async fn a_host_signer_with_no_curve_behind_it_mints_a_well_formed_rfc_9068_token() {
    let signer = RecordingSigner::new("host-kid", 0xAB);
    let config = JwtConfig::new(signer.clone(), "https://rs.example");

    let token = config
        .sign_access_token(&claims("jti-1"))
        .await
        .expect("a signer that answers mints a token");

    let segments: Vec<&str> = token.split('.').collect();
    assert_eq!(segments.len(), 3, "RFC 7515 s3.1 compact form: {token}");

    // RFC 9068 s2.1 fixes `typ`; `alg` is a constant in this crate; `kid` comes from the SIGNER's
    // own public JWK, which is the only place a `kid` can honestly come from once the key may live
    // outside this process.
    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(segments[0])
            .expect("the header is base64url"),
    )
    .expect("the header is JSON");
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "at+jwt");
    assert_eq!(header["kid"], "host-kid");

    // RFC 7515 s5.1 step 5: the signing input is the ASCII of "header.payload", and the signer
    // must be handed THAT, not the claims and not a re-encoding of them.
    assert_eq!(
        signer.seen(),
        vec![format!("{}.{}", segments[0], segments[1])],
        "the signer must see the JWS Signing Input, exactly once"
    );

    // The 64 bytes came back verbatim: `JwtConfig` re-encodes them and does not reinterpret them.
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(segments[2])
            .expect("the signature is base64url"),
        vec![0xABu8; 64]
    );
}

/// The `kid` and the JWKS are the SIGNER's public half, not a copy this crate keeps of a key it
/// was handed. With the private half outside the process there is nothing else they could be.
#[tokio::test]
async fn the_kid_and_the_jwks_come_from_the_signers_public_jwk() {
    let signer = RecordingSigner::new("kms-2026-08", 0x01);
    let config = JwtConfig::new(signer.clone(), "https://rs.example");

    assert_eq!(config.kid(), "kms-2026-08");
    let jwks = config.jwks();
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.keys[0], signer.public_jwk());
}

/// [`Es256Signer::public_jwk`] is SYNC, so the implementor caches it at construction; this crate
/// then reads it ONCE, at construction, and serves the same bytes forever after. A JWKS endpoint
/// that re-asked its signer on every fetch would be a network call on a public, unauthenticated,
/// cacheable document that any client may poll at any rate.
#[tokio::test]
async fn the_public_half_is_read_once_at_construction_and_never_per_request() {
    /// Counts `public_jwk` calls, and CHANGES its answer after the first: if this crate re-read
    /// the key per request, the `kid` below would drift and the assertion would catch it.
    struct DriftingSigner {
        reads: AtomicUsize,
    }

    impl Es256Signer for DriftingSigner {
        #[allow(clippy::manual_async_fn)] // Same reason as BrokenSigner above.
        fn sign(
            &self,
            _signing_input: &[u8],
        ) -> impl Future<Output = Result<[u8; 64], SignerError>> + Send {
            async { Ok([0u8; 64]) }
        }

        fn public_jwk(&self) -> Jwk {
            let n = self.reads.fetch_add(1, Ordering::SeqCst);
            Jwk {
                kty: "EC",
                crv: "P-256",
                x: URL_SAFE_NO_PAD.encode([0x55u8; 32]),
                y: URL_SAFE_NO_PAD.encode([0x66u8; 32]),
                kid: format!("read-{n}"),
                use_: "sig",
                alg: "ES256",
            }
        }
    }

    let config = JwtConfig::new(
        Arc::new(DriftingSigner {
            reads: AtomicUsize::new(0),
        }),
        "https://rs.example",
    );

    assert_eq!(config.kid(), "read-0");
    for _ in 0..5 {
        assert_eq!(config.kid(), "read-0", "the public half is cached");
        assert_eq!(config.jwks().keys[0].kid, "read-0");
        let token = config
            .sign_access_token(&claims("jti"))
            .await
            .expect("signing works");
        let header: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(token.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(header["kid"], "read-0");
    }
}

/// A signer that refuses produces NO token. There is no fallback to an opaque string and no
/// unsigned token: an access token this server could not sign is an access token it must not
/// issue.
#[tokio::test]
async fn a_signer_that_refuses_mints_nothing() {
    let config = JwtConfig::new(Arc::new(BrokenSigner), "https://rs.example");
    let error = config
        .sign_access_token(&claims("jti"))
        .await
        .expect_err("a signer that refuses must not yield a token");
    // The message never carries key material, and never carries the host's own detail onto the
    // wire: the caller in `server.rs` maps this onto `server_error`.
    assert!(error.to_string().contains("signing"), "{error}");
}

/// RETIREMENT DROPS THE SIGNER. `JwtConfig::retired` holds PUBLIC HALVES ONLY, so a retired key
/// cannot sign again BY CONSTRUCTION rather than by a promise the code keeps: there is no signer
/// left to call. Proved by call count, which is the only observable that distinguishes "we chose
/// not to use it" from "it is gone".
#[tokio::test]
async fn rotation_retires_a_public_half_and_drops_the_signer_that_made_it() {
    let old = RecordingSigner::new("old-kid", 0x01);
    let new = RecordingSigner::new("new-kid", 0x02);

    let config = JwtConfig::new(old.clone(), "https://rs.example");
    config
        .sign_access_token(&claims("before"))
        .await
        .expect("the active signer signs");
    assert_eq!(old.calls(), 1);

    let config = config.rotate_to(new.clone());
    let token = config
        .sign_access_token(&claims("after"))
        .await
        .expect("the new active signer signs");

    // The OLD signer was not called again, and cannot be: the configuration holds its public half
    // and nothing else.
    assert_eq!(old.calls(), 1, "a retired key must never sign again");
    assert_eq!(new.calls(), 1);
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(token.split('.').nth(2).unwrap())
            .unwrap(),
        vec![0x02u8; 64]
    );

    // RFC 7517 s4.5 with RFC 7515 s4.1.4: both public halves stay published, active first, so a
    // token minted a moment before the swap still verifies.
    let jwks = config.jwks();
    assert_eq!(jwks.keys.len(), 2);
    assert_eq!(jwks.keys[0].kid, "new-kid");
    assert_eq!(jwks.keys[1].kid, "old-kid");
    assert_eq!(config.retired_kids().collect::<Vec<_>>(), vec!["old-kid"]);
}

/// Two `JwtConfig`s over the SAME signer are equal, and one over a different key is not. Equality
/// is over the PUBLIC identity, which is all that remains once the private half may be a handle to
/// something in another process: there is no scalar left to compare.
#[test]
fn equality_is_over_the_published_identity() {
    let a = JwtConfig::new(RecordingSigner::new("kid-a", 1), "https://rs.example");
    let same = JwtConfig::new(RecordingSigner::new("kid-a", 1), "https://rs.example");
    let other = JwtConfig::new(RecordingSigner::new("kid-b", 1), "https://rs.example");
    assert_eq!(a, same);
    assert_ne!(a, other);
}

/// `ServerConfig` derives `Debug`, so a host that logs its configuration logs this. It must not
/// thereby log anything about the key, and with the key outside the process the only honest thing
/// to print is what is already public.
#[test]
fn debug_prints_the_published_identity_and_redacts_the_signer() {
    let config = JwtConfig::new(RecordingSigner::new("kid-a", 1), "https://rs.example");
    let text = format!("{config:?}");
    assert!(text.contains("kid-a"), "{text}");
    assert!(text.contains("redacted"), "{text}");
}
