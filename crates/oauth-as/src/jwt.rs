// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9068 JWT access tokens and the RFC 7517 key set that lets a resource server verify them.
//! Compiled ONLY under the off-by-default `jwt` feature; with the feature off this module does not
//! exist and the crate's dependency set is unchanged.
//!
//! # Verification: the three rules, and they are the whole of the trust boundary
//!
//! This module SIGNS in its first half and VERIFIES in its second, and the two jobs are not
//! symmetric. The module doc used to be able to say this crate "never parses a JWT it did not
//! make"; the `client-assertion` and `dpop` features ended that. An RFC 7523 client assertion and
//! an RFC 9449 DPoP proof are both JWTs a CLIENT made, so [`CompactJws::parse`], [`PublicJwk`] and
//! [`verify_es256`] are handling attacker-controlled input, and anyone verifying against them
//! needs these three rules rather than a pointer at the source.
//!
//! They are the same three rules every published JWS confusion attack has been aimed at:
//!
//! 1. THE KEY IS CHOSEN BY THE VERIFIER, never by the token. A caller passes the key it already
//!    decided to trust (a registered client's JWK, a registered client's secret); nothing here
//!    resolves a key out of the header on its own authority, and there is no `jku`, `x5u` or `kid`
//!    lookup. DPoP is the one apparent exception and is not really one: its key comes from the
//!    proof, but the proof only ever proves possession of THAT key, and it is the `cnf.jkt`
//!    binding, not this module, that decides whether the key means anything (see the `dpop`
//!    module).
//! 2. THE ALGORITHM IS CHOSEN BY THE VERIFIER, never by the token. [`verify_es256`] and
//!    [`verify_hs256`] are separate functions taking separate key types, so there is no value of
//!    `alg` a caller can be made to route an HMAC verification at a public key it already
//!    published. `none` is not implemented at all: no code path here accepts an unsigned JWS. A
//!    caller still has to check that the `alg` it was handed is the one the REGISTRATION expects,
//!    which is why the `client-assertion` module's `AssertionKeys` holds one algorithm, not a
//!    set.
//! 3. NOTHING IS DECODED TWICE. The signature is verified over the EXACT received bytes of
//!    `header.payload` ([`CompactJws::signing_input`] borrows them), never over a re-serialization
//!    of the parsed claims, so a payload that serializes differently than it arrived cannot verify
//!    under one reading and be interpreted under another.
//!
//! A JWK presented to this module is also refused outright if it carries any PRIVATE or symmetric
//! member (`d`, the RSA CRT parameters, `k`): RFC 9449 section 4.3 makes that a requirement, and
//! [`PublicJwk::from_json`] is the only route from JSON into the type, including through `serde`,
//! whose `Deserialize` impl is routed through it rather than derived. The type's fields are sealed,
//! so the other constructors are the only alternatives and neither can express a private member:
//! [`PublicJwk::from_coordinates`] takes two P-256 coordinates and nothing else, and
//! [`Jwk::to_public_jwk`] converts a key this crate PUBLISHED, which by construction has no private
//! half in it. See [`PublicJwk`] on what each does and does not revalidate.
//!
//! # Why this is hand-rolled
//!
//! This crate ISSUES exactly one token shape. A general
//! JOSE library brings a parser, a validation policy engine and a key-format zoo that an issuer
//! never executes; the compact serialization of RFC 7515 section 3.1 is
//! `BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)` and fits in this file on
//! top of `serde_json` and `base64`, which the crate already depends on.
//!
//! # THE ES256 SEAM: the arithmetic is not in this feature
//!
//! The P-256 arithmetic is the one thing that genuinely needs an implementation, and after 0.9.0
//! it is not one this feature brings. [`Es256Signer`] and [`Es256Verifier`] are the seam; the
//! `jwt-p256` feature is the BACKEND this crate ships over `p256`, and a host may install its own
//! instead. Two reasons, in the order they matter:
//!
//! 1. THE PRIVATE KEY NEED NOT BE IN THIS PROCESS. [`Es256Signer::sign`] is async precisely so it
//!    can be a cloud KMS or a PKCS#11 token, where the key never leaves its boundary and this
//!    process holds only a handle. The signing key is the one secret whose compromise forges every
//!    token the deployment will ever issue, and "the key is in the process" is exactly the property
//!    a regulated deployment must avoid. Through 0.9.0 this module made it structural.
//! 2. It stops `jwt` adding a complete SECOND elliptic curve implementation (measured: 20 packages)
//!    to a host that already has one through `rustls`, which is most Rust HTTP servers.
//!
//! [`Es256Verifier`] is SYNC, and the asymmetry is the design rather than an oversight: verifying
//! holds only PUBLIC keys, so there is nothing to externalise, and it sits on the RFC 9449 DPoP hot
//! path where an ES256 verification is already about 133 microseconds. Making it async would buy
//! nothing and cost bytes on the token future.
//!
//! # What the host owns
//!
//! The signing key. This module will not invent one at startup and does not persist one: a key
//! that appears from nowhere is a key nobody is managing, and a key regenerated on restart
//! silently invalidates every live token. [`EcdsaP256Key::generate`] exists for tests and for a
//! host's own key-provisioning tool, and the host is expected to store what it generates.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
#[cfg(feature = "jwt-p256")]
use p256::ecdsa::signature::{Signer as _, Verifier as _};
#[cfg(feature = "jwt-p256")]
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
#[cfg(feature = "jwt-pkcs8")]
use p256::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
#[cfg(feature = "jwt-p256")]
use p256::SecretKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// A key could not be loaded or exported. The message never contains key material.
#[cfg(feature = "jwt-p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt-p256")))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError(String);

#[cfg(feature = "jwt-p256")]
impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signing key error: {}", self.0)
    }
}

#[cfg(feature = "jwt-p256")]
impl std::error::Error for KeyError {}

/// A token could not be signed or serialized. The message never contains key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtError(String);

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JWT signing error: {}", self.0)
    }
}

impl std::error::Error for JwtError {}

/// A host's ES256 backend could not produce a signature.
///
/// One opaque type rather than an enum, and no source error: the caller in
/// [`JwtConfig::sign_access_token`] has exactly one reaction to any of them (mint no token, answer
/// `server_error`), so distinguishing "the KMS was unreachable" from "the key was disabled" here
/// would only invite somebody to treat one as recoverable on a path where neither is. The host
/// already has the real detail, because the host wrote the signer.
///
/// The message MUST NOT contain key material; nothing in this crate ever prints it on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerError(String);

impl SignerError {
    /// Describe a signing failure. Do not put key material in it.
    pub fn new(message: impl Into<String>) -> Self {
        SignerError(message.into())
    }
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ES256 signer error: {}", self.0)
    }
}

impl std::error::Error for SignerError {}

/// WHERE THIS SERVER'S SIGNING KEY LIVES. The host implements it; this crate holds only a handle.
///
/// Enable `jwt-p256` and use [`EcdsaP256Key`] if the key is a scalar in this process. Implement
/// this if it is not: a cloud KMS, a PKCS#11 token, an HSM, a remote signing service.
///
/// # The two halves are deliberately different shapes
///
/// [`Es256Signer::sign`] is ASYNC because it holds a SECRET, so it is the half that wants to leave
/// the process, and leaving the process is a network round trip (or, for PKCS#11, a blocking call
/// that belongs on a blocking pool). [`Es256Verifier`] is SYNC because it holds only public keys,
/// so there is nothing to externalise.
///
/// # `public_jwk` is SYNC, and that is a REQUIREMENT ON YOU
///
/// A KMS-backed signer may need a network round trip to learn its own public half, and this method
/// gives it nowhere to await. That is deliberate, so it has to be said plainly:
///
/// **Fetch the public half ONCE, AT CONSTRUCTION, and return a cached value here.** Do not block a
/// runtime thread inside this method, and do not panic if a fetch fails; neither is necessary,
/// because construction is where the fetch belongs.
///
/// Sync is the right shape independently of KMS: this crate serialises the RFC 7517 JWKS document
/// ONCE, at construction, exactly as it does the RFC 8414 metadata document. An async
/// `public_jwk()` would invite a network call on a PUBLIC, UNAUTHENTICATED, CACHEABLE endpoint that
/// any client may poll at any rate. Forcing the fetch to construction is the behaviour this crate
/// wants, and making the method sync is how the type system asks for it.
///
/// Two consequences follow, and neither is papered over:
///
/// - **Construction becomes fallible, and may be slow.** Your signer reaches the KMS before you
///   build [`JwtConfig`]. A KMS that is unreachable at boot is then a STARTUP failure, which is the
///   correct time to find out, rather than a 500 on the first token request.
/// - **A KEY ROTATED IN THE KMS BEHIND THIS PROCESS'S BACK GOES STALE SILENTLY.** The cached public
///   half would advertise a key that no longer signs, so every token the deployment issues fails
///   verification against its own published JWKS, and nothing in this process notices. **Rotating
///   in the KMS alone is NOT enough.** Rotation must go through [`JwtConfig::rotate_to`], which
///   keeps the retired PUBLIC half published so tokens minted before the swap keep verifying. This
///   is the mistake an operator makes exactly once, in production, and its symptom (every token
///   suddenly invalid) points nowhere near its cause.
///
/// # What this trait deliberately cannot do
///
/// There is NO method that returns a private key, and there must never be one.
/// [`JwtConfig`]'s retired set holds public halves only, so a retired key cannot sign again BY
/// CONSTRUCTION rather than by a promise the code keeps: retirement drops the signer, and a `Jwk`
/// is all that is left.
///
/// # Before you deploy one
///
/// Run [`crate::signer_conformance`] against it, behind the `test-util` feature. A broken signer
/// fails SILENTLY: a wrong signature is indistinguishable, at a resource server, from a tampered
/// token. Emitting ASN.1 DER instead of the fixed-width form below is the obvious way to be wrong,
/// and it is wrong in a way only a real client notices.
#[cfg(feature = "jwt")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
pub trait Es256Signer: Send + Sync {
    /// The `ES256` signature over `signing_input`, which is the JWS Signing Input of RFC 7515
    /// section 5.1 step 5: the ASCII of `BASE64URL(header) "." BASE64URL(payload)`.
    ///
    /// The return is the FIXED-WIDTH `r || s` concatenation RFC 7518 section 3.4 mandates: 64
    /// bytes, 32 per coordinate, leading zeros KEPT. It is **NOT** the ASN.1 DER
    /// `SEQUENCE { r INTEGER, s INTEGER }` that OpenSSL and nearly every KMS return by default,
    /// and converting is your job. The array type refuses the wrong LENGTH; it cannot refuse the
    /// wrong ENCODING, which is what [`crate::signer_conformance`] is for.
    ///
    /// Sign the bytes as given. Do not hash them first: `ES256` is ECDSA/P-256/SHA-256, so the
    /// SHA-256 is part of the signature scheme, and a KMS whose API wants a digest is a KMS you
    /// hash for exactly once.
    ///
    /// # What you may assume about `signing_input`, and what you MUST NOT do
    ///
    /// `signing_input` is built by THIS crate, not by a client: it is non-empty printable ASCII,
    /// it always contains exactly one `.`, and it is roughly a kilobyte. Its CONTENT is not
    /// entirely this crate's, because the claims carry a `client_id`, a `sub` and a `scope` that
    /// came from somewhere, but its SHAPE is. You may assume nothing further, and in particular
    /// nothing about its length.
    ///
    /// **MUST NOT PANIC, for any input, ever.** Every failure you can have here (the KMS was
    /// unreachable, the key was disabled, the credential expired, the response was the wrong
    /// length) is `Err(SignerError)`, which this crate turns into an RFC 6749 section 5.2
    /// `server_error`. A panic instead unwinds out of [`JwtConfig::sign_access_token`] and into
    /// the host's token endpoint, where a runtime that aborts on panic takes the whole server
    /// down and one that does not leaves a poisoned task; either way the deployment loses more
    /// than the one request. Nothing about the difference is worth an `unwrap`.
    fn sign(
        &self,
        signing_input: &[u8],
    ) -> impl Future<Output = Result<[u8; 64], SignerError>> + Send;

    /// The PUBLIC half, for the RFC 7517 JWKS document and the `kid` on every token header.
    ///
    /// Cached at construction. Read the trait docs above before implementing this one.
    fn public_jwk(&self) -> Jwk;
}

/// Delegating impl so a host can share ONE signer between several [`JwtConfig`]s (two audiences,
/// two servers in one process) without a newtype. `JwtConfig` erases to a `dyn` handle internally,
/// so this costs nothing extra.
#[cfg(feature = "jwt")]
impl<T: Es256Signer + ?Sized> Es256Signer for Arc<T> {
    fn sign(
        &self,
        signing_input: &[u8],
    ) -> impl Future<Output = Result<[u8; 64], SignerError>> + Send {
        (**self).sign(signing_input)
    }

    fn public_jwk(&self) -> Jwk {
        (**self).public_jwk()
    }
}

/// HOW THIS SERVER CHECKS A SIGNATURE SOMEBODY ELSE MADE: RFC 9449 DPoP proofs, RFC 9101 request
/// objects, RFC 7523 client assertions.
///
/// Enable `jwt-p256` for the built-in [`P256Verifier`], or install your own with
/// [`crate::AuthorizationServer::with_es256_verifier`]. With neither, every signed credential is
/// REFUSED: a server that cannot check a signature must never behave as though it had checked one.
///
/// SYNC on purpose. This holds only PUBLIC keys, so there is no secret to externalise and nothing
/// to be gained from a round trip; it also sits on the DPoP hot path, which runs once per token
/// request. See the module docs on the asymmetry with [`Es256Signer`].
///
/// # The contract, and every clause of it is load bearing
///
/// `true` means, and may only mean: `signature` is a valid `ES256` (ECDSA/P-256/SHA-256) signature
/// over exactly `signing_input`, under exactly `key`. In particular:
///
/// - `signature` MUST be the 64-byte fixed-width `r || s` of RFC 7518 section 3.4. Reject any
///   other length, and do NOT also accept the ASN.1 DER form: two encodings of one signature is
///   signature malleability, and a value a deployment recorded as unique stops being unique.
/// - `key` must be checked to be ON THE CURVE. That check is what an invalid-curve attack needs to
///   find missing, and it is the reason this crate hands you a [`PublicJwk`] rather than a parsed
///   point: the coordinates arrived from a client.
/// - There is no `false` you may return for an error and no error you may return at all. A
///   malformed key, a wrong-length signature and a signature that simply does not verify all have
///   the same and only safe answer, and distinguishing them would only invite a caller to treat
///   one as recoverable.
///
/// # What you may assume about the arguments, which is LESS than it looks
///
/// The paragraph above says what `true` may mean. This one says what you are handed, because the
/// clause "reject any other length" is the one an implementor reads as "the length will be 64".
///
/// - **`signature` IS ATTACKER-CONTROLLED BYTES OF ANY LENGTH, INCLUDING ZERO.** It is the third
///   segment of a JWS somebody sent this server, base64url-decoded, and NOTHING between the wire
///   and you checks its length. A DPoP proof, an RFC 9101 request object and an RFC 7523 client
///   assertion all arrive this way; on a 4 kilobyte DPoP header the third segment decodes to
///   anything from 0 to about 3000 bytes, and a token ending in a bare `.` decodes to an EMPTY
///   slice, which parses fine and reaches you.
/// - **`key` HAS PASSED SHAPE VALIDATION AND NOTHING MORE.** [`PublicJwk::from_json`] guarantees
///   `kty` is `EC`, `crv` is `P-256`, and that `x` and `y` are each exactly 32 base64url-decoded
///   bytes. It does NOT guarantee the point is on the curve, is not the point at infinity, or is a
///   point at all: those 64 bytes came from a client. See the on-curve clause above.
/// - **`signing_input` may be empty and is not required to be UTF-8** for your purposes. Hash the
///   bytes as given.
///
/// # MUST NOT PANIC
///
/// **Return `false`. Do not panic, for any input, ever.** Every case above is a `false`: a
/// zero-length signature, a 63-byte one, a 65-byte one, an off-curve key, an empty signing input.
///
/// This is not a formality, and it is the one clause a natural implementation breaks. Having read
/// "MUST be the 64-byte fixed-width `r || s`", the obvious KMS-shaped verifier begins
/// `&signature[..64]` or `Signature::from_slice(&signature[..64])`, and both PANIC on a token whose
/// third segment is empty. The panic unwinds out of this crate and into the host's token endpoint,
/// where it is reachable unauthenticated by anyone who can send a string with two dots in it. Test
/// the length before you slice, or match on `signature.try_into()` into a `[u8; 64]`, which cannot
/// be got wrong.
///
/// # Before you deploy one
///
/// Run [`crate::signer_conformance`] against it. It carries the RFC 7515 appendix A.3 vector,
/// which neither side of your deployment produced, and it is the only thing that can tell a
/// verifier that is right from one that agrees with your signer.
#[cfg(feature = "jwt")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
pub trait Es256Verifier: Send + Sync {
    /// Does `signature` verify over `signing_input` under `key`? See the trait docs for what
    /// `true` is allowed to mean.
    fn verify(&self, key: &PublicJwk, signing_input: &[u8], signature: &[u8]) -> bool;
}

/// The OBJECT-SAFE shadow of [`Es256Signer::sign`], so that [`JwtConfig`] can hold `Arc<dyn ...>`.
///
/// Only `sign` needs shadowing: `public_jwk` is called ONCE, on the concrete type, before the
/// signer is erased, and the `Jwk` it returned is what [`JwtConfig`] keeps.
///
/// It exists because those two requirements are in tension in the language rather than in the
/// design. `async fn` in a trait (return-position `impl Trait`, which is also what [`crate::Storage`]
/// uses and what sets this crate's 1.75 MSRV floor) is what lets a host write a natural
/// `async fn sign`, and it is exactly what makes a trait not object safe. Boxing the future in the
/// PUBLIC trait would push that syntax onto every implementor forever; boxing it here, once, keeps
/// the public shape and confines the cost to one line.
///
/// The cost is ONE allocation per signed access token, paid only by a host that configured RFC 9068
/// tokens at all. The alternative is making [`JwtConfig`] generic over the signer, which is a third
/// monomorphization axis on `AuthorizationServer`: MEASURED at 53,548 bytes per additional
/// `(Storage, Clock)` pair, which is 27% of this crate's entire default binary surface. One
/// allocation and one indirect call against a signing operation that may be a network round trip is
/// not measurable; that is.
#[cfg(feature = "jwt")]
trait DynEs256Signer: Send + Sync {
    fn dyn_sign<'a>(
        &'a self,
        signing_input: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<[u8; 64], SignerError>> + Send + 'a>>;
}

#[cfg(feature = "jwt")]
impl<T: Es256Signer> DynEs256Signer for T {
    fn dyn_sign<'a>(
        &'a self,
        signing_input: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<[u8; 64], SignerError>> + Send + 'a>> {
        Box::pin(self.sign(signing_input))
    }
}

/// A P-256 signing key plus the `kid` that names it.
///
/// The `kid` is what makes rotation possible: an AS publishes the old and new public keys in the
/// same JWKS, signs new tokens under the new `kid`, and retires the old entry once every token
/// signed under it has expired (RFC 7517 section 4.5; RFC 7515 section 4.1.4). Without a `kid` a
/// verifier must trial every advertised key and rotation becomes a guessing game.
///
/// THE BUILT-IN BACKEND, behind `jwt-p256`. It is an [`Es256Signer`] like any other; what makes it
/// the default choice is only that the key is a scalar in this process, which is the right answer
/// for most deployments and the wrong one for a deployment whose policy says the key may not be.
#[cfg(feature = "jwt-p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt-p256")))]
#[derive(Clone)]
pub struct EcdsaP256Key {
    kid: String,
    signing: SigningKey,
}

#[cfg(feature = "jwt-p256")]
impl EcdsaP256Key {
    /// Load from a raw 32 byte big-endian private scalar (SEC 1: `1 <= d <= n-1`; out-of-range and
    /// wrong-length input is rejected rather than reduced, because a silently reduced key is a key
    /// the host did not choose).
    pub fn from_scalar_bytes(kid: impl Into<String>, scalar: &[u8]) -> Result<Self, KeyError> {
        // `SecretKey::from_slice` accepts SHORT inputs and left-pads them, so a truncated key file
        // would load as a valid but different (and much weaker) key. A P-256 scalar is 32 bytes;
        // anything else is a caller mistake worth failing loudly on.
        if scalar.len() != 32 {
            return Err(KeyError(
                "a P-256 private scalar is exactly 32 bytes".into(),
            ));
        }
        let secret = SecretKey::from_slice(scalar)
            .map_err(|_| KeyError("not a valid P-256 private scalar".into()))?;
        Ok(EcdsaP256Key {
            kid: kid.into(),
            signing: SigningKey::from(&secret),
        })
    }

    /// Load from a PKCS#8 (RFC 5208) `PrivateKeyInfo` DER document, the format `openssl pkcs8`
    /// and most KMS exports emit.
    ///
    /// Behind `jwt-pkcs8` rather than `jwt`, for the DEPENDENCY rather than for the bytes: the
    /// split takes the `pkcs8` crate off a `--features jwt` tree. It does NOT save a host any
    /// linked size, because a build with the feature on and these two constructors never called
    /// measures byte for byte identical to one with it off; LTO deletes what nothing reaches. A
    /// host whose key material arrives as a raw scalar uses [`EcdsaP256Key::from_scalar_bytes`]
    /// and pays nothing either way.
    #[cfg(feature = "jwt-pkcs8")]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwt-pkcs8")))]
    pub fn from_pkcs8_der(kid: impl Into<String>, der: &[u8]) -> Result<Self, KeyError> {
        let secret = SecretKey::from_pkcs8_der(der)
            .map_err(|_| KeyError("not a valid PKCS#8 P-256 private key".into()))?;
        Ok(EcdsaP256Key {
            kid: kid.into(),
            signing: SigningKey::from(&secret),
        })
    }

    /// A fresh random key. For TESTS and for a host's own key-provisioning step: this crate never
    /// calls it, because a key that materialises at startup is a key nobody is managing. Whatever
    /// this returns must be exported ([`EcdsaP256Key::to_pkcs8_der`]) and stored by the host, or
    /// the tokens signed with it die with the process.
    ///
    /// # Panics
    /// If the OS refuses randomness, which the rest of this crate also treats as unrecoverable.
    pub fn generate(kid: impl Into<String>) -> Self {
        let kid = kid.into();
        loop {
            let mut buf = [0u8; 32];
            getrandom::fill(&mut buf).expect("OS randomness for OAuth artifacts");
            // Rejection sampling: a uniform 32 byte string is occasionally outside [1, n-1] for
            // P-256's order n. Reducing it instead would bias the key; the probability of a redraw
            // is about 2^-32, so this loop terminates immediately in practice.
            if let Ok(key) = Self::from_scalar_bytes(kid.clone(), &buf) {
                return key;
            }
        }
    }

    /// Export as PKCS#8 DER. PRIVATE KEY MATERIAL: the caller is responsible for where this goes.
    /// Present so a host can persist a key it generated; nothing in this crate calls it.
    ///
    /// Behind `jwt-pkcs8`, for the reason on [`EcdsaP256Key::from_pkcs8_der`].
    #[cfg(feature = "jwt-pkcs8")]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwt-pkcs8")))]
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>, KeyError> {
        let doc = SecretKey::from(&self.signing)
            .to_pkcs8_der()
            .map_err(|_| KeyError("PKCS#8 encoding failed".into()))?;
        Ok(doc.as_bytes().to_vec())
    }

    /// The key identifier published in the JWKS and in every token header.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The PUBLIC half as an RFC 7517 JWK. There is no method that produces a JWK containing `d`,
    /// which is the point: the private parameter cannot be published by accident.
    pub fn public_jwk(&self) -> Jwk {
        let point = self.signing.verifying_key().to_encoded_point(false);
        // Uncompressed SEC 1 form guarantees both affine coordinates are present and each is the
        // FIXED 32 byte width RFC 7518 section 6.2.1.2 requires (left-padded, never trimmed: a
        // trimmed coordinate is the classic JWK interoperability bug).
        let x = point.x().expect("uncompressed point has an x coordinate");
        let y = point.y().expect("uncompressed point has a y coordinate");
        Jwk {
            kty: "EC",
            crv: "P-256",
            x: URL_SAFE_NO_PAD.encode(x),
            y: URL_SAFE_NO_PAD.encode(y),
            kid: self.kid.clone(),
            use_: "sig",
            alg: "ES256",
        }
    }

    /// Sign `message` with ECDSA/P-256/SHA-256, returning the fixed-width `r || s` form RFC 7518
    /// section 3.4 mandates for `ES256` (64 bytes; NOT the DER form OpenSSL emits by default).
    fn sign_es256(&self, message: &[u8]) -> Result<[u8; 64], JwtError> {
        let signature: Signature = self
            .signing
            .try_sign(message)
            .map_err(|_| JwtError("ECDSA signing failed".into()))?;
        let bytes = signature.to_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

#[cfg(feature = "jwt-p256")]
impl fmt::Debug for EcdsaP256Key {
    /// Redacted on purpose: `ServerConfig` derives `Debug`, and a host that logs its config must
    /// not thereby log its signing key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaP256Key")
            .field("kid", &self.kid)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "jwt-p256")]
impl PartialEq for EcdsaP256Key {
    /// Equality over the PUBLIC identity only (kid plus public point). Two handles to the same key
    /// compare equal without any comparison touching the secret scalar.
    fn eq(&self, other: &Self) -> bool {
        self.kid == other.kid
            && self
                .signing
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                == other
                    .signing
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
    }
}

#[cfg(feature = "jwt-p256")]
impl Eq for EcdsaP256Key {}

/// The built-in backend's signing half. `sign` is async by the trait and does no I/O here: the key
/// is in this process, so the future is ready on its first poll and there is no suspension point
/// for the token path to pay for.
#[cfg(feature = "jwt-p256")]
impl Es256Signer for EcdsaP256Key {
    fn sign(
        &self,
        signing_input: &[u8],
    ) -> impl Future<Output = Result<[u8; 64], SignerError>> + Send {
        // Computed BEFORE the async block, so nothing borrows `signing_input` across a suspension
        // point that does not exist. The future this returns owns a `Result` and nothing else.
        let signed = self.sign_es256(signing_input).map_err(|e| SignerError(e.0));
        async move { signed }
    }

    fn public_jwk(&self) -> Jwk {
        EcdsaP256Key::public_jwk(self)
    }
}

/// The built-in backend's verifying half: ES256 (ECDSA/P-256/SHA-256) over `p256`.
///
/// A unit struct rather than a function so it can be INSTALLED, which is what makes a host's own
/// verifier able to replace it. `AuthorizationServer` falls back to this one when the host installs
/// none and `jwt-p256` is compiled in, which is why enabling that feature reproduces exactly the
/// behaviour every consumer had before the seam existed.
#[cfg(feature = "jwt-p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt-p256")))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct P256Verifier;

#[cfg(feature = "jwt-p256")]
impl Es256Verifier for P256Verifier {
    fn verify(&self, key: &PublicJwk, signing_input: &[u8], signature: &[u8]) -> bool {
        verify_es256(key, signing_input, signature)
    }
}

/// One RFC 7517 JWK: the PUBLIC parameters of an EC P-256 signing key and nothing else.
///
/// The fields are the complete set this crate ever emits. There is deliberately no `d`
/// (RFC 7517 section 6.2.2.1, the private key parameter) and no way to add one.
///
/// THE FIELDS ARE PUBLIC, unlike [`PublicJwk`]'s, and the difference is what each type is for: this
/// one is what a HOST FILLS IN. [`Es256Signer::public_jwk`] returns it, so every host implementing
/// that seam over a KMS or a PKCS#11 token has to build one by hand, and sealing it would mean
/// shipping a fallible constructor for a value the host already knows is correct.
///
/// What that costs is worth stating where the literal gets written: [`Jwk::to_public_jwk`] does not
/// revalidate, so a `Jwk` literal whose `x` and `y` are not 32-byte base64url produces a
/// [`PublicJwk`] that [`PublicJwk::from_json`] would have refused. It fails CLOSED — nothing
/// verifies under such a key, so the effect is a signer whose signatures never check out and, on the
/// DPoP path, a token bound to a thumbprint nobody can present — but it fails at verification time
/// rather than here. [`crate::signer_conformance`] is the check that catches it: it verifies a real
/// signature against the key the signer publishes, which is exactly the mismatch this shape allows.
/// Run it against any signer before a deployment trusts it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Jwk {
    /// Key type; always `EC` (RFC 7518 section 6.2).
    pub kty: &'static str,
    /// Curve; always `P-256`.
    pub crv: &'static str,
    /// Base64url (unpadded) x coordinate, fixed 32 byte width.
    pub x: String,
    /// Base64url (unpadded) y coordinate, fixed 32 byte width.
    pub y: String,
    /// The key identifier, matching the `kid` of every token signed with it.
    pub kid: String,
    /// Public key use; always `sig` (RFC 7517 section 4.2).
    #[serde(rename = "use")]
    pub use_: &'static str,
    /// The algorithm this key is for; always `ES256` (RFC 7517 section 4.4).
    pub alg: &'static str,
}

impl Jwk {
    /// The same key in the VERIFYING shape.
    ///
    /// [`Jwk`] exists to be SERIALIZED, so every member this crate fixes is a `&'static str`;
    /// [`PublicJwk`] is parsed from attacker-controlled JSON and is therefore a different type on
    /// purpose (see its own docs). This is the one direction that is always safe, because these
    /// parameters were produced here rather than received: a `Jwk` a signer published is by
    /// construction `EC` / `P-256` with 32-byte coordinates.
    ///
    /// Used by [`crate::signer_conformance`] to check a signer's output against the key that
    /// signer publishes, which is the one check that catches a `public_jwk()` belonging to some
    /// other key.
    ///
    /// It REVALIDATES NOTHING, and cannot usefully: it is infallible, so there is no channel for a
    /// refusal, and making it fallible would push a `Result` onto every caller for a value they
    /// produced themselves. "Produced here" is doing the work, and [`Jwk`]'s own docs say plainly
    /// what it means for a host that hand-builds one with coordinates that are not 32 bytes: this
    /// hands back a [`PublicJwk`] that [`PublicJwk::from_json`] would have refused, which fails
    /// closed at verification rather than being caught here.
    pub fn to_public_jwk(&self) -> PublicJwk {
        PublicJwk {
            kty: self.kty.to_string(),
            crv: self.crv.to_string(),
            x: self.x.clone(),
            y: self.y.clone(),
            kid: Some(self.kid.clone()),
        }
    }
}

/// An RFC 7517 section 5 JWK Set: what the host serves at its `jwks_uri`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Jwks {
    /// The advertised keys.
    pub keys: Vec<Jwk>,
}

/// The `aud` claim, which RFC 9068 section 2.2 requires and RFC 7519 section 4.1.3 allows to be
/// either a single string or an array of strings. Serialized untagged so one audience is a plain
/// string, which is what most resource servers expect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Audience {
    /// Exactly one audience.
    One(String),
    /// Several audiences.
    Many(Vec<String>),
}

impl Audience {
    /// Whether this actually names somebody.
    ///
    /// AN EMPTY `aud` IS NOT A HARMLESS ONE. `Many(vec![])` serializes untagged as the literal
    /// `"aud": []`, and a resource server whose check reads "if `aud` is present and non-empty it
    /// must contain me" treats that as NO RESTRICTION: the fail-open reading of the one claim the
    /// authorization server believed it was constraining. `One(String::new())` is the degenerate
    /// form and fails the other way, a token valid nowhere, which is an outage an operator cannot
    /// see in their configuration. An empty ELEMENT of a list is the first case wearing the second
    /// one's clothes, so it counts against the whole value.
    ///
    /// This is what makes [`AccessTokenClaims`]'s "a missing required claim should be impossible to
    /// express" true rather than aspirational: the type could always express it, so the check has
    /// to stand where the bytes are produced. See `JwtConfig::signing_input` (crate-private: it is
    /// the step [`JwtConfig::sign_access_token`] runs before it hands anything to a signer).
    pub fn names_a_resource_server(&self) -> bool {
        match self {
            Audience::One(one) => !one.is_empty(),
            Audience::Many(many) => !many.is_empty() && many.iter().all(|a| !a.is_empty()),
        }
    }
}

/// The RFC 9068 section 2.2 claim set. Every field here except `scope` is REQUIRED by the RFC, so
/// they are not `Option`: a missing required claim should be impossible to express, not merely
/// discouraged.
///
/// TYPES CANNOT CARRY THAT ALONE, and `aud` is where it showed. Dropping the `Option` stops a claim
/// being ABSENT; it does not stop it being EMPTY, and `Audience::Many(vec![])` serialized untagged
/// as the literal `"aud": []`, which a resource server that checks `aud` only when it is non-empty
/// reads as no restriction at all. So the promise above is kept by a check as well as by a shape:
/// `JwtConfig::signing_input`, the crate-private step behind
/// [`JwtConfig::sign_access_token`], refuses to sign a claim set whose audience names nobody. See
/// [`Audience::names_a_resource_server`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// `#[non_exhaustive]`: `rar` adds `authorization_details`, either sender-constraining feature
/// adds `cnf`, `token-exchange` adds `act` and `consent` adds `auth_time` and `acr`, and the `cnf`
/// doc below records what it cost to get that gate wrong once already.
/// A host DOES construct this, because [`JwtConfig::sign_access_token`] takes one, so
/// [`AccessTokenClaims::new`] takes the claims RFC 9068 section 2.2 makes REQUIRED and leaves the
/// conditional ones as public fields, which is the same split the paragraph above describes.
#[non_exhaustive]
pub struct AccessTokenClaims {
    /// The authorization server's issuer identifier.
    pub iss: String,
    /// Expiry, seconds since the Unix epoch.
    pub exp: u64,
    /// The resource server(s) this token is for.
    pub aud: Audience,
    /// The subject. For a token with no resource owner, RFC 9068 section 2.2 directs the AS to use
    /// the `client_id` here.
    pub sub: String,
    /// The client the token was issued to (RFC 8693 section 4.3 claim, required by RFC 9068).
    pub client_id: String,
    /// Issuance instant, seconds since the Unix epoch.
    pub iat: u64,
    /// A unique identifier for this token; also the AS-side record key.
    pub jti: String,
    /// Space-delimited granted scope, omitted when empty (RFC 9068 section 2.2.3 makes it
    /// conditional, not required).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// RFC 9396 section 9.1: the authorization details this token carries, as a top-level
    /// claim, so a resource server holding the JWT can read what the token authorizes
    /// without calling introspection for it.
    ///
    /// Omitted rather than sent empty when the grant carried none, exactly as `scope` is: a
    /// claim present and empty is a statement about the token, and the truth here is that
    /// there is nothing to state.
    #[cfg(feature = "rar")]
    #[serde(
        default,
        skip_serializing_if = "crate::rar::AuthorizationDetails::is_empty"
    )]
    pub authorization_details: crate::rar::AuthorizationDetails,
    /// RFC 9470 section 6.1 with RFC 9068 section 2.2.1: when the resource owner behind this token
    /// authenticated, as seconds since the Unix epoch (OpenID Connect Core section 2 `auth_time`).
    ///
    /// This is the claim an offline resource server measures a `max_age` against. Section 6 of RFC
    /// 9470 has exactly two subsections because a token reaches a resource server in exactly two
    /// ways: 6.2 is RFC 7662 introspection, which is all an OPAQUE token has, and 6.1 is this,
    /// which is all a resource server verifying signatures locally ever sees. Reporting the
    /// authentication only through introspection left the deployment step-up is aimed at — the
    /// resource server that sent the section 3 challenge and validates the answer offline — with
    /// nothing to check but the client's word.
    ///
    /// Present exactly when the host REPORTED an authentication for the grant (see
    /// [`crate::consent::Authentication`]), and omitted rather than sent as `null` when it did
    /// not, for the reason `cnf` below is: a member present and null reads to a careless resource
    /// server as a freshness it has already checked.
    ///
    /// Answered from the SAME stored report, through the same conversion, that RFC 7662
    /// introspection answers from, so the two channels cannot state different things about one
    /// token.
    #[cfg(feature = "consent")]
    #[cfg_attr(docsrs, doc(cfg(feature = "consent")))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<u64>,
    /// RFC 9470 section 6.1 with RFC 9068 section 2.2.1: the authentication context class the host
    /// reported for the grant (OpenID Connect Core section 2 `acr`). Opaque to this crate; see
    /// [`crate::consent::Authentication::acr`].
    ///
    /// Absent when the host reported an authentication but no class, which is a different
    /// statement from reporting a class of `""`: the first is "we did not say", and only the
    /// second would claim a class was satisfied.
    #[cfg(feature = "consent")]
    #[cfg_attr(docsrs, doc(cfg(feature = "consent")))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// RFC 7800 `cnf`, which RFC 9068 section 2.2.1 lists as the claim carrying how a token is
    /// sender constrained. RFC 9449 section 6.1 puts the DPoP key thumbprint here as `jkt` and
    /// RFC 8705 section 3.1 puts the certificate thumbprint here as `x5t#S256`.
    ///
    /// Gated on EITHER mechanism, and this is load bearing rather than tidiness. RFC 9449
    /// section 6 requires that a resource server be able to "reliably identify whether an access
    /// token is DPoP-bound"; for a signed token verified locally, this claim is the only thing
    /// that says so. Gated on `mtls` alone, a `jwt` + `dpop` build (which is the deployment DPoP
    /// exists for: resource servers verifying signatures rather than calling introspection) issued
    /// tokens whose binding was invisible, so a leaked token was accepted as a plain bearer token
    /// by the servers least able to notice.
    ///
    /// Absent for an ordinary bearer token, and absent from the claim set entirely in a build with
    /// neither mechanism.
    #[cfg(any(feature = "dpop", feature = "mtls"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<crate::token::Confirmation>,
    /// RFC 8693 section 4.1 `act`: who authority was delegated TO, present exactly when this token
    /// came out of a DELEGATION token exchange.
    ///
    /// RFC 9068 section 2.2.3 allows claims beyond the required set, and section 4.1 of RFC 8693
    /// defines this one as a claim IN the issued token, which is what makes it belong here rather
    /// than only on the stored record.
    ///
    /// Both routes are needed and the reason is the two token formats, not belt and braces. A JWT
    /// is typically validated OFFLINE by a resource server that never calls introspection, so a
    /// delegation recorded only on this server's record is invisible to it; an OPAQUE token is the
    /// mirror image, carrying nothing itself and reachable only through RFC 7662. Persisting the
    /// claim without also putting it here would have moved the deficiency from one deployment
    /// shape to the other. See [`crate::token_exchange`]'s module docs.
    ///
    /// Omitted rather than sent as `null`, like `cnf` above: a member that is present and null
    /// invites a careless reader to treat it as answered.
    #[cfg(feature = "token-exchange")]
    #[cfg_attr(docsrs, doc(cfg(feature = "token-exchange")))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<crate::token_exchange::ActClaim>,
}

impl AccessTokenClaims {
    /// The seven claims RFC 9068 section 2.2 makes REQUIRED, in the order the section lists them,
    /// and nothing else.
    ///
    /// `scope` is section 2.2.3 CONDITIONAL and the other two are feature-gated extensions, so all
    /// three are public fields set on the returned value. That is the same distinction the struct
    /// doc draws between a claim that cannot be missing and one that can: a required claim is an
    /// argument the caller cannot forget, and a conditional one is a decision the caller makes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        iss: impl Into<String>,
        exp: u64,
        aud: Audience,
        sub: impl Into<String>,
        client_id: impl Into<String>,
        iat: u64,
        jti: impl Into<String>,
    ) -> Self {
        AccessTokenClaims {
            iss: iss.into(),
            exp,
            aud,
            sub: sub.into(),
            client_id: client_id.into(),
            iat,
            jti: jti.into(),
            scope: None,
            #[cfg(feature = "rar")]
            authorization_details: crate::rar::AuthorizationDetails::none(),
            // The required-set constructor: what the host reported about the login is not one of
            // the seven, and RFC 9470 s6.1 has this server state it only when it has one.
            #[cfg(feature = "consent")]
            auth_time: None,
            #[cfg(feature = "consent")]
            acr: None,
            #[cfg(any(feature = "dpop", feature = "mtls"))]
            cnf: None,
            // The required-set constructor: a delegation is not one of the seven.
            #[cfg(feature = "token-exchange")]
            act: None,
        }
    }
}

/// Everything needed to issue RFC 9068 access tokens: the ACTIVE signing key, any RETIRED keys
/// still being published so tokens already signed under them keep verifying, the audience, and the
/// URL the host serves the key set from.
///
/// # Rotation
///
/// Signing always uses the active key, and its `kid` goes on every token (RFC 7515 section 4.1.4).
/// [`JwtConfig::rotate_to`] promotes a new key and RETIRES the previous one: the retired key's
/// PUBLIC half stays in [`JwtConfig::jwks`], so a resource server that fetches the key set can
/// still select and verify a token minted a minute before the swap. Without that, rotation would
/// invalidate every live access token at the instant of the swap, which is why an AS that can hold
/// only one key has no rotation story at all, scheduled or on compromise.
///
/// Retired keys are dropped by the host, explicitly, with
/// [`JwtConfig::forget_retired_key_breaking_its_live_tokens`]. There is deliberately NO timer here:
/// this crate has no background tasks by design (see the crate doc's "Zero cost until enabled"),
/// and the host is the only party that knows its own [`crate::ServerConfig::access_token_ttl`],
/// which is the number that decides when dropping is safe.
///
/// # Rotating a key that lives in a KMS
///
/// [`JwtConfig::rotate_to`] is the ONLY thing that rotates. Rotating in the KMS alone leaves this
/// process advertising a cached public half that no longer signs, and every token the deployment
/// issues then fails verification against its own published JWKS, silently. See
/// [`Es256Signer::public_jwk`].
///
/// `Clone` shares the signer rather than duplicating it (`Arc`), and `PartialEq` compares the
/// PUBLISHED IDENTITY: the active and retired JWKs, the audience and the `jwks_uri`. There is no
/// private scalar left to compare once the key may be outside this process, and comparing handles
/// would make two configurations over one KMS key unequal for no reason a host could act on.
#[derive(Clone)]
pub struct JwtConfig {
    /// The host's ES256 backend, which may be a key in this process or a handle to one in a KMS.
    ///
    /// `Arc<dyn _>` and not a generic parameter. Making [`JwtConfig`] generic would put a THIRD
    /// monomorphization axis on `AuthorizationServer`, and the second one is MEASURED at 53,548
    /// bytes per additional `(Storage, Clock)` pair, 27% of this crate's whole default binary
    /// surface. One indirect call against a signing operation that may be a network round trip is
    /// not measurable; that is.
    signer: Arc<dyn DynEs256Signer>,
    /// The ACTIVE key's public half, read from the signer ONCE, here.
    ///
    /// Cached rather than re-asked per call, and that is the other half of the contract
    /// [`Es256Signer::public_jwk`] states: the JWKS document is a public, unauthenticated,
    /// cacheable thing any client may poll, and a signer that reaches a KMS to answer would put a
    /// network call behind it. It also keeps [`JwtConfig::kid`] able to return a `&str`.
    active: Jwk,
    /// The PUBLIC halves of previously active keys, most recently retired first.
    ///
    /// Public halves, not signers, and that is the point: a retired key must never sign again, and
    /// dropping the SIGNER at retirement makes that structural rather than a promise the code
    /// merely keeps today. With the private half possibly in a KMS this matters more, not less:
    /// the handle is what could still be called, and there is no handle left. It is also the
    /// cheaper representation, which matters because [`JwtConfig`] sits behind the box in
    /// [`AccessTokenFormat::Jwt`] precisely to keep key material out of every
    /// [`crate::ServerConfig`].
    retired: Vec<Jwk>,
    audience: Audience,
    jwks_uri: Option<String>,
    /// The base64url form of the JOSE protected header, PRECOMPUTED.
    ///
    /// It is a function of the active key's `kid` and two constants, so it is fixed for the life of
    /// a `JwtConfig` and changes only at [`JwtConfig::rotate_to`]. Building it per token cost a
    /// `serde_json::to_vec` and a base64 `String` on every access token this server signs, to
    /// produce the same bytes every time. MEASURED on one `client_credentials` issuance under
    /// `--features jwt`: 28 allocations / 4767 bytes before, 25 / 4560 after.
    encoded_header: Box<str>,
}

/// The base64url form of the RFC 7515 s4.1 protected header for `kid`.
///
/// Built by hand rather than through `serde_json`, and that is not an optimisation: it is what
/// makes precomputing this INFALLIBLE. `serde_json::to_vec` returns a `Result`, which would make
/// [`JwtConfig::new`] and [`JwtConfig::rotate_to`] fallible (or force an `expect` into a library
/// that must not panic on a host's input) for an error that cannot occur. The header has exactly
/// three members, two of them constants, and the third is a string; the only work is escaping it.
fn encoded_jose_header(kid: &str) -> Box<str> {
    // RFC 9068 s2.1 fixes `typ`; `alg` is a constant here, so no code path in this crate can emit
    // an unsigned access token. Member order matches what `JoseHeader`'s derive produced, so the
    // bytes on the wire are unchanged by this precomputation.
    let mut json = String::with_capacity(40 + kid.len());
    json.push_str(r#"{"alg":"ES256","typ":"at+jwt","kid":""#);
    // RFC 8259 s7: a JSON string escapes the quote, the backslash, and everything below 0x20.
    // Nothing else needs escaping, and in particular a `kid` is not required to be ASCII.
    for c in kid.chars() {
        match c {
            '"' => json.push_str("\\\""),
            '\\' => json.push_str("\\\\"),
            '\n' => json.push_str("\\n"),
            '\r' => json.push_str("\\r"),
            '\t' => json.push_str("\\t"),
            '\u{8}' => json.push_str("\\b"),
            '\u{c}' => json.push_str("\\f"),
            c if (c as u32) < 0x20 => json.push_str(&format!("\\u{:04x}", c as u32)),
            c => json.push(c),
        }
    }
    json.push_str(r#""}"#);
    URL_SAFE_NO_PAD.encode(json).into_boxed_str()
}

impl JwtConfig {
    /// Configure signing for one audience. The audience is REQUIRED (RFC 9068 section 2.2) and has
    /// no default: only the deployment knows which resource server a token is meant for, and a
    /// guessed `aud` is a token that is valid somewhere nobody intended.
    /// `signer` is anything implementing [`Es256Signer`]: [`EcdsaP256Key`] under `jwt-p256`, an
    /// `Arc` of one shared with another configuration, or the host's own KMS-backed type. Its
    /// public half is read HERE, once, and never again; see [`Es256Signer::public_jwk`] for what
    /// that requires of an implementor and for why rotation must come back through
    /// [`JwtConfig::rotate_to`].
    pub fn new(signer: impl Es256Signer + 'static, audience: impl Into<String>) -> Self {
        let active = signer.public_jwk();
        JwtConfig {
            encoded_header: encoded_jose_header(&active.kid),
            active,
            signer: Arc::new(signer),
            // A brand new configuration has retired nothing. The single-key deployment, which is
            // most of them, never touches anything below and keeps exactly the API it had.
            retired: Vec::new(),
            audience: Audience::One(audience.into()),
            jwks_uri: None,
        }
    }

    /// Promote `new_active` to the signing key and RETIRE the current one.
    ///
    /// After this call: new tokens are signed under `new_active`'s `kid`, and the previous key's
    /// public half is still published by [`JwtConfig::jwks`], so tokens signed under it keep
    /// verifying until the host drops it. That is the whole mechanism RFC 7517 section 4.5 and RFC
    /// 7515 section 4.1.4 exist to enable: the token names its key, so a verifier selects rather
    /// than trials, and two generations of key can be live at once.
    ///
    /// Rotating to a `kid` that is already published REPLACES that entry rather than publishing
    /// the name twice, because two JWKs sharing a `kid` make selection ambiguous, which is the one
    /// thing `kid` exists to prevent. A host that reuses a `kid` for a genuinely different key is
    /// making a mistake this crate cannot detect, and the RFC's advice is simply to not do that.
    ///
    /// THE SIGNER IS DROPPED, not stored: what is retained of the outgoing key is its public half
    /// and nothing else, so a retired key cannot sign again by construction. For a KMS-backed
    /// signer this is also the ONLY correct way to rotate; rotating in the KMS while this process
    /// holds the old cached public half is silent breakage (see [`Es256Signer::public_jwk`]).
    pub fn rotate_to(mut self, new_active: impl Es256Signer + 'static) -> Self {
        let retiring = std::mem::replace(&mut self.active, new_active.public_jwk());
        // The previous signer is dropped by this assignment. There is deliberately nowhere else it
        // is written down.
        self.signer = Arc::new(new_active);
        // The header names the ACTIVE key, so it is rebuilt exactly here and nowhere else.
        self.encoded_header = encoded_jose_header(&self.active.kid);
        let active_kid = self.active.kid.as_str();
        // A kid appears at most once in the published set: any older entry sharing a name with the
        // key just retired, or with the new active key, goes.
        self.retired
            .retain(|jwk| jwk.kid != retiring.kid && jwk.kid != active_kid);
        if retiring.kid != active_kid {
            // Most recently retired FIRST: it is the one with the most tokens still alive, so it
            // is the one a verifier is most likely to need after the active key itself.
            self.retired.insert(0, retiring);
        }
        self
    }

    /// The `kid`s of the retired keys still being published, most recently retired first.
    ///
    /// This is what a host consults to decide what it may drop: a key retired longer ago than
    /// [`crate::ServerConfig::access_token_ttl`] has no live tokens left.
    pub fn retired_kids(&self) -> impl Iterator<Item = &str> {
        self.retired.iter().map(|jwk| jwk.kid.as_str())
    }

    /// Stop publishing the retired key named `kid`. THIS BREAKS EVERY UNEXPIRED TOKEN SIGNED UNDER
    /// IT: once the key leaves the JWKS, a resource server has nothing to verify those tokens
    /// with, and the client sees them fail mid-session rather than at a renewal boundary.
    ///
    /// The rule: keep a key retired for AT LEAST [`crate::ServerConfig::access_token_ttl`] after
    /// the [`JwtConfig::rotate_to`] that retired it, plus whatever the deployment's resource
    /// servers cache the JWKS for, since a cached copy is not refetched the moment this changes.
    /// Only after that is every token signed under it certain to have expired on its own.
    ///
    /// The one time to call this SOONER is a key compromise, where the point is exactly to
    /// invalidate those tokens, and the breakage is the goal rather than the cost.
    ///
    /// Naming a `kid` that is not retired (including the ACTIVE `kid`) does nothing. Letting a host
    /// drop its own signing key by naming it would leave an AS signing with a key it does not
    /// publish: no token it issues would verify anywhere, which is strictly worse than the state
    /// the host was trying to leave.
    // NO `#[must_use]`, and that is a decision about the whole crate rather than about this one
    // method: see `tests/host_api_shape.rs`. Every builder here CONSUMES its receiver, so dropping
    // the result moves the configuration away and the borrow checker refuses the next use of it.
    // The attribute would add only the case where the entire expression is discarded, which is
    // dead code rather than a misconfiguration. It sat here alone, on one of twenty-nine such
    // builders, which taught a reader a rule the other twenty-eight did not follow.
    pub fn forget_retired_key_breaking_its_live_tokens(mut self, kid: &str) -> Self {
        self.retired.retain(|jwk| jwk.kid != kid);
        self
    }

    /// Configure signing for several audiences (RFC 7519 section 4.1.3 array form).
    ///
    /// FALLIBLE, unlike every other builder here, and the one thing it refuses is an audience that
    /// names nobody: an empty list, or a list with an empty member. It used to accept both and mint
    /// `"aud": []` on every token the configuration signed, which
    /// [`Audience::names_a_resource_server`] explains is the FAIL-OPEN reading of the claim to a
    /// resource server that checks `aud` only when it is non-empty. A `Result` costs a deployment
    /// nothing because this is called once, at construction, on a value the operator wrote down.
    ///
    /// [`JwtConfig::new`] stays infallible and takes one audience, so the same mistake in its
    /// degenerate form (an empty string) is caught at signing time instead; see
    /// [`Audience::names_a_resource_server`] for why both doors need closing.
    pub fn with_audiences(mut self, audiences: Vec<String>) -> Result<Self, JwtError> {
        let audience = Audience::Many(audiences);
        if !audience.names_a_resource_server() {
            return Err(JwtError(
                "aud must name at least one resource server, and no member may be empty".into(),
            ));
        }
        self.audience = audience;
        Ok(self)
    }

    /// The URL at which the host serves [`JwtConfig::jwks`]. This crate does not fetch or serve
    /// it; it exists so the RFC 8414 metadata document can advertise `jwks_uri` exactly when
    /// tokens are actually signed, and never when they are opaque.
    pub fn with_jwks_uri(mut self, uri: impl Into<String>) -> Self {
        self.jwks_uri = Some(uri.into());
        self
    }

    /// The configured `jwks_uri`, if the host set one.
    pub fn jwks_uri(&self) -> Option<&str> {
        self.jwks_uri.as_deref()
    }

    /// The signing key's identifier.
    pub fn kid(&self) -> &str {
        &self.active.kid
    }

    /// The RFC 7517 key set to serve: public parameters only, ACTIVE key first, then every retired
    /// key most recently retired first.
    ///
    /// Publishing the retired keys is what makes rotation non-destructive: a resource server that
    /// fetched this document after the swap can still select, by `kid`, the key a token minted
    /// before the swap was signed under (RFC 7515 section 4.1.4).
    ///
    /// RFC 7517 section 5 places no ordering requirement on `keys`, so the order here is chosen
    /// rather than mandated: active first means a verifier that ignores `kid` and takes the first
    /// `alg`-compatible key is right for the tokens it will mostly be handed. Such a verifier is
    /// wrong in general, which is why `kid` exists, but the ordering costs nothing and the failure
    /// mode it avoids is real.
    pub fn jwks(&self) -> Jwks {
        let mut keys = Vec::with_capacity(1 + self.retired.len());
        keys.push(self.active.clone());
        keys.extend(self.retired.iter().cloned());
        Jwks { keys }
    }

    /// The `aud` value tokens from this config carry.
    pub fn audience(&self) -> &Audience {
        &self.audience
    }

    /// Serialize and sign one access token into RFC 7515 section 3.1 compact form.
    ///
    /// ASYNC because [`Es256Signer::sign`] is, which is because the key may not be in this
    /// process. With the in-process [`EcdsaP256Key`] backend the future is ready on its first poll
    /// and there is no suspension point.
    pub async fn sign_access_token(&self, claims: &AccessTokenClaims) -> Result<String, JwtError> {
        self.finish_signing(self.signing_input(claims)?).await
    }

    /// The SYNC half: everything up to and including `BASE64URL(header) "." BASE64URL(payload)`.
    ///
    /// Split from the await deliberately, and the split is what keeps the token endpoint's future
    /// small. [`AccessTokenClaims`] is eight owned fields; if it were still live across the
    /// signature's suspension point it would join the coroutine frame, and that frame is held
    /// under tokio's 2048-byte debug boxing threshold by `tests/allocation.rs`. Built this way, all
    /// that crosses the await is this `String` and a borrow of `self`.
    pub(crate) fn signing_input(&self, claims: &AccessTokenClaims) -> Result<String, JwtError> {
        // The header is PRECOMPUTED (see `JwtConfig::encoded_header`): it is fixed for the life of
        // this configuration, so serializing and encoding it per token produced identical bytes at
        // a cost paid on every token issued.
        let header = &self.encoded_header;

        // THE LAST DOOR ON AN `aud` THAT NAMES NOBODY, and the only one that closes all of them.
        // `AccessTokenClaims`'s doc says a missing required claim "should be impossible to express",
        // and RFC 9068 section 2.2 makes `aud` required, but `Audience` is a public enum with public
        // variants and the claim set is built by the caller, so the type has never actually made it
        // impossible: `Audience::Many(vec![])` serializes untagged as the literal `"aud": []`, and
        // `JwtConfig::new(signer, "")` yields `"aud": ""`. `with_audiences` refuses its half, but it
        // is a builder and not a chokepoint. This is the chokepoint. See
        // `Audience::names_a_resource_server` for why an empty array is the FAIL-OPEN one of the
        // two and therefore the one worth a refusal rather than a warning.
        //
        // Refusing HERE rather than panicking or minting anyway is what `JwtError`'s doc already
        // prescribes for every other way signing can fail: mint no token, answer RFC 6749 section
        // 5.2 `server_error`. A misconfiguration is a server error; a token valid at a resource
        // server nobody intended is not recoverable at all.
        if !claims.aud.names_a_resource_server() {
            return Err(JwtError(
                "aud must name at least one resource server, and no member may be empty".into(),
            ));
        }

        let claims_json = serde_json::to_vec(claims)
            .map_err(|e| JwtError(format!("claims serialization: {e}")))?;

        // ONE buffer for the whole token, and the JWS Signing Input is a PREFIX of it rather than
        // a string of its own (RFC 7515 section 5.1 steps 5 and 7: the signing input is the ASCII
        // of "header.payload", and the compact serialization is that followed by ".signature").
        // Built with `format!` this was three intermediate `String`s and two full copies of a
        // token that is close to a kilobyte: one to build the signing input, one to build the
        // result from it. Appending instead means the bytes are written once.
        //
        // The capacity is EXACT, not an estimate, so the buffer is allocated once and never grown:
        // base64url without padding is ceil(n * 4 / 3) characters, and an ES256 signature is a
        // fixed 64 bytes, which is 86.
        let mut compact =
            String::with_capacity(header.len() + 1 + base64_len(claims_json.len()) + 1 + 86);
        compact.push_str(header);
        compact.push('.');
        URL_SAFE_NO_PAD.encode_string(&claims_json, &mut compact);
        Ok(compact)
    }

    /// The ASYNC half: the signature over what [`JwtConfig::signing_input`] built, appended in
    /// place so the token's bytes are still written exactly once.
    pub(crate) async fn finish_signing(&self, mut compact: String) -> Result<String, JwtError> {
        let signature = self
            .signer
            .dyn_sign(compact.as_bytes())
            .await
            // The host's own detail is DISCARDED here rather than wrapped: the host wrote the
            // signer, so it already has the real error on its own channel, and `server.rs` maps
            // this onto RFC 6749 s5.2 `server_error` without echoing anything about the key.
            .map_err(|_| JwtError("the ES256 signer could not sign".into()))?;
        compact.push('.');
        URL_SAFE_NO_PAD.encode_string(signature, &mut compact);
        Ok(compact)
    }
}

impl fmt::Debug for JwtConfig {
    /// [`crate::ServerConfig`] derives `Debug`, so a host that logs its configuration logs this. It
    /// prints the PUBLISHED identity, which is public by definition, and says only that a signer is
    /// present: what the signer is, and what it holds, is the host's and may be a live KMS
    /// credential.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtConfig")
            .field("signer", &"<redacted>")
            .field("active", &self.active)
            .field("retired", &self.retired)
            .field("audience", &self.audience)
            .field("jwks_uri", &self.jwks_uri)
            .finish()
    }
}

impl PartialEq for JwtConfig {
    /// Over the PUBLISHED IDENTITY only. There is no private scalar to compare once the key may be
    /// a handle to something in another process, and comparing handles would make two
    /// configurations over one KMS key unequal for no reason a host could act on. The encoded
    /// header is a pure function of `active.kid`, so it is not compared separately.
    fn eq(&self, other: &Self) -> bool {
        self.active == other.active
            && self.retired == other.retired
            && self.audience == other.audience
            && self.jwks_uri == other.jwks_uri
    }
}

impl Eq for JwtConfig {}

/// What the client receives as its `access_token`.
///
/// [`AccessTokenFormat::Opaque`] is the DEFAULT and is what this crate did before the `jwt`
/// feature existed: a 256-bit random string that means nothing without asking the AS. It is the
/// right default because it leaks nothing, is revocable in the only sense that matters (the AS
/// stops honouring it immediately), and costs one introspection call per protected request.
/// Since 0.9.2 a registered resource server can make that call itself
/// ([`crate::ServerConfig::resource_servers`]), so opaque is a real choice for a deployment with
/// resource servers rather than a client-only one. A deployment whose resource servers must
/// validate WITHOUT talking to the AS at all still wants [`AccessTokenFormat::Jwt`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AccessTokenFormat {
    /// Opaque random access tokens (RFC 7662 introspection reads them, for the token's own client
    /// and for a resource server the token is addressed to).
    #[default]
    Opaque,
    /// RFC 9068 `at+jwt` access tokens, signed with ES256. The record is still persisted, so
    /// introspection and revocation continue to work on the exact string the client presents.
    ///
    /// BOXED deliberately. [`JwtConfig`] carries a signing key, an audience and a `jwks_uri`, and
    /// inlining that here put all of it in every [`crate::server::ServerConfig`], which grew
    /// `AuthorizationServer` from 656 to 856 bytes and tripped the size gate in
    /// `tests/allocation.rs`. The box costs ONE allocation per server at construction, never per
    /// request, and keeps the struct the same size for the opaque-token majority who pay for a
    /// feature they did not enable otherwise. The gate caught this; raising the budget instead
    /// would have made the gate meaningless.
    Jwt(Box<JwtConfig>),
}

/// Seconds since the Unix epoch, the only representation RFC 7519 section 2 `NumericDate` allows
/// for `iat`/`exp`.
pub(crate) fn unix_seconds(t: SystemTime) -> Result<u64, JwtError> {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| JwtError("clock is before the Unix epoch".into()))
}

#[cfg(test)]
#[path = "tests/jwt.rs"]
mod tests;

// =============================================================================================
// VERIFICATION.
//
// Everything above this line SIGNS; everything below it VERIFIES, which is a different and much
// more dangerous job because the input is attacker controlled. The three rules that boundary is
// built on are in this module's `//!` docs, where a reader on docs.rs can see them without
// opening this file; they are not repeated here so that there is only one copy to keep true.
// =============================================================================================

/// A JWS could not be parsed, or did not verify.
///
/// The message is deliberately coarse and never names which check failed in a way a client could
/// use to probe a key: callers map this onto one RFC 6749 section 5.2 error code and the detail
/// stays on the host's own audit channel. It never contains key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError(String);

impl VerifyError {
    pub(crate) fn new(msg: impl Into<String>) -> Self {
        VerifyError(msg.into())
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JWS verification error: {}", self.0)
    }
}

impl std::error::Error for VerifyError {}

/// The JWK members that carry PRIVATE or SYMMETRIC key material, in the RFC 7518 section 6
/// spellings: `d` (the EC/RSA private value, sections 6.2.2.1 and 6.3.2.1), the RSA CRT
/// parameters, and `k` (the octets of a symmetric key, section 6.4.1).
///
/// RFC 9449 section 4.3 makes rejecting a proof whose `jwk` contains any of these a REQUIREMENT,
/// and the reason generalises past DPoP: a JWK carrying a private parameter is either a client
/// that has just leaked its own key to us, or an attacker trying to get a key it controls adopted
/// where only a public half was expected. Neither is a request worth serving.
const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// The PUBLIC parameters of one EC P-256 key, as received from a client.
///
/// This is the VERIFYING counterpart of [`Jwk`], which exists to be SERIALIZED and therefore holds
/// `&'static str` for every member this crate fixes. This one is parsed from attacker-controlled
/// JSON, so it is a separate type rather than a relaxation of that one: making [`Jwk`]'s members
/// owned so it could be deserialized would also make it possible to SERVE a `kty` this crate never
/// signs with.
///
/// Deserialization goes through [`PublicJwk::from_json`], including through `serde`, so there is no
/// route from JSON into this type that skips the private-parameter rejection. The two other
/// constructors take no JSON at all: [`PublicJwk::from_coordinates`] takes the two coordinates and
/// runs the same width check, and [`Jwk::to_public_jwk`] converts a key this crate published, which
/// has no private half to reject (see that method on what it does not revalidate).
///
/// The FIELDS ARE SEALED, which is what makes the sentence above true. They were public through
/// 0.9, and a struct literal was exactly such a route: an `AssertionKeys::PublicKeys` built by hand
/// could carry a `kty` this crate never verifies, or coordinates of any width, and
/// [`PublicJwk::thumbprint`] would then hand back a `cnf.jkt` over it. Verification revalidates and
/// so fails closed, but a thumbprint is a value a host WRITES DOWN, and a token bound to a key
/// nobody can present is a token nobody can use. Read them with the accessors; build them with
/// [`PublicJwk::from_json`] or [`PublicJwk::from_coordinates`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicJwk {
    /// Key type; only `EC` is accepted.
    kty: String,
    /// Curve; only `P-256` is accepted.
    crv: String,
    /// Base64url (unpadded) x coordinate, exactly 32 bytes decoded.
    x: String,
    /// Base64url (unpadded) y coordinate, exactly 32 bytes decoded.
    y: String,
    /// The optional key identifier (RFC 7517 section 4.5).
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

impl<'de> Deserialize<'de> for PublicJwk {
    /// Routed through [`PublicJwk::from_json`] rather than derived, so that a JWK loaded from the
    /// host's own client store is held to exactly the same rules as one arriving in a DPoP proof
    /// header. A derived impl would IGNORE an unknown `d` member rather than reject it, and a
    /// registration silently carrying a client's private key is precisely the state this type
    /// exists to make unrepresentable.
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(d)?;
        PublicJwk::from_json(&value).map_err(serde::de::Error::custom)
    }
}

impl PublicJwk {
    /// Parse and validate one JWK.
    ///
    /// Rejects, in this order: a non-object, any member of `PRIVATE_JWK_MEMBERS`, a `kty` other
    /// than `EC`, a `crv` other than `P-256`, and coordinates that are not exactly 32 bytes of
    /// base64url. The width check is not pedantry: RFC 7518 section 6.2.1.2 fixes the octet length
    /// at the curve's field size and requires leading zeros to be KEPT, so a trimmed coordinate is
    /// a different point, and accepting it is the classic JWK interoperability bug.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, VerifyError> {
        let object = value
            .as_object()
            .ok_or_else(|| VerifyError::new("a JWK must be a JSON object"))?;
        for member in PRIVATE_JWK_MEMBERS {
            if object.contains_key(*member) {
                return Err(VerifyError::new(
                    "the JWK carries a private or symmetric key parameter",
                ));
            }
        }
        let string = |name: &str| -> Result<String, VerifyError> {
            object
                .get(name)
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .ok_or_else(|| VerifyError::new("the JWK is missing a required member"))
        };
        let kty = string("kty")?;
        if kty != "EC" {
            return Err(VerifyError::new("only EC keys are supported"));
        }
        let crv = string("crv")?;
        if crv != "P-256" {
            return Err(VerifyError::new("only the P-256 curve is supported"));
        }
        let x = string("x")?;
        let y = string("y")?;
        let coordinate = |b64: &str| -> Result<(), VerifyError> {
            match URL_SAFE_NO_PAD.decode(b64) {
                Ok(bytes) if bytes.len() == 32 => Ok(()),
                _ => Err(VerifyError::new(
                    "a P-256 coordinate is exactly 32 base64url-encoded bytes",
                )),
            }
        };
        coordinate(&x)?;
        coordinate(&y)?;
        Ok(PublicJwk {
            kty,
            crv,
            x,
            y,
            kid: object
                .get("kid")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        })
    }

    /// One P-256 public key from its two RFC 7518 section 6.2.1.2 coordinates, exactly as they
    /// appear in a JWK: base64url, unpadded, 32 bytes each.
    ///
    /// The constructor for a host that holds the coordinates rather than a JSON document, and the
    /// reason the sealed fields cost nobody anything. `kty` and `crv` are not arguments because
    /// there is exactly one pair this crate verifies with, so admitting others would only admit a
    /// key that cannot be used. The same width check [`PublicJwk::from_json`] performs runs here:
    /// a constructor that skipped it would be the hole the fields were sealed to close.
    pub fn from_coordinates(x: &str, y: &str) -> Result<Self, VerifyError> {
        let coordinate = |b64: &str| -> Result<(), VerifyError> {
            match URL_SAFE_NO_PAD.decode(b64) {
                Ok(bytes) if bytes.len() == 32 => Ok(()),
                _ => Err(VerifyError::new(
                    "a P-256 coordinate is exactly 32 base64url-encoded bytes",
                )),
            }
        };
        coordinate(x)?;
        coordinate(y)?;
        Ok(PublicJwk {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: x.to_string(),
            y: y.to_string(),
            kid: None,
        })
    }

    /// Name this key, with the RFC 7517 section 4.5 `kid` a client publishes it under.
    ///
    /// Deliberately NOT part of the thumbprint: see [`PublicJwk::thumbprint`] on why relabelling a
    /// key must not change what a token is bound to.
    pub fn with_kid(mut self, kid: &str) -> Self {
        self.kid = Some(kid.to_string());
        self
    }

    /// Key type. Always `EC`: nothing else parses.
    pub fn kty(&self) -> &str {
        &self.kty
    }

    /// Curve. Always `P-256`: nothing else parses.
    pub fn crv(&self) -> &str {
        &self.crv
    }

    /// The base64url x coordinate.
    pub fn x(&self) -> &str {
        &self.x
    }

    /// The base64url y coordinate.
    pub fn y(&self) -> &str {
        &self.y
    }

    /// The RFC 7517 section 4.5 `kid`, if the key carries one.
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The RFC 7638 section 3 JWK Thumbprint of this key: SHA-256, base64url without padding.
    ///
    /// This is the value RFC 9449 section 6.1 puts in `cnf.jkt` to bind a token to the key a client
    /// proved possession of. The construction is exact and every part of it is load bearing
    /// (sections 3.1 through 3.3): ONLY the members required to identify the key type, in
    /// LEXICOGRAPHIC order, with no whitespace and no other member. `kid`, `use` and `alg` are
    /// deliberately excluded, which is what makes the thumbprint a property of the KEY rather than
    /// of one description of it; including any of them would let the same key produce two
    /// thumbprints and so two tokens a resource server could not tell were bound to one client.
    pub fn thumbprint(&self) -> String {
        // Built by hand rather than through `serde_json`, because a serializer's member order is a
        // property of a struct declaration and this order is a property of the RFC. For `EC` the
        // required set is `crv`, `kty`, `x`, `y`, which is already lexicographic.
        let mut json = String::with_capacity(40 + self.crv.len() + self.x.len() + self.y.len());
        json.push_str("{\"crv\":\"");
        json.push_str(&self.crv);
        json.push_str("\",\"kty\":\"");
        json.push_str(&self.kty);
        json.push_str("\",\"x\":\"");
        json.push_str(&self.x);
        json.push_str("\",\"y\":\"");
        json.push_str(&self.y);
        json.push_str("\"}");
        URL_SAFE_NO_PAD.encode(Sha256::digest(json.as_bytes()))
    }
}

/// One RFC 7515 section 3.1 compact JWS, split and decoded but NOT yet verified.
///
/// Holding the unverified form as its own value is deliberate: it makes "parsed" and "verified"
/// two different things a caller cannot confuse, and it keeps [`CompactJws::signing_input`]
/// borrowing the received bytes, so that verification happens over what actually arrived.
/// `Debug` is HAND-WRITTEN (below). `signing_input` is `header.payload` verbatim and `signature`
/// is the decoded octets, so a derived one reconstructs the whole token from its parts: printing a
/// parsed RFC 7523 client assertion or RFC 9449 DPoP proof yields everything needed to rebuild a
/// bearer credential that is live until its `exp`. `jti` single-use bounds a proof that was
/// ACCEPTED; one that was refused and then logged is still replayable elsewhere.
///
/// The decoded `header` and `payload` DO print. They are what a host debugging a refused assertion
/// actually needs -- which `alg`, which `iss`, which `aud` -- and neither carries key material;
/// what makes the token spendable is the signature over the exact input bytes, and that is what is
/// withheld.
pub struct CompactJws<'a> {
    /// `BASE64URL(header) "." BASE64URL(payload)`: the JWS Signing Input of RFC 7515 section 5.1
    /// step 5, borrowed from the input.
    pub signing_input: &'a str,
    /// The decoded JOSE protected header.
    pub header: serde_json::Map<String, serde_json::Value>,
    /// The decoded payload (the JWT claims set).
    pub payload: serde_json::Map<String, serde_json::Value>,
    /// The decoded signature octets.
    pub signature: Vec<u8>,
}

impl fmt::Debug for CompactJws<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompactJws")
            .field("signing_input", &"[redacted]")
            .field("header", &self.header)
            .field("payload", &self.payload)
            .field("signature", &"[redacted]")
            .finish()
    }
}

impl<'a> CompactJws<'a> {
    /// Split and decode `token`.
    ///
    /// Rejects anything that is not exactly three base64url segments over two dots. A FIVE segment
    /// token (the RFC 7516 JWE compact serialization) is therefore refused here rather than
    /// silently read as a JWS with odd contents, and a two segment token (the unsecured form of
    /// RFC 7515 appendix A.5, whose signature is the empty string) is refused because it has no
    /// third segment at all.
    pub fn parse(token: &'a str) -> Result<Self, VerifyError> {
        let malformed = || VerifyError::new("not a compact JWS of exactly three segments");
        let mut parts = token.split('.');
        let header_b64 = parts.next().ok_or_else(malformed)?;
        let payload_b64 = parts.next().ok_or_else(malformed)?;
        let signature_b64 = parts.next().ok_or_else(malformed)?;
        if parts.next().is_some() {
            return Err(malformed());
        }
        // Borrowed rather than rebuilt with `format!`: the signature must cover the bytes that
        // arrived, and a re-joined string is a second chance to get that wrong.
        let signing_input = &token[..header_b64.len() + 1 + payload_b64.len()];
        let object =
            |b64: &str| -> Result<serde_json::Map<String, serde_json::Value>, VerifyError> {
                let bytes = URL_SAFE_NO_PAD
                    .decode(b64)
                    .map_err(|_| VerifyError::new("a JWS segment is not unpadded base64url"))?;
                match serde_json::from_slice::<serde_json::Value>(&bytes) {
                    Ok(serde_json::Value::Object(map)) => Ok(map),
                    _ => Err(VerifyError::new("a JWS segment is not a JSON object")),
                }
            };
        Ok(CompactJws {
            header: object(header_b64)?,
            payload: object(payload_b64)?,
            signature: URL_SAFE_NO_PAD
                .decode(signature_b64)
                .map_err(|_| VerifyError::new("the signature is not unpadded base64url"))?,
            signing_input,
        })
    }

    /// A string-valued member of the protected header, or `None` when absent or not a string.
    pub fn header_str(&self, name: &str) -> Option<&str> {
        self.header.get(name).and_then(|v| v.as_str())
    }

    /// RFC 7515 section 4.1.11 `crit`: refuse a JWS whose header names an extension this server
    /// does not implement.
    ///
    /// It is UNCONDITIONAL, and that is the point of the member: the producer is stating that
    /// understanding the named parameters is required to process the JWS correctly, so ignoring
    /// one is not a lenient reading, it is processing a different message from the one that was
    /// signed. RFC 8725 section 3.10 names this as an attack surface. This verifier implements NO
    /// JWS extensions, so any `crit` at all is a refusal, and an EMPTY array is separately
    /// forbidden by 4.1.11 itself.
    ///
    /// ON `CompactJws` RATHER THAN AT ONE CALL SITE, deliberately. Until 0.9.1's audit this rule
    /// was implemented once, in `par.rs`, for request objects — while client assertions and DPoP
    /// proofs, which are also attacker-supplied JWS parsed by this same type, checked `typ` and
    /// `alg` and nothing else. One hardened reader and two unhardened ones is the shape that
    /// produced this crate's earlier `claim_time` defect, where the hand-rolled copy was the one
    /// that failed open. Every verifier now asks the same question of the same parser.
    pub fn reject_unknown_crit(&self) -> Result<(), VerifyError> {
        match self.header.get("crit") {
            None => Ok(()),
            Some(serde_json::Value::Array(names)) if names.is_empty() => Err(VerifyError::new(
                "the header has an empty crit, which RFC 7515 s4.1.11 forbids",
            )),
            Some(serde_json::Value::Array(_)) => Err(VerifyError::new(
                "the header's crit names an extension this server does not implement",
            )),
            Some(_) => Err(VerifyError::new("the header's crit is not an array")),
        }
    }

    /// A string-valued claim, or `None` when absent or not a string.
    pub fn claim_str(&self, name: &str) -> Option<&str> {
        self.payload.get(name).and_then(|v| v.as_str())
    }

    /// A `NumericDate` claim (RFC 7519 section 2), or `None` when absent or not a non-negative
    /// integer.
    ///
    /// A negative or fractional value is read as ABSENT rather than truncated: `exp: -1` truncated
    /// towards zero would read as the epoch, and a claim this crate cannot represent exactly must
    /// not be silently reinterpreted as one it can.
    pub fn claim_time(&self, name: &str) -> Option<u64> {
        self.payload.get(name).and_then(|v| v.as_u64())
    }
}

/// Verify an `ES256` signature (RFC 7518 section 3.4) over `signing_input` with a public JWK.
///
/// `false` for every failure, including a malformed key or a signature of the wrong length: a
/// caller has exactly one safe reaction to any of them, so distinguishing them would only invite
/// somebody to treat one as recoverable.
///
/// THIS IS THE BUILT-IN BACKEND'S BODY, and it is the crate's ONE implementation of ES256
/// verification. Everything inside the crate reaches it through [`P256Verifier`] and the
/// [`Es256Verifier`] seam; it stays public because a host writing the resource-server half of RFC
/// 9449 in the same tree needs it directly, and because it is what every existing consumer calls.
#[cfg(feature = "jwt-p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt-p256")))]
pub fn verify_es256(jwk: &PublicJwk, signing_input: &[u8], signature: &[u8]) -> bool {
    // RFC 7518 section 3.4 fixes the ES256 signature as the fixed-width `r || s` concatenation, 64
    // bytes. The DER form OpenSSL emits by default is NOT this, and accepting both would give one
    // signature two encodings.
    if signature.len() != 64 {
        return false;
    }
    let (Ok(x), Ok(y)) = (
        URL_SAFE_NO_PAD.decode(&jwk.x),
        URL_SAFE_NO_PAD.decode(&jwk.y),
    ) else {
        return false;
    };
    if x.len() != 32 || y.len() != 32 {
        return false;
    }
    // Uncompressed SEC 1 point: 0x04 || X || Y. `from_sec1_bytes` is what rejects a coordinate pair
    // that is not actually on the curve, which is the check an invalid-curve attack needs to find
    // missing.
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&x);
    sec1[33..].copy_from_slice(&y);
    let Ok(key) = VerifyingKey::from_sec1_bytes(&sec1) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify(signing_input, &signature).is_ok()
}

/// HMAC-SHA-256 (RFC 2104), the primitive `HS256` is (RFC 7518 section 3.2).
///
/// Hand written rather than pulled in. `hmac` is already in this crate's dependency GRAPH, through
/// `p256`'s RFC 6979 deterministic nonce, but it is not a direct dependency, and taking one on to
/// express twenty lines of fully specified construction would widen a surface this crate promises
/// to keep tiny. The construction has published test vectors, which `src/tests/client_assertion.rs`
/// checks against, so "we wrote it ourselves" is a checkable claim rather than an assertion.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    // RFC 2104: a key longer than the block size is replaced by its own digest; a shorter one is
    // zero padded to the block size. SHA-256's block size is 64 bytes.
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= block[i];
        opad[i] ^= block[i];
    }
    let inner = Sha256::new()
        .chain_update(ipad)
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(opad)
        .chain_update(inner)
        .finalize()
        .into()
}

/// Verify an `HS256` signature (RFC 7518 section 3.2) over `signing_input` with a shared secret.
///
/// The comparison is CONSTANT TIME with respect to the presented tag. A byte-by-byte compare that
/// exits at the first difference lets a network attacker build a valid tag one byte at a time
/// without ever learning the secret, which is the classic MAC verification timing attack; the
/// length here is fixed at 32 bytes by SHA-256, so unlike `client::constant_time_eq` there is no
/// length channel to close as well.
pub fn verify_hs256(secret: &[u8], signing_input: &[u8], signature: &[u8]) -> bool {
    if signature.len() != 32 {
        return false;
    }
    let expected = hmac_sha256(secret, signing_input);
    let mut acc = 0u8;
    for i in 0..32 {
        acc |= expected[i] ^ signature[i];
    }
    acc == 0
}

/// Assemble one RFC 7515 section 3.1 compact JWS from an already-serialized header and payload.
///
/// This crate builds client assertions and DPoP proofs for nobody, so this exists for the OTHER
/// side of the seam: a host writing the CLIENT half of RFC 7523 or RFC 9449, and this crate's own
/// tests, which have to be able to produce a WRONG token (a foreign key, a bad `alg`, a stale
/// `iat`) to demonstrate that the verifier refuses it. A test suite that can only build correct
/// inputs cannot demonstrate an attack, and this crate's rule is that a security check is not
/// trusted until the attack it stops has been watched succeeding without it.
pub fn compact_jws(header: &[u8], payload: &[u8], sign: impl FnOnce(&str) -> Vec<u8>) -> String {
    // ONE buffer, for the reason `sign_access_token` gives: the JWS Signing Input is a PREFIX of
    // the compact serialization (RFC 7515 section 5.1 steps 5 and 7), so it does not need a string
    // of its own and the result does not need to be copied out of one.
    let mut compact =
        String::with_capacity(base64_len(header.len()) + 1 + base64_len(payload.len()) + 1 + 86);
    URL_SAFE_NO_PAD.encode_string(header, &mut compact);
    compact.push('.');
    URL_SAFE_NO_PAD.encode_string(payload, &mut compact);
    let signature = sign(&compact);
    compact.push('.');
    URL_SAFE_NO_PAD.encode_string(signature, &mut compact);
    compact
}

/// How many characters `n` bytes take in base64url WITHOUT padding: four per three bytes, rounded
/// up. Exact, so a caller sizing a buffer with it allocates once and never grows.
fn base64_len(n: usize) -> usize {
    // `div_ceil` is 1.73, comfortably under this crate's measured 1.75 floor.
    (n * 4).div_ceil(3)
}

#[cfg(feature = "jwt-p256")]
impl EcdsaP256Key {
    /// Sign an arbitrary JWS Signing Input with `ES256`: the counterpart of [`verify_es256`], and
    /// the signing half [`compact_jws`] is usually handed.
    pub fn sign_signing_input(&self, signing_input: &str) -> Result<Vec<u8>, JwtError> {
        self.sign_es256(signing_input.as_bytes())
            .map(|s| s.to_vec())
    }

    /// The public half in the VERIFYING shape, for a host registering this key as a client's
    /// `private_key_jwt` key. Same parameters as [`EcdsaP256Key::public_jwk`], which produces the
    /// SERVING shape; there is still no method anywhere in this crate that emits `d`.
    pub fn to_public_jwk(&self) -> PublicJwk {
        Jwk::to_public_jwk(&self.public_jwk())
    }
}
