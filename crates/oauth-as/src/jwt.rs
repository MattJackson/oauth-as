// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9068 JWT access tokens and the RFC 7517 key set that lets a resource server verify them.
//! Compiled ONLY under the off-by-default `jwt` feature; with the feature off this module does not
//! exist and the crate's dependency set is unchanged.
//!
//! # Why this is hand-rolled
//!
//! This crate ISSUES exactly one token shape and never parses a JWT it did not make. A general
//! JOSE library brings a parser, a validation policy engine and a key-format zoo that an issuer
//! never executes; the compact serialization of RFC 7515 section 3.1 is
//! `BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)` and fits in this file on
//! top of `serde_json` and `base64`, which the crate already depends on. The only thing that
//! genuinely needs a library is the P-256 arithmetic, and that is `p256` (see Cargo.toml for why
//! that crate and why ES256 rather than RS256).
//!
//! # What the host owns
//!
//! The signing key. This module will not invent one at startup and does not persist one: a key
//! that appears from nowhere is a key nobody is managing, and a key regenerated on restart
//! silently invalidates every live token. [`EcdsaP256Key::generate`] exists for tests and for a
//! host's own key-provisioning tool, and the host is expected to store what it generates.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
use p256::SecretKey;
use serde::Serialize;

/// A key could not be loaded or exported. The message never contains key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError(String);

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signing key error: {}", self.0)
    }
}

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

/// A P-256 signing key plus the `kid` that names it.
///
/// The `kid` is what makes rotation possible: an AS publishes the old and new public keys in the
/// same JWKS, signs new tokens under the new `kid`, and retires the old entry once every token
/// signed under it has expired (RFC 7517 section 4.5; RFC 7515 section 4.1.4). Without a `kid` a
/// verifier must trial every advertised key and rotation becomes a guessing game.
#[derive(Clone)]
pub struct EcdsaP256Key {
    kid: String,
    signing: SigningKey,
}

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

impl Eq for EcdsaP256Key {}

/// One RFC 7517 JWK: the PUBLIC parameters of an EC P-256 signing key and nothing else.
///
/// The fields are the complete set this crate ever emits. There is deliberately no `d`
/// (RFC 7517 section 6.2.2.1, the private key parameter) and no way to add one.
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

/// The RFC 9068 section 2.2 claim set. Every field here except `scope` is REQUIRED by the RFC, so
/// they are not `Option`: a missing required claim should be impossible to express, not merely
/// discouraged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
}

/// The JOSE protected header. RFC 9068 section 2.1 fixes `typ` to `at+jwt`, which exists to stop a
/// resource server confusing an access token with an ID token or any other JWT the same issuer
/// signs with the same key.
#[derive(Debug, Serialize)]
struct JoseHeader<'a> {
    alg: &'static str,
    typ: &'static str,
    kid: &'a str,
}

/// Everything needed to issue RFC 9068 access tokens: the key, the audience, and the URL the host
/// serves the key set from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtConfig {
    key: EcdsaP256Key,
    audience: Audience,
    jwks_uri: Option<String>,
}

impl JwtConfig {
    /// Configure signing for one audience. The audience is REQUIRED (RFC 9068 section 2.2) and has
    /// no default: only the deployment knows which resource server a token is meant for, and a
    /// guessed `aud` is a token that is valid somewhere nobody intended.
    pub fn new(key: EcdsaP256Key, audience: impl Into<String>) -> Self {
        JwtConfig {
            key,
            audience: Audience::One(audience.into()),
            jwks_uri: None,
        }
    }

    /// Configure signing for several audiences (RFC 7519 section 4.1.3 array form).
    pub fn with_audiences(mut self, audiences: Vec<String>) -> Self {
        self.audience = Audience::Many(audiences);
        self
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
        self.key.kid()
    }

    /// The RFC 7517 key set to serve: public parameters only.
    pub fn jwks(&self) -> Jwks {
        Jwks {
            keys: vec![self.key.public_jwk()],
        }
    }

    /// The `aud` value tokens from this config carry.
    pub fn audience(&self) -> &Audience {
        &self.audience
    }

    /// Serialize and sign one access token into RFC 7515 section 3.1 compact form.
    pub fn sign_access_token(&self, claims: &AccessTokenClaims) -> Result<String, JwtError> {
        let header = JoseHeader {
            // RFC 9068 section 2.1: the algorithm MUST NOT be `none`. It is a constant here, so
            // there is no code path in this crate that can emit an unsigned access token.
            alg: "ES256",
            typ: "at+jwt",
            kid: self.key.kid(),
        };
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&header)
                .map_err(|e| JwtError(format!("header serialization: {e}")))?,
        );
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(claims)
                .map_err(|e| JwtError(format!("claims serialization: {e}")))?,
        );
        // The JWS Signing Input is the ASCII of "header.payload" (RFC 7515 section 5.1 step 5).
        let signing_input = format!("{header}.{payload}");
        let signature = self.key.sign_es256(signing_input.as_bytes())?;
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }
}

/// What the client receives as its `access_token`.
///
/// [`AccessTokenFormat::Opaque`] is the DEFAULT and is what this crate did before the `jwt`
/// feature existed: a 256-bit random string that means nothing without asking the AS. It is the
/// right default because it leaks nothing, is revocable in the only sense that matters (the AS
/// stops honouring it immediately), and costs a resource server one introspection call.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AccessTokenFormat {
    /// Opaque random access tokens (RFC 7662 introspection is how a resource server reads them).
    #[default]
    Opaque,
    /// RFC 9068 `at+jwt` access tokens, signed with ES256. The record is still persisted, so
    /// introspection and revocation continue to work on the exact string the client presents.
    Jwt(JwtConfig),
}

/// Seconds since the Unix epoch, the only representation RFC 7519 section 2 `NumericDate` allows
/// for `iat`/`exp`.
pub(crate) fn unix_seconds(t: SystemTime) -> Result<u64, JwtError> {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| JwtError("clock is before the Unix epoch".into()))
}
