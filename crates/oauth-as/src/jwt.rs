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
//! make"; the `client_assertion` and `dpop` features ended that. An RFC 7523 client assertion and
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
//!    which is why the `client_assertion` module's `AssertionKeys` holds one algorithm, not a
//!    set.
//! 3. NOTHING IS DECODED TWICE. The signature is verified over the EXACT received bytes of
//!    `header.payload` ([`CompactJws::signing_input`] borrows them), never over a re-serialization
//!    of the parsed claims, so a payload that serializes differently than it arrived cannot verify
//!    under one reading and be interpreted under another.
//!
//! A JWK presented to this module is also refused outright if it carries any PRIVATE or symmetric
//! member (`d`, the RSA CRT parameters, `k`): RFC 9449 section 4.3 makes that a requirement, and
//! [`PublicJwk::from_json`] is the only route into the type, including through `serde`.
//!
//! # Why this is hand-rolled
//!
//! This crate ISSUES exactly one token shape. A general
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
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
use p256::SecretKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtConfig {
    key: EcdsaP256Key,
    /// The PUBLIC halves of previously active keys, most recently retired first.
    ///
    /// Public halves, not [`EcdsaP256Key`]s, and that is the point: a retired key must never sign
    /// again, and dropping the private scalar at retirement makes that structural rather than a
    /// promise the code merely keeps today. It is also the cheaper representation, which matters
    /// because [`JwtConfig`] sits behind the box in [`AccessTokenFormat::Jwt`] precisely to keep
    /// key material out of every [`crate::ServerConfig`].
    retired: Vec<Jwk>,
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
    pub fn rotate_to(mut self, new_active: EcdsaP256Key) -> Self {
        let retiring = self.key.public_jwk();
        self.key = new_active;
        let active_kid = self.key.kid();
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
    #[must_use = "this returns the updated configuration; the receiver is consumed"]
    pub fn forget_retired_key_breaking_its_live_tokens(mut self, kid: &str) -> Self {
        self.retired.retain(|jwk| jwk.kid != kid);
        self
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
        keys.push(self.key.public_jwk());
        keys.extend(self.retired.iter().cloned());
        Jwks { keys }
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
/// route into this type that skips the private-parameter rejection.
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
#[derive(Debug)]
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
    let header = URL_SAFE_NO_PAD.encode(header);
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{header}.{payload}");
    let signature = sign(&signing_input);
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

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
        let jwk = self.public_jwk();
        PublicJwk {
            kty: jwk.kty.to_string(),
            crv: jwk.crv.to_string(),
            x: jwk.x,
            y: jwk.y,
            kid: Some(jwk.kid),
        }
    }
}
