// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RS256 + PS256 backends (Phase B of crypto agility): RSASSA-PKCS1-v1.5 (RFC 8017 §8.2, which RFC
//! 7518 §3.3 names `RS256`) and RSASSA-PSS with MGF1-SHA-256 and salt length 32 (RFC 8017 §8.1, which
//! RFC 7518 §3.5 names `PS256`), both with SHA-256, over the pure-Rust RustCrypto [`rsa`] crate.
//!
//! These are the RSA analogues of the `p256` ES256 backend (`EcdsaP256Key`): a [`RsaSigner`] /
//! [`Ps256Signer`] that implement [`JwsSigner`] and a [`RsaVerifier`] / [`Ps256Verifier`] that
//! implement [`JwsVerifier`]. Both PADDINGS ride the SAME `jwt-rsa` feature and the SAME `rsa` crate
//! (`rsa::pss` is unconditional there — no extra feature, no extra dependency). It is ADDITIVE — a
//! tree that enables both `jwt-p256` and `jwt-rsa` compiles, and a host that installs its own signer
//! still wins, because installation beats a feature flag.
//!
//! RS256 and PS256 are the SAME RSA key with DIFFERENT padding. What keeps the two apart is NOT the
//! key (both are `Jwk::Rsa`, both `KeyKind::Rsa`) but the algorithm's own [`crate::jwt::JwsVerifiers`]
//! slot: `RS256` routes only to [`RsaVerifier`] (PKCS#1 v1.5) and `PS256` only to [`Ps256Verifier`]
//! (PSS), so a signature made under one padding fails verification under the other, structurally.
//!
//! # The RS256 backend module
//! This module is WIRED and LIVE: `lib.rs` pulls it in with `mod backends;` behind the `jwt-rsa`
//! feature, and it builds on the JWS seam in `src/jwt.rs` (`JwsAlg::Rs256`, `JwsSignature::Rs256`,
//! `Jwk::Rsa`, the `JwsSigner`/`JwsVerifier` traits). The feature-independent RFC 7515 A.2 crypto
//! proof (the `rsa` crate driven directly, no seam) lives in `tests/rsa_rfc7515_a2.rs`; the
//! trait-level tests at the bottom of this file drive the same vector THROUGH the seam.
//!
//! # RUSTSEC-2023-0071 — the "Marvin Attack" (in-process RSA signing)
//! The `rsa` crate carries [RUSTSEC-2023-0071], a timing/key-recovery side channel in the RSA
//! private-key operation (decryption/**signing**) with no fix available in the 0.9 line. It matters
//! here for [`RsaSigner`] and ONLY for [`RsaSigner`]:
//!
//! - **Signing is affected.** [`RsaSigner`] and [`Ps256Signer`] perform the private-key operation in
//!   THIS process, so a local attacker able to measure signing time precisely could, in principle,
//!   recover the key. (PSS applies no blinding on the plain `rsa::pss::SigningKey`, same posture.)
//! - **Verification is NOT affected.** [`RsaVerifier`] and [`Ps256Verifier`] are public-key only
//!   (modular exponentiation with the public exponent); the advisory does not apply to them. A
//!   deployment that only needs to VERIFY RS256/PS256 (RFC 9449 DPoP, RFC 9101 request objects, RFC
//!   7523 `private_key_jwt` from clients) can use this backend with no exposure.
//!
//! **Recommendation for production RSA signing:** do the private-key operation OUT OF PROCESS. The
//! whole point of the `JwsSigner` seam being async is that a host can implement it against a cloud
//! KMS, a PKCS#11 token or an HSM, where the key never enters this address space and the timing
//! channel is not this crate's to leak. Reserve [`RsaSigner`] (in-process) for development, tests,
//! and deployments whose threat model excludes a co-located timing attacker; prefer ES256
//! ([`EcdsaP256Key`]) or an out-of-process RSA signer otherwise.
//!
//! [RUSTSEC-2023-0071]: https://rustsec.org/advisories/RUSTSEC-2023-0071
//! [`EcdsaP256Key`]: crate::jwt::EcdsaP256Key

use std::fmt;
use std::future::Future;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::DecodePrivateKey as _;
use rsa::pss::{
    Signature as PssSignature, SigningKey as PssSigningKey, VerifyingKey as PssVerifyingKey,
};
use rsa::signature::{RandomizedSigner as _, SignatureEncoding as _, Signer as _, Verifier as _};
use rsa::traits::PublicKeyParts as _;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

// The JWS seam types this backend implements against, all in `crate::jwt`: `JwsAlg`,
// `JwsSignature`, `Jwk`, the `JwsSigner`/`JwsVerifier` traits, and the `KeyError`/`SignerError`
// error types (gated on `jwt`, so an RSA-only build has them too).
use crate::jwt::{Jwk, JwsAlg, JwsSignature, JwsSigner, JwsVerifier, KeyError, SignerError};

/// The RS256 policy floor: a modulus below 2048 bits is rejected at construction. Matches RFC 7518
/// §3.3's "a key size of 2048 bits or larger" and NIST SP 800-57's current RSA floor. The `rsa`
/// crate does not enforce any minimum for us (confirmed unenforced — see `tests/CRYPTO_VECTORS.md`
/// §4), so this is the backend's own responsibility, exactly as `EcdsaP256Key::from_scalar_bytes`
/// rejects a wrong-length scalar rather than silently accepting it.
pub const MIN_RSA_MODULUS_BITS: usize = 2048;

/// An in-process RS256 signing key: RSASSA-PKCS1-v1.5 + SHA-256 over a `rsa::RsaPrivateKey`.
///
/// SECURITY: read the module-level RUSTSEC-2023-0071 note before using this to sign in production.
/// The private-key operation runs in this process; a KMS/HSM async `JwsSigner` is the production
/// posture for RSA. Verification has no such caveat — see [`RsaVerifier`].
pub struct RsaSigner {
    kid: String,
    signing: SigningKey<Sha256>,
    public: RsaPublicKey,
}

impl RsaSigner {
    /// Load from a `rsa::RsaPrivateKey`, rejecting a modulus below [`MIN_RSA_MODULUS_BITS`].
    ///
    /// This is the primitive every other constructor funnels through, so the 2048-bit floor is
    /// enforced in exactly one place and cannot be bypassed by picking a different loader.
    pub fn from_private_key(
        kid: impl Into<String>,
        private_key: RsaPrivateKey,
    ) -> Result<Self, KeyError> {
        let bits = private_key.n().bits();
        if bits < MIN_RSA_MODULUS_BITS {
            return Err(KeyError::new(format!(
                "RSA modulus is {bits} bits; RS256 requires at least {MIN_RSA_MODULUS_BITS}"
            )));
        }
        let public = private_key.to_public_key();
        Ok(RsaSigner {
            kid: kid.into(),
            signing: SigningKey::<Sha256>::new(private_key),
            public,
        })
    }

    /// Load from a PKCS#8 (RFC 5208) `PrivateKeyInfo` DER document, the format most KMS exports and
    /// `openssl pkcs8` emit. DER, not PEM: the `pem` feature is off (see `Cargo.toml`), and JWK/DER
    /// bytes are what a host hands in.
    ///
    /// Funnels through [`RsaSigner::from_private_key`], so the [`MIN_RSA_MODULUS_BITS`] floor is
    /// enforced on this path too: a sub-2048-bit PKCS#8 key is REJECTED here exactly as a raw one
    /// is, and the guard cannot be bypassed by choosing the DER loader.
    ///
    /// SHIPS WITH `jwt-rsa`, not a separate `jwt-rsa-pkcs8`, because `rsa` 0.9 has no `pkcs8` cargo
    /// feature — it depends on the `pkcs8` crate unconditionally — so there is no dependency for a
    /// split feature to gate off (contrast `EcdsaP256Key::from_pkcs8_der` under `jwt-pkcs8` and
    /// `Ed25519Signer::from_pkcs8_der` under `jwt-ed25519-pkcs8`, whose backends make `pkcs8`
    /// optional).
    pub fn from_pkcs8_der(kid: impl Into<String>, der: &[u8]) -> Result<Self, KeyError> {
        let private_key = RsaPrivateKey::from_pkcs8_der(der)
            .map_err(|_| KeyError::new("not a valid PKCS#8 RSA private key"))?;
        Self::from_private_key(kid, private_key)
    }

    /// A freshly generated key of `bits` bits, for TESTS and a host's own provisioning step. Refuses
    /// anything below the 2048-bit floor before spending time generating it. This crate never calls
    /// it; a key that materialises at startup is a key nobody is managing.
    ///
    /// The RNG is INJECTED rather than reached for, on purpose: it keeps this backend from pulling
    /// `rsa`'s `getrandom` feature (which would drag a second `getrandom`/`rand_core` major into a
    /// tree that already carries `getrandom` 0.3), and it lets a caller pick its own CSPRNG. Pass
    /// `rsa::rand_core::OsRng` if the host has enabled `rsa`'s `getrandom` feature, or any other
    /// `CryptoRngCore`.
    pub fn generate<R: rsa::rand_core::CryptoRngCore>(
        kid: impl Into<String>,
        bits: usize,
        rng: &mut R,
    ) -> Result<Self, KeyError> {
        if bits < MIN_RSA_MODULUS_BITS {
            return Err(KeyError::new(format!(
                "refusing to generate a {bits}-bit RSA key; RS256 requires at least {MIN_RSA_MODULUS_BITS}"
            )));
        }
        let private_key = RsaPrivateKey::new(rng, bits)
            .map_err(|_| KeyError::new("RSA key generation failed"))?;
        Self::from_private_key(kid, private_key)
    }

    /// The key identifier published in the JWKS and in every token header signed with this key.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The PUBLIC half as an RFC 7517 RSA JWK. There is no method that produces a JWK containing the
    /// private members (`d`, `p`, `q`, ...): the private parameters cannot be published by accident.
    pub fn public_jwk(&self) -> Jwk {
        rsa_public_jwk(&self.public, Some(self.kid.clone()))
    }

    /// Sign a JWS Signing Input with RS256. PKCS#1 v1.5 is DETERMINISTIC (no RNG), so this is a pure
    /// function of the key and the input, which is what makes the RFC 7515 A.2 vector reproducible.
    fn sign_rs256(&self, message: &[u8]) -> Result<Box<[u8]>, SignerError> {
        let signature: Signature = self
            .signing
            .try_sign(message)
            .map_err(|_| SignerError::new("RSA signing failed"))?;
        // `to_bytes` yields exactly `k` octets (the modulus size): 256 for RSA-2048, 384 for 3072,
        // 512 for 4096. The `Box<[u8]>` shape of `JwsSignature::Rs256` carries any of them.
        Ok(signature.to_bytes())
    }
}

impl JwsSigner for RsaSigner {
    fn alg(&self) -> JwsAlg {
        JwsAlg::Rs256
    }

    fn sign(&self, input: &[u8]) -> impl Future<Output = Result<JwsSignature, SignerError>> + Send {
        // In-process signing is synchronous; the async signature exists for the KMS/HSM case. The
        // work happens before the future is created so it is ready on first poll, matching how the
        // in-process ES256 backend behaves.
        let result = self.sign_rs256(input).map(JwsSignature::Rs256);
        async move { result }
    }

    fn public_jwk(&self) -> Jwk {
        RsaSigner::public_jwk(self)
    }
}

impl fmt::Debug for RsaSigner {
    /// Redacted on purpose: a host that logs its config must not thereby log its signing key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaSigner")
            .field("kid", &self.kid)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

/// The RS256 verifier. Public-key only, so it is NOT subject to RUSTSEC-2023-0071 (see the module
/// note). Stateless: it verifies against whatever `Jwk` the caller — never the token — chose.
#[derive(Debug, Clone, Copy, Default)]
pub struct RsaVerifier;

impl JwsVerifier for RsaVerifier {
    fn alg(&self) -> JwsAlg {
        JwsAlg::Rs256
    }

    /// Verify an RS256 signature. Returns `false` — NEVER panics — on any failure: a non-RSA `Jwk`,
    /// malformed `n`/`e`, a policy-failing key size, a signature whose length is not the modulus
    /// length, or an arithmetic verification failure.
    ///
    /// The key is the caller's: this function performs no `kid`/`jku`/`x5u` lookup and never routes
    /// on the token's `alg`. That is rule 1 and rule 2 of the verification banner in `crate::jwt`.
    fn verify(&self, key: &Jwk, input: &[u8], sig: &[u8]) -> bool {
        // Rule: reject any key that is not an RSA JWK. An EC (or OKP) key reaching an RS256 verifier
        // is an algorithm-confusion attempt; refuse rather than coerce.
        let Jwk::Rsa { n, e, .. } = key else {
            return false;
        };

        let (Ok(n_bytes), Ok(e_bytes)) = (URL_SAFE_NO_PAD.decode(n), URL_SAFE_NO_PAD.decode(e))
        else {
            return false;
        };
        // RFC 7518 §6.3.1 base64urlUInt: the value is a non-empty big-endian unsigned integer.
        if n_bytes.is_empty() || e_bytes.is_empty() {
            return false;
        }
        let n_int = BigUint::from_bytes_be(&n_bytes);
        let e_int = BigUint::from_bytes_be(&e_bytes);

        let Ok(public) = RsaPublicKey::new(n_int, e_int) else {
            return false;
        };

        // Enforce the same 2048-bit floor at verification time: a signature over a sub-2048 key must
        // not be treated as valid just because the arithmetic checks out.
        if public.n().bits() < MIN_RSA_MODULUS_BITS {
            return false;
        }

        // The design's length contract: an RS256 signature is exactly `k` octets, `k` == modulus
        // size. `rsa`'s `Signature::try_from` is length-lenient (it parses any big-endian integer),
        // so this explicit guard — not `try_from` — is what enforces the contract.
        if sig.len() != public.size() {
            return false;
        }
        let Ok(signature) = Signature::try_from(sig) else {
            return false;
        };

        VerifyingKey::<Sha256>::new(public)
            .verify(input, &signature)
            .is_ok()
    }
}

/// Build an RFC 7517 RSA public JWK (`kty`/`n`/`e`, plus optional `kid`) from a public key. `n` and
/// `e` are RFC 7518 §6.3.1 base64urlUInt: minimal big-endian bytes, no leading zero octet, base64url
/// without padding — which is exactly `BigUint::to_bytes_be`.
pub fn rsa_public_jwk(public: &RsaPublicKey, kid: Option<String>) -> Jwk {
    Jwk::Rsa {
        n: URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
        e: URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
        kid,
    }
}

// ---------------------------------------------------------------------------------------------
// PS256 (RSASSA-PSS) — the SAME RSA key material, DIFFERENT padding.
// ---------------------------------------------------------------------------------------------

/// The OS CSPRNG as a `rand_core` 0.6 RNG, for the one randomized signer in the crate.
///
/// PSS signing draws a fresh 32-byte salt per signature (RFC 8017 §9.1), so unlike deterministic
/// PKCS#1 v1.5 it needs randomness. Zero-state: it holds nothing and reaches the OS synchronously per
/// call through [`getrandom::fill`] — the SAME source [`crate::jwt::EcdsaP256Key::generate`] uses —
/// so there is no hidden global, no background thread, and no new dependency. It exists to feed
/// `RandomizedSigner::try_sign_with_rng`, which lets this backend avoid `rsa`'s `getrandom` feature
/// (whose blanket `Signer::sign` would drag a second `getrandom`/`rand_core` major into the tree).
///
/// `RngCore::fill_bytes` is infallible, so an OS randomness failure PANICS here rather than surfacing
/// as a `SignerError` — the same house style as `EcdsaP256Key::generate`'s `.expect(...)`. An AS that
/// cannot draw randomness cannot safely mint artifacts; failing loudly is correct.
struct OsFillRng;

impl rsa::rand_core::RngCore for OsFillRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("OS CSPRNG must be available to sign OAuth artifacts");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rsa::rand_core::CryptoRng for OsFillRng {}

/// An in-process PS256 signing key: RSASSA-PSS (MGF1-SHA-256, salt length 32) + SHA-256 over a
/// `rsa::RsaPrivateKey`.
///
/// SECURITY: read the module-level RUSTSEC-2023-0071 note before using this to sign in production —
/// the private-key operation (and no PSS blinding on the plain signing key) runs in this process; a
/// KMS/HSM async [`JwsSigner`] is the production posture for RSA. Verification has no such caveat —
/// see [`Ps256Verifier`]. PS256 shares the [`MIN_RSA_MODULUS_BITS`] 2048-bit floor with RS256.
pub struct Ps256Signer {
    kid: String,
    signing: PssSigningKey<Sha256>,
    public: RsaPublicKey,
}

impl Ps256Signer {
    /// Load from a `rsa::RsaPrivateKey`, rejecting a modulus below [`MIN_RSA_MODULUS_BITS`]. The one
    /// primitive every other constructor funnels through, so the 2048-bit floor lives in one place.
    ///
    /// `PssSigningKey::<Sha256>::new` fixes the salt length at the SHA-256 output size, 32 octets
    /// (RFC 7518 §3.5); there is no `new_with_salt_len` on this path, so a non-standard salt length
    /// cannot be configured by accident.
    pub fn from_private_key(
        kid: impl Into<String>,
        private_key: RsaPrivateKey,
    ) -> Result<Self, KeyError> {
        let bits = private_key.n().bits();
        if bits < MIN_RSA_MODULUS_BITS {
            return Err(KeyError::new(format!(
                "RSA modulus is {bits} bits; PS256 requires at least {MIN_RSA_MODULUS_BITS}"
            )));
        }
        let public = private_key.to_public_key();
        Ok(Ps256Signer {
            kid: kid.into(),
            signing: PssSigningKey::<Sha256>::new(private_key),
            public,
        })
    }

    /// Load from a PKCS#8 (RFC 5208) `PrivateKeyInfo` DER document. Funnels through
    /// [`Ps256Signer::from_private_key`], so the [`MIN_RSA_MODULUS_BITS`] floor is enforced here too.
    /// The key material is padding-agnostic: an RSA private key is a PS256 or an RS256 key depending
    /// only on which signer wraps it.
    pub fn from_pkcs8_der(kid: impl Into<String>, der: &[u8]) -> Result<Self, KeyError> {
        let private_key = RsaPrivateKey::from_pkcs8_der(der)
            .map_err(|_| KeyError::new("not a valid PKCS#8 RSA private key"))?;
        Self::from_private_key(kid, private_key)
    }

    /// A freshly generated key of `bits` bits, for TESTS and a host's own provisioning step. Refuses
    /// anything below the 2048-bit floor before spending time generating it. The RNG is INJECTED, for
    /// the same reason [`RsaSigner::generate`] injects one.
    pub fn generate<R: rsa::rand_core::CryptoRngCore>(
        kid: impl Into<String>,
        bits: usize,
        rng: &mut R,
    ) -> Result<Self, KeyError> {
        if bits < MIN_RSA_MODULUS_BITS {
            return Err(KeyError::new(format!(
                "refusing to generate a {bits}-bit RSA key; PS256 requires at least {MIN_RSA_MODULUS_BITS}"
            )));
        }
        let private_key = RsaPrivateKey::new(rng, bits)
            .map_err(|_| KeyError::new("RSA key generation failed"))?;
        Self::from_private_key(kid, private_key)
    }

    /// The key identifier published in the JWKS and in every token header signed with this key.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The PUBLIC half as an RFC 7517 RSA JWK. Never carries the private members.
    pub fn public_jwk(&self) -> Jwk {
        rsa_public_jwk(&self.public, Some(self.kid.clone()))
    }

    /// Sign a JWS Signing Input with PS256. RANDOMIZED (a fresh salt per call), so — unlike RS256 —
    /// the output is not a pure function of key and input; verification stays deterministic.
    fn sign_ps256(&self, message: &[u8]) -> Result<Box<[u8]>, SignerError> {
        let signature: PssSignature = self
            .signing
            .try_sign_with_rng(&mut OsFillRng, message)
            .map_err(|_| SignerError::new("RSA-PSS signing failed"))?;
        // `to_bytes` yields exactly `k` octets (the modulus size), which `JwsSignature::Ps256`'s
        // `Box<[u8]>` carries for any 2048/3072/4096-bit key.
        Ok(signature.to_bytes())
    }
}

impl JwsSigner for Ps256Signer {
    fn alg(&self) -> JwsAlg {
        JwsAlg::Ps256
    }

    fn sign(&self, input: &[u8]) -> impl Future<Output = Result<JwsSignature, SignerError>> + Send {
        // The salt is drawn and the signature computed BEFORE the future is created (synchronous
        // `try_sign_with_rng`), so it is ready on first poll, matching the other in-process backends.
        let result = self.sign_ps256(input).map(JwsSignature::Ps256);
        async move { result }
    }

    fn public_jwk(&self) -> Jwk {
        Ps256Signer::public_jwk(self)
    }
}

impl fmt::Debug for Ps256Signer {
    /// Redacted on purpose: a host that logs its config must not thereby log its signing key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ps256Signer")
            .field("kid", &self.kid)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

/// The PS256 verifier. Public-key only, so it is NOT subject to RUSTSEC-2023-0071 (see the module
/// note). Stateless: it verifies against whatever `Jwk` the caller — never the token — chose.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ps256Verifier;

impl JwsVerifier for Ps256Verifier {
    fn alg(&self) -> JwsAlg {
        JwsAlg::Ps256
    }

    /// Verify a PS256 signature. Returns `false` — NEVER panics — on any failure: a non-RSA `Jwk`, a
    /// PKCS#1 v1.5 (RS256) signature over the same key, a signature made with any salt length other
    /// than 32, malformed `n`/`e`, a sub-2048-bit modulus, a wrong-length signature, or an arithmetic
    /// failure. The key is the caller's; this routes on neither the token's `alg` nor any lookup.
    fn verify(&self, key: &Jwk, input: &[u8], sig: &[u8]) -> bool {
        // Reject any key that is not an RSA JWK — an EC/OKP key reaching a PS256 verifier is an
        // algorithm-confusion attempt. (RS256↔PS256 confusion is handled a layer up, by the slot: an
        // RS256 header never reaches this verifier at all.)
        let Jwk::Rsa { n, e, .. } = key else {
            return false;
        };

        let (Ok(n_bytes), Ok(e_bytes)) = (URL_SAFE_NO_PAD.decode(n), URL_SAFE_NO_PAD.decode(e))
        else {
            return false;
        };
        if n_bytes.is_empty() || e_bytes.is_empty() {
            return false;
        }
        let n_int = BigUint::from_bytes_be(&n_bytes);
        let e_int = BigUint::from_bytes_be(&e_bytes);

        let Ok(public) = RsaPublicKey::new(n_int, e_int) else {
            return false;
        };

        // Same 2048-bit floor as RS256, enforced at verification time.
        if public.n().bits() < MIN_RSA_MODULUS_BITS {
            return false;
        }

        // A PS256 signature is exactly `k` octets (`k` == modulus size). `rsa`'s own PSS verify also
        // rejects a wrong-length signature internally, so this explicit guard is defense-in-depth
        // (matching `RsaVerifier`), not the sole gate.
        if sig.len() != public.size() {
            return false;
        }
        let Ok(signature) = PssSignature::try_from(sig) else {
            return false;
        };

        // `PssVerifyingKey::<Sha256>::new` fixes the expected salt length at 32 (the SHA-256 output
        // size) and MGF1-SHA-256; `verify` enforces that salt length exactly — a signature made with
        // any other salt length is rejected. There is no salt-length-autodetect path.
        PssVerifyingKey::<Sha256>::new(public)
            .verify(input, &signature)
            .is_ok()
    }
}

// NOTE: the RFC 7638 RSA thumbprint is NOT duplicated here. The canonical, production
// implementation is `crate::jwt::Jwk::thumbprint` (the `Jwk::Rsa` arm); the tests below call it
// directly so this backend cannot drift a second, unreviewed copy of it.

// ---------------------------------------------------------------------------------------------
// TRAIT-LEVEL TESTS.
//
// They exercise `RsaSigner`/`RsaVerifier` through the `JwsSigner`/`JwsVerifier`/`Jwk` seam. The
// feature-INDEPENDENT proof of the same crypto (the RFC 7515 A.2 vector, verified with `rsa`
// directly, no seam) is `tests/rsa_rfc7515_a2.rs`.
// ---------------------------------------------------------------------------------------------
#[cfg(test)]
mod seam_tests {
    use super::*;

    // RFC 7515 A.2 public key (n, e) and the vector's signature/input, base64url.
    const N_B64URL: &str = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";
    const E_B64URL: &str = "AQAB";
    const D_B64URL: &str = "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ";
    const P_B64URL: &str = "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc";
    const Q_B64URL: &str = "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc";
    const SIGNING_INPUT: &[u8] =
        b"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    const EXPECTED_SIG_B64URL: &str = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

    fn b64u(s: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(s).unwrap()
    }

    fn rsa_jwk() -> Jwk {
        Jwk::Rsa {
            n: N_B64URL.to_string(),
            e: E_B64URL.to_string(),
            kid: Some("test-rsa".to_string()),
        }
    }

    /// The A.2 private key, rebuilt deterministically from its components (no RNG needed).
    fn a2_signer() -> RsaSigner {
        let private_key = RsaPrivateKey::from_components(
            BigUint::from_bytes_be(&b64u(N_B64URL)),
            BigUint::from_bytes_be(&b64u(E_B64URL)),
            BigUint::from_bytes_be(&b64u(D_B64URL)),
            vec![
                BigUint::from_bytes_be(&b64u(P_B64URL)),
                BigUint::from_bytes_be(&b64u(Q_B64URL)),
            ],
        )
        .unwrap();
        // kid matches `rsa_jwk()` so `public_jwk()` round-trips it.
        RsaSigner::from_private_key("test-rsa", private_key).unwrap()
    }

    /// The verifier ACCEPTS the RFC 7515 A.2 vector through the `Jwk::Rsa` seam.
    #[test]
    fn verifier_accepts_rfc7515_a2_vector() {
        let sig = URL_SAFE_NO_PAD.decode(EXPECTED_SIG_B64URL).unwrap();
        assert!(RsaVerifier.verify(&rsa_jwk(), SIGNING_INPUT, &sig));
    }

    /// The verifier REJECTS an EC key (algorithm-confusion guard), returning false, never panicking.
    #[test]
    fn verifier_rejects_ec_key() {
        let sig = URL_SAFE_NO_PAD.decode(EXPECTED_SIG_B64URL).unwrap();
        let ec_key = Jwk::Ec {
            crv: crate::jwt::EcCurve::P256,
            x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU".to_string(),
            y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0".to_string(),
            kid: Some("an-ec-key".to_string()),
        };
        assert!(!RsaVerifier.verify(&ec_key, SIGNING_INPUT, &sig));
    }

    /// The verifier REJECTS a truncated signature (length != modulus size), returning false.
    #[test]
    fn verifier_rejects_truncated_signature() {
        let mut sig = URL_SAFE_NO_PAD.decode(EXPECTED_SIG_B64URL).unwrap();
        sig.pop();
        assert!(!RsaVerifier.verify(&rsa_jwk(), SIGNING_INPUT, &sig));
    }

    /// A round-trip through the async signer: sign the A.2 input, the verifier accepts it, the
    /// deterministic PKCS#1 v1.5 output equals the RFC's signature, and `public_jwk` round-trips the
    /// same `n`/`e` it verifies against.
    #[tokio::test]
    async fn signer_roundtrips_and_matches_vector() {
        let signer = a2_signer();
        let jwk = JwsSigner::public_jwk(&signer);
        assert_eq!(jwk, rsa_jwk(), "public_jwk must publish the A.2 n/e");
        let JwsSignature::Rs256(sig) = JwsSigner::sign(&signer, SIGNING_INPUT).await.unwrap()
        else {
            panic!("RsaSigner must produce an Rs256 signature");
        };
        assert_eq!(
            sig.as_ref(),
            b64u(EXPECTED_SIG_B64URL).as_slice(),
            "deterministic RS256 signature must equal the RFC 7515 A.2 vector"
        );
        assert!(RsaVerifier.verify(&jwk, SIGNING_INPUT, &sig));
    }

    // A genuine sub-2048-bit (1024-bit) RSA key, generated offline with OpenSSL and pinned by its
    // components so the test needs no RNG and no `getrandom` feature on `rsa`. RS256 requires a
    // modulus of at least 2048 bits, so both the signer constructor AND the verifier's modulus
    // check must REJECT this key.
    const SMALL_N: &str = "0TQGH4DQ5AEY7CyqdeEV2xddIqLFJxJMZSN8b8TybBhOyQfdzQMst7zaJF1N9K2d-9lnSfCUjXW17ekMct2XTM--IEAlrtkEZ0O_xGeOV0rSYTCQ-mEHoVG_8Ru-Whnc5Fku3YceVap3V_kclLdrDP61ceoqpUlFP70ShHNl_r0";
    const SMALL_E: &str = "AQAB";
    const SMALL_D: &str = "BbKuDAOdLOievigFSIql5r6_KadXSVYlQIfz5rNtiuYqly0grGnOuP5qzpy_988Ww3pLZucnlKbFGsLDNQm2CjPuUuFyjudHp4wmZpheB-wwthbvwAzRCZkTadcT3X6vJr6sLhhmN_AMK7g_LlOaYsjHEfuuVpOY6BRh2uTcv50";
    const SMALL_P: &str =
        "7HERNSUGW0OqV1ipwZyirmfbfHaa1PJKVBQ5rza8fCywLaRYzdSHQpfh0fPrQYYpV2dizjZp9q-Ok6cFmBmVww";
    const SMALL_Q: &str =
        "4oImc-vP9EdugI9w4BTx0Yh01K6Gebaf-V3aWOx_2YtItDqGXJh-e--Owsfqml0EeQCBKWOhTTWBXMXPEUZRfw";

    fn small_private_key() -> RsaPrivateKey {
        RsaPrivateKey::from_components(
            BigUint::from_bytes_be(&b64u(SMALL_N)),
            BigUint::from_bytes_be(&b64u(SMALL_E)),
            BigUint::from_bytes_be(&b64u(SMALL_D)),
            vec![
                BigUint::from_bytes_be(&b64u(SMALL_P)),
                BigUint::from_bytes_be(&b64u(SMALL_Q)),
            ],
        )
        .expect("the pinned 1024-bit components form a valid RSA key")
    }

    /// The 2048-bit floor is enforced BOTH at construction and at verification: a genuine
    /// 1024-bit key is refused by `RsaSigner::from_private_key` and a genuine signature made with
    /// it is refused by `RsaVerifier`.
    #[test]
    fn rejects_sub_2048_key() {
        use rsa::signature::{SignatureEncoding as _, Signer as _};

        let small = small_private_key();
        assert_eq!(
            small.n().bits(),
            1024,
            "the pinned test key must be 1024 bits, genuinely below the RS256 floor"
        );

        // 1. The signer constructor refuses it. Deleting the `if bits < MIN_RSA_MODULUS_BITS` guard
        //    in `from_private_key` turns this Err into an Ok, so this assertion goes red.
        assert!(
            RsaSigner::from_private_key("small", small.clone()).is_err(),
            "from_private_key must reject a sub-2048-bit modulus"
        );

        // 2. The verifier's modulus check refuses even a GENUINELY VALID signature made with the
        //    small key. Signed here with `rsa` directly, because `from_private_key` would refuse to
        //    build a signer for it; the signature is exactly the modulus width (128 bytes), so the
        //    verifier's length guard passes and the ONLY thing returning `false` is the 2048-bit
        //    floor. Deleting that floor in `RsaVerifier::verify` turns this into `true`, red.
        let signing = SigningKey::<Sha256>::new(small);
        let signature: Signature = signing.sign(SIGNING_INPUT);
        let sig_bytes = signature.to_bytes();
        assert_eq!(
            sig_bytes.len(),
            128,
            "a 1024-bit RSA signature is 128 bytes"
        );
        let small_pub = Jwk::Rsa {
            n: SMALL_N.to_string(),
            e: SMALL_E.to_string(),
            kid: None,
        };
        assert!(
            !RsaVerifier.verify(&small_pub, SIGNING_INPUT, &sig_bytes),
            "the verifier must reject a signature under a sub-2048-bit key"
        );
    }

    /// `from_pkcs8_der` round-trips: encode the RFC 7515 A.2 key to PKCS#8 DER, load it back, and
    /// the resulting signer publishes the A.2 `n`/`e`, signs the A.2 input, and the verifier accepts
    /// that signature under the very JWK the signer published.
    #[test]
    fn from_pkcs8_der_roundtrips_the_a2_key() {
        use rsa::pkcs8::EncodePrivateKey as _;

        let private_key = RsaPrivateKey::from_components(
            BigUint::from_bytes_be(&b64u(N_B64URL)),
            BigUint::from_bytes_be(&b64u(E_B64URL)),
            BigUint::from_bytes_be(&b64u(D_B64URL)),
            vec![
                BigUint::from_bytes_be(&b64u(P_B64URL)),
                BigUint::from_bytes_be(&b64u(Q_B64URL)),
            ],
        )
        .unwrap();
        let der = private_key
            .to_pkcs8_der()
            .expect("the A.2 key encodes to PKCS#8 DER");

        let signer = RsaSigner::from_pkcs8_der("test-rsa", der.as_bytes())
            .expect("a valid 2048-bit PKCS#8 RSA key loads");
        assert_eq!(
            JwsSigner::public_jwk(&signer),
            rsa_jwk(),
            "public_jwk must publish the A.2 n/e after a PKCS#8 round-trip"
        );
        let sig = signer.sign_rs256(SIGNING_INPUT).unwrap();
        assert!(
            RsaVerifier.verify(&signer.public_jwk(), SIGNING_INPUT, &sig),
            "a signature from the PKCS#8-loaded signer verifies under its own JWK"
        );
    }

    /// The 2048-bit floor is enforced on the PKCS#8 path too, because `from_pkcs8_der` funnels
    /// through `from_private_key`: a GENUINE 1024-bit key, encoded to valid PKCS#8 DER, is REJECTED.
    /// Red-before-green: deleting the `if bits < MIN_RSA_MODULUS_BITS` guard in `from_private_key`
    /// turns this Err into an Ok.
    #[test]
    fn from_pkcs8_der_rejects_sub_2048_key() {
        use rsa::pkcs8::EncodePrivateKey as _;

        let small = small_private_key();
        assert_eq!(
            small.n().bits(),
            1024,
            "the pinned key is genuinely 1024 bits"
        );
        let der = small
            .to_pkcs8_der()
            .expect("even a sub-2048 key encodes to well-formed PKCS#8 DER");
        // The DER is structurally valid; the ONLY thing returning Err is the shared modulus floor.
        assert!(
            RsaSigner::from_pkcs8_der("small", der.as_bytes()).is_err(),
            "from_pkcs8_der must reject a sub-2048-bit modulus via the shared floor"
        );
    }

    /// Malformed DER is an `Err`, never a panic: the third-party bytes a host might hand in are not
    /// trusted to be well-formed.
    #[test]
    fn from_pkcs8_der_rejects_malformed_der() {
        assert!(RsaSigner::from_pkcs8_der("k", b"not pkcs8 der").is_err());
        assert!(RsaSigner::from_pkcs8_der("k", &[]).is_err());
    }

    // A PS256 (RSASSA-PSS, salt length 32) signature over `SIGNING_INPUT` under the RFC 7515 A.2 RSA
    // key. PSS is randomized, so there is no RFC known-answer vector; this one was produced once by
    // this crate's `Ps256Signer` (equivalently `openssl dgst -sha256 -sigopt rsa_padding_mode:pss
    // -sigopt rsa_pss_saltlen:32`) and PINNED. VERIFICATION is deterministic — the salt is carried in
    // the signature — so any conforming PSS verifier that enforces salt length 32 accepts these exact
    // bytes, which is what makes a pinned, externally-checkable vector meaningful here.
    const PS256_A2_SIG: &str = "VPsxqpmiWCZjFcc9Oid-KEUsg3LR7ewNlohr2ZUUkpc63KZW4yJrYHZzSQn2jpMZRLrGB-A-SUU5R3_wzfH6upgpN3RorvmZc91E8aZWJqj0hu151XRTxvIO4Cnma8Qi1cFP6cftLOPs49aXP9OEzzZvmpBXWE0FTWIHLA0gKF9kZNX3xavVfR6owwN1-n6ZcC6SUwgthYdbTlME71p6IvtfBKS4JltoPYJKOQgEls44RomWn-RbpKEkD3Y1okxFZajveVNR7oXLQ_6WBPtY__L2Pfd365OVzcurpvXIcJs1EbeSorecaaIVHyeBBmWej2Gfi-2P-NNvCot3aUhdKA";

    fn a2_signer_ps256() -> Ps256Signer {
        let private_key = RsaPrivateKey::from_components(
            BigUint::from_bytes_be(&b64u(N_B64URL)),
            BigUint::from_bytes_be(&b64u(E_B64URL)),
            BigUint::from_bytes_be(&b64u(D_B64URL)),
            vec![
                BigUint::from_bytes_be(&b64u(P_B64URL)),
                BigUint::from_bytes_be(&b64u(Q_B64URL)),
            ],
        )
        .unwrap();
        Ps256Signer::from_private_key("test-rsa", private_key).unwrap()
    }

    /// `Ps256Verifier` ACCEPTS the pinned salt-32 PSS vector under the A.2 key, and `public_jwk`
    /// round-trips the same `n`/`e`. A round-trip through the async signer also verifies.
    #[tokio::test]
    async fn ps256_verifier_accepts_pinned_vector_and_roundtrips() {
        let sig = URL_SAFE_NO_PAD.decode(PS256_A2_SIG).unwrap();
        assert!(
            Ps256Verifier.verify(&rsa_jwk(), SIGNING_INPUT, &sig),
            "the pinned salt-32 PSS vector must verify"
        );

        let signer = a2_signer_ps256();
        assert_eq!(
            JwsSigner::public_jwk(&signer),
            rsa_jwk(),
            "public_jwk must publish the A.2 n/e"
        );
        let JwsSignature::Ps256(fresh) = JwsSigner::sign(&signer, SIGNING_INPUT).await.unwrap()
        else {
            panic!("Ps256Signer must produce a Ps256 signature");
        };
        assert!(
            Ps256Verifier.verify(&signer.public_jwk(), SIGNING_INPUT, &fresh),
            "a freshly signed PS256 signature verifies under its own JWK"
        );
    }

    /// THE HEADLINE CONFUSION TEST: under the IDENTICAL RSA public key, an RS256 (PKCS#1 v1.5)
    /// signature must NOT verify through `Ps256Verifier`, and a PS256 (PSS) signature must NOT verify
    /// through `RsaVerifier`. This is what makes RS256↔PS256 a genuine algorithm distinction rather
    /// than two names for the same check. Red-before-green: pointing either verifier at the other's
    /// padding (or giving `Ps256`/`Rs256` the same `JwsAlg::slot`) flips one of these to `true`.
    #[test]
    fn rs256_and_ps256_signatures_do_not_cross_verify() {
        let rs256_sig = URL_SAFE_NO_PAD.decode(EXPECTED_SIG_B64URL).unwrap();
        let ps256_sig = URL_SAFE_NO_PAD.decode(PS256_A2_SIG).unwrap();

        // Sanity: each verifies under its OWN padding.
        assert!(RsaVerifier.verify(&rsa_jwk(), SIGNING_INPUT, &rs256_sig));
        assert!(Ps256Verifier.verify(&rsa_jwk(), SIGNING_INPUT, &ps256_sig));

        // The confusion each direction: same key, wrong padding → false.
        assert!(
            !Ps256Verifier.verify(&rsa_jwk(), SIGNING_INPUT, &rs256_sig),
            "an RS256 (PKCS#1 v1.5) signature must not verify as PS256"
        );
        assert!(
            !RsaVerifier.verify(&rsa_jwk(), SIGNING_INPUT, &ps256_sig),
            "a PS256 (PSS) signature must not verify as RS256"
        );
    }

    /// A PSS signature made with a salt length OTHER than 32 is rejected: `Ps256Verifier` pins salt
    /// length 32 (the SHA-256 output size) via `PssVerifyingKey::<Sha256>::new`. Red-before-green:
    /// the verifier using `new_with_salt_len(_, 48)` would accept this.
    #[test]
    fn ps256_rejects_non_standard_salt_length() {
        use rsa::pss::SigningKey as PssSigningKey;
        use rsa::signature::RandomizedSigner as _;

        let private_key = RsaPrivateKey::from_components(
            BigUint::from_bytes_be(&b64u(N_B64URL)),
            BigUint::from_bytes_be(&b64u(E_B64URL)),
            BigUint::from_bytes_be(&b64u(D_B64URL)),
            vec![
                BigUint::from_bytes_be(&b64u(P_B64URL)),
                BigUint::from_bytes_be(&b64u(Q_B64URL)),
            ],
        )
        .unwrap();
        let salt48 = PssSigningKey::<Sha256>::new_with_salt_len(private_key, 48);
        let sig = salt48
            .sign_with_rng(&mut OsFillRng, SIGNING_INPUT)
            .to_bytes();
        assert!(
            !Ps256Verifier.verify(&rsa_jwk(), SIGNING_INPUT, &sig),
            "a salt-48 PSS signature must be rejected by the salt-32 verifier"
        );
    }

    /// The 2048-bit floor and the non-RSA guard port to PS256 exactly as for RS256: a genuine
    /// 1024-bit PSS signature is refused by the modulus floor, an EC key is refused, and malformed
    /// inputs (zero-length, truncated) return `false` without panicking.
    #[test]
    fn ps256_enforces_floor_and_guards() {
        use rsa::pss::SigningKey as PssSigningKey;
        use rsa::signature::RandomizedSigner as _;

        // 1024-bit key: constructor refuses, and a genuine 1024-bit PSS signature (128 bytes, its own
        // modulus width, so the length guard passes) is refused by the 2048-bit floor.
        let small = small_private_key();
        assert!(Ps256Signer::from_private_key("small", small.clone()).is_err());
        let salt = PssSigningKey::<Sha256>::new(small);
        let small_sig = salt.sign_with_rng(&mut OsFillRng, SIGNING_INPUT).to_bytes();
        assert_eq!(
            small_sig.len(),
            128,
            "a 1024-bit PSS signature is 128 bytes"
        );
        let small_pub = Jwk::Rsa {
            n: SMALL_N.to_string(),
            e: SMALL_E.to_string(),
            kid: None,
        };
        assert!(
            !Ps256Verifier.verify(&small_pub, SIGNING_INPUT, &small_sig),
            "the PS256 verifier must reject a sub-2048-bit key"
        );

        // Non-RSA key.
        let ec_key = Jwk::Ec {
            crv: crate::jwt::EcCurve::P256,
            x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU".to_string(),
            y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0".to_string(),
            kid: None,
        };
        let good = URL_SAFE_NO_PAD.decode(PS256_A2_SIG).unwrap();
        assert!(!Ps256Verifier.verify(&ec_key, SIGNING_INPUT, &good));

        // Truncated / empty signatures.
        assert!(!Ps256Verifier.verify(&rsa_jwk(), SIGNING_INPUT, &good[..good.len() - 1]));
        assert!(!Ps256Verifier.verify(&rsa_jwk(), SIGNING_INPUT, &[]));
    }

    /// `from_pkcs8_der` round-trips a PS256 signer: the A.2 key encodes to PKCS#8 DER, loads back, and
    /// signs a signature its own published JWK verifies. Padding is a property of the SIGNER, not the
    /// key bytes, so the same DER that loads an `RsaSigner` loads a `Ps256Signer`.
    #[test]
    fn ps256_from_pkcs8_der_roundtrips() {
        use rsa::pkcs8::EncodePrivateKey as _;

        let private_key = RsaPrivateKey::from_components(
            BigUint::from_bytes_be(&b64u(N_B64URL)),
            BigUint::from_bytes_be(&b64u(E_B64URL)),
            BigUint::from_bytes_be(&b64u(D_B64URL)),
            vec![
                BigUint::from_bytes_be(&b64u(P_B64URL)),
                BigUint::from_bytes_be(&b64u(Q_B64URL)),
            ],
        )
        .unwrap();
        let der = private_key.to_pkcs8_der().unwrap();
        let signer = Ps256Signer::from_pkcs8_der("test-rsa", der.as_bytes()).unwrap();
        let sig = signer.sign_ps256(SIGNING_INPUT).unwrap();
        assert!(Ps256Verifier.verify(&signer.public_jwk(), SIGNING_INPUT, &sig));
    }

    /// The canonical `Jwk::thumbprint` produces the EXACT RFC 7638 §3.2 thumbprint of the RFC 7515
    /// A.2 RSA public key: SHA-256 over `{"e":..,"kty":"RSA","n":..}` in lexicographic member order,
    /// base64url without padding, with `kid` excluded. A reorder of the members in `Jwk::thumbprint`
    /// changes the hash and this exact-value assertion goes red.
    #[test]
    fn thumbprint_member_order() {
        const A2_RSA_THUMBPRINT: &str = "IsUn6_e04MaShXFIISMp4kG62LWzMIPy_MvSA5pJgX8";
        let jwk = Jwk::Rsa {
            n: N_B64URL.to_string(),
            e: E_B64URL.to_string(),
            // Present on purpose: the thumbprint must ignore it (RFC 7638 §3.2.1).
            kid: Some("ignored-by-thumbprint".to_string()),
        };
        assert_eq!(jwk.thumbprint(), A2_RSA_THUMBPRINT);
    }
}
