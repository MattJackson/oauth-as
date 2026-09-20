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
//! an RFC 9449 DPoP proof are both JWTs a CLIENT made, so [`CompactJws::parse`], [`Jwk`] and
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
//! [`Jwk::from_json`] is the only route from JSON into the type, including through `serde`,
//! whose `Deserialize` impl is routed through it rather than derived. The type's fields are sealed,
//! so the other constructors are the only alternatives and neither can express a private member:
//! [`Jwk::from_coordinates`] takes two P-256 coordinates and nothing else, and
//! [`EcdsaP256Key::to_public_jwk`] converts a key this crate PUBLISHED, which by construction has no private
//! half in it. See [`Jwk`] on what each does and does not revalidate.
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
//! it is not one this feature brings. [`JwsSigner`] and [`JwsVerifier`] are the seam; the
//! `jwt-p256` feature is the BACKEND this crate ships over `p256`, and a host may install its own
//! instead. Two reasons, in the order they matter:
//!
//! 1. THE PRIVATE KEY NEED NOT BE IN THIS PROCESS. [`JwsSigner::sign`] is async precisely so it
//!    can be a cloud KMS or a PKCS#11 token, where the key never leaves its boundary and this
//!    process holds only a handle. The signing key is the one secret whose compromise forges every
//!    token the deployment will ever issue, and "the key is in the process" is exactly the property
//!    a regulated deployment must avoid. Through 0.9.0 this module made it structural.
//! 2. It stops `jwt` adding a complete SECOND elliptic curve implementation (measured: 20 packages)
//!    to a host that already has one through `rustls`, which is most Rust HTTP servers.
//!
//! [`JwsVerifier`] is SYNC, and the asymmetry is the design rather than an oversight: verifying
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

// =============================================================================================
// THE ALGORITHM-TAGGED SEAM.
//
// The algorithm-tagged JWS seam of crypto agility, generalized off the ES256-hardcoded shape it
// had through 0.9.x; the wired algorithms are ES256, RS256, EdDSA and PS256. `JwsAlg` is a CLOSED enum on
// purpose (see the module note): a new algorithm is a crate release with a new variant and new
// match arms, which is where an algorithm belongs to be vetted, not a registry a deployment can extend.
// =============================================================================================

/// The elliptic curve of an `EC` key. Phase A ships only P-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
pub enum EcCurve {
    /// NIST P-256 (RFC 7518 section 6.2.1.1 `crv` value `P-256`).
    P256,
}

impl EcCurve {
    /// The RFC 7518 section 6.2.1.1 `crv` spelling.
    pub fn jose_name(self) -> &'static str {
        match self {
            EcCurve::P256 => "P-256",
        }
    }
}

/// The Edwards curve of an `OKP` key. Phase C ships only Ed25519.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
pub enum OkpCurve {
    /// Ed25519 (RFC 8037 section 3.1 `crv` value `Ed25519`). The ONLY OKP curve this crate wires:
    /// Ed448 shares the `EdDSA` JOSE algorithm name but is a different curve, not implemented here.
    Ed25519,
}

impl OkpCurve {
    /// The RFC 8037 section 2 `crv` spelling.
    pub fn jose_name(self) -> &'static str {
        match self {
            OkpCurve::Ed25519 => "Ed25519",
        }
    }
}

/// The KIND of key an algorithm signs with: the axis on which algorithm confusion happens.
///
/// [`consistent`] compares a [`JwsAlg`]'s key kind against a presented [`Jwk`]'s, so an `RS256`
/// `alg` can never route a verification at an `EC` or `OKP` key, nor an `ES256`/`EdDSA` `alg` at an
/// `RSA` key: the check that stops algorithm confusion across the three wired key kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
pub enum KeyKind {
    /// An elliptic-curve key on the given curve.
    Ec(EcCurve),
    /// An RSA key (RFC 7518 section 6.3). One kind: the modulus size is a property of the key, not
    /// a distinct KIND for the confusion check.
    Rsa,
    /// An octet-key-pair (Edwards-curve) key on the given curve (RFC 8037 section 2).
    Okp(OkpCurve),
}

/// A JWS signing algorithm this crate can wire an asymmetric verification (and, for the ones it
/// also signs, a signature) to.
///
/// A CLOSED enum, deliberately NOT `#[non_exhaustive]`: adding `Rs256` or `EdDsa` is a crate
/// release that adds a variant here and forces every `match` in this file to grow an arm, which is
/// exactly the review a new signature algorithm should compel. HMAC (`HS256`) is NOT a member and
/// cannot be spelled here: it verifies with a secret both parties hold, has its own
/// [`verify_hs256`] path, and must never reach a [`JwsVerifier`]. `none` is likewise absent, so no
/// code path can route an unsigned JWS through this seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
pub enum JwsAlg {
    /// ECDSA using P-256 and SHA-256 (RFC 7518 section 3.4).
    Es256,
    /// RSASSA-PKCS1-v1.5 using SHA-256 (RFC 7518 section 3.3).
    Rs256,
    /// EdDSA using Ed25519 (RFC 8037 section 3.1). `EdDSA` on the wire; Ed25519 only.
    EdDsa,
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256, salt length 32 (RFC 7518 section 3.5).
    ///
    /// Shares [`KeyKind::Rsa`] with [`JwsAlg::Rs256`] on purpose: the two are the SAME RSA key with
    /// DIFFERENT padding, so [`consistent`] cannot and must not tell them apart. What keeps a PS256
    /// signature from ever being checked with PKCS#1 v1.5 padding (or an RS256 one with PSS) is the
    /// SLOT: `Ps256` occupies its own [`JwsVerifiers`] slot behind its own PSS verifier, and
    /// [`expect_alg`] pins the algorithm before any key is read, so `alg → slot → verifier` routes an
    /// `RS256` header only to the PKCS#1 v1.5 verifier and a `PS256` header only to the PSS one. FAPI
    /// 2.0 permits `PS256` and `ES256` for `private_key_jwt` and FORBIDS `RS256`; see [`AlgAllowList`].
    Ps256,
}

impl JwsAlg {
    /// Every wired algorithm, in a stable order.
    pub const ALL: &'static [JwsAlg] =
        &[JwsAlg::Es256, JwsAlg::Rs256, JwsAlg::EdDsa, JwsAlg::Ps256];

    /// The RFC 7515 section 4.1.1 `alg` spelling.
    pub fn jose_name(self) -> &'static str {
        match self {
            JwsAlg::Es256 => "ES256",
            JwsAlg::Rs256 => "RS256",
            JwsAlg::EdDsa => "EdDSA",
            JwsAlg::Ps256 => "PS256",
        }
    }

    /// The kind of key this algorithm uses, for [`consistent`].
    pub fn key_kind(self) -> KeyKind {
        match self {
            JwsAlg::Es256 => KeyKind::Ec(EcCurve::P256),
            // RS256 and PS256 are the same RSA key with different padding: SAME kind, on purpose.
            // The padding is separated by the slot/verifier, never by `key_kind` (see `JwsAlg::Ps256`).
            JwsAlg::Rs256 | JwsAlg::Ps256 => KeyKind::Rsa,
            JwsAlg::EdDsa => KeyKind::Okp(OkpCurve::Ed25519),
        }
    }

    /// The slot this algorithm occupies in a [`JwsVerifiers`], one per variant.
    ///
    /// SECURITY: `Ps256` and `Rs256` MUST hold DISTINCT slots. The whole RS256↔PS256 confusion
    /// defense reduces to this: the slot selects the padding-specific verifier, so a one-character
    /// typo giving them the same slot would silently route one algorithm's signature through the
    /// other's padding. The `algorithm_confusion` integration test pins it (RS256 sig → false via
    /// the PSS verifier and vice-versa, under the identical RSA key).
    const fn slot(self) -> usize {
        match self {
            JwsAlg::Es256 => 0,
            JwsAlg::Rs256 => 1,
            JwsAlg::EdDsa => 2,
            JwsAlg::Ps256 => 3,
        }
    }
}

/// Classify a JOSE `alg` header value into the algorithm this crate would verify it under, or
/// `None` for anything this seam refuses to route: `none`, any HMAC (`HS256`), and every value not
/// yet wired.
///
/// EXHAUSTIVE and total: it is the one function that reads an `alg` string, and it cannot spell
/// `none` or an HMAC, so neither can be turned into a [`JwsAlg`] no matter what a token header
/// says. See [`expect_alg`], which is the only caller that reads a header's `alg` at all.
pub fn classify_alg(name: &str) -> Option<JwsAlg> {
    match name {
        "ES256" => Some(JwsAlg::Es256),
        "RS256" => Some(JwsAlg::Rs256),
        // RFC 8037 s3.1: `EdDSA` is the JOSE name shared by Ed25519 and Ed448. This crate wires
        // Ed25519 ONLY, and the verifier refuses any OKP key on another curve.
        "EdDSA" => Some(JwsAlg::EdDsa),
        "PS256" => Some(JwsAlg::Ps256),
        // "none", "HS256", "ES384", and everything not wired: refused, not routed.
        _ => None,
    }
}

/// How a call site decides which algorithm a JWS is allowed to carry.
///
/// [`AlgPolicy::Registered`] is the rule everywhere but DPoP: the REGISTRATION names the one
/// algorithm, and the token header only gets to agree with it. [`AlgPolicy::AnyInstalled`] is the
/// single documented exception, used ONLY by RFC 9449 DPoP, whose proof key is self-carried by
/// design (section 4.3): there is no prior registration to name an algorithm, so the header selects
/// among the algorithms this server actually has a verifier installed for, and nothing wider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
pub enum AlgPolicy {
    /// The header's `alg` must be exactly this algorithm.
    Registered(JwsAlg),
    /// The header's `alg` may be any algorithm with an installed verifier. DPoP ONLY.
    AnyInstalled,
}

/// Why [`expect_alg`] refused a JWS header's algorithm. Callers map this onto their own wire error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
pub enum AlgRefusal {
    /// The header carried no `alg`, or it was not a string (RFC 7515 section 4.1.1 makes it
    /// REQUIRED).
    Missing,
    /// The `alg` is one this seam refuses to route: `none`, an HMAC, or an unwired value. See
    /// [`classify_alg`].
    Unclassified,
    /// The `alg` names a wired algorithm, but not the one the registration expects.
    Mismatch,
    /// The `alg` names a wired algorithm, but no verifier is installed for it (DPoP only).
    NotInstalled,
}

/// Decide which [`JwsAlg`] a parsed JWS is allowed to be verified under.
///
/// This is the ONLY function in the crate that reads a JWS header's `alg` for the ASYMMETRIC seam,
/// which is what makes "the algorithm is chosen by the verifier, never by the token" a property of
/// one place rather than a rule spread over three. For [`AlgPolicy::Registered`] the `installed`
/// set is not consulted (the registration already fixed the algorithm); for
/// [`AlgPolicy::AnyInstalled`] it is the whole of the decision.
pub fn expect_alg(
    jws: &CompactJws<'_>,
    policy: AlgPolicy,
    installed: &JwsVerifiers,
) -> Result<JwsAlg, AlgRefusal> {
    let name = jws.header_str("alg").ok_or(AlgRefusal::Missing)?;
    let alg = classify_alg(name).ok_or(AlgRefusal::Unclassified)?;
    match policy {
        AlgPolicy::Registered(expected) => {
            if alg != expected {
                return Err(AlgRefusal::Mismatch);
            }
        }
        AlgPolicy::AnyInstalled => {
            if installed.get(alg).is_none() {
                return Err(AlgRefusal::NotInstalled);
            }
        }
    }
    Ok(alg)
}

/// Whether `key` is the KIND of key `alg` signs with.
///
/// REJECTS a mismatch; it never INFERS an algorithm from a key. The direction matters: an
/// algorithm-confusion attack is a token whose header names one algorithm while the key it is
/// verified against is another kind, and the safe check is "does the key match the algorithm the
/// verifier already chose", not "what algorithm does this key imply". With ES256, RS256 and EdDSA
/// all wired, the check genuinely bites: `consistent(JwsAlg::Rs256, ec_jwk)` is `false`.
pub fn consistent(alg: JwsAlg, key: &Jwk) -> bool {
    alg.key_kind() == key.key_kind()
}

/// A JWS signature, tagged with the algorithm that produced it.
///
/// The width is enforced by the variant's fixed-size array, which is what a host's backend cannot
/// get wrong by returning too few or too many bytes: RFC 7518 section 3.4 fixes ES256 at the
/// 64-byte `r || s` concatenation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
pub enum JwsSignature {
    /// A 64-byte fixed-width `r || s` ES256 signature (RFC 7518 section 3.4).
    Es256([u8; 64]),
    /// An RS256 signature (RFC 7518 section 3.3). Its width is the modulus size `k` (256 bytes for
    /// RSA-2048, 384 for 3072, 512 for 4096), so unlike the fixed-width curves it is boxed octets.
    /// The `length == modulus` check is the verifier's, not the wire's: `rsa`'s parse is
    /// length-lenient, so [`crate::backends::rsa::RsaVerifier`] guards it per key.
    Rs256(Box<[u8]>),
    /// A 64-byte fixed-width Ed25519 signature (RFC 8032 section 5.1; RFC 8037 section 3.1).
    EdDsa([u8; 64]),
    /// A PS256 (RSASSA-PSS) signature (RFC 7518 section 3.5). Its width is the modulus size `k`, the
    /// same as [`JwsSignature::Rs256`], so it is boxed octets. A SEPARATE variant from `Rs256`, not a
    /// reuse: the variant IS the algorithm tag ([`JwsSignature::alg`]), so RS256 and PS256 must tag
    /// distinctly even though both are RSA. The `length == modulus` check is the verifier's; `rsa`'s
    /// PSS parse is length-lenient (see [`crate::backends::rsa::Ps256Verifier`]).
    Ps256(Box<[u8]>),
}

impl JwsSignature {
    /// The algorithm that produced this signature.
    pub fn alg(&self) -> JwsAlg {
        match self {
            JwsSignature::Es256(_) => JwsAlg::Es256,
            JwsSignature::Rs256(_) => JwsAlg::Rs256,
            JwsSignature::EdDsa(_) => JwsAlg::EdDsa,
            JwsSignature::Ps256(_) => JwsAlg::Ps256,
        }
    }

    /// The signature octets, exactly as they go on the wire.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            JwsSignature::Es256(bytes) => bytes,
            JwsSignature::Rs256(bytes) => bytes,
            JwsSignature::EdDsa(bytes) => bytes,
            JwsSignature::Ps256(bytes) => bytes,
        }
    }

    /// Build a signature of `alg` from wire octets, returning `None` when the width is wrong for the
    /// algorithm. This is the width check the fixed-size arrays make impossible to skip.
    ///
    /// The fixed-width curves (ES256, EdDSA) require EXACTLY 64 bytes. RS256 and PS256 accept the
    /// decoded octets as-is: an RSA signature's width is the signer's modulus size, which is not
    /// known here, so the `length == modulus` check is the verifier's (see [`JwsSignature::Rs256`]).
    pub fn from_wire(alg: JwsAlg, raw: &[u8]) -> Option<Self> {
        match alg {
            JwsAlg::Es256 => raw.try_into().ok().map(JwsSignature::Es256),
            JwsAlg::EdDsa => raw.try_into().ok().map(JwsSignature::EdDsa),
            JwsAlg::Rs256 => Some(JwsSignature::Rs256(raw.into())),
            JwsAlg::Ps256 => Some(JwsSignature::Ps256(raw.into())),
        }
    }
}

/// The installed asymmetric verifiers, one slot per [`JwsAlg`] variant.
///
/// A fixed-slot array rather than a map: the algorithm set is closed and tiny, so a slot per
/// variant is the whole of it, and `get` is an index rather than a hash. A verifier installs itself
/// into the slot for its own [`JwsVerifier::alg`], so a host cannot register a verifier under the
/// wrong algorithm.
#[derive(Clone, Default)]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
pub struct JwsVerifiers {
    slots: [Option<Arc<dyn JwsVerifier>>; JwsAlg::ALL.len()],
}

impl JwsVerifiers {
    /// An empty set: nothing installed.
    pub fn new() -> Self {
        JwsVerifiers::default()
    }

    /// Install `verifier` into the slot for its own algorithm, replacing any previous one.
    pub fn install(&mut self, verifier: Arc<dyn JwsVerifier>) {
        let slot = verifier.alg().slot();
        self.slots[slot] = Some(verifier);
    }

    /// The verifier installed for `alg`, or `None`.
    pub fn get(&self, alg: JwsAlg) -> Option<&dyn JwsVerifier> {
        self.slots[alg.slot()].as_deref()
    }

    /// The algorithms that have a verifier installed, in [`JwsAlg::ALL`] order.
    pub fn installed(&self) -> impl Iterator<Item = JwsAlg> + '_ {
        JwsAlg::ALL
            .iter()
            .copied()
            .filter(move |alg| self.slots[alg.slot()].is_some())
    }

    /// Clear the verifier slot of every algorithm `allow` forbids. Idempotent.
    ///
    /// This is the DPoP half of the server-level [`AlgAllowList`]. The `AnyInstalled` policy
    /// ([`expect_alg`]) selects among the algorithms with an occupied slot, so emptying a forbidden
    /// algorithm's slot here makes it `NotInstalled` no matter what key a self-carried DPoP proof
    /// brings — the allow-list cannot be reintroduced by the proof.
    ///
    /// Gated on `dpop`, its only caller ([`crate::AuthorizationServer::resolved_jws_verifiers`]): the
    /// `AnyInstalled` set exists only for DPoP, so a build without it has no whole-set to restrict.
    #[cfg(feature = "dpop")]
    pub(crate) fn restrict_to(&mut self, allow: &AlgAllowList) {
        for alg in JwsAlg::ALL {
            if !allow.is_allowed(*alg) {
                self.slots[alg.slot()] = None;
            }
        }
    }
}

/// A server-level restriction on which asymmetric [`JwsAlg`] this authorization server will VERIFY
/// and ADVERTISE, on top of the per-registration algorithm pinning every client already carries.
///
/// The motivating case is FAPI 2.0, which permits `PS256` and `ES256` for `private_key_jwt` and
/// FORBIDS `RS256`: a deployment must be able to enforce that centrally rather than trusting every
/// registration. [`AlgAllowList::fapi`] is exactly that subset.
///
/// The default ([`AlgAllowList::all`]) allows every wired algorithm, so an existing deployment that
/// never sets one is unchanged. Representation mirrors [`JwsVerifiers`]: a fixed `[bool; ALL.len()]`
/// indexed by [`JwsAlg`]'s own slot, `Copy`, no allocation, and `is_allowed` is a slot read.
///
/// SCOPE: this governs the algorithms the server ACCEPTS and DERIVES its RFC 8414 metadata from. It
/// does not rewrite host-authored free-form fields such as the RFC 9728 resource-metadata alg lists
/// (those are the host's declaration about a protected resource), and it does not reach a host that
/// calls a low-level verify entry point (e.g. [`crate::dpop::verify_proof`]) with its own verifier
/// set — that is the host operating its own crypto, outside this server's mediation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
pub struct AlgAllowList {
    allowed: [bool; JwsAlg::ALL.len()],
}

impl AlgAllowList {
    /// Every wired algorithm is allowed. The DEFAULT, and byte-for-byte the behaviour of a server
    /// with no allow-list: an all-true filter changes nothing.
    pub const fn all() -> Self {
        AlgAllowList {
            allowed: [true; JwsAlg::ALL.len()],
        }
    }

    /// Only the listed algorithms; every other is refused at verification and never advertised.
    pub fn only(algs: &[JwsAlg]) -> Self {
        let mut allowed = [false; JwsAlg::ALL.len()];
        for alg in algs {
            allowed[alg.slot()] = true;
        }
        AlgAllowList { allowed }
    }

    /// The FAPI 2.0 Security Profile subset: `ES256` and `PS256`, with `RS256` (and everything else)
    /// forbidden (FAPI 2.0 §5.3.2, RFC 8725).
    pub fn fapi() -> Self {
        AlgAllowList::only(&[JwsAlg::Es256, JwsAlg::Ps256])
    }

    /// Whether `alg` is permitted by this list.
    pub fn is_allowed(&self, alg: JwsAlg) -> bool {
        self.allowed[alg.slot()]
    }
}

impl Default for AlgAllowList {
    fn default() -> Self {
        AlgAllowList::all()
    }
}

// mutants: equivalent — this Debug output is diagnostic, not a contract; no caller anywhere in the
// crate depends on its content (nothing formats a `JwsVerifiers` and asserts on the result), so a
// mutation that emptied it cannot change observable behaviour.
impl fmt::Debug for JwsVerifiers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwsVerifiers")
            .field("installed", &self.installed().collect::<Vec<_>>())
            .finish()
    }
}

/// A key could not be loaded or exported. The message never contains key material.
///
/// Gated on `jwt`, not on any one backend: `jwt-p256`, `jwt-rsa` and `jwt-ed25519` each hand back
/// one of these from their key constructors, so a build enabling only RSA or only EdDSA needs it
/// too.
#[cfg(feature = "jwt")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError(String);

#[cfg(feature = "jwt")]
impl KeyError {
    /// Describe a key-loading failure. Do not put key material in it.
    pub fn new(message: impl Into<String>) -> Self {
        KeyError(message.into())
    }
}

#[cfg(feature = "jwt")]
impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signing key error: {}", self.0)
    }
}

#[cfg(feature = "jwt")]
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

/// A signing backend could not produce a signature.
///
/// The generic signing error for the whole seam: [`EcdsaP256Key`], the RSA and Ed25519 backends,
/// and any host [`JwsSigner`] all report failure through this one type, so it names no algorithm.
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
        write!(f, "signer error: {}", self.0)
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
/// [`JwsSigner::sign`] is ASYNC because it holds a SECRET, so it is the half that wants to leave
/// the process, and leaving the process is a network round trip (or, for PKCS#11, a blocking call
/// that belongs on a blocking pool). [`JwsVerifier`] is SYNC because it holds only public keys,
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
/// Run [`crate::signer_conformance`] against it, behind the `test-util` feature. It validates
/// ES256, RS256, EdDSA and PS256 signers, dispatching on this trait's [`JwsSigner::alg`] to select
/// the matching known-answer vector (a published RFC one where it exists; a pinned salt-32 signature
/// for randomised PS256). A broken signer fails SILENTLY: a wrong signature is
/// indistinguishable, at a resource server, from a tampered token. For ES256, emitting ASN.1 DER
/// instead of the fixed-width form below is the obvious way to be wrong, and it is wrong in a way
/// only a real client notices.
#[cfg(feature = "jwt")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
pub trait JwsSigner: Send + Sync {
    /// The algorithm this signer produces. This, not any token header, is what
    /// [`JwtConfig`] writes into the JOSE `alg` and what [`crate::signer_conformance`] selects its
    /// RFC test vector by.
    fn alg(&self) -> JwsAlg;

    /// The signature over `signing_input`, which is the JWS Signing Input of RFC 7515
    /// section 5.1 step 5: the ASCII of `BASE64URL(header) "." BASE64URL(payload)`.
    ///
    /// Return the [`JwsSignature`] variant for your [`alg`](JwsSigner::alg), in that algorithm's
    /// canonical JOSE encoding:
    ///
    /// - `ES256` → [`JwsSignature::Es256`], the FIXED-WIDTH `r || s` of RFC 7518 section 3.4: 64
    ///   bytes, 32 per coordinate, leading zeros KEPT. It is **NOT** the ASN.1 DER
    ///   `SEQUENCE { r INTEGER, s INTEGER }` that OpenSSL and nearly every KMS return by default,
    ///   and converting is your job.
    /// - `RS256` → [`JwsSignature::Rs256`], the RSASSA-PKCS1-v1_5 signature of RFC 7518 section
    ///   3.3, whose width is your modulus size `k` (boxed octets, not a fixed array).
    /// - `EdDSA` → [`JwsSignature::EdDsa`], the 64-byte Ed25519 signature of RFC 8037 section 3.1.
    ///
    /// The fixed-width variants refuse the wrong LENGTH; no variant can refuse the wrong ENCODING,
    /// which is what [`crate::signer_conformance`] is for.
    ///
    /// Sign the bytes as given. Do not hash them first: every wired algorithm folds its own hash
    /// in (`ES256` is ECDSA/P-256/SHA-256, `RS256` is RSASSA-PKCS1-v1_5/SHA-256, `EdDSA`/Ed25519
    /// hashes the message internally), so a KMS whose API wants a digest is one you feed the bytes
    /// to exactly once.
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
    ) -> impl Future<Output = Result<JwsSignature, SignerError>> + Send;

    /// The PUBLIC half, for the RFC 7517 JWKS document and the `kid` on every token header.
    ///
    /// Cached at construction. Read the trait docs above before implementing this one.
    fn public_jwk(&self) -> Jwk;
}

/// Delegating impl so a host can share ONE signer between several [`JwtConfig`]s (two audiences,
/// two servers in one process) without a newtype. `JwtConfig` erases to a `dyn` handle internally,
/// so this costs nothing extra.
#[cfg(feature = "jwt")]
impl<T: JwsSigner + ?Sized> JwsSigner for Arc<T> {
    fn alg(&self) -> JwsAlg {
        (**self).alg()
    }

    fn sign(
        &self,
        signing_input: &[u8],
    ) -> impl Future<Output = Result<JwsSignature, SignerError>> + Send {
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
/// [`crate::AuthorizationServer::with_jws_verifier`]. With neither, every signed credential is
/// REFUSED: a server that cannot check a signature must never behave as though it had checked one.
///
/// SYNC on purpose. This holds only PUBLIC keys, so there is no secret to externalise and nothing
/// to be gained from a round trip; it also sits on the DPoP hot path, which runs once per token
/// request. See the module docs on the asymmetry with [`JwsSigner`].
///
/// # The contract, and every clause of it is load bearing
///
/// `true` means, and may only mean: `signature` is a valid signature UNDER THE ALGORITHM THIS
/// VERIFIER IMPLEMENTS ([`alg`](JwsVerifier::alg)), over exactly `signing_input`, under exactly
/// `key`, in that algorithm's one canonical JOSE encoding. In particular:
///
/// - `signature` MUST be in the single canonical encoding for your algorithm, and every OTHER
///   encoding of the same signature MUST be rejected: two encodings of one signature is signature
///   malleability, and a value a deployment recorded as unique stops being unique. For `ES256`
///   that is the 64-byte fixed-width `r || s` of RFC 7518 section 3.4 — reject any other length,
///   and do NOT also accept the ASN.1 DER form; for `EdDSA`, the 64-byte Ed25519 signature; for
///   `RS256`, the RSASSA-PKCS1-v1_5 octets of your key's modulus width and no other.
/// - `key` must be checked to belong to your algorithm and be well-formed for it. For the curve
///   algorithm (`ES256`) that means ON THE CURVE and not the point at infinity — the check an
///   invalid-curve attack needs to find missing, and the reason this crate hands you a [`Jwk`]
///   rather than a parsed point, because the coordinates arrived from a client. For `RS256` it
///   means the modulus clears your size floor.
/// - There is no `false` you may return for an error and no error you may return at all. A
///   malformed key, a wrong-length signature and a signature that simply does not verify all have
///   the same and only safe answer, and distinguishing them would only invite a caller to treat
///   one as recoverable.
///
/// # What you may assume about the arguments, which is LESS than it looks
///
/// The paragraph above says what `true` may mean. This one says what you are handed, because the
/// clause "reject any other length" is the one an implementor reads as "the length will be 64".
/// The concrete widths and key shape below are the `ES256` case (an `RS256` verifier is handed an
/// RSA `Jwk` and an `EdDSA` one an OKP `Jwk`); the universal rule — attacker bytes of any length,
/// never panic — is the same for all three.
///
/// - **`signature` IS ATTACKER-CONTROLLED BYTES OF ANY LENGTH, INCLUDING ZERO.** It is the third
///   segment of a JWS somebody sent this server, base64url-decoded, and NOTHING between the wire
///   and you checks its length. A DPoP proof, an RFC 9101 request object and an RFC 7523 client
///   assertion all arrive this way; on a 4 kilobyte DPoP header the third segment decodes to
///   anything from 0 to about 3000 bytes, and a token ending in a bare `.` decodes to an EMPTY
///   slice, which parses fine and reaches you.
/// - **`key` HAS PASSED SHAPE VALIDATION AND NOTHING MORE.** [`Jwk::from_json`] guarantees
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
/// Run [`crate::signer_conformance`] against it. It carries a known-answer vector per algorithm — a
/// published RFC one where it exists (RFC 7515 appendix A.3 for ES256, appendix A.2 for RS256, RFC
/// 8037 appendix A.4 for EdDSA) and, for randomised PS256 (which has none), a pinned salt-32
/// signature over the A.2 key whose verification is deterministic — which neither side of your
/// deployment produced, and it is the only thing that can tell a verifier that is right from one
/// that agrees with your signer.
#[cfg(feature = "jwt")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
pub trait JwsVerifier: Send + Sync {
    /// The algorithm this verifier checks. A verifier installs itself into the
    /// [`JwsVerifiers`] slot for this algorithm, so it can never be consulted for another.
    fn alg(&self) -> JwsAlg;

    /// Does `signature` verify over `signing_input` under `key`? See the trait docs for what
    /// `true` is allowed to mean.
    ///
    /// Returns `false` (never panics) on ANY mismatch of key kind, coordinate width, or curve, as
    /// well as on a signature that simply does not verify: the caller already chose the algorithm,
    /// and a key of the wrong kind for it is one more thing that is not a valid signature rather
    /// than an error to distinguish.
    fn verify(&self, key: &Jwk, signing_input: &[u8], signature: &[u8]) -> bool;
}

/// The OBJECT-SAFE shadow of [`JwsSigner::sign`], so that [`JwtConfig`] can hold `Arc<dyn ...>`.
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
trait DynJwsSigner: Send + Sync {
    fn dyn_sign<'a>(
        &'a self,
        signing_input: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<JwsSignature, SignerError>> + Send + 'a>>;
}

#[cfg(feature = "jwt")]
impl<T: JwsSigner> DynJwsSigner for T {
    fn dyn_sign<'a>(
        &'a self,
        signing_input: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<JwsSignature, SignerError>> + Send + 'a>> {
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
/// THE BUILT-IN BACKEND, behind `jwt-p256`. It is an [`JwsSigner`] like any other; what makes it
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
        Jwk::Ec {
            crv: EcCurve::P256,
            x: URL_SAFE_NO_PAD.encode(x),
            y: URL_SAFE_NO_PAD.encode(y),
            kid: Some(self.kid.clone()),
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
impl JwsSigner for EcdsaP256Key {
    fn alg(&self) -> JwsAlg {
        JwsAlg::Es256
    }

    fn sign(
        &self,
        signing_input: &[u8],
    ) -> impl Future<Output = Result<JwsSignature, SignerError>> + Send {
        // Computed BEFORE the async block, so nothing borrows `signing_input` across a suspension
        // point that does not exist. The future this returns owns a `Result` and nothing else.
        let signed = self
            .sign_es256(signing_input)
            .map(JwsSignature::Es256)
            .map_err(|e| SignerError(e.0));
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
impl JwsVerifier for P256Verifier {
    fn alg(&self) -> JwsAlg {
        JwsAlg::Es256
    }

    fn verify(&self, key: &Jwk, signing_input: &[u8], signature: &[u8]) -> bool {
        verify_es256(key, signing_input, signature)
    }
}

/// One RFC 7517 JWK: the PUBLIC parameters of one key this crate signs with or verifies against.
///
/// ONE `kty`-tagged type for BOTH jobs, where 0.9.x had a `Jwk` it serialized and a `Jwk` it
/// parsed. The two jobs are still not symmetric, and this type keeps the asymmetry where it belongs
/// rather than in a second type:
///
/// - PARSING attacker-controlled JSON (a DPoP proof's `jwk`, a stored client registration) goes
///   through [`Jwk::from_json`], including through `serde`, whose `Deserialize` impl is routed
///   through it rather than derived. There is therefore no route from JSON into this type that
///   skips the PRIVATE-PARAMETER rejection (`d`, the RSA CRT parameters, `k`): RFC 9449 section 4.3
///   makes that a MUST, and it generalises past DPoP.
/// - SERVING it (the RFC 7517 JWKS document, and a registration read back out of a host's store)
///   is [`Serialize`], which emits only the public members. A signer publishes one with
///   [`JwsSigner::public_jwk`]; the JWKS document adds `use` and `alg` around it (see [`Jwks`]).
///
/// The coordinate fields are OWNED strings because they arrive as strings, and the width check that
/// [`Jwk::from_json`] and [`Jwk::from_coordinates`] run is what a construction from a JSON literal
/// cannot skip. There is deliberately no variant carrying `d` and no way to add one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Jwk {
    /// An elliptic-curve public key (RFC 7518 section 6.2).
    Ec {
        /// The curve. Phase A: only P-256.
        crv: EcCurve,
        /// Base64url (unpadded) x coordinate, fixed 32 byte width.
        x: String,
        /// Base64url (unpadded) y coordinate, fixed 32 byte width.
        y: String,
        /// The optional key identifier (RFC 7517 section 4.5).
        kid: Option<String>,
    },
    /// An RSA public key (RFC 7518 section 6.3).
    Rsa {
        /// Base64urlUInt modulus `n` (RFC 7518 section 6.3.1.1): minimal big-endian bytes, no
        /// leading zero octet, base64url without padding.
        n: String,
        /// Base64urlUInt exponent `e` (RFC 7518 section 6.3.1.2).
        e: String,
        /// The optional key identifier (RFC 7517 section 4.5).
        kid: Option<String>,
    },
    /// An octet-key-pair (Edwards-curve) public key (RFC 8037 section 2).
    Okp {
        /// The curve. Phase C: only Ed25519.
        crv: OkpCurve,
        /// Base64url (unpadded) public key `x`, fixed 32 byte width for Ed25519.
        x: String,
        /// The optional key identifier (RFC 7517 section 4.5).
        kid: Option<String>,
    },
}

/// The minimal RFC 7517 public members of a [`Jwk`], in the order 0.9.x's `Jwk` emitted them:
/// `kty`, then the key-type members, then `kid`. This is what a stored client registration
/// serializes to, and it is byte-for-byte what `Jwk` produced.
#[derive(Serialize)]
#[serde(tag = "kty")]
enum JwkWire<'a> {
    #[serde(rename = "EC")]
    Ec {
        crv: &'static str,
        x: &'a str,
        y: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        kid: Option<&'a str>,
    },
    #[serde(rename = "RSA")]
    Rsa {
        n: &'a str,
        e: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        kid: Option<&'a str>,
    },
    #[serde(rename = "OKP")]
    Okp {
        crv: &'static str,
        x: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        kid: Option<&'a str>,
    },
}

impl Serialize for Jwk {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Jwk::Ec { crv, x, y, kid } => JwkWire::Ec {
                crv: crv.jose_name(),
                x,
                y,
                kid: kid.as_deref(),
            }
            .serialize(serializer),
            Jwk::Rsa { n, e, kid } => JwkWire::Rsa {
                n,
                e,
                kid: kid.as_deref(),
            }
            .serialize(serializer),
            Jwk::Okp { crv, x, kid } => JwkWire::Okp {
                crv: crv.jose_name(),
                x,
                kid: kid.as_deref(),
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Jwk {
    /// Routed through [`Jwk::from_json`] rather than derived, so that a JWK loaded from the host's
    /// own client store is held to exactly the same rules as one arriving in a DPoP proof header. A
    /// derived impl would IGNORE an unknown `d` member rather than reject it, and a registration
    /// silently carrying a client's private key is precisely the state this type exists to make
    /// unrepresentable.
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(d)?;
        Jwk::from_json(&value).map_err(serde::de::Error::custom)
    }
}

/// One RFC 7517 section 4 JWKS entry, as SERVED: the public members plus `use` and `alg`.
///
/// The published `use`/`alg` are hints a resource server reads to select a key; they are a function
/// of the key's kind (an EC P-256 key serves as `sig`/`ES256`), and deriving them for the SERVING
/// document is not the same as inferring an algorithm from a key for a VERIFICATION, which
/// [`consistent`] forbids. Field order (`kty`, `crv`, `x`, `y`, `kid`, `use`, `alg`) is what 0.9.x
/// emitted and is preserved byte-for-byte.
#[derive(Serialize)]
#[serde(tag = "kty")]
enum JwksEntry<'a> {
    #[serde(rename = "EC")]
    Ec {
        crv: &'static str,
        x: &'a str,
        y: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        kid: Option<&'a str>,
        #[serde(rename = "use")]
        use_: &'static str,
        alg: &'static str,
    },
    #[serde(rename = "RSA")]
    Rsa {
        n: &'a str,
        e: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        kid: Option<&'a str>,
        #[serde(rename = "use")]
        use_: &'static str,
        // OPTIONAL and, for RSA, OMITTED. Unlike an EC or OKP key whose `alg` is fixed by its curve,
        // a bare RSA public key is dual-use: it verifies BOTH `RS256` (PKCS#1 v1.5) and `PS256`
        // (RSASSA-PSS), and `Jwk::Rsa` carries nothing to say which. RFC 7517 section 4.4 makes `alg`
        // OPTIONAL, so publishing NONE is honest where publishing one would be an over-specification
        // (and, for a PS256 signing key, an outright lie of `"RS256"`). A relying party selects by
        // `kid` and reads the algorithm from the token header it is verifying, never from this hint.
        #[serde(skip_serializing_if = "Option::is_none")]
        alg: Option<&'static str>,
    },
    #[serde(rename = "OKP")]
    Okp {
        crv: &'static str,
        x: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        kid: Option<&'a str>,
        #[serde(rename = "use")]
        use_: &'static str,
        alg: &'static str,
    },
}

impl<'a> JwksEntry<'a> {
    fn of(jwk: &'a Jwk) -> Self {
        match jwk {
            Jwk::Ec { crv, x, y, kid } => JwksEntry::Ec {
                crv: crv.jose_name(),
                x,
                y,
                kid: kid.as_deref(),
                use_: "sig",
                // The serving `alg` for an EC key is fixed by its curve; Phase A has one.
                alg: match crv {
                    EcCurve::P256 => "ES256",
                },
            },
            Jwk::Rsa { n, e, kid } => JwksEntry::Rsa {
                n,
                e,
                kid: kid.as_deref(),
                use_: "sig",
                // Omitted: an RSA key serves both RS256 and PS256 and this document cannot know
                // which. See the `alg` field on `JwksEntry::Rsa`.
                alg: None,
            },
            Jwk::Okp { crv, x, kid } => JwksEntry::Okp {
                crv: crv.jose_name(),
                x,
                kid: kid.as_deref(),
                use_: "sig",
                alg: match crv {
                    OkpCurve::Ed25519 => "EdDSA",
                },
            },
        }
    }
}

/// An RFC 7517 section 5 JWK Set: what the host serves at its `jwks_uri`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwks {
    /// The advertised keys.
    pub keys: Vec<Jwk>,
}

impl Serialize for Jwks {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        let entries: Vec<JwksEntry<'_>> = self.keys.iter().map(JwksEntry::of).collect();
        let mut state = serializer.serialize_struct("Jwks", 1)?;
        state.serialize_field("keys", &entries)?;
        state.end()
    }
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
/// [`JwsSigner::public_jwk`].
///
/// `Clone` shares the signer rather than duplicating it (`Arc`), and `PartialEq` compares the
/// PUBLISHED IDENTITY: the active and retired JWKs, the audience and the `jwks_uri`. There is no
/// private scalar left to compare once the key may be outside this process, and comparing handles
/// would make two configurations over one KMS key unequal for no reason a host could act on.
#[derive(Clone)]
pub struct JwtConfig {
    /// The host's signing backend (ES256, RS256, EdDSA, or PS256), which may be a key in this process or a
    /// handle to one in a KMS.
    ///
    /// `Arc<dyn _>` and not a generic parameter. Making [`JwtConfig`] generic would put a THIRD
    /// monomorphization axis on `AuthorizationServer`, and the second one is MEASURED at 53,548
    /// bytes per additional `(Storage, Clock)` pair, 27% of this crate's whole default binary
    /// surface. One indirect call against a signing operation that may be a network round trip is
    /// not measurable; that is.
    signer: Arc<dyn DynJwsSigner>,
    /// The algorithm the active signer produces, cached alongside its public half so the JOSE
    /// header can be rebuilt at rotation without re-consulting the signer.
    alg: JwsAlg,
    /// The ACTIVE key's public half, read from the signer ONCE, here.
    ///
    /// Cached rather than re-asked per call, and that is the other half of the contract
    /// [`JwsSigner::public_jwk`] states: the JWKS document is a public, unauthenticated,
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
fn encoded_jose_header(alg: JwsAlg, kid: &str) -> Box<str> {
    // RFC 9068 s2.1 fixes `typ`; `alg` is the signer's OWN algorithm (`signer.alg().jose_name()`),
    // so no code path in this crate can emit an unsigned access token, and the wire bytes are
    // unchanged for a given algorithm. Member order matches what `JoseHeader`'s derive produced.
    let mut json = String::with_capacity(40 + kid.len());
    json.push_str(r#"{"alg":""#);
    json.push_str(alg.jose_name());
    json.push_str(r#"","typ":"at+jwt","kid":""#);
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
    /// `signer` is anything implementing [`JwsSigner`]: [`EcdsaP256Key`] under `jwt-p256`, an
    /// `Arc` of one shared with another configuration, or the host's own KMS-backed type. Its
    /// public half is read HERE, once, and never again; see [`JwsSigner::public_jwk`] for what
    /// that requires of an implementor and for why rotation must come back through
    /// [`JwtConfig::rotate_to`].
    pub fn new(signer: impl JwsSigner + 'static, audience: impl Into<String>) -> Self {
        let alg = signer.alg();
        let active = signer.public_jwk();
        JwtConfig {
            encoded_header: encoded_jose_header(alg, active.kid().unwrap_or_default()),
            alg,
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
    /// holds the old cached public half is silent breakage (see [`JwsSigner::public_jwk`]).
    pub fn rotate_to(mut self, new_active: impl JwsSigner + 'static) -> Self {
        self.alg = new_active.alg();
        let retiring = std::mem::replace(&mut self.active, new_active.public_jwk());
        // The previous signer is dropped by this assignment. There is deliberately nowhere else it
        // is written down.
        self.signer = Arc::new(new_active);
        // The header names the ACTIVE key, so it is rebuilt exactly here and nowhere else.
        self.encoded_header = encoded_jose_header(self.alg, self.active.kid().unwrap_or_default());
        let active_kid = self.active.kid();
        // A kid appears at most once in the published set: any older entry sharing a name with the
        // key just retired, or with the new active key, goes.
        self.retired
            .retain(|jwk| jwk.kid() != retiring.kid() && jwk.kid() != active_kid);
        if retiring.kid() != active_kid {
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
        self.retired.iter().map(|jwk| jwk.kid().unwrap_or_default())
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
        self.retired.retain(|jwk| jwk.kid() != Some(kid));
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
        self.active.kid().unwrap_or_default()
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
    /// ASYNC because [`JwsSigner::sign`] is, which is because the key may not be in this
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
        // The capacity is sized for the fixed-width signatures (ES256 and EdDSA are 64 bytes, which
        // is 86 base64url characters without padding: ceil(n * 4 / 3)), so the buffer holding
        // "header.payload.signature" is allocated once and never grown for those. An RS256
        // signature is the modulus width (256-512 bytes), larger than the reserve, so that path
        // grows the buffer once when the signature is appended — the common ES256/EdDSA path does not.
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
            .map_err(|_| JwtError("the JWS signer could not sign".into()))?;
        compact.push('.');
        URL_SAFE_NO_PAD.encode_string(signature.as_bytes(), &mut compact);
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
    /// RFC 9068 `at+jwt` access tokens, signed with the [`JwtConfig`]'s configured algorithm
    /// (ES256, RS256, EdDSA, or PS256). The record is still persisted, so introspection and revocation
    /// continue to work on the exact string the client presents.
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

/// A well-formed EC P-256 [`Jwk`], for the backend unit tests that need a key of the WRONG kind to
/// prove an RSA/EdDSA verifier refuses it (algorithm-confusion guard). Coordinates are the RFC 7515
/// appendix A.3 P-256 public key.
///
/// Gated on `jwt-ed25519` because that is the ONLY backend whose tests call it (the RS256 tests in
/// `backends/rsa.rs` build their own EC `Jwk` inline). In a single-backend build that has this
/// helper compiled but no caller — a `--features jwt-rsa` or `--features jwt-p256` test build —
/// leaving it at a bare `#[cfg(test)]` is dead code that fails `clippy -D warnings`, so the gate is
/// the feature that actually reaches it rather than a blanket `#[allow(dead_code)]`.
#[cfg(all(test, feature = "jwt-ed25519"))]
pub(crate) fn sample_ec_jwk_for_tests() -> Jwk {
    Jwk::from_coordinates(
        "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    )
    .expect("a valid P-256 coordinate pair")
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

impl Jwk {
    /// Parse and validate one JWK, from either a client's attacker-controlled JSON or a host's own
    /// store.
    ///
    /// Rejects, PRIVATE MEMBERS FIRST (RFC 9449 section 4.3), then: a non-object, a `kty` this crate
    /// does not verify, a `crv` it does not, and coordinates that are not exactly 32 bytes of
    /// base64url. The width check is not pedantry: RFC 7518 section 6.2.1.2 fixes the octet length
    /// at the curve's field size and requires leading zeros to be KEPT, so a trimmed coordinate is
    /// a different point, and accepting it is the classic JWK interoperability bug.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, VerifyError> {
        let object = value
            .as_object()
            .ok_or_else(|| VerifyError::new("a JWK must be a JSON object"))?;
        // PRIVATE members are rejected FIRST, before any other member is read, so that a JWK
        // carrying `d` is refused whatever else is wrong or right about it.
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
        let kid = || {
            object
                .get("kid")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        let kty = string("kty")?;
        match kty.as_str() {
            "EC" => {
                let crv = string("crv")?;
                if crv != "P-256" {
                    return Err(VerifyError::new("only the P-256 curve is supported"));
                }
                let x = string("x")?;
                let y = string("y")?;
                check_coordinate(&x)?;
                check_coordinate(&y)?;
                Ok(Jwk::Ec {
                    crv: EcCurve::P256,
                    x,
                    y,
                    kid: kid(),
                })
            }
            "RSA" => {
                // The private members (`d`, and the CRT parameters `p`, `q`, `dp`, `dq`, `qi`,
                // `oth`) were already rejected above, before any member was read. What remains is
                // the public pair, both REQUIRED (RFC 7518 section 6.3.1). The base64urlUInt width
                // is not fixed the way a P-256 coordinate is, so there is no length check here; the
                // `length == modulus` guard belongs at verification, per key.
                let n = string("n")?;
                let e = string("e")?;
                if URL_SAFE_NO_PAD.decode(&n).is_err() || URL_SAFE_NO_PAD.decode(&e).is_err() {
                    return Err(VerifyError::new(
                        "an RSA n/e is base64urlUInt (unpadded base64url)",
                    ));
                }
                Ok(Jwk::Rsa { n, e, kid: kid() })
            }
            "OKP" => {
                // `d` (the private seed) was rejected above. RFC 8037 section 2: `crv` and `x` are
                // required, and this crate wires Ed25519 only (Ed448 shares the `EdDSA` alg name
                // but is a different curve).
                let crv = string("crv")?;
                if crv != "Ed25519" {
                    return Err(VerifyError::new("only the Ed25519 curve is supported"));
                }
                let x = string("x")?;
                match URL_SAFE_NO_PAD.decode(&x) {
                    Ok(bytes) if bytes.len() == 32 => {}
                    _ => {
                        return Err(VerifyError::new(
                            "an Ed25519 public key is exactly 32 base64url-encoded bytes",
                        ))
                    }
                }
                Ok(Jwk::Okp {
                    crv: OkpCurve::Ed25519,
                    x,
                    kid: kid(),
                })
            }
            _ => Err(VerifyError::new("only EC, RSA, and OKP keys are supported")),
        }
    }

    /// One P-256 public key from its two RFC 7518 section 6.2.1.2 coordinates, exactly as they
    /// appear in a JWK: base64url, unpadded, 32 bytes each.
    ///
    /// The constructor for a host that holds the coordinates rather than a JSON document. `kty` and
    /// `crv` are not arguments because this constructor builds only the P-256 `EC` key; an RSA or
    /// Ed25519 key has its own constructor, so admitting other `kty`/`crv` values here would only
    /// admit a key it cannot produce. The same width check [`Jwk::from_json`] performs runs here: a
    /// constructor that skipped it would be a hole.
    pub fn from_coordinates(x: &str, y: &str) -> Result<Self, VerifyError> {
        check_coordinate(x)?;
        check_coordinate(y)?;
        Ok(Jwk::Ec {
            crv: EcCurve::P256,
            x: x.to_string(),
            y: y.to_string(),
            kid: None,
        })
    }

    /// Name this key, with the RFC 7517 section 4.5 `kid` a client publishes it under.
    ///
    /// Deliberately NOT part of the thumbprint: see [`Jwk::thumbprint`] on why relabelling a key
    /// must not change what a token is bound to.
    pub fn with_kid(self, kid: &str) -> Self {
        let kid = Some(kid.to_string());
        match self {
            Jwk::Ec { crv, x, y, .. } => Jwk::Ec { crv, x, y, kid },
            Jwk::Rsa { n, e, .. } => Jwk::Rsa { n, e, kid },
            Jwk::Okp { crv, x, .. } => Jwk::Okp { crv, x, kid },
        }
    }

    /// The KIND of key this is, for [`consistent`].
    pub fn key_kind(&self) -> KeyKind {
        match self {
            Jwk::Ec { crv, .. } => KeyKind::Ec(*crv),
            Jwk::Rsa { .. } => KeyKind::Rsa,
            Jwk::Okp { crv, .. } => KeyKind::Okp(*crv),
        }
    }

    /// Key type: `EC`, `RSA`, or `OKP`.
    pub fn kty(&self) -> &str {
        match self {
            Jwk::Ec { .. } => "EC",
            Jwk::Rsa { .. } => "RSA",
            Jwk::Okp { .. } => "OKP",
        }
    }

    /// Curve, for an EC key; `None` for RSA and OKP keys.
    pub fn crv(&self) -> Option<EcCurve> {
        match self {
            Jwk::Ec { crv, .. } => Some(*crv),
            Jwk::Rsa { .. } | Jwk::Okp { .. } => None,
        }
    }

    /// The base64url x coordinate, for an EC or OKP key; the empty string for RSA (which has no
    /// `x`). Callers that need to distinguish should match on the variant.
    pub fn x(&self) -> &str {
        match self {
            Jwk::Ec { x, .. } | Jwk::Okp { x, .. } => x,
            Jwk::Rsa { .. } => "",
        }
    }

    /// The base64url y coordinate, for an EC key; the empty string otherwise.
    pub fn y(&self) -> &str {
        match self {
            Jwk::Ec { y, .. } => y,
            Jwk::Rsa { .. } | Jwk::Okp { .. } => "",
        }
    }

    /// The RFC 7517 section 4.5 `kid`, if the key carries one.
    pub fn kid(&self) -> Option<&str> {
        match self {
            Jwk::Ec { kid, .. } | Jwk::Rsa { kid, .. } | Jwk::Okp { kid, .. } => kid.as_deref(),
        }
    }

    /// The RFC 7638 section 3 JWK Thumbprint of this key: SHA-256, base64url without padding.
    ///
    /// This is the value RFC 9449 section 6.1 puts in `cnf.jkt` to bind a token to the key a client
    /// proved possession of. The construction is exact and every part of it is load bearing
    /// (sections 3.1 through 3.3): ONLY the members required to identify the key type, in
    /// LEXICOGRAPHIC order, with no whitespace and no other member. `kid`, `use` and `alg` are
    /// deliberately excluded, which is what makes the thumbprint a property of the KEY rather than
    /// of one description of it; including any of them would let the same key produce two
    /// thumbprints and so two tokens a resource server could not tell were bound to one client. The
    /// required-member set and its order are per key TYPE (RFC 7638 section 3.2).
    pub fn thumbprint(&self) -> String {
        // Built by hand rather than through `serde_json`, because a serializer's member order is a
        // property of a struct declaration and this order is a property of the RFC. For `EC` the
        // required set is `crv`, `kty`, `x`, `y`, which is already lexicographic.
        match self {
            Jwk::Ec { crv, x, y, .. } => {
                let crv = crv.jose_name();
                let mut json = String::with_capacity(40 + crv.len() + x.len() + y.len());
                json.push_str("{\"crv\":\"");
                json.push_str(crv);
                json.push_str("\",\"kty\":\"EC\",\"x\":\"");
                json.push_str(x);
                json.push_str("\",\"y\":\"");
                json.push_str(y);
                json.push_str("\"}");
                URL_SAFE_NO_PAD.encode(Sha256::digest(json.as_bytes()))
            }
            // RFC 7638 section 3.2: the RSA required set is `e`, `kty`, `n`, already lexicographic
            // (`e` < `k` < `n`).
            Jwk::Rsa { n, e, .. } => {
                let mut json = String::with_capacity(24 + n.len() + e.len());
                json.push_str("{\"e\":\"");
                json.push_str(e);
                json.push_str("\",\"kty\":\"RSA\",\"n\":\"");
                json.push_str(n);
                json.push_str("\"}");
                URL_SAFE_NO_PAD.encode(Sha256::digest(json.as_bytes()))
            }
            // OKP required set is `crv`, `kty`, `x` (RFC 8037 section 2; the order every
            // interoperable JOSE library uses), already lexicographic (`c` < `k` < `x`).
            Jwk::Okp { crv, x, .. } => {
                let crv = crv.jose_name();
                let mut json = String::with_capacity(28 + crv.len() + x.len());
                json.push_str("{\"crv\":\"");
                json.push_str(crv);
                json.push_str("\",\"kty\":\"OKP\",\"x\":\"");
                json.push_str(x);
                json.push_str("\"}");
                URL_SAFE_NO_PAD.encode(Sha256::digest(json.as_bytes()))
            }
        }
    }
}

/// The RFC 7518 section 6.2.1.2 coordinate width check, shared by [`Jwk::from_json`] and
/// [`Jwk::from_coordinates`] so the two cannot drift on what a coordinate is.
fn check_coordinate(b64: &str) -> Result<(), VerifyError> {
    match URL_SAFE_NO_PAD.decode(b64) {
        Ok(bytes) if bytes.len() == 32 => Ok(()),
        _ => Err(VerifyError::new(
            "a P-256 coordinate is exactly 32 base64url-encoded bytes",
        )),
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
/// [`JwsVerifier`] seam; it stays public because a host writing the resource-server half of RFC
/// 9449 in the same tree needs it directly, and because it is what every existing consumer calls.
///
/// A `key` that is not an EC P-256 key is `false`, never a panic: the caller already chose ES256,
/// and a key of the wrong kind is one more thing that is not a valid ES256 signature.
#[cfg(feature = "jwt-p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt-p256")))]
pub fn verify_es256(key: &Jwk, signing_input: &[u8], signature: &[u8]) -> bool {
    // Read the EC P-256 coordinates, refusing any other key KIND with `false` rather than a panic.
    let Jwk::Ec {
        crv: EcCurve::P256,
        x,
        y,
        ..
    } = key
    else {
        return false;
    };
    // RFC 7518 section 3.4 fixes the ES256 signature as the fixed-width `r || s` concatenation, 64
    // bytes. The DER form OpenSSL emits by default is NOT this, and accepting both would give one
    // signature two encodings.
    if signature.len() != 64 {
        return false;
    }
    let (Ok(x), Ok(y)) = (URL_SAFE_NO_PAD.decode(x), URL_SAFE_NO_PAD.decode(y)) else {
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

    /// The public half as a [`Jwk`], for a host registering this key as a client's
    /// `private_key_jwt` key. Identical to [`EcdsaP256Key::public_jwk`] now that one [`Jwk`] serves
    /// both jobs; retained so existing callers keep compiling. There is still no method anywhere in
    /// this crate that emits `d`.
    pub fn to_public_jwk(&self) -> Jwk {
        self.public_jwk()
    }
}
