// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A RUNNABLE conformance harness for the [`JwsSigner`] and [`JwsVerifier`] contracts, behind
//! the `test-util` cargo feature (off by default), for a HOST to run from its OWN test suite
//! against the backend it is about to deploy.
//!
//! It validates ES256, RS256 and EdDSA (Ed25519) backends: [`SignerConformance::run`] dispatches on
//! the signer's own [`JwsSigner::alg`] and selects the matching published RFC known-answer vector
//! (RFC 7515 appendix A.3 for ES256, appendix A.2 for RS256, RFC 8037 appendix A.4 for EdDSA),
//! signature width, and public-JWK key kind. The ES256-only encoding hazards — the ASN.1 DER
//! versus fixed-width `r || s` ambiguity of RFC 7518 section 3.4, and the off-curve public key —
//! are checked for an ES256 signer and skipped for RS256/EdDSA, which have neither.
//!
//! # Why this exists
//!
//! The signing seam lets the private key live in a cloud KMS or an HSM, which is the whole point
//! of it. The price is that this crate no longer knows how the signature was produced, and **a
//! wrong signature fails SILENTLY**: to a resource server a token whose signature does not verify
//! looks exactly like a token that was tampered with, so the deployment does not learn about it
//! from a stack trace, it learns about it from its users, at the far end of somebody else's
//! integration.
//!
//! Every failure mode below has been shipped by somebody:
//!
//! - **DER instead of fixed-width `R || S`.** RFC 7518 section 3.4 fixes the ES256 signature as
//!   the 64-byte concatenation. Nearly every KMS, and OpenSSL by default, returns the ASN.1 DER
//!   `SEQUENCE { r INTEGER, s INTEGER }` instead. It is the obvious way to be wrong and it is
//!   wrong in a way only a real client notices.
//! - **A signature over the wrong bytes.** A signer that hashes the input before handing it to a
//!   KMS that hashes it again, or one that signs a digest where the API wanted a message, produces
//!   64 well-formed bytes that verify against nothing.
//! - **A `public_jwk()` that is not the public half of the signing key.** A copy-pasted JWK, or a
//!   key rotated in the KMS while this process cached the old public half (see [`JwsSigner`] on
//!   why rotation must go through [`crate::jwt::JwtConfig::rotate_to`]). The JWKS then advertises a
//!   key that does not sign, and EVERY token the deployment issues fails verification against its
//!   own published document.
//! - **A verifier that says yes.** The failure with no symptom at all, until someone forges a
//!   token.
//!
//! Nothing inside this crate can detect any of that, because the backend is the host's. So the
//! check has to be runnable where the host's backend is, which is what this module is for.
//!
//! # Using it
//!
//! ```toml
//! [dev-dependencies]
//! oauth-as = { version = "*", features = ["test-util", "jwt"] }
//! ```
//!
//! ```no_run
//! use oauth_as::signer_conformance::SignerConformance;
//!
//! # use oauth_as::jwt::{JwsSigner, JwsVerifier};
//! # async fn doc(my_signer: impl JwsSigner, my_verifier: impl JwsVerifier) {
//! let violations = SignerConformance::new(my_signer, my_verifier).run().await;
//! assert!(violations.is_empty(), "{violations:#?}");
//! # }
//! ```
//!
//! It RETURNS the violations rather than panicking, so a host can report them the way it likes.
//! Every violation names a check from [`CHECKS`] plus a human-readable detail.
//!
//! # What it can and cannot prove
//!
//! Read this before quoting a green run at anyone.
//!
//! WHAT IT PROVES. That the verifier accepts a signature the RFC itself vouches for, rejects four
//! specific corruptions of it, rejects six wrong LENGTHS (including the zero-length one a JWS
//! ending in a bare `.` produces), rejects an OFF-CURVE key and an EMPTY signing input, and does
//! not PANIC on any of them; that the signer's output is the fixed-width form, is bound to the
//! bytes it was handed, verifies under the key the signer publishes, and that the signer does not
//! PANIC either.
//!
//! Those five are the exact list [`crate::jwt::JwsVerifier`]'s MUST NOT PANIC clause enumerates
//! ("a zero-length signature, a 63-byte one, a 65-byte one, an off-curve key, an empty signing
//! input"), and every one of them is reachable by an unauthenticated client, so a harness that
//! presented only some of them left the rest enforced NOWHERE.
//!
//! WHAT IT DOES NOT PROVE:
//!
//! - **That the verifier checks the key is ON THE CURVE**, which [`crate::jwt::JwsVerifier`]
//!   requires and which [`crate::jwt::Jwk`] deliberately does not do for it. The off-curve
//!   key IS presented, so a verifier that decodes the point with an `unwrap` is caught, and that is
//!   the failure that actually reaches production. What stays invisible is the quiet half: handed
//!   an off-curve key and any signature, a verifier that VALIDATES and one that merely fails to
//!   verify both answer `false`, and telling them apart needs a signature forged on the curve's
//!   twist, which means the very arithmetic this crate stopped shipping. Use a backend whose point
//!   decoding validates (`p256`'s does) or read the one that does not.
//!
//! - **Nothing about the private key's protection.** A green run says the arithmetic is right, not
//!   that the key is in an HSM, not that it is non-exportable, not that the IAM policy around it
//!   is sound. Those are deployment properties and this crate cannot see them.
//! - **Nothing about side channels.** Verification here is over public data, so there is nothing
//!   to leak; signing is the host's, and whether it is constant time is a property of the backend.
//! - **Nothing about availability.** A signer that works once may be rate limited at ten times the
//!   throughput, and a KMS round trip is on the token issuance path.
//! - **Nothing about nonce quality.** ECDSA with a repeated or biased per-signature nonce leaks
//!   the private key (CVE-2013-2094's cousin, and the PlayStation 3 defect), and a black-box
//!   harness cannot see it. Prefer a backend that implements RFC 6979 deterministic ECDSA or that
//!   documents its nonce source.
//!
//! # Cost when you do not enable it
//!
//! Nothing. `test-util` adds no dependency and no code to a default build; the whole module is
//! behind the feature.

use std::fmt;
use std::future::Future as _;
use std::panic::AssertUnwindSafe;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::jwt::{Jwk, JwsAlg, JwsSigner, JwsVerifier, OkpCurve, SignerError};

/// One way in which a signer or a verifier failed its contract.
///
/// `check` is one of [`CHECKS`], so a host can group, filter or waive by a stable name; `detail`
/// says what was observed and what was required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// The check that failed; always a member of [`CHECKS`].
    pub check: &'static str,
    /// What went wrong, in terms of what was produced and what was required.
    pub detail: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.check, self.detail)
    }
}

/// Every check name [`SignerConformance::run`] can report, so a host can assert that a name it
/// filters on still exists rather than silently waiving a check that was renamed.
pub const CHECKS: &[&str] = &[
    VERIFIER_RFC7515_A3,
    VERIFIER_REJECTS_A_FOREIGN_KEY,
    VERIFIER_REJECTS_A_TAMPERED_INPUT,
    VERIFIER_REJECTS_A_TAMPERED_SIGNATURE,
    VERIFIER_REJECTS_DER,
    VERIFIER_REJECTS_A_WRONG_LENGTH_SIGNATURE,
    VERIFIER_DOES_NOT_PANIC,
    SIGNER_SIGNS,
    SIGNER_DOES_NOT_PANIC,
    SIGNER_IS_NOT_DER,
    SIGNER_VERIFIES_UNDER_ITS_OWN_JWK,
    SIGNER_REJECTED_BY_ANOTHER_KEY,
    SIGNER_BINDS_THE_SIGNING_INPUT,
    SIGNER_PUBLIC_JWK_IS_STABLE,
    SIGNER_PUBLIC_JWK_IS_ES256,
    SIGNER_PUBLIC_JWK_HAS_A_KID,
    SIGNER_IS_NOT_THE_PUBLISHED_EXAMPLE_KEY,
];

const VERIFIER_RFC7515_A3: &str = "verifier/rfc7515_appendix_a3_vector";
const VERIFIER_REJECTS_A_FOREIGN_KEY: &str = "verifier/rejects_a_foreign_key";
const VERIFIER_REJECTS_A_TAMPERED_INPUT: &str = "verifier/rejects_a_tampered_signing_input";
const VERIFIER_REJECTS_A_TAMPERED_SIGNATURE: &str = "verifier/rejects_a_tampered_signature";
const VERIFIER_REJECTS_DER: &str = "verifier/rejects_the_der_encoding";
const VERIFIER_REJECTS_A_WRONG_LENGTH_SIGNATURE: &str = "verifier/rejects_a_wrong_length_signature";
const VERIFIER_DOES_NOT_PANIC: &str = "verifier/does_not_panic";
const SIGNER_SIGNS: &str = "signer/signs";
const SIGNER_DOES_NOT_PANIC: &str = "signer/does_not_panic";
const SIGNER_IS_NOT_DER: &str = "signer/output_is_not_der";
const SIGNER_VERIFIES_UNDER_ITS_OWN_JWK: &str = "signer/verifies_under_its_own_public_jwk";
const SIGNER_REJECTED_BY_ANOTHER_KEY: &str = "signer/does_not_verify_under_another_key";
const SIGNER_BINDS_THE_SIGNING_INPUT: &str = "signer/binds_the_signing_input";
const SIGNER_PUBLIC_JWK_IS_STABLE: &str = "signer/public_jwk_is_stable";
const SIGNER_PUBLIC_JWK_IS_ES256: &str = "signer/public_jwk_is_an_es256_p256_key";
const SIGNER_PUBLIC_JWK_HAS_A_KID: &str = "signer/public_jwk_has_a_kid";
const SIGNER_IS_NOT_THE_PUBLISHED_EXAMPLE_KEY: &str = "signer/is_not_the_published_example_key";

// ------------------------------------------------------------------ the RFC 7515 A.3 vector

/// The JWS Signing Input of RFC 7515 appendix A.3: `BASE64URL(header) "." BASE64URL(payload)` for
/// the appendix's `{"alg":"ES256"}` header and its example claim set.
///
/// Quoted from the RFC rather than recomputed, which is the same discipline
/// `crates/oauth-as-conformance` applies to its vectors: a vector this repository derived from its
/// own code proves only that the code agrees with itself.
const A3_SIGNING_INPUT: &str = concat!(
    "eyJhbGciOiJFUzI1NiJ9",
    ".",
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
);

/// The `x` coordinate of the appendix A.3 key (RFC 7515 appendix A.3.1).
const A3_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
/// The `y` coordinate of the appendix A.3 key.
const A3_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

/// The appendix A.3 signature, base64url, which is the 64-byte fixed-width `R || S` of RFC 7518
/// section 3.4.
const A3_SIGNATURE: &str =
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

/// A valid ES256 signature whose FIRST BYTE IS ZERO, with the key and message it was made over.
///
/// It exists for exactly one case in [`SignerConformance::check_wrong_length_signatures`], and the
/// leading zero is the whole point. A verifier that LEFT-PADS a short signature up to 64 bytes is
/// undetectable with a truncation of any ordinary signature, because padding a truncation back out
/// produces a different 64 bytes that verify under nothing. Strip the leading ZERO byte from this
/// one and the 63 bytes that remain pad back to exactly the signature that made them, so a padding
/// verifier answers `true` and a conforming verifier answers `false`. Nothing else can tell the
/// two apart from outside.
///
/// Generated here rather than quoted from an RFC, because no RFC prints a vector chosen for this
/// property, and the choosing is what makes it useful. That it is genuinely valid is not taken on
/// trust: `tests/signer_conformance_selftest.rs` drives a verifier that pads short signatures and
/// REJECTS long ones, which no case in this file can catch except this one, and asserts on the
/// reported detail rather than on the check name. A wrong constant fails that test.
///
/// Both halves of that arrangement were bought with a defect. The padding fault used to truncate
/// long inputs as well, so the 65-byte case below caught it, and the selftest asserted only that
/// the check name appeared: `verifier/rejects_a_wrong_length_signature` went red without these
/// four constants ever being consulted, a typo in any of them was invisible, and a backend that
/// left-pads short signatures while handling long ones correctly passed. The signature is
/// deterministic (RFC 6979), so it is reproducible from the message and the scalar `[3u8; 32]`.
const LEADING_ZERO_X: &str = "WRq3ceu8_W2cuQlNEGUordGmnUTCwfYn8InsWLnGGt8";
const LEADING_ZERO_Y: &str = "n05qvw0EXAxpOjxorXyXynK-ZN70om_s0mPdmKkngPA";
const LEADING_ZERO_INPUT: &str = "oauth-as.signer-conformance.leading-zero.250";
const LEADING_ZERO_SIGNATURE: &str =
    "ABYodUnuRFUgxNDUB00nlZCrb6c1obObltfhhXjcK115K8XgwahkHOzKfoLF_A_RxR9Oj31_WVjYyXl7-xEuTg";

/// A second well-formed P-256 public key, used as the key a signature must NOT verify under.
///
/// The RFC's own key is not reused for that job: a host whose signer IS the appendix key would
/// then pass the foreign-key check for the worst possible reason, so that case is reported by
/// [`SIGNER_IS_NOT_THE_PUBLISHED_EXAMPLE_KEY`] instead. These coordinates are RFC 7517 appendix
/// A.1's example EC public key.
const OTHER_X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
const OTHER_Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";

/// A pair of coordinates of the RIGHT WIDTH that is NOT a point on P-256: the appendix A.3 key's
/// `x` with its `y` altered in the lowest bit.
///
/// This is not a hypothetical input. [`crate::jwt::Jwk::from_json`] checks `kty`, `crv` and
/// that each coordinate is exactly 32 bytes, and deliberately does NOT check the curve equation,
/// because doing so would mean this crate carrying the arithmetic the [`JwsVerifier`] seam exists
/// to externalise. RFC 9449 section 4.3 hands the `jwk` straight out of a DPoP proof header, so
/// these 64 bytes are whatever an unauthenticated client typed, and a verifier written
/// `VerifyingKey::from_sec1_bytes(&sec1).unwrap()` PANICS on them while passing every other check
/// in this file. `y ^ 1` rather than random bytes because it is checkable by inspection: for a
/// point on the curve the only other `y` over the same `x` is `p - y`, which differs in nearly
/// every bit, so a one-bit change cannot land back on the curve.
const OFF_CURVE_X: &str = A3_X;
const OFF_CURVE_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a4";

/// The two signing inputs the signer is asked for. They must differ, since
/// [`SIGNER_BINDS_THE_SIGNING_INPUT`] is exactly the check that one signature does not cover the
/// other. Deliberately NOT valid JWS signing inputs: a signer that inspects what it is asked to
/// sign, rather than signing it, is a signer with an opinion it has no business having.
const INPUT_A: &str = "oauth-as.signer-conformance.a";
const INPUT_B: &str = "oauth-as.signer-conformance.b";

// ------------------------------------------------------------------ the RS256 vector (RFC 7515 A.2)

/// The JWS Signing Input of RFC 7515 appendix A.2: `{"alg":"RS256"}` over the appendix's claim set.
/// Quoted from the RFC, the same discipline as the A.3 ES256 vector above.
const A2_SIGNING_INPUT: &str = concat!(
    "eyJhbGciOiJSUzI1NiJ9",
    ".",
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
);
/// The RFC 7515 appendix A.2 RSA public key modulus `n` (RFC 7518 base64urlUInt); `e` is `AQAB`.
const A2_N: &str = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";
/// The RFC 7518 exponent shared by both RSA keys below (`AQAB` == 65537).
const RSA_E: &str = "AQAB";
/// The RFC 7515 appendix A.2 signature (256 bytes / 2048-bit modulus, base64url).
const A2_SIGNATURE: &str = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
/// A second, well-formed 2048-bit RSA public key, used as the key an A.2 signature must NOT verify
/// under. Generated offline; its private half is not this crate's, so it can only ever reject. The
/// A.2 key is not reused for this job (that would pass the foreign-key check for the worst reason:
/// a host whose signer IS the RFC example key), which is reported under its own check instead.
const OTHER_RSA_N: &str = "4-QFArXj8EHf7YtUPQelHj3thYoTF0_9V1onh-E-UeHXjJoFS1Mfw_LKNhJD_lwHdefGCSdVuMGtFeXUNtN0XTA9_Z4Q2YSS0mVo_HM25e_phlKkk6Nxy7JfmSnto0O-enYCSIJx4MJ2NOqvpZrv0C8HRSilH5PJ9b82jnxV4n2153xQsTNBIVc5N9McB3TIF1zYh3O3h1fGfP3JsR6qLQerehoJc8FQ9bD_0y2CEpHLaeYn6qgv279-dQo-wuw3Xsj8loaqZW0WPyhjE9TZsaMM9SR3J7RBUf2fKvqki7tgIuiZQ7J0XeJ3rdsPsmF1hP7Muvre1MtPmeC_7VDlKQ";

// ------------------------------------------------------------------ the EdDSA vector (RFC 8037 A.4)

/// The JWS Signing Input of RFC 8037 appendix A.4: `{"alg":"EdDSA"}` over the payload
/// `Example of Ed25519 signing`. Quoted from the RFC.
const A4_SIGNING_INPUT: &str = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
/// The RFC 8037 appendix A.4 Ed25519 public key `x` (32 bytes, base64url).
const A4_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
/// The RFC 8037 appendix A.4 signature (64 bytes, base64url).
const A4_SIGNATURE: &str =
    "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";
/// A second, well-formed Ed25519 public key (RFC 8032 section 7.1 test 2), used as the foreign key,
/// for the same reason the A.4 key is not reused for it.
const OTHER_OKP_X: &str = "PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw";

/// The published RFC known-answer vector for one algorithm, plus a same-KIND foreign key the
/// signature must not verify under. [`SignerConformance::run`] selects one of these on the signer's
/// own [`JwsSigner::alg`], so an RS256 or EdDSA backend is held to its own RFC vector rather than to
/// the ES256 one.
struct AlgProfile {
    /// The JWS Signing Input the vector signs.
    signing_input: &'static [u8],
    /// The public key the vector verifies under.
    vector_key: Jwk,
    /// The RFC vector's signature octets.
    vector_signature: Vec<u8>,
    /// A second, well-formed key of the SAME kind, under which the vector must NOT verify.
    foreign_key: Jwk,
}

fn rsa_jwk(n: &str) -> Jwk {
    Jwk::Rsa {
        n: n.to_string(),
        e: RSA_E.to_string(),
        kid: None,
    }
}

fn okp_jwk(x: &str) -> Jwk {
    Jwk::Okp {
        crv: OkpCurve::Ed25519,
        x: x.to_string(),
        kid: None,
    }
}

/// The [`AlgProfile`] for `alg`. Its constants are quoted from the cited RFC, so neither side of a
/// host's deployment produced the vector it is checked against.
fn alg_profile(alg: JwsAlg) -> AlgProfile {
    match alg {
        JwsAlg::Es256 => AlgProfile {
            signing_input: A3_SIGNING_INPUT.as_bytes(),
            vector_key: jwk(A3_X, A3_Y),
            vector_signature: decode(A3_SIGNATURE),
            foreign_key: jwk(OTHER_X, OTHER_Y),
        },
        JwsAlg::Rs256 => AlgProfile {
            signing_input: A2_SIGNING_INPUT.as_bytes(),
            vector_key: rsa_jwk(A2_N),
            vector_signature: decode(A2_SIGNATURE),
            foreign_key: rsa_jwk(OTHER_RSA_N),
        },
        JwsAlg::EdDsa => AlgProfile {
            signing_input: A4_SIGNING_INPUT.as_bytes(),
            vector_key: okp_jwk(A4_X),
            vector_signature: decode(A4_SIGNATURE),
            foreign_key: okp_jwk(OTHER_OKP_X),
        },
    }
}

/// The [`JwsSigner`] and [`JwsVerifier`] conformance harness. See the module docs, in
/// particular the honest account of what a green run does not prove.
pub struct SignerConformance<S, V> {
    signer: S,
    verifier: V,
}

impl<S: JwsSigner, V: JwsVerifier> SignerConformance<S, V> {
    /// Build a harness over the backend a host is about to install.
    ///
    /// BOTH halves, together, because that is how they are deployed and because the interesting
    /// failure is disagreement between them: a signer and a verifier that are each self-consistent
    /// and wrong in the same direction pass every check either one could run alone. The RFC 7515
    /// appendix A.3 vector is what makes that impossible here, since neither side produced it.
    pub fn new(signer: S, verifier: V) -> Self {
        SignerConformance { signer, verifier }
    }

    /// Run every check in [`CHECKS`] and return what failed. An empty vector is a pass.
    pub async fn run(&self) -> Vec<Violation> {
        let mut out = Vec::new();
        match self.signer.alg() {
            // ES256 carries encoding hazards RS256 and EdDSA do not: the ASN.1 DER versus
            // fixed-width `r || s` ambiguity of RFC 7518 s3.4, and an off-curve public key. Its
            // verifier checks are their own routine (below); RS256 and EdDSA share the
            // algorithm-independent core, selected by the signer's own algorithm.
            JwsAlg::Es256 => self.check_verifier(&mut out),
            JwsAlg::Rs256 | JwsAlg::EdDsa => {
                let profile = alg_profile(self.signer.alg());
                self.check_verifier_generic(&profile, &mut out);
            }
        }
        self.check_signer(&mut out).await;
        out
    }

    // ------------------------------------------------------------------------ the verifier

    /// EVERY call this harness makes to the verifier under test goes through here, and a PANIC is
    /// reported as [`VERIFIER_DOES_NOT_PANIC`] rather than being allowed to end the run.
    ///
    /// Two reasons it is not enough to simply call `verify`. A host runs this harness from its own
    /// test suite, and a panic there aborts the whole test binary, so the one line the host needs
    /// ("your verifier panicked on a zero-length signature") arrives as a stack trace in the middle
    /// of an unrelated failure, if it arrives at all. And a verifier that panics has broken the
    /// contract whatever it would have RETURNED, so the harness has to keep going to report the
    /// rest.
    ///
    /// `AssertUnwindSafe` is required and is honest here: `V` is a host type this harness never
    /// mutates, the harness's own state across the boundary is `&self` plus a `&mut Vec` it only
    /// appends to, and the run ends in a returned value rather than in any state a caller could
    /// observe half-updated.
    ///
    /// A panic is treated as `false` for the purpose of the check that made the call. That is the
    /// reading that cannot invent a pass: a check asking "did this WRONGLY verify?" gets `false`
    /// and stays quiet, since the real defect is already reported under its own name; a check
    /// asking "did this verify?" gets `false` and goes red, which is correct, because a verifier
    /// that panics did not verify anything.
    ///
    /// Under `panic = "abort"` there is nothing to catch and the host's test binary dies on the
    /// spot. That is a build the host chose, and it is still a louder failure than shipping.
    fn verify(
        &self,
        context: &str,
        key: &Jwk,
        signing_input: &[u8],
        signature: &[u8],
        out: &mut Vec<Violation>,
    ) -> bool {
        let called = std::panic::catch_unwind(AssertUnwindSafe(|| {
            self.verifier.verify(key, signing_input, signature)
        }));
        match called {
            Ok(verified) => verified,
            Err(_) => {
                // ONE violation per run, naming the FIRST input that panicked. Six checks feeding
                // one panicking verifier would otherwise report six times and bury the length that
                // mattered.
                if !out.iter().any(|v| v.check == VERIFIER_DOES_NOT_PANIC) {
                    out.push(Violation {
                        check: VERIFIER_DOES_NOT_PANIC,
                        detail: format!(
                            "the verifier PANICKED on {context} ({} signature bytes, {} \
                             signing-input bytes). `signature` is the third segment of a JWS an \
                             unauthenticated client sent, base64url-decoded, and nothing checks \
                             its length before you see it: `signature[..64]` and \
                             `Signature::from_slice(&signature[..64])` both panic on the empty \
                             slice a token ending in a bare '.' produces. Test the length, or use \
                             `signature.try_into()` into a [u8; 64]. `key` is no safer: its \
                             coordinates are width-checked and NOT curve-checked, so \
                             `VerifyingKey::from_sec1_bytes(&sec1).unwrap()` panics on the jwk of \
                             a DPoP proof anyone can send. Every input must return false instead",
                            signature.len(),
                            signing_input.len()
                        ),
                    });
                }
                false
            }
        }
    }

    fn check_verifier(&self, out: &mut Vec<Violation>) {
        let key = jwk(A3_X, A3_Y);
        let signature = decode(A3_SIGNATURE);

        // The known-answer test. A verifier that fails this is wrong in a way no amount of
        // agreement with the host's own signer would reveal.
        if !self.verify(
            "the RFC 7515 A.3 vector",
            &key,
            A3_SIGNING_INPUT.as_bytes(),
            &signature,
            out,
        ) {
            out.push(Violation {
                check: VERIFIER_RFC7515_A3,
                detail: "the RFC 7515 appendix A.3 ES256 vector did not verify. Either the \
                         verifier is not ES256 (ECDSA/P-256/SHA-256), or it expects a signature \
                         encoding other than the 64-byte fixed-width R || S of RFC 7518 s3.4"
                    .to_string(),
            });
        }

        // The three rejections. Each one is a separate check because they fail for different
        // reasons and a verifier can get one right and the others wrong: an implementation that
        // ignores the key, one that ignores the message, and one that ignores the signature are
        // three different defects with three different blast radii.
        if self.verify(
            "the A.3 vector under a foreign key",
            &jwk(OTHER_X, OTHER_Y),
            A3_SIGNING_INPUT.as_bytes(),
            &signature,
            out,
        ) {
            out.push(Violation {
                check: VERIFIER_REJECTS_A_FOREIGN_KEY,
                detail: "a valid signature verified under a DIFFERENT public key. The verifier is \
                         not using the key it was given, so every signature verifies under every \
                         key and no token is bound to any issuer"
                    .to_string(),
            });
        }

        let mut tampered = A3_SIGNING_INPUT.as_bytes().to_vec();
        // The LAST byte, which is inside the payload segment: a verifier that hashes a prefix of
        // its input (a fixed length, a truncation) still covers the header and would pass a check
        // that flipped a byte near the front.
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        if self.verify("a tampered signing input", &key, &tampered, &signature, out) {
            out.push(Violation {
                check: VERIFIER_REJECTS_A_TAMPERED_INPUT,
                detail: "a signature verified over a signing input that was not the one signed. \
                         The verifier is not covering the whole message, so a token's claims can \
                         be edited without invalidating it"
                    .to_string(),
            });
        }

        let mut bad_signature = signature.clone();
        bad_signature[0] ^= 0x01;
        if self.verify(
            "a byte-flipped signature",
            &key,
            A3_SIGNING_INPUT.as_bytes(),
            &bad_signature,
            out,
        ) {
            out.push(Violation {
                check: VERIFIER_REJECTS_A_TAMPERED_SIGNATURE,
                detail: "a corrupted signature verified. The verifier is not checking the \
                         signature at all, which makes every unsigned token a valid one"
                    .to_string(),
            });
        }

        // RFC 7518 s3.4 admits exactly ONE encoding. A verifier that also accepts DER gives one
        // signature two spellings, which is signature malleability: a value a deployment recorded
        // as a unique identifier (a replay cache key, an audit line) stops being unique.
        if self.verify(
            "the DER re-encoding of a valid signature",
            &key,
            A3_SIGNING_INPUT.as_bytes(),
            &der(&signature),
            out,
        ) {
            out.push(Violation {
                check: VERIFIER_REJECTS_DER,
                detail: "the ASN.1 DER encoding of a valid signature verified. RFC 7518 s3.4 \
                         fixes ES256 as the 64-byte fixed-width R || S and admits no other \
                         encoding; accepting both gives one signature two forms"
                    .to_string(),
            });
        }

        // THE OTHER TWO INPUTS THE CONTRACT NAMES. `JwsVerifier`'s MUST NOT PANIC clause lists
        // five: a zero-length signature, a 63-byte one, a 65-byte one, an OFF-CURVE KEY, and an
        // EMPTY SIGNING INPUT. The lengths are below; these two are here, and until they were
        // presented a verifier could panic on either one and collect a green run from this file.
        //
        // Both are unauthenticated-reachable. The key is the `jwk` member of a DPoP proof header,
        // which `Jwk::from_json` width-checks and does not curve-check; the signing input is
        // empty for a JWS whose first two segments are empty, which parses.
        //
        // A `true` here is reported under the rejection check it violates rather than under a name
        // of its own, because that is what it means: a signature that verifies under a point that
        // is not on the curve verified under a key that did not produce it, and one that verifies
        // over no bytes at all verified over a message that was not signed.
        if self.verify(
            "an OFF-CURVE key of the correct coordinate width",
            &jwk(OFF_CURVE_X, OFF_CURVE_Y),
            A3_SIGNING_INPUT.as_bytes(),
            &signature,
            out,
        ) {
            out.push(Violation {
                check: VERIFIER_REJECTS_A_FOREIGN_KEY,
                detail: "a signature verified under coordinates that are NOT a point on P-256. \
                         Jwk only width-checks the coordinates, so the curve check is the \
                         verifier's, and it is what an invalid-curve attack needs to find missing"
                    .to_string(),
            });
        }

        if self.verify("an EMPTY signing input", &key, &[], &signature, out) {
            out.push(Violation {
                check: VERIFIER_REJECTS_A_TAMPERED_INPUT,
                detail: "a valid 64-byte signature verified over an EMPTY signing input. The \
                         verifier is not hashing the message it was handed, so a signature made \
                         over one token is good for every other"
                    .to_string(),
            });
        }

        self.check_wrong_length_signatures(&key, &signature, out);
    }

    /// THE LENGTHS NOBODY ELSE PRESENTS. Every check above hands the verifier 64 bytes or more (the
    /// A.3 vector, three corruptions of it that are still 64 bytes, and a DER form that is 70 to
    /// 72), so a verifier that indexes `signature[..64]` and PANICS, or that pads a short input up
    /// to 64 and ACCEPTS it, passed all of them and shipped.
    ///
    /// That was the harness failing at exactly its own stated purpose. The host's backend is
    /// unreachable from this crate's tests, so an obligation this harness does not exercise is
    /// enforced NOWHERE, and the obligation in question is the one [`crate::jwt::JwsVerifier`]
    /// states most explicitly. Worse, it is the obligation whose input is reachable by anyone:
    /// `signature` is the third JWS segment base64url-decoded, so a DPoP proof, a request object or
    /// a client assertion ending in a bare `.` hands the verifier a ZERO-LENGTH slice, and a 4
    /// kilobyte DPoP header can hand it three thousand bytes.
    ///
    /// The cases are DERIVED FROM THE VALID SIGNATURE rather than made of random bytes, so the only
    /// thing wrong with each one is its length: a verifier that rejects them for being noise would
    /// prove nothing about a verifier that pads. Every one must be `false`.
    fn check_wrong_length_signatures(&self, key: &Jwk, signature: &[u8], out: &mut Vec<Violation>) {
        // 65 bytes is the valid signature with one trailing zero, which is what an encoder that
        // emits a length prefix or a DER-style sign pad produces; a verifier that reads a 64-byte
        // PREFIX and ignores the rest accepts it.
        let mut too_long = signature.to_vec();
        too_long.push(0x00);

        // The padding case needs its OWN key and message: see `LEADING_ZERO_SIGNATURE` for why no
        // truncation of the A.3 vector can catch a verifier that left-pads.
        let padding_key = jwk(LEADING_ZERO_X, LEADING_ZERO_Y);
        let leading_zero = decode(LEADING_ZERO_SIGNATURE);
        let a3 = A3_SIGNING_INPUT.as_bytes();

        let cases: [(&str, &Jwk, &[u8], &[u8]); 6] = [
            // The one that arrives from the wire for free: a token ending in a bare `.`.
            ("0 bytes (an empty third JWS segment)", key, a3, &[]),
            ("1 byte", key, a3, &signature[..1]),
            ("32 bytes (R alone, S missing)", key, a3, &signature[..32]),
            (
                "63 bytes (a valid signature, truncated by one)",
                key,
                a3,
                &signature[..63],
            ),
            (
                "63 bytes (a valid signature with its LEADING ZERO byte removed, which a verifier \
                 that left-pads back up to 64 reconstructs exactly)",
                &padding_key,
                LEADING_ZERO_INPUT.as_bytes(),
                &leading_zero[1..],
            ),
            (
                "65 bytes (a valid signature plus a trailing zero)",
                key,
                a3,
                &too_long,
            ),
        ];

        for (description, case_key, case_input, wrong) in cases {
            if self.verify(
                &format!("a wrong-length signature of {description}"),
                case_key,
                case_input,
                wrong,
                out,
            ) {
                out.push(Violation {
                    check: VERIFIER_REJECTS_A_WRONG_LENGTH_SIGNATURE,
                    detail: format!(
                        "a signature of {description} VERIFIED. RFC 7518 s3.4 fixes the ES256 \
                         signature at exactly 64 bytes of fixed-width R || S, so anything else \
                         must be false. A verifier that pads a short input up to 64, or that \
                         reads a 64-byte prefix and ignores the rest, gives a valid signature \
                         many spellings and accepts values the signer never produced"
                    ),
                });
            }
        }
    }

    /// The RS256/EdDSA verifier routine: the algorithm-independent core of [`check_verifier`], run
    /// against the profile's published RFC vector. It presents the known-answer test, the same
    /// three rejections (a foreign key, a tampered signing input, a tampered signature), the empty
    /// signing input, and three wrong LENGTHS (zero, one short, one long). It omits the two checks
    /// that are meaningful only for ES256: the DER re-encoding (RS256 and EdDSA have a single
    /// canonical signature form, no DER-versus-raw ambiguity) and the off-curve key (RSA has no
    /// curve, and an Ed25519 point is validated by the verifier's own decode).
    fn check_verifier_generic(&self, profile: &AlgProfile, out: &mut Vec<Violation>) {
        let key = &profile.vector_key;
        let signature = &profile.vector_signature;
        let input = profile.signing_input;
        let alg = self.signer.alg().jose_name();

        // The known-answer test, from a vector neither side of the deployment produced.
        if !self.verify(
            "the published RFC known-answer vector",
            key,
            input,
            signature,
            out,
        ) {
            out.push(Violation {
                check: VERIFIER_RFC7515_A3,
                detail: format!(
                    "the published {alg} RFC known-answer vector did not verify. Either the \
                     verifier is not {alg}, or it expects a signature encoding this crate does not \
                     produce"
                ),
            });
        }

        // The three rejections: a key it should not use, a message it should cover, a signature it
        // should check. Each is a separate defect with a separate blast radius.
        if self.verify(
            "the vector under a foreign key",
            &profile.foreign_key,
            input,
            signature,
            out,
        ) {
            out.push(Violation {
                check: VERIFIER_REJECTS_A_FOREIGN_KEY,
                detail:
                    "a valid signature verified under a DIFFERENT public key of the same kind. \
                         The verifier is not using the key it was given, so no token is bound to \
                         any issuer"
                        .to_string(),
            });
        }

        let mut tampered = input.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        if self.verify("a tampered signing input", key, &tampered, signature, out) {
            out.push(Violation {
                check: VERIFIER_REJECTS_A_TAMPERED_INPUT,
                detail: "a signature verified over a signing input that was not the one signed. \
                         The verifier is not covering the whole message, so a token's claims can \
                         be edited without invalidating it"
                    .to_string(),
            });
        }

        let mut bad_signature = signature.clone();
        bad_signature[0] ^= 0x01;
        if self.verify("a byte-flipped signature", key, input, &bad_signature, out) {
            out.push(Violation {
                check: VERIFIER_REJECTS_A_TAMPERED_SIGNATURE,
                detail: "a corrupted signature verified. The verifier is not checking the \
                         signature at all, which makes every unsigned token a valid one"
                    .to_string(),
            });
        }

        // The empty signing input a JWS whose first two segments are empty produces.
        if self.verify("an EMPTY signing input", key, &[], signature, out) {
            out.push(Violation {
                check: VERIFIER_REJECTS_A_TAMPERED_INPUT,
                detail: "a valid signature verified over an EMPTY signing input. The verifier is \
                         not hashing the message it was handed, so a signature made over one token \
                         is good for every other"
                    .to_string(),
            });
        }

        // Wrong LENGTHS, derived from the valid signature so the only thing wrong with each is its
        // length. A fixed-width scheme (EdDSA: 64 bytes) and RS256 (the modulus length) both admit
        // exactly one width; the zero-length case is the one a token ending in a bare `.` produces.
        let mut too_long = signature.clone();
        too_long.push(0x00);
        let truncated = &signature[..signature.len() - 1];
        let cases: [(&str, &[u8]); 3] = [
            ("0 bytes (an empty third JWS segment)", &[]),
            ("the valid signature truncated by one byte", truncated),
            ("the valid signature with a trailing zero byte", &too_long),
        ];
        for (description, wrong) in cases {
            if self.verify(
                &format!("a wrong-length signature: {description}"),
                key,
                input,
                wrong,
                out,
            ) {
                out.push(Violation {
                    check: VERIFIER_REJECTS_A_WRONG_LENGTH_SIGNATURE,
                    detail: format!(
                        "a signature of {description} VERIFIED. A {alg} signature has one width \
                         (64 bytes for EdDSA; the RSA modulus length for RS256), so anything else \
                         must be false"
                    ),
                });
            }
        }
    }

    // -------------------------------------------------------------------------- the signer

    /// EVERY call this harness makes to the signer under test goes through here, and a PANIC is
    /// reported as [`SIGNER_DOES_NOT_PANIC`] and then handed on as an `Err`.
    ///
    /// [`crate::jwt::JwsSigner::sign`] says "**MUST NOT PANIC, for any input, ever**" and says
    /// why: a panic unwinds out of `JwtConfig::sign_access_token` and into the host's token
    /// endpoint, where a runtime that aborts takes the whole server down and one that does not
    /// leaves a poisoned task. Until this existed, that clause was checked NOWHERE — the verifier
    /// had `SignerConformance::verify` and the signer was called bare — and the reasons given
    /// there apply here with a larger blast radius: a panic in the host's test suite aborts the
    /// test binary, so the one line the host needs arrives as a stack trace in the middle of an
    /// unrelated failure, and a signer that panicked has broken the contract whatever it would
    /// have returned, so the harness has to keep going to report the rest.
    ///
    /// TWO catches, because a `sign` returning `impl Future` has two places to panic and an
    /// implementor's `unwrap` is as likely to sit in either: the synchronous part that BUILDS the
    /// future (where a KMS client marshals its request) and the poll (where it reads the response).
    /// The future is boxed so the second catch needs no `unsafe`; this crate forbids it, and one
    /// allocation per signature in a conformance harness is not worth a pin projection.
    ///
    /// `AssertUnwindSafe` is honest for the same reasons it is on the verifier: `S` is a host type
    /// this harness never mutates and the run ends in a returned value rather than in state a
    /// caller could observe half-updated.
    ///
    /// The panic is then returned as `Err`, so [`SIGNER_SIGNS`] reports it too and the run stops
    /// where it stops for a signer that refused. Nothing below a missing signature can be checked,
    /// and a cascade of failures caused by one absent signature would bury the fact worth reading.
    async fn sign(
        &self,
        context: &str,
        signing_input: &[u8],
        out: &mut Vec<Violation>,
    ) -> Result<Vec<u8>, SignerError> {
        let built = std::panic::catch_unwind(AssertUnwindSafe(|| {
            Box::pin(self.signer.sign(signing_input))
        }));
        let signed = match built {
            Ok(mut future) => {
                std::future::poll_fn(move |cx| {
                    match std::panic::catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
                        Ok(polled) => polled.map(Some),
                        Err(_) => std::task::Poll::Ready(None),
                    }
                })
                .await
            }
            Err(_) => None,
        };
        match signed {
            // The wire octets, whatever their width: 64 bytes for ES256/EdDSA, the modulus length
            // for RS256. The per-algorithm width contract is enforced by the wrong-length checks and
            // by verification, not here, so this returns the bytes as produced.
            Some(Ok(signature)) => Ok(signature.as_bytes().to_vec()),
            Some(Err(e)) => Err(e),
            None => {
                out.push(Violation {
                    check: SIGNER_DOES_NOT_PANIC,
                    detail: format!(
                        "the signer PANICKED while signing {context} ({} signing-input bytes). \
                         Every failure you can have (the KMS was unreachable, the key was \
                         disabled, the credential expired, the response was the wrong length or \
                         the wrong encoding) is an Err(SignerError), which this crate turns into \
                         an RFC 6749 s5.2 server_error. A panic instead unwinds into the host's \
                         token endpoint, and the deployment loses more than the one request",
                        signing_input.len()
                    ),
                });
                Err(SignerError::new("the signer panicked"))
            }
        }
    }

    async fn check_signer(&self, out: &mut Vec<Violation>) {
        let profile = alg_profile(self.signer.alg());
        let published = self.signer.public_jwk();

        // Shape first, because every check below reads this key and a malformed one would make
        // their failures unreadable.
        self.check_published_key(&published, out);

        // RFC 7515 s4.1.4: the `kid` is what lets a verifier SELECT rather than trial, and it is
        // what makes `JwtConfig::rotate_to` non-destructive. A signer with no name for its key
        // gives a deployment no rotation story at all.
        if published.kid().unwrap_or_default().is_empty() {
            out.push(Violation {
                check: SIGNER_PUBLIC_JWK_HAS_A_KID,
                detail: "public_jwk().kid is empty. Every token this server signs carries it \
                         (RFC 7515 s4.1.4), and key rotation selects on it"
                    .to_string(),
            });
        }

        // Section 3.2.1 of the design this seam implements: `public_jwk()` is SYNC precisely so
        // that the implementor caches it at construction. One that varies between calls is one
        // that is fetching, or generating, per call: `JwtConfig` reads it ONCE, so a value that
        // drifts afterwards is a JWKS document that no longer describes the signing key.
        if self.signer.public_jwk() != published {
            out.push(Violation {
                check: SIGNER_PUBLIC_JWK_IS_STABLE,
                detail: "public_jwk() returned two different keys on two calls. It must return a \
                         value cached at construction: JwtConfig reads it once, so a key that \
                         changes afterwards is advertised nowhere"
                    .to_string(),
            });
        }

        // The RFC's own example key has its PRIVATE half printed in the appendix. A deployment
        // signing with it is not signing with anything. The comparison is per algorithm: the ES256
        // example is RFC 7515 A.3, RS256 is RFC 7515 A.2, EdDSA is RFC 8037 A.4.
        let is_published_example_key = match self.signer.alg() {
            JwsAlg::Es256 => published.x() == A3_X && published.y() == A3_Y,
            JwsAlg::Rs256 => {
                matches!(&published, Jwk::Rsa { n, e, .. } if n.as_str() == A2_N && e.as_str() == RSA_E)
            }
            JwsAlg::EdDsa => matches!(&published, Jwk::Okp { x, .. } if x.as_str() == A4_X),
        };
        if is_published_example_key {
            out.push(Violation {
                check: SIGNER_IS_NOT_THE_PUBLISHED_EXAMPLE_KEY,
                detail: "the signing key is the published RFC example key, whose private half is \
                         printed in the RFC. Anyone can forge every token this server issues"
                    .to_string(),
            });
        }

        // Bound to a local before the `match`, so that the `&mut out` the call borrows is released
        // before the arms use it again.
        let signed = self.sign("the first input", INPUT_A.as_bytes(), out).await;
        let signature = match signed {
            Ok(signature) => signature,
            Err(e) => {
                // Nothing below can run, and reporting a cascade of failures caused by one absent
                // signature would bury the one fact worth reading.
                out.push(Violation {
                    check: SIGNER_SIGNS,
                    detail: format!("the signer refused to sign: {e}"),
                });
                return;
            }
        };

        // The DER mistake, named explicitly rather than left to show up as a verification
        // failure, because "your signature does not verify" sends an implementor looking at their
        // key and this sends them to their encoder.
        //
        // A DER ES256 signature is `30 LL 02 <len> r... 02 <len> s...`, and a P-256 one is 70 to
        // 72 bytes, so the `LL` byte is around 0x44 and the whole structure does NOT fit in the 64
        // this trait returns: what an implementor does when the compiler tells them the length is
        // wrong is truncate. So the shape is recognised from its first three bytes rather than
        // from its total length. Two fixed bytes plus a plausible length is about one chance in
        // two million of a false accusation against a random R || S, and the check is advisory
        // anyway: `signer/verifies_under_its_own_public_jwk` catches this too, less legibly.
        //
        // ES256 ONLY: the DER-versus-raw ambiguity is specific to ECDSA's `r || s`. RS256 and EdDSA
        // each have a single canonical signature form, so there is nothing here for them to get
        // wrong, and their signatures are not the 64 bytes this heuristic reads.
        if self.signer.alg() == JwsAlg::Es256
            && signature.len() >= 3
            && signature[0] == 0x30
            && signature[2] == 0x02
            && (0x40..=0x48).contains(&signature[1])
        {
            out.push(Violation {
                check: SIGNER_IS_NOT_DER,
                detail: "the signature looks like an ASN.1 DER SEQUENCE (it begins 0x30 with a \
                         consistent length byte). RFC 7518 s3.4 requires the 64-byte fixed-width \
                         R || S concatenation; most KMS APIs and OpenSSL return DER by default \
                         and it must be converted"
                    .to_string(),
            });
        }

        let public = published.clone();
        if !self.verify(
            "the signer's own signature under its own JWK",
            &public,
            INPUT_A.as_bytes(),
            &signature,
            out,
        ) {
            out.push(Violation {
                check: SIGNER_VERIFIES_UNDER_ITS_OWN_JWK,
                detail: format!(
                    "the signature did not verify under the signer's OWN public_jwk(). Either \
                     public_jwk() is not the public half of the signing key, or the signature is \
                     not {} over the bytes it was handed. Every token this server issues would \
                     fail verification against its own published JWKS",
                    self.signer.alg().jose_name()
                ),
            });
        }

        if self.verify(
            "the signer's own signature under a foreign key",
            &profile.foreign_key,
            INPUT_A.as_bytes(),
            &signature,
            out,
        ) {
            out.push(Violation {
                check: SIGNER_REJECTED_BY_ANOTHER_KEY,
                detail: "the signature verified under a key that did not produce it. A signer \
                         that returns a constant, or a verifier that ignores its key, would both \
                         land here"
                    .to_string(),
            });
        }

        // Binding, which is what makes a signature a statement ABOUT something. Checked with a
        // second signature rather than by reusing the first against a different message, so that a
        // signer which ignores its argument entirely (returning one fixed signature, or signing a
        // fixed message) is caught by the value it returns as well as by where it verifies.
        let signed_again = self.sign("the second input", INPUT_B.as_bytes(), out).await;
        match signed_again {
            Ok(other) => {
                // TWO facts, reported as one check because they are one property. The second
                // signature must cover the SECOND input (a signer that signs a fixed message, or
                // returns a constant, fails here on a different message than the check above used,
                // which is what stops that check passing by coincidence); and neither signature
                // may verify over the other's input.
                let covers_its_own = self.verify(
                    "the second input's signature over the second input",
                    &public,
                    INPUT_B.as_bytes(),
                    &other,
                    out,
                );
                // Both arms are evaluated deliberately: `||` would short circuit past the second
                // call, and a panic there is a fact worth reporting.
                let one_way = self.verify(
                    "the second input's signature over the FIRST input",
                    &public,
                    INPUT_A.as_bytes(),
                    &other,
                    out,
                );
                let other_way = self.verify(
                    "the first input's signature over the SECOND input",
                    &public,
                    INPUT_B.as_bytes(),
                    &signature,
                    out,
                );
                let crosses = one_way || other_way;
                if !covers_its_own || crosses {
                    out.push(Violation {
                        check: SIGNER_BINDS_THE_SIGNING_INPUT,
                        detail: "a signature is not bound to the input it was made over: either a \
                                 second input's signature did not cover that input, or one \
                                 input's signature verified over the other's. The signer is not \
                                 signing the bytes it was given (a fixed message, a double hash, \
                                 or a constant), so the signature says nothing about the token \
                                 that carries it"
                            .to_string(),
                    });
                }
            }
            Err(e) => out.push(Violation {
                check: SIGNER_SIGNS,
                detail: format!("the signer signed once and then refused: {e}"),
            }),
        }
    }

    fn check_published_key(&self, published: &Jwk, out: &mut Vec<Violation>) {
        let mut wrong = Vec::new();
        // RFC 7518 s6.2 and RFC 7517 s4.2/s4.4. These are the members a resource server reads to
        // decide whether it can use the key at all, so a wrong one makes the JWKS unusable even
        // though the arithmetic underneath it is right. The seam is algorithm-tagged now, so the
        // key's kind is checked against the signer's OWN algorithm rather than against a fixed
        // "ES256": a Phase B/C RS256 signer must publish an RSA key, not an EC one.
        let alg = self.signer.alg();
        if published.key_kind() != alg.key_kind() {
            wrong.push(format!(
                "public_jwk() is a {:?} key but the signer's algorithm {} needs a {:?} key",
                published.key_kind(),
                alg.jose_name(),
                alg.key_kind()
            ));
        }
        // The remaining members, per key TYPE. For ES256 (and EdDSA) RFC 7518 s6.2.1.2 / RFC 8037
        // s2 fix each coordinate at exactly 32 octets with leading zeros KEPT — a trimmed coordinate
        // is a different point, the classic JWK interoperability bug that works for 255 keys out of
        // 256 and then does not. For RS256 the RFC 7518 s6.3.1 base64urlUInt `n`/`e` have no fixed
        // width, so only their encoding is checked here; the `length == modulus` guard is the
        // verifier's, per key.
        match alg {
            JwsAlg::Es256 => {
                for (name, value) in [("x", published.x()), ("y", published.y())] {
                    check_32_byte_coordinate(name, value, &mut wrong);
                }
            }
            JwsAlg::EdDsa => check_32_byte_coordinate("x", published.x(), &mut wrong),
            JwsAlg::Rs256 => {
                if let Jwk::Rsa { n, e, .. } = published {
                    for (name, value) in [("n", n.as_str()), ("e", e.as_str())] {
                        match URL_SAFE_NO_PAD.decode(value) {
                            Ok(bytes) if !bytes.is_empty() => {}
                            _ => wrong.push(format!(
                                "{name} is not a non-empty base64urlUInt (RFC 7518 s6.3.1)"
                            )),
                        }
                    }
                }
            }
        }
        if !wrong.is_empty() {
            out.push(Violation {
                check: SIGNER_PUBLIC_JWK_IS_ES256,
                detail: format!(
                    "public_jwk() is not a usable {} JWK: {}",
                    alg.jose_name(),
                    wrong.join("; ")
                ),
            });
        }
    }
}

/// RFC 7518 s6.2.1.2 / RFC 8037 s2: a P-256 coordinate or an Ed25519 public key is exactly 32
/// base64url-decoded octets, leading zeros kept. Appends a human-readable reason to `wrong` when it
/// is not.
fn check_32_byte_coordinate(name: &str, value: &str, wrong: &mut Vec<String>) {
    match URL_SAFE_NO_PAD.decode(value) {
        Ok(bytes) if bytes.len() == 32 => {}
        Ok(bytes) => wrong.push(format!(
            "{name} decodes to {} bytes, must be exactly 32 with leading zeros kept",
            bytes.len()
        )),
        Err(_) => wrong.push(format!("{name} is not unpadded base64url")),
    }
}

/// One of the harness's own fixed keys. The coordinates are constants in this file, so a failure
/// here would be a defect in the harness rather than in the backend under test, which is why it
/// panics rather than reporting a violation against the host.
fn jwk(x: &str, y: &str) -> Jwk {
    Jwk::from_coordinates(x, y).expect("the harness's own fixed vectors are well formed")
}

fn decode(b64: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(b64)
        .expect("the harness's own fixed vectors are base64url")
}

/// Re-encode a 64-byte `R || S` as the ASN.1 DER `SEQUENCE { r INTEGER, s INTEGER }` that OpenSSL
/// and most KMS APIs emit, so [`VERIFIER_REJECTS_DER`] can present a verifier with the exact wrong
/// thing rather than with random bytes.
///
/// Hand written, in about twenty lines, because pulling a DER encoder into this crate to build one
/// test input would undo the dependency reduction the seam exists for.
fn der(fixed_width: &[u8]) -> Vec<u8> {
    /// One DER INTEGER over a big-endian unsigned value: minimal length, and a leading 0x00 when
    /// the top bit is set, since DER INTEGERs are signed.
    fn integer(value: &[u8], out: &mut Vec<u8>) {
        let start = value
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(value.len() - 1);
        let body = &value[start..];
        let pad = usize::from(body[0] & 0x80 != 0);
        out.push(0x02);
        out.push((body.len() + pad) as u8);
        if pad == 1 {
            out.push(0x00);
        }
        out.extend_from_slice(body);
    }
    let mut body = Vec::with_capacity(72);
    integer(&fixed_width[..32], &mut body);
    integer(&fixed_width[32..], &mut body);
    let mut out = Vec::with_capacity(body.len() + 2);
    out.push(0x30);
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::der;

    /// `der` encodes an all-zero 32-byte integer as the single zero octet: `02 01 00`.
    ///
    /// Kills `replace - with +` and `replace - with /` in `der::integer`.
    /// `position(|b| *b != 0)` returns `None` only for an all-zero coordinate, and
    /// `unwrap_or(value.len() - 1)` is what keeps the single trailing zero as the integer's body.
    /// `value.len() + 1` indexes one past the end (`&value[33..]` on a 32-byte half panics), and
    /// `value.len() / 1` is `value.len()`, an empty slice whose `body[0]` panics; either way the
    /// exact-bytes assertion below is never reached. The harness's own A.3 signature has non-zero r
    /// and s, so its live path never selects this default -- which is exactly why the sweep saw
    /// these two survive with no test exercising a zero integer.
    #[test]
    fn der_encodes_an_all_zero_integer_as_a_single_zero_octet() {
        assert_eq!(
            der(&[0u8; 64]),
            vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00],
        );
    }
}
