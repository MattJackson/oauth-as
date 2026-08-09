// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A RUNNABLE conformance harness for the [`Es256Signer`] and [`Es256Verifier`] contracts, behind
//! the `test-util` cargo feature (off by default), for a HOST to run from its OWN test suite
//! against the backend it is about to deploy.
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
//!   key rotated in the KMS while this process cached the old public half (see [`Es256Signer`] on
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
//! # use oauth_as::jwt::{Es256Signer, Es256Verifier};
//! # async fn doc(my_signer: impl Es256Signer, my_verifier: impl Es256Verifier) {
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
//! WHAT IT PROVES. That the verifier accepts a signature the RFC itself vouches for and rejects
//! four specific corruptions of it; that the signer's output is the fixed-width form, is bound to
//! the bytes it was handed, and verifies under the key the signer publishes.
//!
//! WHAT IT DOES NOT PROVE:
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

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::jwt::{Es256Signer, Es256Verifier, Jwk, PublicJwk};

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
    SIGNER_SIGNS,
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
const SIGNER_SIGNS: &str = "signer/signs";
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

/// A second well-formed P-256 public key, used as the key a signature must NOT verify under.
///
/// The RFC's own key is not reused for that job: a host whose signer IS the appendix key would
/// then pass the foreign-key check for the worst possible reason, so that case is reported by
/// [`SIGNER_IS_NOT_THE_PUBLISHED_EXAMPLE_KEY`] instead. These coordinates are RFC 7517 appendix
/// A.1's example EC public key.
const OTHER_X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
const OTHER_Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";

/// The two signing inputs the signer is asked for. They must differ, since
/// [`SIGNER_BINDS_THE_SIGNING_INPUT`] is exactly the check that one signature does not cover the
/// other. Deliberately NOT valid JWS signing inputs: a signer that inspects what it is asked to
/// sign, rather than signing it, is a signer with an opinion it has no business having.
const INPUT_A: &str = "oauth-as.signer-conformance.a";
const INPUT_B: &str = "oauth-as.signer-conformance.b";

/// The [`Es256Signer`] and [`Es256Verifier`] conformance harness. See the module docs, in
/// particular the honest account of what a green run does not prove.
pub struct SignerConformance<S, V> {
    signer: S,
    verifier: V,
}

impl<S: Es256Signer, V: Es256Verifier> SignerConformance<S, V> {
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
        self.check_verifier(&mut out);
        self.check_signer(&mut out).await;
        out
    }

    // ------------------------------------------------------------------------ the verifier

    fn check_verifier(&self, out: &mut Vec<Violation>) {
        let key = jwk(A3_X, A3_Y);
        let signature = decode(A3_SIGNATURE);

        // The known-answer test. A verifier that fails this is wrong in a way no amount of
        // agreement with the host's own signer would reveal.
        if !self
            .verifier
            .verify(&key, A3_SIGNING_INPUT.as_bytes(), &signature)
        {
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
        if self.verifier.verify(
            &jwk(OTHER_X, OTHER_Y),
            A3_SIGNING_INPUT.as_bytes(),
            &signature,
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
        if self.verifier.verify(&key, &tampered, &signature) {
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
        if self
            .verifier
            .verify(&key, A3_SIGNING_INPUT.as_bytes(), &bad_signature)
        {
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
        if self
            .verifier
            .verify(&key, A3_SIGNING_INPUT.as_bytes(), &der(&signature))
        {
            out.push(Violation {
                check: VERIFIER_REJECTS_DER,
                detail: "the ASN.1 DER encoding of a valid signature verified. RFC 7518 s3.4 \
                         fixes ES256 as the 64-byte fixed-width R || S and admits no other \
                         encoding; accepting both gives one signature two forms"
                    .to_string(),
            });
        }
    }

    // -------------------------------------------------------------------------- the signer

    async fn check_signer(&self, out: &mut Vec<Violation>) {
        let published = self.signer.public_jwk();

        // Shape first, because every check below reads this key and a malformed one would make
        // their failures unreadable.
        self.check_published_key(&published, out);

        // RFC 7515 s4.1.4: the `kid` is what lets a verifier SELECT rather than trial, and it is
        // what makes `JwtConfig::rotate_to` non-destructive. A signer with no name for its key
        // gives a deployment no rotation story at all.
        if published.kid.is_empty() {
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

        // The RFC's own example key has its PRIVATE half printed in appendix A.3.1. A deployment
        // signing with it is not signing with anything.
        if published.x == A3_X && published.y == A3_Y {
            out.push(Violation {
                check: SIGNER_IS_NOT_THE_PUBLISHED_EXAMPLE_KEY,
                detail: "the signing key is the RFC 7515 appendix A.3 example key, whose private \
                         half is printed in the RFC. Anyone can forge every token this server \
                         issues"
                    .to_string(),
            });
        }

        let signature = match self.signer.sign(INPUT_A.as_bytes()).await {
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
        if signature[0] == 0x30 && signature[2] == 0x02 && (0x40..=0x48).contains(&signature[1]) {
            out.push(Violation {
                check: SIGNER_IS_NOT_DER,
                detail: "the signature looks like an ASN.1 DER SEQUENCE (it begins 0x30 with a \
                         consistent length byte). RFC 7518 s3.4 requires the 64-byte fixed-width \
                         R || S concatenation; most KMS APIs and OpenSSL return DER by default \
                         and it must be converted"
                    .to_string(),
            });
        }

        let public = published.to_public_jwk();
        if !self
            .verifier
            .verify(&public, INPUT_A.as_bytes(), &signature)
        {
            out.push(Violation {
                check: SIGNER_VERIFIES_UNDER_ITS_OWN_JWK,
                detail: "the signature did not verify under the signer's OWN public_jwk(). Either \
                         public_jwk() is not the public half of the signing key, or the signature \
                         is not ES256 over the bytes it was handed. Every token this server \
                         issues would fail verification against its own published JWKS"
                    .to_string(),
            });
        }

        if self
            .verifier
            .verify(&jwk(OTHER_X, OTHER_Y), INPUT_A.as_bytes(), &signature)
        {
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
        match self.signer.sign(INPUT_B.as_bytes()).await {
            Ok(other) => {
                // TWO facts, reported as one check because they are one property. The second
                // signature must cover the SECOND input (a signer that signs a fixed message, or
                // returns a constant, fails here on a different message than the check above used,
                // which is what stops that check passing by coincidence); and neither signature
                // may verify over the other's input.
                let covers_its_own = self.verifier.verify(&public, INPUT_B.as_bytes(), &other);
                let crosses = self.verifier.verify(&public, INPUT_A.as_bytes(), &other)
                    || self
                        .verifier
                        .verify(&public, INPUT_B.as_bytes(), &signature);
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
        // though the arithmetic underneath it is right.
        if published.kty != "EC" {
            wrong.push(format!("kty is {:?}, must be \"EC\"", published.kty));
        }
        if published.crv != "P-256" {
            wrong.push(format!("crv is {:?}, must be \"P-256\"", published.crv));
        }
        if published.alg != "ES256" {
            wrong.push(format!("alg is {:?}, must be \"ES256\"", published.alg));
        }
        if published.use_ != "sig" {
            wrong.push(format!("use is {:?}, must be \"sig\"", published.use_));
        }
        // RFC 7518 s6.2.1.2 fixes the octet length at the curve's field size and requires leading
        // zeros to be KEPT. A trimmed coordinate is a different point, and it is the classic JWK
        // interoperability bug: it works for 255 keys out of 256 and then does not.
        for (name, value) in [("x", &published.x), ("y", &published.y)] {
            match URL_SAFE_NO_PAD.decode(value) {
                Ok(bytes) if bytes.len() == 32 => {}
                Ok(bytes) => wrong.push(format!(
                    "{name} decodes to {} bytes, must be exactly 32 with leading zeros kept \
                     (RFC 7518 s6.2.1.2)",
                    bytes.len()
                )),
                Err(_) => wrong.push(format!("{name} is not unpadded base64url")),
            }
        }
        if !wrong.is_empty() {
            out.push(Violation {
                check: SIGNER_PUBLIC_JWK_IS_ES256,
                detail: format!(
                    "public_jwk() is not a usable ES256 JWK: {}",
                    wrong.join("; ")
                ),
            });
        }
    }
}

/// One of the harness's own fixed keys. The coordinates are constants in this file, so a failure
/// here would be a defect in the harness rather than in the backend under test, which is why it
/// panics rather than reporting a violation against the host.
fn jwk(x: &str, y: &str) -> PublicJwk {
    PublicJwk::from_coordinates(x, y).expect("the harness's own fixed vectors are well formed")
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
