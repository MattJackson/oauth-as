// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! `RsaVerifier::verify`, RFC 7518 section 3.3 (RS256) reached with attacker-controlled key,
//! signature and signing input.
//!
//! This is the RS256 half of the crypto-agility work that 0.10.0 added. The `JwsVerifier` contract
//! (see the VERIFICATION banner in `crate::jwt`) is absolute about this seam: the key is the
//! caller's, the algorithm was already chosen, and EVERY failure — a non-RSA `Jwk`, a malformed or
//! oversized `n`/`e`, a sub-2048-bit modulus, a signature whose length is not the modulus size, or
//! an arithmetic mismatch — must be a `false`, never a panic and never a `true`. A verifier that
//! panics on a hostile key is a denial of service; one that returns `true` on bytes the attacker
//! chose is a full authentication bypass. Both are the bug this target hunts.
//!
//! # Why this one is structure aware
//!
//! `Jwk`'s variant fields are public, so the generator builds the key DIRECTLY rather than through
//! `Jwk::from_json`. That is deliberate: it lets the fuzzer hand the verifier keys that
//! `from_json` would have rejected (a wrong-width `n`, a non-base64url `e`, an EC or OKP key in an
//! RS256 verifier's hand), which is exactly the defence-in-depth the verifier promises to hold on
//! its own. The signature and signing input are unconstrained bytes.
//!
//! # The invariants
//!
//! 1. NEVER PANICS, for any key/signature/input triple.
//! 2. FALSE ON GARBAGE. A fuzzer cannot produce a valid RSA signature, so `verify` MUST return
//!    `false` for every input this target generates. A `true` is a forgery this target caught.
//! 3. THE KIND GUARD HOLDS. An EC or OKP key handed to the RS256 verifier is an
//!    algorithm-confusion attempt and returns `false` (covered by invariant 2, but the generator
//!    feeds non-RSA keys explicitly so the path is exercised).

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use libfuzzer_sys::fuzz_target;
use oauth_as::jwt::{EcCurve, Jwk, OkpCurve};
use oauth_as::{JwsVerifier, RsaVerifier};

/// A base64url string of a fuzzer-chosen length, sometimes not base64url at all, for a JWK member.
fn member(u: &mut Unstructured<'_>, plausible_len: usize) -> arbitrary::Result<String> {
    Ok(match u.int_in_range(0..=3)? {
        0 => URL_SAFE_NO_PAD.encode(u.bytes(plausible_len)?),
        1 => {
            let len = u.int_in_range(0..=8)?;
            URL_SAFE_NO_PAD.encode(u.bytes(len)?)
        }
        // An OVERSIZED modulus: well formed base64url, far past any real key, to prove the size
        // path is a `false` rather than an unbounded allocation panic.
        2 => {
            let len = u.int_in_range(512..=2048)?;
            URL_SAFE_NO_PAD.encode(u.bytes(len)?)
        }
        _ => String::arbitrary(u)?,
    })
}

/// The key handed to the verifier: mostly RSA (well-formed-ish and malformed), sometimes a non-RSA
/// key so the kind guard is exercised.
fn arbitrary_key(u: &mut Unstructured<'_>) -> arbitrary::Result<Jwk> {
    Ok(match u.int_in_range(0..=4)? {
        // A plausible 2048-bit modulus with the standard exponent. Still garbage — the fuzzer
        // cannot sign for it — so `verify` returns false, but it drives the arithmetic path rather
        // than bailing at a shape check.
        0 => Jwk::Rsa {
            n: URL_SAFE_NO_PAD.encode(u.bytes(256)?),
            e: "AQAB".into(),
            kid: None,
        },
        // A fuzzer-shaped RSA key: any width `n`, any `e`, occasionally non-base64url.
        1 | 2 => Jwk::Rsa {
            n: member(u, 256)?,
            e: member(u, 3)?,
            kid: None,
        },
        // A non-RSA key, so the kind guard's `return false` is reached. EC and OKP both.
        3 => Jwk::Ec {
            crv: EcCurve::P256,
            x: member(u, 32)?,
            y: member(u, 32)?,
            kid: None,
        },
        _ => Jwk::Okp {
            crv: OkpCurve::Ed25519,
            x: member(u, 32)?,
            kid: None,
        },
    })
}

#[derive(Debug)]
struct Input {
    key: Jwk,
    signing_input: Vec<u8>,
    signature: Vec<u8>,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let key = arbitrary_key(u)?;
        let signing_input = <Vec<u8>>::arbitrary(u)?;
        // The signature length straddles the common RSA modulus sizes so the `sig.len() ==
        // public.size()` guard is hit from both sides, plus the empty and enormous cases.
        let signature = if u.arbitrary()? {
            let len = *u.choose(&[0usize, 1, 64, 128, 255, 256, 384, 512, 4096])?;
            u.bytes(len)?.to_vec()
        } else {
            <Vec<u8>>::arbitrary(u)?
        };
        Ok(Input {
            key,
            signing_input,
            signature,
        })
    }
}

fuzz_target!(|input: Input| {
    let Input {
        key,
        signing_input,
        signature,
    } = input;

    // 1 and 2: the call must return (never panic) and must return false (no forgery).
    let verified = RsaVerifier.verify(&key, &signing_input, &signature);
    assert!(
        !verified,
        "RsaVerifier::verify returned true on fuzzer-generated bytes: \
         key {key:?}, input {signing_input:?}, sig {signature:?}"
    );
});
