// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! `Jwk::from_json`, RFC 7517 section 4 and RFC 7518 section 6 — EC, RSA and OKP.
//!
//! This is the parser that turns a key a CLIENT sent into a key this server will verify a DPoP
//! proof against, and whose thumbprint (RFC 7638) becomes the `cnf.jkt` that binds an access
//! token. Since 0.10.0's crypto-agility work the type is a THREE-VARIANT enum (`Jwk::Ec`,
//! `Jwk::Rsa`, `Jwk::Okp`), so this target feeds all three key-type shapes — valid-ish and
//! malformed — into one entry point. Two things it must never do: accept a private or symmetric
//! parameter (a registration carrying a client's private key is the state the type exists to make
//! unrepresentable), and, for the fixed-width curves, accept a coordinate of the wrong width
//! (RFC 7518 section 6.2.1.2 and RFC 8037 fix the octet length at the field size and require
//! leading zeros to be KEPT, so a trimmed coordinate is a DIFFERENT point).
//!
//! # Why this one is structure aware
//!
//! The function takes a `serde_json::Value`, so the interesting axis is not "is this JSON" but
//! "which `kty` does the object claim and which members does it carry". The generator therefore
//! picks a key type, builds an object of that shape, and lets the fuzzer choose the members, the
//! coordinate widths, the `n`/`e` encodings, and whether a private member sneaks in.
//!
//! # The invariant
//!
//! `Jwk::from_json` NEVER PANICS on any input. It returns `Result`; a malformed key is an `Err`,
//! not a crash. Everything below the parse is a consistency check on an ACCEPTED key, each of
//! which must also hold and none of which may panic:
//!
//! 1. NO PRIVATE PARAMETER SURVIVES. If the input object carried any of RFC 7517/7518's private
//!    or symmetric members (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`), `from_json` returns
//!    `Err`. Unconditionally, whatever else the object contains.
//! 2. THE ACCEPTED SHAPE IS ONE OF EXACTLY THREE. An accepted key is EC/P-256 with 32-byte
//!    coordinates, RSA with base64url `n`/`e`, or OKP/Ed25519 with a 32-byte `x`.
//! 3. THE THUMBPRINT IS A PROPERTY OF THE KEY, NOT OF ITS DESCRIPTION. Adding, changing or
//!    removing `kid`, `use` or `alg` (the members RFC 7638 section 3.2 excludes) does not change
//!    the thumbprint. If it did, one key would produce two `cnf.jkt` values and a resource server
//!    could not tell two tokens were bound to the same client.
//! 4. THE THUMBPRINT IS WELL FORMED. Unpadded base64url of exactly 32 bytes, always.
//! 5. SERIALIZATION ROUND TRIP. A key this crate accepted, re-serialized, is accepted again and
//!    is equal. Hosts persist these.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use libfuzzer_sys::fuzz_target;
use oauth_as::jwt::Jwk;
use serde_json::{Map, Value};

/// RFC 7517 section 4 and RFC 7518 sections 6.2.2, 6.3.2 and 6.4: everything that is a private key
/// half or a symmetric key. Restated here rather than imported, because the crate's list is
/// private and because an invariant checked against the implementation's own constant would move
/// whenever the implementation did.
const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

#[derive(Debug)]
struct Input(Value);

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // One in six is a value that is not an object at all, so the very first refusal is
        // reached too.
        if u.int_in_range(0..=5)? == 0 {
            return Ok(Input(match u.int_in_range(0..=3)? {
                0 => Value::Null,
                1 => Value::Array(vec![]),
                2 => Value::String(String::arbitrary(u)?),
                _ => Value::from(u.arbitrary::<i64>()?),
            }));
        }
        let mut object = Map::new();
        // The claimed key type, most of the time one of the three the crate verifies, sometimes a
        // near miss (case, a curve name in the kty slot) or nothing at all.
        if u.arbitrary()? {
            object.insert(
                "kty".into(),
                Value::String(
                    u.choose(&["EC", "RSA", "OKP", "oct", "ec", "rsa", "okp", ""])?
                        .to_string(),
                ),
            );
        }
        // Which member-shape to lay down. Independent of the claimed `kty` on purpose: a
        // `kty:"RSA"` object carrying EC coordinates and no `n`/`e` is exactly the confusion the
        // parser has to refuse.
        match u.int_in_range(0..=2)? {
            0 => ec_members(u, &mut object)?,
            1 => rsa_members(u, &mut object)?,
            _ => okp_members(u, &mut object)?,
        }
        if u.arbitrary()? {
            object.insert("kid".into(), Value::String(String::arbitrary(u)?));
        }
        // The whole point of invariant 1: put a private member in, sometimes, and see it refused.
        if u.int_in_range(0..=3)? == 0 {
            let name = u.choose(PRIVATE_MEMBERS)?;
            object.insert((*name).into(), Value::String(String::arbitrary(u)?));
        }
        if u.arbitrary()? {
            object.insert(
                "use".into(),
                Value::String(u.choose(&["sig", "enc"])?.to_string()),
            );
        }
        if u.arbitrary()? {
            object.insert(
                "alg".into(),
                Value::String(
                    u.choose(&["ES256", "RS256", "EdDSA", "none", "HS256"])?
                        .to_string(),
                ),
            );
        }
        Ok(Input(Value::Object(object)))
    }
}

/// The EC/P-256 shape: `crv` plus the two coordinates, at the right width sometimes and the wrong
/// width often (invariant 2's subject for this key type).
fn ec_members(u: &mut Unstructured<'_>, object: &mut Map<String, Value>) -> arbitrary::Result<()> {
    if u.arbitrary()? {
        object.insert(
            "crv".into(),
            Value::String(
                u.choose(&["P-256", "P-384", "P-521", "secp256k1", "p-256", ""])?
                    .to_string(),
            ),
        );
    }
    for name in ["x", "y"] {
        if u.arbitrary()? {
            object.insert(name.into(), coordinate(u, 32)?);
        }
    }
    Ok(())
}

/// The RSA shape: `n` and `e` as RFC 7518 section 6.3.1 base64urlUInt, sometimes well formed,
/// sometimes not base64url, sometimes oversized, sometimes absent.
fn rsa_members(u: &mut Unstructured<'_>, object: &mut Map<String, Value>) -> arbitrary::Result<()> {
    if u.arbitrary()? {
        object.insert("n".into(), rsa_uint(u)?);
    }
    if u.arbitrary()? {
        // `e` is almost always the well-known 65537 = `AQAB`, so put that on the table alongside
        // the fuzzer's own choices.
        object.insert(
            "e".into(),
            match u.int_in_range(0..=2)? {
                0 => Value::String("AQAB".into()),
                1 => {
                    let len = u.int_in_range(0..=5)?;
                    Value::String(URL_SAFE_NO_PAD.encode(u.bytes(len)?))
                }
                _ => Value::String(String::arbitrary(u)?),
            },
        );
    }
    Ok(())
}

/// The OKP/Ed25519 shape: `crv` and a 32-byte `x`, again straddling the width check.
fn okp_members(u: &mut Unstructured<'_>, object: &mut Map<String, Value>) -> arbitrary::Result<()> {
    if u.arbitrary()? {
        object.insert(
            "crv".into(),
            Value::String(
                u.choose(&["Ed25519", "Ed448", "X25519", "ed25519", ""])?
                    .to_string(),
            ),
        );
    }
    if u.arbitrary()? {
        object.insert("x".into(), coordinate(u, 32)?);
    }
    Ok(())
}

/// An RSA `n`: usually a plausible 256-byte (2048-bit) modulus, but also an OVERSIZED one (up to
/// 2 KiB, the "huge n" case) and a not-base64url one, so the verifier's later size guard has a
/// well formed key to reject and the parser has a malformed one.
fn rsa_uint(u: &mut Unstructured<'_>) -> arbitrary::Result<Value> {
    Ok(match u.int_in_range(0..=4)? {
        0 => Value::String(URL_SAFE_NO_PAD.encode(u.bytes(256)?)),
        1 => {
            let len = u.int_in_range(0..=64)?;
            Value::String(URL_SAFE_NO_PAD.encode(u.bytes(len)?))
        }
        2 => {
            let len = u.int_in_range(512..=2048)?;
            Value::String(URL_SAFE_NO_PAD.encode(u.bytes(len)?))
        }
        3 => Value::String(String::arbitrary(u)?),
        _ => Value::from(u.arbitrary::<i64>()?),
    })
}

/// A fixed-width coordinate: the right width sometimes, the wrong width often, and occasionally
/// not base64url at all. The width check is invariant 2's whole subject, so the generator has to
/// straddle it.
fn coordinate(u: &mut Unstructured<'_>, width: usize) -> arbitrary::Result<Value> {
    Ok(match u.int_in_range(0..=6)? {
        // Exactly `width` bytes: the accepted width.
        0 => Value::String(URL_SAFE_NO_PAD.encode(u.bytes(width)?)),
        // A fuzzer-chosen width, mostly wrong.
        1 => {
            let len = u.int_in_range(0..=40)?;
            Value::String(URL_SAFE_NO_PAD.encode(u.bytes(len)?))
        }
        // `width` bytes with STANDARD base64 padding and alphabet: the interoperability trap.
        2 => Value::String(STANDARD.encode(u.bytes(width)?)),
        // Not base64 at all.
        3 => Value::String(String::arbitrary(u)?),
        // Not a string.
        4 => Value::from(u.arbitrary::<i64>()?),
        // One byte short: RFC 7518 section 6.2.1.2's "leading zeros were kept" trap.
        5 => Value::String(URL_SAFE_NO_PAD.encode(u.bytes(width.saturating_sub(1))?)),
        // One byte long.
        _ => Value::String(URL_SAFE_NO_PAD.encode(u.bytes(width + 1)?)),
    })
}

fuzz_target!(|input: Input| {
    let value = input.0;
    let private_present = value
        .as_object()
        .is_some_and(|o| PRIVATE_MEMBERS.iter().any(|m| o.contains_key(*m)));

    // The invariant: from_json returns a Result and never panics. `Err` is a legitimate answer
    // for the overwhelming majority of these inputs; nothing is asserted about it beyond that it
    // did not crash.
    let jwk = match Jwk::from_json(&value) {
        Ok(jwk) => jwk,
        Err(_) => return,
    };

    // 1.
    assert!(
        !private_present,
        "from_json accepted a JWK carrying a private or symmetric parameter: {value}"
    );

    // 2. One of exactly three shapes, and each accepted key's members decode to the RFC widths.
    match jwk.kty() {
        "EC" => {
            for (name, coord) in [("x", jwk.x()), ("y", jwk.y())] {
                let decoded = URL_SAFE_NO_PAD
                    .decode(coord.as_bytes())
                    .unwrap_or_else(|e| {
                        panic!("accepted EC {name} is not unpadded base64url ({e}): {coord}")
                    });
                assert_eq!(
                    decoded.len(),
                    32,
                    "accepted EC {name} is {} bytes, not the RFC 7518 s6.2.1.2 width of 32: {coord}",
                    decoded.len()
                );
            }
        }
        "RSA" => {
            // An accepted RSA key's `n`/`e` are re-emitted through serialization; that they decode
            // is covered by invariant 5 below. Here only the kind guard: EC accessors are empty.
            assert!(
                jwk.x().is_empty() && jwk.y().is_empty(),
                "an accepted RSA JWK reports EC coordinates: {value}"
            );
        }
        "OKP" => {
            let x = jwk.x();
            let decoded = URL_SAFE_NO_PAD
                .decode(x.as_bytes())
                .unwrap_or_else(|e| panic!("accepted OKP x is not unpadded base64url ({e}): {x}"));
            assert_eq!(
                decoded.len(),
                32,
                "accepted OKP x is {} bytes, not the Ed25519 width of 32: {x}",
                decoded.len()
            );
        }
        other => panic!("from_json accepted a JWK with an unsupported kty {other:?}: {value}"),
    }

    // 4.
    let thumbprint = jwk.thumbprint();
    let digest = URL_SAFE_NO_PAD
        .decode(thumbprint.as_bytes())
        .expect("the thumbprint is unpadded base64url");
    assert_eq!(digest.len(), 32, "the thumbprint is not a SHA-256 digest");

    // 3. Same key, described differently: RFC 7638 s3.2 excludes `kid`, `use` and `alg` from the
    // hash input, so all three of these must produce the same thumbprint.
    if let Some(object) = value.as_object() {
        for variant in ["kid", "use", "alg"] {
            let mut other = object.clone();
            other.insert(variant.into(), Value::String("a-different-value".into()));
            if let Ok(described) = Jwk::from_json(&Value::Object(other)) {
                assert_eq!(
                    thumbprint,
                    described.thumbprint(),
                    "changing {variant} changed the RFC 7638 thumbprint: {value}"
                );
            }
        }
    }

    // 5.
    let rendered = serde_json::to_value(&jwk).expect("an accepted JWK serializes");
    let reparsed = Jwk::from_json(&rendered)
        .expect("a JWK this crate serialized must be one this crate accepts");
    assert_eq!(
        jwk, reparsed,
        "a Jwk did not survive its own serialization: {value}"
    );
});
