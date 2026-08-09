// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! `PublicJwk::from_json`, RFC 7517 section 4 and RFC 7518 section 6.2.
//!
//! This is the parser that turns a key a CLIENT sent into a key this server will verify a DPoP
//! proof against, and whose thumbprint (RFC 7638) becomes the `cnf.jkt` that binds an access
//! token. Two things it must never do: accept a private or symmetric parameter (a registration
//! carrying a client's private key is the state the type exists to make unrepresentable), and
//! accept a coordinate of the wrong width (RFC 7518 section 6.2.1.2 fixes the octet length at the
//! field size and requires leading zeros to be KEPT, so a trimmed coordinate is a DIFFERENT
//! point).
//!
//! # Why this one is structure aware
//!
//! The function takes a `serde_json::Value`, so the interesting axis is not "is this JSON" but
//! "which members does the object have and what is in them". The generator therefore builds an
//! object and lets the fuzzer choose the members, the coordinate widths, and the encodings.
//!
//! # The invariants
//!
//! 1. NO PRIVATE PARAMETER SURVIVES. If the input object carried any of RFC 7517/7518's private
//!    or symmetric members (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`), `from_json` returns
//!    `Err`. Unconditionally, whatever else the object contains.
//! 2. THE ACCEPTED SHAPE IS EXACTLY ONE SHAPE. An accepted key has `kty == "EC"`,
//!    `crv == "P-256"`, and coordinates that decode, as unpadded base64url, to exactly 32 bytes
//!    each.
//! 3. THE THUMBPRINT IS A PROPERTY OF THE KEY, NOT OF ITS DESCRIPTION. Adding, changing or
//!    removing `kid` (and any other member RFC 7638 section 3.2 excludes) does not change the
//!    thumbprint. If it did, one key would produce two `cnf.jkt` values and a resource server
//!    could not tell two tokens were bound to the same client.
//! 4. THE THUMBPRINT IS WELL FORMED. Unpadded base64url of exactly 32 bytes, always.
//! 5. SERIALIZATION ROUND TRIP. A key this crate accepted, re-serialized, is accepted again and
//!    is equal. Hosts persist these.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use libfuzzer_sys::fuzz_target;
use oauth_as::jwt::PublicJwk;
use serde_json::{Map, Value};

/// RFC 7517 section 4 and RFC 7518 sections 6.2.2 and 6.4: everything that is a private key half
/// or a symmetric key. Restated here rather than imported, because the crate's list is private
/// and because an invariant checked against the implementation's own constant would move
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
        if u.arbitrary()? {
            object.insert(
                "kty".into(),
                Value::String(
                    u.choose(&["EC", "RSA", "oct", "OKP", "ec", ""])?
                        .to_string(),
                ),
            );
        }
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
                object.insert(name.into(), coordinate(u)?);
            }
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
            object.insert("alg".into(), Value::String("ES256".into()));
        }
        Ok(Input(Value::Object(object)))
    }
}

/// A coordinate: the right width sometimes, the wrong width often, and occasionally not base64url
/// at all. The 32-byte check is invariant 2's whole subject, so the generator has to straddle it.
fn coordinate(u: &mut Unstructured<'_>) -> arbitrary::Result<Value> {
    Ok(match u.int_in_range(0..=5)? {
        // Exactly 32 bytes: the accepted width.
        0 => Value::String(URL_SAFE_NO_PAD.encode(u.bytes(32)?)),
        // A fuzzer-chosen width, mostly wrong.
        1 => {
            let len = u.int_in_range(0..=40)?;
            Value::String(URL_SAFE_NO_PAD.encode(u.bytes(len)?))
        }
        // 32 bytes with STANDARD base64 padding and alphabet: the interoperability trap.
        2 => Value::String(STANDARD.encode(u.bytes(32)?)),
        // Not base64 at all.
        3 => Value::String(String::arbitrary(u)?),
        // Not a string.
        4 => Value::from(u.arbitrary::<i64>()?),
        _ => Value::String(URL_SAFE_NO_PAD.encode(u.bytes(31)?)),
    })
}

fuzz_target!(|input: Input| {
    let value = input.0;
    let private_present = value
        .as_object()
        .is_some_and(|o| PRIVATE_MEMBERS.iter().any(|m| o.contains_key(*m)));

    let jwk = match PublicJwk::from_json(&value) {
        Ok(jwk) => jwk,
        Err(_) => return,
    };

    // 1.
    assert!(
        !private_present,
        "from_json accepted a JWK carrying a private or symmetric parameter: {value}"
    );

    // 2.
    assert_eq!(jwk.kty(), "EC", "an accepted JWK has a non-EC kty: {value}");
    assert_eq!(
        jwk.crv(),
        "P-256",
        "an accepted JWK has a non-P-256 crv: {value}"
    );
    for (name, coord) in [("x", jwk.x()), ("y", jwk.y())] {
        let decoded = URL_SAFE_NO_PAD
            .decode(coord.as_bytes())
            .unwrap_or_else(|e| panic!("accepted {name} is not unpadded base64url ({e}): {coord}"));
        assert_eq!(
            decoded.len(),
            32,
            "accepted {name} is {} bytes, not the RFC 7518 s6.2.1.2 field width of 32: {coord}",
            decoded.len()
        );
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
            if let Ok(described) = PublicJwk::from_json(&Value::Object(other)) {
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
    let reparsed = PublicJwk::from_json(&rendered)
        .expect("a JWK this crate serialized must be one this crate accepts");
    assert_eq!(
        jwk, reparsed,
        "a PublicJwk did not survive its own serialization: {value}"
    );
});
