// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! `AuthorizationDetails::parse`, RFC 9396 section 2.
//!
//! This is the sharpest parser in the crate: attacker-supplied JSON arriving unauthenticated at
//! the authorization endpoint, with a `#[serde(flatten)]` catch-all that carries whatever it is
//! given straight into a stored grant. The DECLARED BOUNDS are the security property, so the
//! bounds are what this target attacks.
//!
//! # Why this one is structure aware
//!
//! A random byte string is not a JSON array. Measured over a few thousand random draws, the
//! parser refuses essentially all of them at `serde_json::from_str`, which means a raw-bytes
//! target would spend its entire budget proving that `serde_json` rejects garbage: a fact about
//! `serde_json`, established by `serde_json`'s own fuzzers, and nothing at all about the bounds
//! this module adds on top. So this target GENERATES a well formed array and lets the fuzzer
//! choose its shape: how many elements, how deeply nested each unknown member is, how long each
//! string is. A `Raw` arm is kept alongside it, because the byte-length check runs before the
//! parser and is reachable from garbage.
//!
//! # The invariants
//!
//! 1. THE BYTE BOUND IS ABSOLUTE. `parse` NEVER returns `Ok` for a raw parameter longer than
//!    [`MAX_AUTHORIZATION_DETAILS_BYTES`]. This is the bound that makes every other cost finite,
//!    so an input that slips past it is a denial-of-service primitive at an unauthenticated
//!    endpoint.
//! 2. THE ELEMENT BOUND IS ABSOLUTE. An accepted value never has more than
//!    [`MAX_AUTHORIZATION_DETAILS_ELEMENTS`] elements.
//! 3. THE DEPTH BOUND IS ABSOLUTE. No member of an accepted element nests deeper than
//!    [`MAX_AUTHORIZATION_DETAILS_DEPTH`] counted from the array itself (the array is one level,
//!    the element object is the second, so a member may hold six).
//! 4. NO EMPTY TYPE. Section 2 makes `type` the identifier of the vocabulary the rest of the
//!    object is written in, and the empty string names none.
//! 5. STORAGE ROUND TRIP. A parsed value re-serializes and re-parses to itself. This is not
//!    cosmetic: the value is persisted in the authorization code record and compared member by
//!    member by `is_narrowing_of` at the token endpoint, so a value that does not survive that
//!    trip is a grant that means something different when it is redeemed than when it was
//!    approved.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use oauth_as::{
    AuthorizationDetails, MAX_AUTHORIZATION_DETAILS_BYTES, MAX_AUTHORIZATION_DETAILS_DEPTH,
    MAX_AUTHORIZATION_DETAILS_ELEMENTS,
};
use serde_json::{Map, Value};

/// The two ways in: bytes the fuzzer chose freely, or an array it built.
#[derive(Debug)]
enum Input {
    /// Raw text. Reaches the byte-length check and `serde_json`'s own refusals.
    Raw(String),
    /// A generated `authorization_details` array, serialized.
    Shaped(String),
}

/// How many elements the generator may emit. Deliberately ABOVE
/// [`MAX_AUTHORIZATION_DETAILS_ELEMENTS`] so that the bound is straddled rather than approached:
/// a generator that can never exceed a limit can never test it.
const MAX_GENERATED_ELEMENTS: usize = 24;
/// The same reasoning for nesting: [`MAX_AUTHORIZATION_DETAILS_DEPTH`] is 8, so 12 puts inputs on
/// both sides of the refusal.
const MAX_GENERATED_DEPTH: u32 = 12;

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // One in four inputs is raw. The split is fixed rather than uniform over the enum so the
        // budget stays mostly on the shaped arm, which is the one that reaches the bounds.
        if u.int_in_range(0..=3)? == 0 {
            return Ok(Input::Raw(String::arbitrary(u)?));
        }
        let count = u.int_in_range(0..=MAX_GENERATED_ELEMENTS)?;
        let mut array = Vec::with_capacity(count);
        for _ in 0..count {
            array.push(detail(u)?);
        }
        Ok(Input::Shaped(Value::Array(array).to_string()))
    }
}

/// One RFC 9396 section 2 element: the required `type`, a fuzzer-chosen subset of the section 2.2
/// common fields, and a fuzzer-chosen number of unknown members that land in the `flatten` map.
fn detail(u: &mut Unstructured<'_>) -> arbitrary::Result<Value> {
    let mut object = Map::new();
    // `type` present but sometimes empty, sometimes not a string: invariant 4 is about exactly
    // that, and the deserializer's own handling of a non-string is worth reaching too.
    match u.int_in_range(0..=9)? {
        0 => {}
        1 => {
            object.insert("type".into(), Value::String(String::new()));
        }
        2 => {
            object.insert("type".into(), Value::Bool(u.arbitrary()?));
        }
        _ => {
            object.insert("type".into(), Value::String(short_string(u)?));
        }
    }
    for name in ["locations", "actions", "datatypes", "privileges"] {
        if u.arbitrary()? {
            let n = u.int_in_range(0..=4)?;
            let mut items = Vec::with_capacity(n);
            for _ in 0..n {
                items.push(Value::String(short_string(u)?));
            }
            object.insert(name.into(), Value::Array(items));
        }
    }
    if u.arbitrary()? {
        object.insert("identifier".into(), Value::String(short_string(u)?));
    }
    let extras = u.int_in_range(0..=3)?;
    for _ in 0..extras {
        let depth = u.int_in_range(1..=MAX_GENERATED_DEPTH)?;
        object.insert(short_string(u)?, nested(u, depth)?);
    }
    Ok(Value::Object(object))
}

/// A value nested exactly `depth` levels, so the generator can place an input precisely on either
/// side of the depth bound rather than hoping to land there.
fn nested(u: &mut Unstructured<'_>, depth: u32) -> arbitrary::Result<Value> {
    if depth <= 1 {
        return Ok(match u.int_in_range(0..=3)? {
            0 => Value::Null,
            1 => Value::Bool(u.arbitrary()?),
            2 => Value::from(u.arbitrary::<i32>()?),
            _ => Value::String(short_string(u)?),
        });
    }
    let inner = nested(u, depth - 1)?;
    Ok(if u.arbitrary()? {
        Value::Array(vec![inner])
    } else {
        let mut object = Map::new();
        object.insert(short_string(u)?, inner);
        Value::Object(object)
    })
}

/// A short member name or string value. Short on purpose: the byte bound is straddled by ELEMENT
/// COUNT and by the `Raw` arm, and long random strings would just push every shaped input over
/// the size check before it reached the parser.
fn short_string(u: &mut Unstructured<'_>) -> arbitrary::Result<String> {
    let len = u.int_in_range(0..=8)?;
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        s.push(char::from(u.int_in_range(b'a'..=b'z')?));
    }
    Ok(s)
}

/// The nesting depth of one JSON value: 1 for a scalar, 1 + the deepest child for a container.
///
/// Written here rather than reused from the crate because the crate's copy is private and,
/// more to the point, because an invariant checked with the implementation's own helper is not an
/// independent check at all.
fn depth_of(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(depth_of).max().unwrap_or(0),
        Value::Object(members) => 1 + members.values().map(depth_of).max().unwrap_or(0),
        _ => 1,
    }
}

fuzz_target!(|input: Input| {
    let raw = match &input {
        Input::Raw(s) => s.as_str(),
        Input::Shaped(s) => s.as_str(),
    };

    let parsed = match AuthorizationDetails::parse(raw) {
        Ok(parsed) => parsed,
        // Every refusal is fine. The bounds are one-directional promises: they say what is never
        // accepted, not what is always accepted.
        Err(_) => return,
    };

    // 1.
    assert!(
        raw.len() <= MAX_AUTHORIZATION_DETAILS_BYTES,
        "parse accepted {} bytes, over the declared bound of {MAX_AUTHORIZATION_DETAILS_BYTES}",
        raw.len()
    );

    // 2.
    assert!(
        parsed.len() <= MAX_AUTHORIZATION_DETAILS_ELEMENTS,
        "parse accepted {} elements, over the declared bound of \
         {MAX_AUTHORIZATION_DETAILS_ELEMENTS}",
        parsed.len()
    );

    for detail in parsed.iter() {
        // 4.
        assert!(
            !detail.detail_type.is_empty(),
            "parse accepted an element with an empty type"
        );
        // 3. Two levels are spent before a member is reached: the array, then the element object.
        for (name, value) in &detail.other {
            let total = 2 + depth_of(value);
            assert!(
                total <= MAX_AUTHORIZATION_DETAILS_DEPTH,
                "member {name:?} nests to {total}, over the declared bound of \
                 {MAX_AUTHORIZATION_DETAILS_DEPTH}"
            );
        }
    }

    // 5. Guarded on the size bound, which is a property of the SERIALIZED form and so has to be
    // re-checked: an accepted input near the limit may render slightly differently.
    let rendered = serde_json::to_string(&parsed).expect("a parsed value serializes");
    if rendered.len() <= MAX_AUTHORIZATION_DETAILS_BYTES {
        let reparsed = AuthorizationDetails::parse(&rendered).expect(
            "a value this crate itself serialized must re-parse: it is what the authorization \
             code record stores and the token endpoint reads back",
        );
        assert_eq!(
            parsed, reparsed,
            "authorization_details did not survive the storage round trip: {raw:?}"
        );
    }
});
