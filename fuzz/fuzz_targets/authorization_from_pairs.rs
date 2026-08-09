// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! `AuthorizationRequest::from_pairs`, RFC 6749 section 3.1 and RFC 8707 section 2.
//!
//! # Why the collection rule is a security property and not bookkeeping
//!
//! RFC 6749 section 3.1 says a request parameter MUST NOT be sent more than once, and leaves what
//! to do when one is anyway. FIRST-WINS and LAST-WINS are both defensible readings and they are
//! not equally safe: when two intermediaries disagree about which copy counts, last-wins is the
//! one that lets a duplicate appended late in the chain override what the earlier layers
//! inspected and approved. `redirect_uri` and `code_challenge` are the parameters that matters
//! most for, and both are collected here. So "the first occurrence wins, always, for every
//! parameter except `resource`" is the invariant this target exists to hold.
//!
//! # Why this one is structure aware
//!
//! The input is already-decoded `(name, value)` pairs, not bytes, so the interesting axis is the
//! MULTISET OF NAMES: which parameters repeat, in what order, mixed with names the function must
//! ignore. A random byte string cannot express that. The generator draws names from the real
//! parameter set most of the time and from arbitrary text the rest, so both the collection rule
//! and RFC 6749 section 3.1's "ignore what you do not recognise" are exercised.
//!
//! # The invariants
//!
//! 1. FIRST WINS. Every singleton field equals the FIRST value in the input with that name.
//! 2. NOTHING IS INVENTED. A field is `Some` if and only if its name appeared in the input.
//! 3. `resource` IS COMPLETE AND ORDERED. RFC 8707 section 2 permits repetition and every
//!    occurrence is part of the request, so the collected vector is every `resource` value in
//!    wire order. Dropping one would issue a token for a subset of what the client asked for;
//!    reordering would matter to any host that treats the first as primary.
//! 4. NO TRANSFORMATION. Values are carried through byte for byte. This function is downstream of
//!    percent decoding, so a second decode here would be a double decode and `%2500` would become
//!    `%00`.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use oauth_as::AuthorizationRequest;

/// Every name `from_pairs` recognises under the feature set this fuzz crate builds with.
const KNOWN: &[&str] = &[
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
    "resource",
    "authorization_details",
];

#[derive(Debug)]
struct Pairs(Vec<(String, String)>);

impl<'a> Arbitrary<'a> for Pairs {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let count = u.int_in_range(0..=12)?;
        let mut pairs = Vec::with_capacity(count);
        for _ in 0..count {
            // Mostly real names, so duplicates actually collide; sometimes arbitrary text, so the
            // "ignore the unrecognised" path and near-miss names (`Client_id`, `client_id `) are
            // reached as well.
            let name = if u.int_in_range(0..=4)? == 0 {
                String::arbitrary(u)?
            } else {
                (*u.choose(KNOWN)?).to_string()
            };
            pairs.push((name, String::arbitrary(u)?));
        }
        Ok(Pairs(pairs))
    }
}

/// The first value in `pairs` with this name, which is what invariants 1 and 2 compare against.
fn first<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fuzz_target!(|pairs: Pairs| {
    let pairs = pairs.0;
    let request =
        AuthorizationRequest::from_pairs(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));

    // 1, 2 and 4 together: `Option<&str>` equality covers presence, choice of occurrence, and
    // byte-for-byte identity in one comparison, and there is no way to satisfy it by accident.
    let checks: [(&str, Option<&str>); 8] = [
        ("response_type", request.response_type.as_deref()),
        ("client_id", request.client_id.as_deref()),
        ("redirect_uri", request.redirect_uri.as_deref()),
        ("scope", request.scope.as_deref()),
        ("state", request.state.as_deref()),
        ("code_challenge", request.code_challenge.as_deref()),
        (
            "code_challenge_method",
            request.code_challenge_method.as_deref(),
        ),
        (
            "authorization_details",
            request.authorization_details.as_deref(),
        ),
    ];
    for (name, got) in checks {
        assert_eq!(
            got,
            first(&pairs, name),
            "{name} is not the first occurrence in {pairs:?}"
        );
    }

    // 3.
    let expected: Vec<&str> = pairs
        .iter()
        .filter(|(k, _)| k == "resource")
        .map(|(_, v)| v.as_str())
        .collect();
    let got: Vec<&str> = request.resource.iter().map(|c| c.as_ref()).collect();
    assert_eq!(
        got, expected,
        "RFC 8707 resource indicators were dropped or reordered: {pairs:?}"
    );
});
