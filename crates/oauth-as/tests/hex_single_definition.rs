// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Lower-case hex encoding is ONE function, defined once.
//!
//! Through 0.9.0 there were two: `server::hex_encode`, which encodes the random bytes behind every
//! device code, authorization code and opaque token, and `client::hex_lower`, which encodes the
//! SHA-256 digest behind every stored client secret. Same private sixteen-byte digit table, same
//! two-nibble loop, byte for byte. Two copies of one function is the same defect
//! `tests/clock_skew_single_definition.rs` was written for, and this file is its counterpart: the
//! only structural defence against two implementations drifting is that there is only one.
//!
//! The drift is not hypothetical for THIS function. One of the two copies carries a measurement in
//! its comment (a nibble table against `write!(out, "{b:02x}")`, 1092 ns against 1335 ns for 32
//! bytes) and the other carried none, so a reader improving the uncommented copy had nothing
//! telling them the other existed.
//!
//! A text scan rather than a `syn` parse, in the same idiom (and for the same dependency-policy
//! reason) as `tests/allocation.rs`'s scan for module-level statics.

/// The encoder is defined once. Both call sites reach the same function through `crate::hex`.
#[test]
fn the_crate_defines_the_hex_encoder_exactly_once() {
    // The top level of `src/` only, NOT the `src/tests/` tree: that tree is `#[cfg(test)]`-only,
    // never ships, and a fixture there is free to spell out its own table rather than reach into
    // the implementation it is grading. Same scope as `tests/allocation.rs`'s statics scan.
    let src_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    let mut definitions: Vec<String> = Vec::new();
    let mut tables: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(src_dir).expect("the crate's src/ must be readable") {
        let path = entry.expect("a readable directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("a readable source file");
        for line in text.lines() {
            let trimmed = line.trim_start();
            // A DEFINITION, not a call and not a `use`: `fn <name>(` after an optional
            // visibility, where the name is one of the two spellings this crate has used.
            let bare = trimmed
                .strip_prefix("pub(crate)")
                .or_else(|| trimmed.strip_prefix("pub"))
                .unwrap_or(trimmed)
                .trim_start();
            // `hex::encode` is the surviving name; `hex_encode` and `hex_lower` are the two the
            // crate used when there were two of them, and they stay in the scan so that
            // reintroducing either is what fails rather than what passes unnoticed.
            if bare.starts_with("fn encode(")
                || bare.starts_with("fn hex_encode(")
                || bare.starts_with("fn hex_lower(")
            {
                definitions.push(format!("{}: {}", path.display(), line.trim()));
            }
            // And the table it reads from, which is the other half of the duplication: two
            // private `b"0123456789abcdef"` constants is two things to get wrong.
            if bare.contains("b\"0123456789abcdef\"") {
                tables.push(format!("{}: {}", path.display(), line.trim()));
            }
        }
    }
    assert_eq!(
        definitions.len(),
        1,
        "the lower-case hex encoder must be defined exactly once and called from everywhere \
         else; found {} definitions:\n{}",
        definitions.len(),
        definitions.join("\n")
    );
    assert_eq!(
        tables.len(),
        1,
        "the hex digit table must be declared exactly once; found {} declarations:\n{}",
        tables.len(),
        tables.join("\n")
    );
}

/// And it still encodes what it always encoded. A structural test that let the FUNCTION change
/// while unifying it would be worse than no test: `SecretHash::sha256` is a stored verifier, so a
/// changed encoding silently invalidates every registration a deployment already has.
#[test]
fn the_surviving_encoder_still_produces_the_same_text() {
    // RFC 6234's SHA-256 of the empty string, which is what `SecretHash::sha256("")` hashes, in
    // the lower-case hex this crate stores.
    let hash = oauth_as::SecretHash::sha256("");
    assert_eq!(
        hash.encoded(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert!(
        hash.verify("", None),
        "the stored verifier must still match"
    );
    assert!(!hash.verify("x", None));
}
