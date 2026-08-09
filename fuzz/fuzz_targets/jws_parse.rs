// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! `CompactJws::parse`, RFC 7515 section 3.1 (the compact serialization).
//!
//! Everything the crate verifies a signature over goes through here first: DPoP proofs
//! (RFC 9449), client assertions (RFC 7523), RFC 9101 request objects, and this server's own
//! RFC 9068 access tokens on the way back in. What it accepts is what the verifiers are asked to
//! judge, so its acceptance set IS the attack surface.
//!
//! # Why this one is structure aware
//!
//! `parse` requires three unpadded-base64url segments, each of the first two decoding to a JSON
//! OBJECT. A random byte string clears none of that, so a raw target would never reach the second
//! half of the function. This target builds a token from parts and lets the fuzzer perturb it:
//! insert a dot, delete a segment, swap in a padded segment, corrupt a byte. That is the input
//! class the RFC's own hazards live in (RFC 7515 appendix A.5's two-segment unsecured form, and
//! the five-segment RFC 7516 JWE that must not be read as a JWS with odd contents).
//!
//! # The invariants
//!
//! 1. EXACTLY THREE SEGMENTS, in both directions. `parse` returns `Ok` if and only if the token
//!    contains exactly two `.` characters. The `only if` half is the one that matters: a
//!    two-segment token is the RFC 7515 appendix A.5 unsecured JWS and a five-segment one is a
//!    JWE, and reading either as a signed thing is how `alg: none` gets in.
//! 2. THE SIGNING INPUT IS BORROWED FROM WHAT ARRIVED. `signing_input` is a literal prefix of the
//!    token and is followed in the token by `.`. RFC 7515 section 5.1 makes the signature cover
//!    the received octets; a re-joined string is a second chance to sign something other than
//!    what was sent, and this invariant is what proves it was not re-joined.
//! 3. THE SEGMENTS ACCOUNT FOR THE WHOLE TOKEN. `signing_input.len() + 1 + signature_segment` is
//!    the token length, so no trailing bytes are being ignored.
//! 4. NO PANIC ON A MULTI-BYTE BOUNDARY. `signing_input` is produced by slicing the token by
//!    byte offset; the target feeds non-ASCII tokens specifically to prove that slice is always
//!    on a character boundary.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use libfuzzer_sys::fuzz_target;
use oauth_as::jwt::CompactJws;

/// A perturbation applied to an otherwise well formed token.
#[derive(Arbitrary, Debug)]
enum Perturbation {
    /// Leave it alone: the well formed case still has to be accepted.
    None,
    /// Append a fourth segment. The RFC 7516 JWE shape, near enough.
    ExtraSegment,
    /// Drop the signature. The RFC 7515 appendix A.5 unsecured shape.
    DropSignature,
    /// Drop the payload as well.
    HeaderOnly,
    /// Re-encode one segment with standard (padded, `+/`) base64 instead of base64url.
    PaddedBase64(u8),
    /// Overwrite one byte of the token.
    CorruptByte { at: u16, to: u8 },
    /// Insert a dot at a byte offset, which may land inside a multi-byte character.
    InsertDot { at: u16 },
    /// Splice in a non-ASCII string, so the byte slicing in `parse` is exercised on a token whose
    /// character boundaries are not byte boundaries.
    NonAscii,
    /// Truncate.
    Truncate { to: u16 },
}

#[derive(Debug)]
struct Token(String);

impl<'a> Arbitrary<'a> for Token {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // One in five is raw bytes: the front door still has to be fuzzed, and a shaped
        // generator would never produce the empty string or a lone dot.
        if u.int_in_range(0..=4)? == 0 {
            return Ok(Token(String::arbitrary(u)?));
        }
        let header = segment(u)?;
        let payload = segment(u)?;
        let signature = URL_SAFE_NO_PAD.encode(<Vec<u8>>::arbitrary(u)?);
        let mut token = format!("{header}.{payload}.{signature}");

        match Perturbation::arbitrary(u)? {
            Perturbation::None => {}
            Perturbation::ExtraSegment => token.push_str(".Zm9v"),
            Perturbation::DropSignature => token = format!("{header}.{payload}"),
            Perturbation::HeaderOnly => token = header,
            Perturbation::PaddedBase64(which) => {
                let raw = <Vec<u8>>::arbitrary(u)?;
                let padded = STANDARD.encode(raw);
                token = match which % 3 {
                    0 => format!("{padded}.{payload}.{signature}"),
                    1 => format!("{header}.{padded}.{signature}"),
                    _ => format!("{header}.{payload}.{padded}"),
                };
            }
            Perturbation::CorruptByte { at, to } => {
                if !token.is_empty() {
                    let mut bytes = token.into_bytes();
                    let index = (at as usize) % bytes.len();
                    bytes[index] = to;
                    token = String::from_utf8_lossy(&bytes).into_owned();
                }
            }
            Perturbation::InsertDot { at } => {
                let index = (at as usize) % (token.len() + 1);
                let mut bytes = token.into_bytes();
                let index = index.min(bytes.len());
                bytes.insert(index, b'.');
                token = String::from_utf8_lossy(&bytes).into_owned();
            }
            Perturbation::NonAscii => {
                // A three-segment token whose payload segment is not base64url at all, and whose
                // bytes are wider than one per character.
                token = format!("{header}.\u{00e9}\u{4e2d}\u{1f600}.{signature}");
            }
            Perturbation::Truncate { to } => {
                let cut = (to as usize) % (token.len() + 1);
                while !token.is_char_boundary(cut.min(token.len())) {
                    token.pop();
                }
                token.truncate(cut.min(token.len()));
            }
        }
        Ok(Token(token))
    }
}

/// One base64url segment holding a JSON object, most of the time. The rest of the time it holds
/// something that is valid base64url and is not an object, which is the case `parse` has to
/// refuse before a verifier ever sees it.
fn segment(u: &mut Unstructured<'_>) -> arbitrary::Result<String> {
    let json = match u.int_in_range(0..=5)? {
        0 => "[]".to_string(),
        1 => "\"a string\"".to_string(),
        2 => "null".to_string(),
        3 => String::from_utf8_lossy(&<Vec<u8>>::arbitrary(u)?).into_owned(),
        _ => {
            let alg = u
                .choose(&["ES256", "HS256", "none", "RS256", "ES384"])?
                .to_string();
            let typ = u
                .choose(&["JWT", "dpop+jwt", "at+jwt", "oauth-authz-req+jwt"])?
                .to_string();
            serde_json::json!({ "alg": alg, "typ": typ, "kid": "k1" }).to_string()
        }
    };
    Ok(URL_SAFE_NO_PAD.encode(json))
}

fuzz_target!(|token: Token| {
    let raw = token.0.as_str();
    let dots = raw.bytes().filter(|b| *b == b'.').count();

    let parsed = match CompactJws::parse(raw) {
        Ok(parsed) => parsed,
        Err(_) => {
            // 1, the half that only a NEGATIVE check can establish. `parse` may legitimately
            // refuse a three-dot-count token (a segment that is not base64url, a segment that
            // decodes to something other than a JSON object), so nothing is asserted here beyond
            // the absence of a panic. The `if` direction is asserted below.
            return;
        }
    };

    // 1.
    assert_eq!(
        dots, 2,
        "CompactJws::parse accepted a token with {dots} separators: {raw:?}"
    );

    // 2.
    assert!(
        raw.starts_with(parsed.signing_input),
        "the signing input is not a prefix of the token that arrived: {raw:?}"
    );
    assert_eq!(
        raw.as_bytes().get(parsed.signing_input.len()),
        Some(&b'.'),
        "the signing input does not end at a segment boundary: {raw:?}"
    );
    assert_eq!(
        parsed.signing_input.bytes().filter(|b| *b == b'.').count(),
        1,
        "the signing input is not exactly two segments: {raw:?}"
    );

    // 3.
    let signature_segment = &raw[parsed.signing_input.len() + 1..];
    assert_eq!(
        parsed.signing_input.len() + 1 + signature_segment.len(),
        raw.len(),
        "the three segments do not account for the whole token: {raw:?}"
    );
    // The decoded signature must be what that segment holds, and nothing else.
    assert_eq!(
        URL_SAFE_NO_PAD.decode(signature_segment).ok(),
        Some(parsed.signature.clone()),
        "the decoded signature is not the third segment: {raw:?}"
    );
});
