// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC-published test vectors: inputs and expected outputs taken VERBATIM from the RFCs, so the
//! oracle is the spec author, not this codebase.
//!
//! Coverage honesty: RFC 7636 (PKCE) appendix B publishes the only vector applicable to what this
//! crate computes today. RFC 7515 (JWS) appendix A and RFC 9068 (JWT access tokens) vectors are
//! NOT exercised because this crate issues opaque tokens and contains no JOSE code; the day a JWT
//! issuer lands, its vectors land beside it in this file.

use oauth_as::pkce;

/// RFC 7636 appendix B, verbatim: the example `code_verifier` and its S256 `code_challenge`.
const APPENDIX_B_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const APPENDIX_B_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

#[test]
fn rfc7636_appendix_b_s256_derivation() {
    assert_eq!(
        pkce::code_challenge_s256(APPENDIX_B_VERIFIER),
        APPENDIX_B_CHALLENGE
    );
}

#[test]
fn rfc7636_appendix_b_verification_accepts_the_pair_and_rejects_tampering() {
    assert!(pkce::verify_s256(APPENDIX_B_VERIFIER, APPENDIX_B_CHALLENGE));
    // Flip one character of the verifier: verification must fail.
    let tampered = APPENDIX_B_VERIFIER.replace('d', "e");
    assert_ne!(tampered, APPENDIX_B_VERIFIER);
    assert!(!pkce::verify_s256(&tampered, APPENDIX_B_CHALLENGE));
    // And against a truncated challenge.
    assert!(!pkce::verify_s256(
        APPENDIX_B_VERIFIER,
        &APPENDIX_B_CHALLENGE[..42]
    ));
}

#[test]
fn rfc7636_appendix_b_verifier_is_grammatical() {
    // The appendix's own verifier satisfies the section 4.1 grammar; our validator must agree.
    assert!(pkce::verifier_is_valid(APPENDIX_B_VERIFIER));
}

/// RFC 7636 appendix B also fixes the byte sequence of the verifier's SHA-256 digest via the
/// base64url mapping; decode our challenge output and pin the first bytes the RFC's example
/// walkthrough implies. This is a red-proof of the harness itself: if the challenge constant above
/// were ever "updated" to match a broken implementation, this independent decode would disagree.
#[test]
fn rfc7636_challenge_is_unpadded_base64url_of_a_32_byte_digest() {
    let c = pkce::code_challenge_s256(APPENDIX_B_VERIFIER);
    assert_eq!(
        c.len(),
        43,
        "32 bytes maps to exactly 43 unpadded base64url chars"
    );
    assert!(!c.ends_with('='));
    assert!(c
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));

    // THE PART THIS TEST'S NAME AND DOC ALWAYS CLAIMED, and did not do until the 0.9.1 audit
    // found it. The three assertions above are satisfied by ANY 43-character base64url string, so
    // this test passed while proving nothing about the digest. That mattered more than it looks:
    // `rfc7636_appendix_b_s256_derivation` compares the implementation against the constant at the
    // top of this file, and `verify_s256` is the same code path, so corrupting
    // `code_challenge_s256` and "updating" the constant to match would have shipped green through
    // the whole in-crate suite. This crate's headline PKCE claim (`Cargo.toml`, `lib.rs`: "verified
    // against the RFC's appendix B vector") rested on a guard that was inert.
    //
    // The digest below is RFC 7636 appendix B's own byte sequence, and the decoder is written out
    // here on purpose: decoding with the crate's own base64 would compare the implementation
    // against itself, which is the tautology the doc says this exists to avoid.
    let decoded = decode_base64url(&c);
    assert_eq!(
        decoded, RFC7636_APPENDIX_B_DIGEST,
        "the challenge must decode to appendix B's SHA-256 of the verifier, byte for byte"
    );
}

/// RFC 7636 appendix B: `SHA-256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")`, as bytes.
const RFC7636_APPENDIX_B_DIGEST: [u8; 32] = [
    19, 211, 30, 150, 26, 26, 216, 236, 47, 22, 177, 12, 76, 152, 46, 8, 118, 168, 120, 173, 109,
    241, 68, 86, 110, 225, 137, 74, 203, 112, 249, 195,
];

/// An unpadded base64url decoder written for this test alone.
///
/// Deliberately NOT the crate's decoder: the point is to check the crate's output against the RFC
/// with something that shares no code with it. A bug common to both would otherwise cancel out and
/// the comparison would pass.
fn decode_base64url(s: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for ch in s.bytes() {
        let value = ALPHABET
            .iter()
            .position(|a| *a == ch)
            .unwrap_or_else(|| panic!("{ch:?} is not a base64url character"))
            as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}
