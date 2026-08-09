// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Lower-case hex encoding, defined once.
//!
//! Two unrelated-looking places in this crate turn bytes into lower-case hex text: `server`
//! encodes fresh OS randomness into device codes, authorization codes and opaque tokens, and
//! `client` encodes a SHA-256 digest into the stored form of a client secret. Through 0.9.0 each
//! had its own copy, `server::hex_encode` and `client::hex_lower`, with its own private
//! sixteen-byte digit table and the same two-nibble loop, byte for byte identical.
//!
//! That is the same defect `skew.rs` was created to fix for `CLOCK_SKEW_LEEWAY`, and it is fixed
//! the same way: one definition, in a private module, called from both. It matters more here than
//! the duplication alone suggests, because only ONE of the two copies carried the measurement
//! below, so a reader who found the other had nothing telling them the question had been settled.
//!
//! `tests/hex_single_definition.rs` is what keeps it at one.

/// The lower-case hex alphabet, as a table rather than a format string.
///
/// `write!(out, "{b:02x}")` per byte goes through `core::fmt`, which for 32 bytes is 32 trips
/// through a formatter with width and fill handling that a fixed two-nibble encoding never needs.
/// MEASURED at 1335 ns against 1092 ns for a 32-byte draw-and-encode. The output is identical, so
/// nothing about the artifact changes; this is the same string arrived at without the machinery.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Hex-encode `bytes`, lower case, two characters per byte.
///
/// The output is a stored and compared value in both callers (an opaque token is a storage key, a
/// [`crate::client::SecretHash`] is a verifier a deployment already has rows of), so the encoding
/// is not free to change: it is lower case, unpadded, and exactly `2 * bytes.len()` characters.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX_DIGITS[(b >> 4) as usize] as char);
        out.push(HEX_DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}
