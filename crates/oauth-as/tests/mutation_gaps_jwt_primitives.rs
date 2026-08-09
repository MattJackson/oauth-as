// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The three JWT primitives a mutation sweep found nothing constraining: the precomputed JOSE
//! header, the RFC 2104 key-block branch, and the coordinate widths `verify_es256` relies on.
//!
//! Each test below names the mutant it kills and what a real caller would have lost. The common
//! thread is that every one of them is invisible to a suite that signs and verifies with the SAME
//! function: `tests/client_assertion.rs` mints its HS256 assertions with this crate's own
//! `hmac_sha256`, so a wrong HMAC still round-trips, and `tests/jwt.rs` reads the `kid` back out of
//! a header this crate also wrote. The oracle has to come from outside the code under test, so it
//! does here: an independently computed RFC 2104 vector, and RFC 8259's own rules about what a
//! JSON string may contain.

#![cfg(feature = "jwt")]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use oauth_as::jwt::{hmac_sha256, AccessTokenClaims, Audience, EcdsaP256Key, JwtConfig, PublicJwk};

const SCALAR: [u8; 32] = [0x2a; 32];
const AUDIENCE: &str = "https://rs.example";

/// A minimal RFC 9068 claim set. The claims are irrelevant to every assertion in this file: what
/// is under test is the PROTECTED HEADER, which is a function of the `kid` alone.
fn claims() -> AccessTokenClaims {
    AccessTokenClaims {
        iss: "https://as.example".to_string(),
        exp: 4_000_000_000,
        aud: Audience::One(AUDIENCE.to_string()),
        sub: "app".to_string(),
        client_id: "app".to_string(),
        iat: 1_700_000_000,
        jti: "jti".to_string(),
        scope: None,
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        #[cfg(feature = "mtls")]
        cnf: None,
    }
}

/// The decoded protected header of an access token signed under `kid`, as bytes, exactly as they
/// travel on the wire. A resource server gets these bytes and nothing else: the header is not
/// re-serialized anywhere between here and it.
fn protected_header(kid: &str) -> Vec<u8> {
    let config = JwtConfig::new(
        EcdsaP256Key::from_scalar_bytes(kid, &SCALAR).expect("a valid P-256 scalar"),
        AUDIENCE,
    );
    let token = config.sign_access_token(&claims()).expect("signing");
    let first = token
        .split('.')
        .next()
        .expect("a compact JWS has three parts");
    URL_SAFE_NO_PAD
        .decode(first)
        .expect("the protected header must be base64url")
}

/// KILLS: `jwt.rs replace match guard (c as u32) < 0x20 with false in encoded_jose_header`, and
/// the same site's `replace < with ==`.
///
/// RFC 8259 section 7 forbids a raw character below 0x20 inside a JSON string. Without the guard
/// (or with it narrowed to `== 0x20`, which no control character satisfies) a `kid` carrying one
/// is written into the header UNESCAPED, and the protected header of EVERY access token this
/// server signs stops being JSON. A resource server would fail to parse the token it was handed,
/// which is a total outage of the JWT format, caused by nothing more than a host naming its key
/// carelessly.
///
/// The `kid` is host-supplied through `EcdsaP256Key::from_scalar_bytes`, so this is reachable
/// without an attacker at all.
#[test]
fn a_kid_carrying_a_control_character_still_produces_a_json_header() {
    let header = protected_header("kid\u{1}one");
    let parsed: serde_json::Value = serde_json::from_slice(&header).unwrap_or_else(|e| {
        panic!(
            "the protected header must be JSON (RFC 7515 s4), got {:?}: {e}",
            String::from_utf8_lossy(&header)
        )
    });
    assert_eq!(
        parsed.get("kid").and_then(|v| v.as_str()),
        Some("kid\u{1}one"),
        "the kid a verifier reads back must be the kid the host configured, escaping and all"
    );
}

/// KILLS: `jwt.rs replace match guard (c as u32) < 0x20 with true in encoded_jose_header`, and
/// the same site's `replace < with >`.
///
/// The escape this function writes is `\u{:04x}`, a SINGLE BMP escape. That is correct for the
/// characters the guard admits (all of them below 0x20) and wrong for anything above 0xFFFF, which
/// RFC 8259 section 7 requires to be written as a surrogate PAIR. Widening the guard so that an
/// astral character reaches it produces a backslash-u followed by FIVE hex digits, which is not an
/// escape at all: JSON reads the first four digits as one character and the fifth as a literal, so
/// the `kid` a verifier reads back is a different string, and one that names no key in the
/// published JWKS. Rotation breaks silently.
///
/// The crate's own documentation says a `kid` "is not required to be ASCII", so this is a
/// configuration a host is invited to make.
#[test]
fn a_kid_outside_the_basic_multilingual_plane_survives_the_header() {
    let kid = "kid-\u{1f600}";
    let header = protected_header(kid);
    let parsed: serde_json::Value = serde_json::from_slice(&header).unwrap_or_else(|e| {
        panic!(
            "the protected header must be JSON (RFC 7515 s4), got {:?}: {e}",
            String::from_utf8_lossy(&header)
        )
    });
    assert_eq!(
        parsed.get("kid").and_then(|v| v.as_str()),
        Some(kid),
        "a verifier must be able to select the signing key by the name the host gave it"
    );
}

/// KILLS: `jwt.rs replace < with <= in encoded_jose_header`.
///
/// 0x20 is the space, and RFC 8259 section 7 lists exactly what must be escaped: the quote, the
/// reverse solidus, and the control characters BELOW 0x20. A space is none of those. Escaping it
/// anyway would still parse, so what is lost is not correctness: it is that the header stops being
/// the bytes the module says it is. This function exists to PRECOMPUTE what a derived
/// `Serialize` produced, and its own comment commits to "the bytes on the wire are unchanged by
/// this precomputation"; six bytes per space, on every token this server ever signs, is the cost
/// of that claim quietly becoming false.
#[test]
fn an_ordinary_kid_is_written_literally_rather_than_escaped() {
    let header = protected_header("2026 signing key");
    assert_eq!(
        String::from_utf8_lossy(&header),
        r#"{"alg":"ES256","typ":"at+jwt","kid":"2026 signing key"}"#,
        "the precomputed header must be byte-for-byte what a JSON serializer would have written"
    );
}

/// KILLS: `jwt.rs replace > with >= in hmac_sha256`.
///
/// RFC 2104 splits on the BLOCK SIZE: a key LONGER than 64 bytes is replaced by its own digest, a
/// key of 64 bytes or shorter is used as it stands, zero padded. At exactly 64 the two rules give
/// different keys and therefore different MACs, and `>=` picks the wrong one.
///
/// What a real deployment loses is `client_secret_jwt` for any client whose secret is exactly 64
/// characters, which is the length a 32-byte secret printed as hex has. The client signs with a
/// standard HMAC, this server verifies with a non-standard one, the two never agree, and the
/// client is refused with `invalid_client` on every request it will ever make. Nothing in the
/// existing suite could see it: `tests/client_assertion.rs` signs its assertions with this very
/// function, so a wrong HMAC still verifies against itself.
///
/// The expected values are computed OUTSIDE this crate (Python's `hmac` module over
/// `hashlib.sha256`, an independent implementation of RFC 2104), which is the only kind of oracle
/// that can settle this.
#[test]
fn the_rfc_2104_key_block_rule_switches_above_the_block_size_not_at_it() {
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    const MESSAGE: &[u8] = b"Hi There";

    // 63 bytes: short key, zero padded. Both readings agree here, so this is the control.
    assert_eq!(
        hex(&hmac_sha256(&[0x0b; 63], MESSAGE)),
        "60becd3ada41eee378b576c2e0b3cc5d7392ae1f2e70e58b44aa88ab4a562149",
        "a key shorter than the block is used as it stands"
    );
    // 64 bytes: exactly the block. RFC 2104 says use it as it stands; `>=` would hash it first.
    assert_eq!(
        hex(&hmac_sha256(&[0x0b; 64], MESSAGE)),
        "21cd586aeca0579d99a1c938127c92525a371f807bc5ba6eb78bc825bd4f2be3",
        "a key of exactly the block size is used as it stands, not replaced by its digest"
    );
    // 65 bytes: over the block, so the digest replaces it. This pins the branch that DOES fire.
    assert_eq!(
        hex(&hmac_sha256(&[0x0b; 65], MESSAGE)),
        "727b82fba264393c5d67fd6d6ad783e9019a1fa6a857fccb70f5852f04be5d5d",
        "a key longer than the block is replaced by its own digest"
    );
}

/// The PREMISE that makes `jwt.rs replace || with && in verify_es256` an equivalent mutant, pinned
/// so it cannot drift out from under that argument.
///
/// `verify_es256` re-checks `x.len() != 32 || y.len() != 32` after decoding the JWK's coordinates.
/// Weakening that `||` to `&&` would let a JWK with ONE malformed coordinate reach the
/// `copy_from_slice` below it, which panics on a length mismatch: an unauthenticated panic, since
/// a JWK arrives in a DPoP proof header. It survives the sweep because `PublicJwk`'s fields are
/// PRIVATE and both of its constructors already refuse a coordinate that is not exactly 32 decoded
/// bytes, so no reachable value can tell the two spellings apart.
///
/// That argument is only as good as the seal, and this is the seal: either coordinate, either
/// constructor, refused. If someone adds a third constructor that skips the width check, this test
/// keeps passing and the equivalence claim becomes false, so `MUTANTS.md` says explicitly that the
/// check inside `verify_es256` is retained as defence in depth for exactly that day.
#[test]
fn a_jwk_coordinate_that_is_not_thirty_two_bytes_cannot_be_constructed() {
    // A well-formed P-256 point, so that only the width under test differs between the cases.
    const X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
    const Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";
    // 31 bytes, base64url unpadded: one byte short of a coordinate.
    let short = URL_SAFE_NO_PAD.encode([0x01u8; 31]);
    // 33 bytes: one byte long. The check is a width EQUALITY, not a ceiling.
    let long = URL_SAFE_NO_PAD.encode([0x01u8; 33]);

    for (x, y, what) in [
        (short.as_str(), Y, "a short x"),
        (X, short.as_str(), "a short y"),
        (long.as_str(), Y, "a long x"),
        (X, long.as_str(), "a long y"),
    ] {
        assert!(
            PublicJwk::from_coordinates(x, y).is_err(),
            "from_coordinates must refuse {what}"
        );
        let json = serde_json::json!({"kty": "EC", "crv": "P-256", "x": x, "y": y});
        assert!(
            PublicJwk::from_json(&json).is_err(),
            "from_json must refuse {what}"
        );
    }
}
