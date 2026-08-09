// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for [`crate::client`], kept out of the implementation file. These reach
//! private items, so they live in the crate rather than in `tests/`.

use super::*;

#[test]
fn public_client_rejects_a_presented_secret() {
    let auth = ClientAuth::Public;
    assert!(auth.verify(None));
    assert!(!auth.verify(Some("anything")));
}

#[test]
fn confidential_client_requires_the_exact_secret() {
    let auth = ClientAuth::ConfidentialSecret {
        secret: "s3cret".into(),
    };
    assert!(auth.verify(Some("s3cret")));
    assert!(!auth.verify(Some("s3creT")));
    assert!(!auth.verify(Some("s3cret-and-more")));
    assert!(!auth.verify(Some("")));
    assert!(!auth.verify(None));
}

#[test]
fn c9_length_wraparound_no_longer_compares_unequal_secrets_as_equal() {
    // GREEN, post-fix. Before the fix (see git history / the audit report), this exact case was
    // observed to PASS as `constant_time_eq(&short, &long) == true`: the old accumulator only
    // folded bits 0..=15 of (a.len() ^ b.len()) into the check, and missing bytes were treated as
    // 0 via unwrap_or(0), so padding the shorter input out to a length whose difference is an
    // exact multiple of 65536 defeated both the length check and the byte loop.
    // "hunter2" vs "hunter2" + 65536 NUL bytes must NOT be equal, and now correctly is not: the
    // SHA-256-digest-first comparison has no length-dependent loop bound and no truncated length
    // check for this padding to exploit.
    let short = b"hunter2".to_vec();
    let mut long = short.clone();
    long.extend(vec![0u8; 65536]);
    assert_eq!(
        short.len() ^ long.len(),
        65536,
        "test setup: needs an exact 2^16 length gap"
    );
    assert!(
        !constant_time_eq(&short, &long),
        "unequal secrets must never compare equal, regardless of padding"
    );
}

#[test]
fn c13_confidential_secret_debug_format_is_redacted() {
    let auth = ClientAuth::ConfidentialSecret {
        secret: "top-secret-value".into(),
    };
    let printed = format!("{auth:?}");
    assert!(
        !printed.contains("top-secret-value"),
        "debug format leaked the secret: {printed}"
    );
    assert!(
        printed.contains("[redacted]"),
        "debug format should say the secret was redacted: {printed}"
    );
}

#[test]
fn c13_public_client_debug_format_is_unaffected() {
    // Nothing secret to redact on the Public variant; Debug should still say what it is.
    assert_eq!(format!("{:?}", ClientAuth::Public), "Public");
}

/// The built-in verifier scheme is exactly "lower-case hex of SHA-256 over the secret's UTF-8
/// bytes", so a host can compute it with `sha256sum` or with any other language's standard library
/// and get a value this crate accepts. Pinned against the NIST one-block message vector for
/// SHA-256 ("abc"), so a change of digest or encoding cannot pass unnoticed.
#[test]
fn the_builtin_hash_scheme_is_lower_case_hex_sha256() {
    let hash = SecretHash::sha256("abc");
    assert_eq!(hash.scheme(), SecretHash::SHA256_HEX);
    assert_eq!(
        hash.encoded(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(hash.encoded().len(), 64);
    assert!(hash
        .encoded()
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()));
}

/// `verify_builtin` answers ONLY for the scheme it implements. A host scheme reaching it must be
/// `false` and not, say, a comparison of the presented secret against a PHC string, which would be
/// a silent way for an unverifiable registration to start authenticating.
#[test]
fn verify_builtin_refuses_a_scheme_it_does_not_implement() {
    let hash = SecretHash::custom("argon2id", "$argon2id$v=19$m=65536$c2FsdA$aGFzaA");
    assert!(!hash.verify_builtin("$argon2id$v=19$m=65536$c2FsdA$aGFzaA"));
    assert!(!hash.verify_builtin("anything"));
}

/// The hashed path answers EXACTLY what `==` on the two digests would answer, at equal and
/// unequal lengths, and never on a prefix.
///
/// # What this test does not claim
///
/// It does not claim the comparison is constant time, and it is worth being blunt about why: no
/// `#[test]` in this suite can. A previous version of this test asserted that the literal text
/// `constant_time_eq(` appeared in the source of [`SecretHash::verify_builtin`], which exercised
/// no comparison at all: it would have passed for `constant_time_eq(a, b) || a == b` and failed on
/// a rename that changed nothing. That is coverage reported rather than provided, so it is gone.
///
/// The constant-time claim rests where it can actually be supported: STRUCTURALLY on
/// [`constant_time_eq`] itself (fixed-width fold, no early exit, lengths folded in), which
/// `constant_time_eq_agrees_with_eq` below and `tests/constant_time.rs` pin functionally, and
/// EMPIRICALLY on `benches/constant_time.rs`, which measures whether the position of the first
/// differing byte is observable. What is left for this test is the functional half, asserted
/// honestly: the answers themselves.
#[test]
fn the_hashed_path_answers_exactly_what_comparing_the_digests_would() {
    const SECRET: &str = "a-high-entropy-registered-client-secret";
    let hash = SecretHash::sha256(SECRET);

    assert!(hash.verify_builtin(SECRET), "the registered secret");

    // Equal length, one byte different: the case a comparison that stopped at the first difference
    // would answer correctly and leak how far it got.
    let mut near = SECRET.to_string();
    near.replace_range(0..1, "b");
    assert_ne!(near, SECRET, "the fixture must actually differ");
    assert!(!hash.verify_builtin(&near), "differs at the first byte");
    let mut near_end = SECRET.to_string();
    near_end.replace_range(SECRET.len() - 1..SECRET.len(), "X");
    assert!(!hash.verify_builtin(&near_end), "differs at the last byte");

    // Different lengths, in both directions, including a presented secret that has the whole
    // registered one as a prefix. C9 was a length-handling defect, so length is asserted rather
    // than assumed.
    assert!(!hash.verify_builtin(""), "the empty secret");
    assert!(
        !hash.verify_builtin(&SECRET[..SECRET.len() - 1]),
        "a prefix"
    );
    assert!(
        !hash.verify_builtin(&format!("{SECRET}x")),
        "an extension of the registered secret"
    );
    assert!(
        !hash.verify_builtin(&format!("{SECRET}{}", "\0".repeat(65536))),
        "the C9 padding: a length difference that only shows in bits above 15"
    );
    assert!(
        SecretHash::sha256("").verify_builtin(""),
        "an empty registered secret still verifies against itself"
    );

    // A STORED verifier that is a prefix of the right digest must not verify either: the digest is
    // fixed width, so a truncated one can only come from corruption or from a comparison that
    // stopped when one side ran out.
    let full = SecretHash::sha256(SECRET).encoded().to_string();
    let truncated = SecretHash::custom(SecretHash::SHA256_HEX, &full[..full.len() - 1]);
    assert!(
        !truncated.verify_builtin(SECRET),
        "a truncated stored digest must not match the secret it is a prefix of"
    );

    // The full agreement property, swept: `verify_builtin` and comparing the two digests by hand
    // must never disagree, whatever the shapes. The reference hex is written out here with
    // `{:02x}` rather than by calling the crate's own `hex_lower`, so that a defect in the
    // encoder cannot cancel itself out on both sides of this comparison.
    fn reference_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    for registered in ["", "a", "hunter2", SECRET] {
        let hash = SecretHash::sha256(registered);
        assert_eq!(
            hash.encoded(),
            reference_hex(&Sha256::digest(registered.as_bytes())),
            "the stored verifier is lower-case hex of the SHA-256 digest"
        );
        for presented in ["", "a", "A", "hunter2", "hunter20", SECRET, "\u{0}"] {
            assert_eq!(
                hash.verify_builtin(presented),
                reference_hex(&Sha256::digest(presented.as_bytes())) == *hash.encoded(),
                "verify_builtin({presented:?}) against a hash of {registered:?}"
            );
        }
    }
}

/// A hashed registration is confidential, and a public one is not. Three endpoints
/// (`client_credentials`, introspection, revocation) refuse public clients, and they must keep
/// refusing exactly the same set now that a second confidential storage form exists.
#[test]
fn confidentiality_is_asked_about_the_credential_not_the_variant() {
    assert!(!ClientAuth::Public.is_confidential());
    assert!(ClientAuth::ConfidentialSecret { secret: "s".into() }.is_confidential());
    assert!(ClientAuth::ConfidentialSecretHash {
        hash: SecretHash::sha256("s")
    }
    .is_confidential());
}

#[test]
fn constant_time_eq_agrees_with_eq() {
    let cases: &[(&[u8], &[u8], bool)] = &[
        (b"", b"", true),
        (b"a", b"", false),
        (b"", b"a", false),
        (b"abc", b"abc", true),
        (b"abc", b"abd", false),
        (b"abc", b"abcd", false),
    ];
    for (a, b, want) in cases {
        assert_eq!(constant_time_eq(a, b), *want, "{:?} vs {:?}", a, b);
    }
}
