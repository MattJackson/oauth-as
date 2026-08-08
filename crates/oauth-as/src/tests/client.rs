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

/// The hashed comparison goes through [`constant_time_eq`], NOT through `==`. The property that
/// matters is the one C9 was about: a length difference must not be observable, and the digest hex
/// is fixed width so there is nothing length-dependent left. This pins the wiring, since a
/// `self.encoded == computed` would pass every functional test in the suite and quietly reintroduce
/// an early-exit comparison on a credential.
#[test]
fn the_hashed_path_compares_in_constant_time() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client.rs"))
        .expect("src/client.rs must be readable");
    let start = source
        .find("fn verify_builtin(")
        .expect("verify_builtin must exist");
    let body = &source[start..start + 400];
    assert!(
        body.contains("constant_time_eq("),
        "the hashed verification path must use constant_time_eq, not =="
    );
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
