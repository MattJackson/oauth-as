// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9449 DPoP: the proof's JOSE header and claim validation, reached through the token
//! endpoint, plus the public `htu_of` normalizer.
//!
//! `dpop::verify_proof` is `pub(crate)`, so the fuzzer arrives the way a client does, on
//! `TokenRequestContext::dpop_proof`. What makes this parser unusual, and worth a target of its
//! own, is that the VERIFICATION KEY comes out of the proof itself: section 4.2 puts the public
//! JWK in the protected header. Every other signature check in this crate selects its key from a
//! registration; this one is handed one by the attacker and must still end up binding a token to
//! something the attacker actually holds.
//!
//! # The invariants
//!
//! 1. A PROOF NEVER WIDENS THE REQUEST. `client_credentials` for a client authenticated by
//!    secret: a success is only legitimate when the secret was presented. No proof, however it is
//!    shaped, may authenticate on its own.
//! 2. AN ISSUED TOKEN IS BOUND. If a token comes back for a request that carried a proof, its
//!    type is `DPoP` (section 5) rather than `Bearer`. A proof accepted but not bound is DPoP
//!    being decorative, and it is silent: every functional test still passes.
//! 3. `alg: none` AND A KEYLESS HEADER ARE REFUSED. Section 4.3 requires an asymmetric algorithm
//!    and a `jwk` member, and RFC 8725 s3.1 forbids `none` outright.
//! 4. `htu_of` IS A TRUNCATION AND NOTHING ELSE. Section 4.3 defines `htu` as the request URI
//!    without query or fragment, so the result must be a PREFIX of its input, must contain
//!    neither `?` nor `#`, and must be idempotent. A normalizer that rewrites rather than
//!    truncates is one an attacker can steer.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use oauth_as::dpop::htu_of;
use oauth_as::{TokenRequest, TokenRequestContext, TokenType};
use oauth_as_fuzz::{
    assertion_key, jws_signed, jws_with_signature, runtime, server, CONFIDENTIAL_ID,
    CONFIDENTIAL_SECRET, TOKEN_ENDPOINT,
};

/// What the protected header's `jwk` member holds.
#[derive(Arbitrary, Debug)]
enum HeaderKey {
    /// The public half of the key that actually signs. The honest case.
    Matching,
    /// No `jwk` at all: section 4.3 requires one.
    Absent,
    /// A JWK carrying a PRIVATE parameter, which `PublicJwk::from_json` must refuse.
    WithPrivateParameter,
    /// A JWK of the wrong key type or curve.
    WrongCurve,
    /// Arbitrary JSON.
    Arbitrary(String),
}

#[derive(Arbitrary, Debug)]
enum Signing {
    /// Signed by the key whose public half the header advertises.
    Correct,
    /// No signature at all.
    Empty,
    /// A wrong signature of the right length.
    Wrong([u8; 64]),
}

#[derive(Arbitrary, Debug)]
struct Input {
    key: HeaderKey,
    signing: Signing,
    alg: Option<String>,
    typ: Option<String>,
    htm: Option<String>,
    htu: Option<String>,
    jti: Option<String>,
    iat_offset: Option<i32>,
    /// One draw in a few is a raw string instead of a built proof.
    raw: Option<String>,
    /// Whether the registered secret is presented alongside. Invariant 1 is written against this.
    present_secret: bool,
    /// The input to the `htu_of` half of this target, which needs no server at all.
    url: String,
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn build(input: &Input) -> String {
    if let Some(raw) = &input.raw {
        return raw.clone();
    }
    let key = assertion_key();
    let public = key.to_public_jwk();

    let mut header = serde_json::Map::new();
    header.insert(
        "alg".into(),
        input.alg.clone().unwrap_or_else(|| "ES256".into()).into(),
    );
    header.insert(
        "typ".into(),
        input.typ.clone().unwrap_or_else(|| "dpop+jwt".into()).into(),
    );
    match &input.key {
        HeaderKey::Matching => {
            header.insert(
                "jwk".into(),
                serde_json::to_value(&public).unwrap_or(serde_json::Value::Null),
            );
        }
        HeaderKey::Absent => {}
        HeaderKey::WithPrivateParameter => {
            let mut jwk = serde_json::to_value(&public)
                .ok()
                .and_then(|v| v.as_object().cloned())
                .unwrap_or_default();
            jwk.insert("d".into(), "AAAA".into());
            header.insert("jwk".into(), serde_json::Value::Object(jwk));
        }
        HeaderKey::WrongCurve => {
            header.insert(
                "jwk".into(),
                serde_json::json!({
                    "kty": "EC",
                    "crv": "P-384",
                    "x": public.x,
                    "y": public.y,
                }),
            );
        }
        HeaderKey::Arbitrary(text) => {
            header.insert("jwk".into(), serde_json::Value::String(text.clone()));
        }
    }
    let header = serde_json::Value::Object(header).to_string();

    let mut claims = serde_json::Map::new();
    claims.insert(
        "htm".into(),
        input.htm.clone().unwrap_or_else(|| "POST".into()).into(),
    );
    claims.insert(
        "htu".into(),
        input
            .htu
            .clone()
            .unwrap_or_else(|| TOKEN_ENDPOINT.to_string())
            .into(),
    );
    claims.insert(
        "jti".into(),
        input
            .jti
            .clone()
            .unwrap_or_else(|| format!("jti-{}", now_secs()))
            .into(),
    );
    claims.insert(
        "iat".into(),
        (now_secs() + i64::from(input.iat_offset.unwrap_or(0))).into(),
    );
    let payload = serde_json::Value::Object(claims).to_string();

    match &input.signing {
        Signing::Correct => jws_signed(key, header.as_bytes(), payload.as_bytes()),
        Signing::Empty => jws_with_signature(header.as_bytes(), payload.as_bytes(), Vec::new()),
        Signing::Wrong(bytes) => {
            jws_with_signature(header.as_bytes(), payload.as_bytes(), bytes.to_vec())
        }
    }
}

fuzz_target!(|input: Input| {
    // 4. Pure, cheap, and independent of everything below.
    let htu = htu_of(&input.url);
    assert!(
        input.url.starts_with(htu),
        "htu_of rewrote rather than truncated {:?} into {htu:?}",
        input.url
    );
    assert!(
        !htu.contains('?') && !htu.contains('#'),
        "htu_of left a query or fragment in {htu:?} (RFC 9449 s4.3)"
    );
    assert_eq!(
        htu_of(htu),
        htu,
        "htu_of is not idempotent on {:?}",
        input.url
    );

    let proof = build(&input);

    let outcome = runtime().block_on(server().token_with_context(
        TokenRequest::ClientCredentials {
            client_id: oauth_as::ClientId::new(CONFIDENTIAL_ID),
            client_secret: input
                .present_secret
                .then(|| CONFIDENTIAL_SECRET.to_string()),
            scope: None,
        },
        TokenRequestContext {
            dpop_proof: Some(&proof),
            ..Default::default()
        },
    ));

    let Ok(token) = outcome else {
        return;
    };

    // 1.
    assert!(
        input.present_secret,
        "a token was issued to a confidential client with no secret presented; proof={proof:?}"
    );

    // 3, via 2: a proof that was accepted at all must have been a signed ES256 proof carrying the
    // matching public key. Anything else reaching a bound token is an algorithm or key confusion.
    if token.token_type == TokenType::Dpop {
        assert!(
            matches!(input.signing, Signing::Correct),
            "a proof was accepted with no valid signature: {input:?}"
        );
        assert!(
            matches!(input.key, HeaderKey::Matching),
            "a proof was accepted without advertising the key that signed it: {input:?}"
        );
        assert!(
            input.alg.as_deref().unwrap_or("ES256") == "ES256",
            "a proof was accepted under an alg other than ES256 (RFC 8725 s3.1): {input:?}"
        );
    }

    // 2. The server may legitimately answer a request carrying an UNACCEPTABLE proof by refusing
    // it, which is the `Err` arm above. What it must not do is accept the proof, issue a token,
    // and hand back a bearer token anyway: that is a token an attacker who steals it can use.
    if matches!(input.signing, Signing::Correct)
        && matches!(input.key, HeaderKey::Matching)
        && input.alg.is_none()
        && input.typ.is_none()
        && input.htm.is_none()
        && input.htu.is_none()
        && input.iat_offset.unwrap_or(0) == 0
        && input.raw.is_none()
    {
        assert_eq!(
            token.token_type,
            TokenType::Dpop,
            "a conforming RFC 9449 s4.2 proof produced an unbound token: {input:?}"
        );
    }
});
