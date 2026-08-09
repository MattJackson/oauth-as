// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 7523 client authentication: the JOSE header and claim validation reached through the token
//! endpoint, plus the public `unverified_subject` reader.
//!
//! # What is actually under test
//!
//! `client_assertion::verify_assertion` is `pub(crate)`, so the fuzzer reaches it the way a client
//! does: `TokenRequestContext::credential = ClientCredential::assertion(...)` on a real token
//! request. The registered client authenticates with `private_key_jwt` under a FIXED P-256 key
//! held by the fixture, and the generator is given that key. That is deliberate: a generator that
//! could only produce garbage signatures would never get past the signature check, and everything
//! interesting in RFC 7523 section 3 (the `iss`/`sub`/`aud`/`exp`/`jti` rules, and RFC 8725's
//! algorithm and type confusion hazards) lives AFTER it. So the fuzzer can sign correctly and
//! then lie in the claims, which is the attacker who has stolen nothing.
//!
//! # The invariants
//!
//! 1. ALGORITHM CONFUSION IS REFUSED. A `private_key_jwt` registration holds an ES256 public key.
//!    An assertion presenting `alg: none`, or `alg: HS256` with a MAC computed over that public
//!    key material, must never authenticate. This is RFC 8725 section 3.1 and section 2.1, and it
//!    is the single most consequential bug this whole feature could have.
//! 2. AUTHENTICATION IMPLIES THE FIXTURE KEY. Any success means the assertion was signed by the
//!    registered key AND named the registered client in both `iss` and `sub` AND named this
//!    server's token endpoint in `aud`. Every one of those is checked here against what the
//!    generator actually put in, not against what the server says it read.
//! 3. `unverified_subject` NEVER SPEAKS FOR AN UNPARSEABLE TOKEN. It returns `Some` only when the
//!    input is a three-segment JWS whose payload carries a string `sub`, and the string it
//!    returns is exactly that claim. It is used to pick which registration to check against, so a
//!    value it invents is a key selection an attacker chose.
//! 4. A REFUSAL IS AN RFC 6749 s5.2 BODY. `error` and `error_description` stay inside the
//!    section's charset whatever the assertion contained.

#![no_main]

use arbitrary::Arbitrary;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use libfuzzer_sys::fuzz_target;
use oauth_as::client_assertion::CLIENT_ASSERTION_TYPE;
use oauth_as::jwt::{hmac_sha256, CompactJws};
use oauth_as::{ClientCredential, TokenRequest, TokenRequestContext};
use oauth_as_fuzz::{
    assertion_key, is_nqschar, jws_signed, jws_with_signature, runtime, server, ASSERTION_ID,
    TOKEN_ENDPOINT,
};

/// How the assertion is signed.
#[derive(Arbitrary, Debug)]
enum Signing {
    /// The registered key. The honest case, and the only one that may succeed.
    RegisteredKey,
    /// `alg: none` with an empty signature: RFC 7515 appendix A.5, forbidden by RFC 8725 s3.1.
    None,
    /// HS256 with the registered PUBLIC key's coordinates as the MAC key. The classic
    /// confusion of RFC 8725 s2.1: the "secret" is a value the attacker also has.
    HmacOverPublicKey,
    /// A signature of the right length and the wrong content.
    WrongSignature(Vec<u8>),
    /// A signature of a fuzzer-chosen length, so the verifier's length handling is reached.
    ArbitrarySignature(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
enum Alg {
    Es256,
    Hs256,
    None,
    Rs256,
    /// Any string at all, including one that is not an algorithm.
    Other(String),
}

impl Alg {
    fn as_str(&self) -> &str {
        match self {
            Alg::Es256 => "ES256",
            Alg::Hs256 => "HS256",
            Alg::None => "none",
            Alg::Rs256 => "RS256",
            Alg::Other(s) => s.as_str(),
        }
    }
}

/// A claim: the honest value, a chosen wrong value, or absent. Spelled as an enum rather than an
/// `Option<String>` so the fuzzer can cheaply produce the CORRECT value, which it would otherwise
/// almost never generate and which every interesting input needs most of.
#[derive(Arbitrary, Debug)]
enum Claim {
    Correct,
    Absent,
    Other(String),
    NotAString,
}

#[derive(Arbitrary, Debug)]
struct Input {
    signing: Signing,
    alg: Alg,
    typ: Option<String>,
    kid: Option<String>,
    iss: Claim,
    sub: Claim,
    aud: Claim,
    jti: Option<String>,
    /// Seconds from now. Signed, so an expired assertion is reachable.
    exp_offset: Option<i32>,
    iat_offset: Option<i32>,
    /// A raw token, instead of everything above, one draw in eight. The front door still needs
    /// fuzzing: an empty string, a lone dot and a five-segment JWE are all reachable only here.
    raw: Option<String>,
    /// The `client_assertion_type` presented. Section 2.2 fixes exactly one value.
    assertion_type: Option<String>,
}

fn claim(value: &Claim, correct: &str) -> Option<serde_json::Value> {
    match value {
        Claim::Correct => Some(serde_json::Value::String(correct.to_string())),
        Claim::Absent => None,
        Claim::Other(s) => Some(serde_json::Value::String(s.clone())),
        Claim::NotAString => Some(serde_json::json!({ "not": "a string" })),
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Build the assertion, and say whether the generator signed it with the registered key over a
/// header that actually claims ES256. Invariant 2 is written against that flag.
fn build(input: &Input) -> (String, bool) {
    if let Some(raw) = &input.raw {
        return (raw.clone(), false);
    }
    let mut header = serde_json::Map::new();
    header.insert("alg".into(), input.alg.as_str().into());
    if let Some(typ) = &input.typ {
        header.insert("typ".into(), typ.as_str().into());
    }
    if let Some(kid) = &input.kid {
        header.insert("kid".into(), kid.as_str().into());
    }
    let header = serde_json::Value::Object(header).to_string();

    let mut claims = serde_json::Map::new();
    for (name, value, correct) in [
        ("iss", &input.iss, ASSERTION_ID),
        ("sub", &input.sub, ASSERTION_ID),
        ("aud", &input.aud, TOKEN_ENDPOINT),
    ] {
        if let Some(value) = claim(value, correct) {
            claims.insert(name.into(), value);
        }
    }
    if let Some(jti) = &input.jti {
        claims.insert("jti".into(), jti.as_str().into());
    }
    let now = now_secs();
    if let Some(offset) = input.exp_offset {
        claims.insert("exp".into(), (now + i64::from(offset)).into());
    }
    if let Some(offset) = input.iat_offset {
        claims.insert("iat".into(), (now + i64::from(offset)).into());
    }
    let payload = serde_json::Value::Object(claims).to_string();

    let key = assertion_key();
    match &input.signing {
        Signing::RegisteredKey => (
            jws_signed(key, header.as_bytes(), payload.as_bytes()),
            matches!(input.alg, Alg::Es256),
        ),
        Signing::None => (
            jws_with_signature(header.as_bytes(), payload.as_bytes(), Vec::new()),
            false,
        ),
        Signing::HmacOverPublicKey => {
            // The "key" an algorithm-confusion attacker uses: the PUBLIC coordinates, which are
            // published in the JWKS and in every proof the client ever sent.
            let jwk = key.to_public_jwk();
            let mut mac_key = URL_SAFE_NO_PAD.decode(&jwk.x).unwrap_or_default();
            mac_key.extend(URL_SAFE_NO_PAD.decode(&jwk.y).unwrap_or_default());
            let unsigned = jws_with_signature(header.as_bytes(), payload.as_bytes(), Vec::new());
            let signing_input = unsigned.trim_end_matches('.');
            let mac = hmac_sha256(&mac_key, signing_input.as_bytes());
            (
                format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(mac)),
                false,
            )
        }
        Signing::WrongSignature(bytes) => {
            let mut signature = bytes.clone();
            signature.resize(64, 0);
            (
                jws_with_signature(header.as_bytes(), payload.as_bytes(), signature),
                false,
            )
        }
        Signing::ArbitrarySignature(bytes) => (
            jws_with_signature(header.as_bytes(), payload.as_bytes(), bytes.clone()),
            false,
        ),
    }
}

fuzz_target!(|input: Input| {
    let (assertion, signed_es256_by_registered_key) = build(&input);

    // 3. The public reader, checked independently of the endpoint.
    let subject = oauth_as::client_assertion::unverified_subject(&assertion);
    let expected = CompactJws::parse(&assertion)
        .ok()
        .and_then(|jws| jws.claim_str("sub").map(str::to_string));
    assert_eq!(
        subject, expected,
        "unverified_subject disagrees with the parsed sub claim: {assertion:?}"
    );

    let assertion_type = input
        .assertion_type
        .clone()
        .unwrap_or_else(|| CLIENT_ASSERTION_TYPE.to_string());

    let outcome = runtime().block_on(server().token_with_context(
        // `client_credentials` because it is the grant that reaches client authentication with no
        // other artifact in hand, so a refusal can only be about the assertion.
        TokenRequest::ClientCredentials {
            client_id: oauth_as::ClientId::new(ASSERTION_ID),
            client_secret: None,
            scope: None,
        },
        TokenRequestContext {
            credential: ClientCredential::assertion(Some(&assertion_type), &assertion),
            ..Default::default()
        },
    ));

    match outcome {
        Err(error) => {
            // 4.
            assert!(
                is_nqschar(error.error.as_str()),
                "an error code left RFC 6749 s5.2's charset"
            );
            if let Some(description) = &error.error_description {
                assert!(
                    is_nqschar(description),
                    "an error_description left RFC 6749 s5.2's charset: {description:?}"
                );
            }
        }
        Ok(_) => {
            // 1 and 2. Every clause is checked against what the GENERATOR did.
            assert!(
                signed_es256_by_registered_key,
                "an assertion authenticated without an ES256 signature from the registered key: \
                 {input:?}"
            );
            assert!(
                matches!(input.iss, Claim::Correct) && matches!(input.sub, Claim::Correct),
                "an assertion authenticated without naming the registered client in iss and sub \
                 (RFC 7523 s3): {input:?}"
            );
            assert!(
                matches!(input.aud, Claim::Correct),
                "an assertion authenticated without naming this server's token endpoint in aud \
                 (RFC 7523 s3): {input:?}"
            );
            assert_eq!(
                assertion_type, CLIENT_ASSERTION_TYPE,
                "an assertion authenticated under a client_assertion_type RFC 7523 s2.2 does not \
                 define"
            );
        }
    }
});
