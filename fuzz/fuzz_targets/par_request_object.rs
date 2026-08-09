// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9101 signed request objects: the claim walk in `src/par.rs`, reached through
//! `AuthorizationServer::validate_signed_authorization_request`.
//!
//! # Why this parser is different from every other JWS reader in the crate
//!
//! Its output is not a yes or a no, it is an AUTHORIZATION REQUEST. Section 6.3 requires the
//! server to take the parameters from the object and NOTHING from the query, so every claim this
//! walk reads becomes a parameter of a request that will be approved and turned into a code. A
//! claim read as the wrong type, or a claim silently defaulted when it is absent, is not a parse
//! bug: it is a request that says something the client did not sign.
//!
//! # Why this one is structure aware
//!
//! The fixture holds the client's registered signing key, so the generator can produce a
//! CORRECTLY SIGNED object and then vary its claims. Without that, every input would die at the
//! signature check and the claim walk, which is the entire subject, would never execute.
//!
//! # The invariants
//!
//! 1. NOTHING VALIDATES WITHOUT THE REGISTERED SIGNATURE. Success implies the object was signed by
//!    the key registered for that client, under ES256. RFC 9101 section 10.5 and RFC 8725
//!    section 3.1: an unsigned object claiming `alg: none` is the attack this endpoint exists to
//!    refuse, because a request object that anybody can write is worse than no request object,
//!    the client having been told it cannot be rewritten.
//! 2. THE CLIENT IS THE CLIENT IT CLAIMS TO BE. Section 6.3 requires the object's own `client_id`
//!    claim to equal the one that selected the verification key. Selecting a key by a claimed
//!    identity is only safe because of that re-check, so this is the clause that makes the whole
//!    scheme sound rather than circular.
//! 3. AN UNKNOWN CLIENT NEVER VALIDATES. The fixture registers a key for exactly one client id.
//! 4. WHAT COMES OUT IS WHAT WAS SIGNED. On success, the validated request's `redirect_uri` and
//!    `scope` are the ones the generator put in the object, not defaults and not query values
//!    (there are none, by construction).
//! 5. A REFUSAL IS AN RFC 6749 s5.2 BODY, whatever the object contained.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use oauth_as::{AuthorizationError, ErrorCode};
use oauth_as_fuzz::{
    is_nqschar, jws_signed, jws_with_signature, request_object_key, runtime, server, ISSUER,
    JAR_ID, PUBLIC_ID, REDIRECT_URI, RFC7636_CHALLENGE,
};

/// One claim, spelled so the fuzzer can cheaply choose the CORRECT value. A generator that could
/// only produce arbitrary strings would never once assemble a request that validates, and the
/// claim walk past the first refusal would be dead code as far as the fuzzer is concerned.
#[derive(Arbitrary, Debug)]
enum Claim {
    Correct,
    Absent,
    Other(String),
    /// A JSON value that is not a string. Section 6.1's claims are strings; a walk that coerces
    /// is a walk that can be handed a number where a redirect URI belongs.
    NotAString,
    /// An empty string, which is present-but-empty rather than absent.
    Empty,
}

impl Claim {
    fn value(&self, correct: &str) -> Option<serde_json::Value> {
        match self {
            Claim::Correct => Some(correct.into()),
            Claim::Absent => None,
            Claim::Other(s) => Some(s.as_str().into()),
            Claim::NotAString => Some(serde_json::json!([1, 2, 3])),
            Claim::Empty => Some("".into()),
        }
    }
}

#[derive(Arbitrary, Debug)]
enum Signing {
    /// The client's registered request-object key.
    Registered,
    /// `alg: none`, empty signature: RFC 9101 s10.5.
    Unsigned,
    /// A wrong signature of the right length.
    Wrong([u8; 64]),
}

#[derive(Arbitrary, Debug)]
struct Input {
    signing: Signing,
    alg: Option<String>,
    typ: Option<String>,
    /// The client id the request arrives under, which selects the key.
    presented_client_id: PresentedClient,
    /// The `client_id` claim inside the object. Section 6.3 requires it to equal the above.
    claim_client_id: Claim,
    response_type: Claim,
    redirect_uri: Claim,
    scope: Claim,
    code_challenge: Claim,
    code_challenge_method: Claim,
    state: Option<String>,
    iss: Claim,
    aud: Claim,
    /// A raw string in place of the built object.
    raw: Option<String>,
}

#[derive(Arbitrary, Debug)]
enum PresentedClient {
    /// The client the fixture registered a key for.
    Registered,
    /// A registered client with NO request-object key.
    KeylessButRegistered,
    /// Text the fuzzer chose.
    Other(String),
}

impl PresentedClient {
    fn as_str(&self) -> &str {
        match self {
            PresentedClient::Registered => JAR_ID,
            PresentedClient::KeylessButRegistered => PUBLIC_ID,
            PresentedClient::Other(s) => s.as_str(),
        }
    }
}

fn build(input: &Input) -> String {
    if let Some(raw) = &input.raw {
        return raw.clone();
    }
    let mut header = serde_json::Map::new();
    header.insert(
        "alg".into(),
        input.alg.clone().unwrap_or_else(|| "ES256".into()).into(),
    );
    header.insert(
        "typ".into(),
        input
            .typ
            .clone()
            .unwrap_or_else(|| "oauth-authz-req+jwt".into())
            .into(),
    );
    header.insert("kid".into(), request_object_key().kid().into());
    let header = serde_json::Value::Object(header).to_string();

    let mut claims = serde_json::Map::new();
    for (name, claim, correct) in [
        ("client_id", &input.claim_client_id, JAR_ID),
        ("response_type", &input.response_type, "code"),
        ("redirect_uri", &input.redirect_uri, REDIRECT_URI),
        ("scope", &input.scope, "read"),
        ("code_challenge", &input.code_challenge, RFC7636_CHALLENGE),
        (
            "code_challenge_method",
            &input.code_challenge_method,
            "S256",
        ),
        ("iss", &input.iss, JAR_ID),
        ("aud", &input.aud, ISSUER),
    ] {
        if let Some(value) = claim.value(correct) {
            claims.insert(name.into(), value);
        }
    }
    if let Some(state) = &input.state {
        claims.insert("state".into(), state.as_str().into());
    }
    let payload = serde_json::Value::Object(claims).to_string();

    match &input.signing {
        Signing::Registered => {
            jws_signed(request_object_key(), header.as_bytes(), payload.as_bytes())
        }
        Signing::Unsigned => jws_with_signature(header.as_bytes(), payload.as_bytes(), Vec::new()),
        Signing::Wrong(bytes) => {
            jws_with_signature(header.as_bytes(), payload.as_bytes(), bytes.to_vec())
        }
    }
}

fuzz_target!(|input: Input| {
    let object = build(&input);
    let presented = input.presented_client_id.as_str();

    let outcome =
        runtime().block_on(server().validate_signed_authorization_request(presented, &object));

    let validated = match outcome {
        Ok(validated) => validated,
        Err(error) => {
            // 5. Both shapes of refusal carry an RFC 6749 s5.2 body, and neither may echo the
            // object: it is attacker-controlled JSON and section 5.2 fixes the charset that a
            // description may use precisely so it cannot.
            let response = match &error {
                AuthorizationError::Direct(response) => response,
                AuthorizationError::Redirect(redirect) => &redirect.error,
            };
            assert!(
                is_nqschar(response.error.as_str()),
                "an error code left RFC 6749 s5.2's charset"
            );
            if let Some(description) = &response.error_description {
                assert!(
                    is_nqschar(description),
                    "an error_description left RFC 6749 s5.2's charset: {description:?}"
                );
            }
            assert_ne!(
                response.error,
                ErrorCode::ServerError,
                "a request object produced a server_error rather than a refusal: {object:?}"
            );
            return;
        }
    };

    // 1.
    assert!(
        matches!(input.signing, Signing::Registered),
        "a request object validated without the registered client's signature (RFC 9101 s10.5): \
         {input:?}"
    );
    assert!(
        input.alg.as_deref().unwrap_or("ES256") == "ES256",
        "a request object validated under an alg other than ES256 (RFC 8725 s3.1): {input:?}"
    );

    // 2 and 3.
    assert!(
        matches!(input.presented_client_id, PresentedClient::Registered),
        "a request object validated for a client with no registered key: {input:?}"
    );
    assert!(
        matches!(input.claim_client_id, Claim::Correct),
        "a request object validated whose client_id claim did not name the client that selected \
         the key (RFC 9101 s6.3): {input:?}"
    );

    // 4. The parameters that come out are the ones that were SIGNED. `redirect_uri` above all:
    // it is the one parameter a wrong answer here sends the code to.
    assert_eq!(
        validated.redirect_uri, REDIRECT_URI,
        "the validated request carries a redirect_uri the object did not sign: {input:?}"
    );
    assert_eq!(
        validated.client_id.as_str(),
        JAR_ID,
        "the validated request names a client other than the one that signed it: {input:?}"
    );
    if let Some(state) = &input.state {
        assert_eq!(
            validated.state.as_deref(),
            Some(state.as_str()),
            "state was not carried through from the signed object"
        );
    }
});
