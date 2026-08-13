// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! THE ACCEPTING SIDE OF THE BOUNDS, which is the side an off-by-one breaks.
//!
//! Every cap in this crate is tested one past its limit, because that is the refusal the cap exists
//! for. A bound tested only on the refusing side is half tested: `>=` where `>` was meant refuses a
//! request the constant says is legal, every assertion about the refusal still passes, and the
//! defect shows up as a client that cannot make a request the documentation says it may.
//!
//! Most of this crate's caps already have an at-cap acceptance test (`MAX_FORM_PARAMETERS`,
//! `MAX_REGISTERED_REDIRECT_URIS`, `MAX_CONSENT_RESOURCES`, `MAX_AUDIENCE_VALUES`, all three
//! `authorization_details` bounds, and `MAX_RESOURCE_INDICATORS` at the AUTHORIZATION endpoint).
//! The ones here did not.
//!
//! Two more sit elsewhere because their boundary is not where the constant's name suggests, and
//! both are named here so the claim above stays checkable. `MAX_FORM_PARAMETERS` is enforced as
//! `separators >= MAX`, so its smallest REFUSED request carries one fewer parameter than the
//! constant reads as; that request is `a_token_request_one_past_the_parameter_cap_is_refused` in
//! `tests/http_parameter_cap.rs`. `MIN_CLIENT_SECRET_JWT_KEY_LENGTH` is a FLOOR rather than a
//! ceiling, so its one-past case is one character BELOW it, in
//! `a_client_secret_jwt_key_below_the_entropy_floor_is_refused` in `tests/api_safety.rs`.

mod support;

use oauth_as::{ClientId, ErrorCode, TokenRequest};

use support::{server_with, ManualClock, PUBLIC_REDIRECT, RFC7636_VERIFIER};

/// The crate's built-in ES256 backend. Verification now goes through the [`oauth_as::jwt::Es256Verifier`] seam,
/// so a verifier is a per-call argument; this is the one a consumer who enables `jwt-p256` gets by
/// default, which is what keeps these tests measuring the behaviour they always measured.
#[cfg(all(
    feature = "jwt-p256",
    any(feature = "dpop", feature = "client-assertion")
))]
const VERIFIER: &oauth_as::jwt::P256Verifier = &oauth_as::jwt::P256Verifier;

/// `MAX_RESOURCE_INDICATORS` at the TOKEN endpoint. The authorization endpoint's half of this pair
/// has had an at-cap acceptance case since the cap was added; the token endpoint's had only the
/// refusal, and the two run through the same `validate_resources`, so an off-by-one there would
/// have broken both while only one of them could see it.
///
/// Exactly the cap must get PAST the size gate. It is then refused for the unrelated reason that
/// the code is made up, and `invalid_grant` rather than `invalid_target` is precisely the evidence
/// that the size check let it through.
#[tokio::test]
async fn the_token_endpoint_accepts_exactly_the_resource_indicator_cap() {
    let srv = server_with(ManualClock::at_epoch(), vec![support::public_client()]).await;
    let at_cap: Vec<String> = (0..oauth_as::server::MAX_RESOURCE_INDICATORS)
        .map(|i| format!("https://rs{i}.example/api"))
        .collect();
    assert_eq!(at_cap.len(), oauth_as::server::MAX_RESOURCE_INDICATORS);

    let refused = srv
        .token_with_resources(
            TokenRequest::AuthorizationCode {
                client_id: ClientId::new("public-app"),
                client_secret: None,
                code: "no-such-code".to_string(),
                redirect_uri: Some(PUBLIC_REDIRECT.to_string()),
                code_verifier: Some(RFC7636_VERIFIER.to_string()),
            },
            &at_cap,
        )
        .await
        .expect_err("the code is made up, so the request is refused either way");
    assert_eq!(
        refused.error,
        ErrorCode::InvalidGrant,
        "exactly {} resource indicators is inside the cap, so the request must be refused for the \
         made-up code and NOT with invalid_target",
        oauth_as::server::MAX_RESOURCE_INDICATORS
    );
}

/// `MAX_PROOF_BYTES` at the cap. The refusal at one past it has been tested since the cap was
/// added; a proof of exactly the cap had not been, and RFC 9449 section 4.2 proofs are not small:
/// they carry a whole public JWK, so a cap enforced with `>=` would refuse conforming proofs from
/// clients whose key or `kid` happened to sit on the boundary.
#[cfg(all(feature = "jwt-p256", feature = "dpop"))]
#[test]
fn a_proof_of_exactly_the_cap_is_accepted() {
    use oauth_as::dpop::{verify_proof, MAX_PROOF_BYTES};
    use oauth_as::jwt::{compact_jws, EcdsaP256Key};
    use std::time::{Duration, UNIX_EPOCH};

    const TOKEN_ENDPOINT: &str = "https://as.example/token";
    let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    // The compact form is `b64(header).b64(payload).b64(signature)`, and every part but the
    // payload is a fixed length for a given key: an ES256 signature is 64 raw bytes whatever it
    // signs. So the total is a pure function of two lengths and the padding can be SOLVED for
    // rather than searched. Two knobs are needed, not one, because base64url without padding does
    // not make every total reachable: `ceil(4n/3)` steps by 2, 1, 1, so one byte of `jti` padding
    // can only reach three totals in four. Padding the `kid` shifts the HEADER's length by one and
    // covers the fourth.
    //
    // THE PADDING IS NOT THE `jti`, and must not be. `MAX_JTI_BYTES` caps what a proof asks the
    // host to WRITE DOWN, separately from `MAX_PROOF_BYTES` capping what it asks the host to read,
    // so a fixture that reached the proof cap by growing the `jti` would be refused by the jti cap
    // long before it reached the boundary under test, and would then be measuring the wrong cap
    // while claiming to measure this one. The `jti` here is a realistic 22-character base64url
    // random and the bulk is an unregistered claim, which is what a real proof carrying a large
    // public JWK and a client's own extensions looks like.
    let payload_for = |pad: usize| {
        serde_json::to_vec(&serde_json::json!({
            "jti": "0123456789012345678901",
            "htm": "POST",
            "htu": TOKEN_ENDPOINT,
            "iat": 1_700_000_000u64,
            "client_padding": "x".repeat(pad),
        }))
        .unwrap()
    };
    let b64_len = |n: usize| n.div_ceil(3) * 4 - (3 - n % 3) % 3;
    let mut found = None;
    for kid_pad in 0..4 {
        let key = EcdsaP256Key::generate(format!("boundary{}", "y".repeat(kid_pad)));
        let header = serde_json::to_vec(&serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": serde_json::to_value(key.to_public_jwk()).unwrap(),
        }))
        .unwrap();
        let fixed = b64_len(header.len()) + 1 + 1 + b64_len(64);
        if let Some(pad) = (0..MAX_PROOF_BYTES)
            .find(|&pad| fixed + b64_len(payload_for(pad).len()) == MAX_PROOF_BYTES)
        {
            found = Some((key, header, pad));
            break;
        }
    }
    let (key, header, pad) =
        found.expect("some (kid, jti) padding puts the compact proof on exactly the cap");

    let proof = compact_jws(&header, &payload_for(pad), |input| {
        key.sign_signing_input(input).unwrap()
    });
    assert_eq!(
        proof.len(),
        MAX_PROOF_BYTES,
        "the whole point of this test is that the proof is EXACTLY the cap"
    );
    assert!(
        verify_proof(VERIFIER, &proof, "POST", TOKEN_ENDPOINT, now).is_ok(),
        "a proof of exactly MAX_PROOF_BYTES is inside the cap and must verify; refusing it would \
         be `>=` where the constant means `>`"
    );
}

/// The deepest `authorization_details` that fits inside `MAX_AUTHORIZATION_DETAILS_BYTES` is
/// REFUSED rather than crashing.
///
/// WHAT THIS DOES AND DOES NOT EXERCISE, because the version of this test that sent 2048 open
/// brackets did neither of the things it was cited for. `serde_json` is taken with default
/// features, so its `RECURSION_LIMIT` of 128 refuses at level 128: no `Value` tree is ever built,
/// `rar::depth` never runs, and the recursive `Drop` the production comment calls the falsifiable
/// half of its argument never happens. Nor could the assertion say which rule refused — all six
/// refusal arms of `parse` answer `invalid_authorization_details`, and this one was answered by
/// the very first, "must be a JSON array of objects", from the parser giving up on the brackets.
///
/// That case is still worth pinning and is pinned below, as the parser refusal it actually is.
#[cfg(feature = "rar")]
#[test]
fn a_document_past_the_parsers_own_recursion_limit_is_refused_not_fatal() {
    use oauth_as::rar::{AuthorizationDetails, MAX_AUTHORIZATION_DETAILS_BYTES};

    // As many open brackets as the byte cap admits, closed off so it is well formed JSON. Half
    // opens and half closes, so the nesting is the deepest a conforming document of this size can
    // reach.
    let levels = MAX_AUTHORIZATION_DETAILS_BYTES / 2;
    let mut raw = String::with_capacity(MAX_AUTHORIZATION_DETAILS_BYTES);
    for _ in 0..levels {
        raw.push('[');
    }
    for _ in 0..levels {
        raw.push(']');
    }
    assert!(raw.len() <= MAX_AUTHORIZATION_DETAILS_BYTES);

    let refused = AuthorizationDetails::parse(&raw)
        .expect_err("2048 levels of nesting is not an RFC 9396 s2 array of objects");
    assert_eq!(refused.error, ErrorCode::InvalidAuthorizationDetails);
    assert!(
        refused
            .error_description
            .unwrap_or_default()
            .contains("must be a JSON array of objects"),
        "this document never becomes a tree: the PARSER refuses it, and naming that is the only \
         way the test can be said to have exercised anything in particular"
    );
}

/// THE DEPTH BOUND ITSELF, on a document that really does become a tree.
///
/// `MAX_MEMBER_DEPTH` is `MAX_AUTHORIZATION_DETAILS_DEPTH - 2`, enforced by `depth(value) >
/// MAX_MEMBER_DEPTH` on each member of each element. Reaching that arm needs a document that is a
/// well formed RFC 9396 s2 array of typed objects AND inside `serde_json`'s own recursion limit,
/// so the parse succeeds, a `Value` tree exists, the recursive `depth` walk runs over it, and the
/// tree's recursive `Drop` runs when the refusal returns. All three are the work the production
/// comment argues is bounded; none of them happened under a bracket storm the parser threw out.
///
/// Deep enough to be nowhere near the bound (so this cannot be a boundary test in disguise, which
/// is what the at-cap acceptance cases in `src/tests/rar.rs` are for) and shallow enough that the
/// parser is not what answers.
#[cfg(feature = "rar")]
#[test]
fn a_member_nested_past_the_depth_bound_is_refused_by_the_depth_rule() {
    use oauth_as::rar::{AuthorizationDetails, MAX_AUTHORIZATION_DETAILS_BYTES};

    // 120 levels inside the member, plus the array and the element object, is 122 containers: well
    // under `serde_json`'s 128 and far over this crate's own bound of 6.
    const LEVELS: usize = 120;
    let mut raw = String::from(r#"[{"type":"example","vendor_extension":"#);
    for _ in 0..LEVELS {
        raw.push('[');
    }
    for _ in 0..LEVELS {
        raw.push(']');
    }
    raw.push_str("}]");
    assert!(raw.len() <= MAX_AUTHORIZATION_DETAILS_BYTES);

    let refused = AuthorizationDetails::parse(&raw)
        .expect_err("120 levels inside one member is far past MAX_AUTHORIZATION_DETAILS_DEPTH");
    assert_eq!(refused.error, ErrorCode::InvalidAuthorizationDetails);
    assert!(
        refused
            .error_description
            .unwrap_or_default()
            .contains("nested more deeply than this server accepts"),
        "the DEPTH rule has to be what refused: every arm of parse answers with the same code, so \
         the code alone cannot tell this from a parser failure or a missing type"
    );
}
