// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Unit tests for [`crate::token_exchange`], kept out of the implementation file. These reach
//! private items and pin the wire spellings, which are the part of RFC 8693 that a typo makes
//! wrong in a way no behavioural test would notice: a `subject_token_type` misspelled by one
//! character simply never matches, and the request is refused for the wrong reason.

use super::*;

/// RFC 8693 section 3 registers each identifier as a full URN. A shortened spelling is a different
/// token type, not an abbreviation of this one.
#[test]
fn every_token_type_identifier_round_trips_through_its_registered_urn() {
    for (id, urn) in [
        (
            TokenTypeIdentifier::AccessToken,
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        (
            TokenTypeIdentifier::RefreshToken,
            "urn:ietf:params:oauth:token-type:refresh_token",
        ),
        (
            TokenTypeIdentifier::IdToken,
            "urn:ietf:params:oauth:token-type:id_token",
        ),
        (
            TokenTypeIdentifier::Saml1,
            "urn:ietf:params:oauth:token-type:saml1",
        ),
        (
            TokenTypeIdentifier::Saml2,
            "urn:ietf:params:oauth:token-type:saml2",
        ),
        (
            TokenTypeIdentifier::Jwt,
            "urn:ietf:params:oauth:token-type:jwt",
        ),
    ] {
        assert_eq!(id.as_str(), urn);
        assert_eq!(id.to_string(), urn);
        assert_eq!(TokenTypeIdentifier::from_str(urn), Ok(id));
        // The serde spelling and the FromStr spelling must be the same string, or a document
        // deserialized from the wire and one parsed from a form body disagree.
        assert_eq!(
            serde_json::to_value(id).unwrap(),
            serde_json::Value::String(urn.to_string())
        );
    }
}

/// An unrecognised identifier is a REFUSAL, never a default. Section 2.2.2 makes an unacceptable
/// subject token an error, and a parse that fell back to `access_token` would check a string a way
/// the caller did not ask for.
#[test]
fn an_unregistered_token_type_identifier_does_not_parse() {
    assert!(TokenTypeIdentifier::from_str("access_token").is_err());
    assert!(TokenTypeIdentifier::from_str("urn:ietf:params:oauth:token-type:mac").is_err());
    assert!(TokenTypeIdentifier::from_str("").is_err());
}

/// RFC 8693 section 2.1 registers the grant type URN; this is the string a host matches
/// `grant_type` against.
#[test]
fn the_grant_type_urn_is_the_registered_one() {
    assert_eq!(
        TOKEN_EXCHANGE_GRANT_URN,
        "urn:ietf:params:oauth:grant-type:token-exchange"
    );
}

/// The house rule that no credential reaches a debug format. This type carries THREE (the client
/// secret, the subject token and the actor token) and is the value a host is most likely to
/// debug-print, because it is the request it just parsed.
#[test]
fn the_request_debug_prints_no_credential() {
    let client_id = ClientId::new("some-client");
    let mut request = TokenExchangeRequest::new(&client_id, "SUBJECT-TOKEN-SECRET");
    request.client_secret = Some("CLIENT-SECRET-VALUE");
    request.actor_token = Some("ACTOR-TOKEN-SECRET");
    request.actor_token_type = Some(TokenTypeIdentifier::AccessToken);
    let rendered = format!("{request:?}");

    for secret in [
        "SUBJECT-TOKEN-SECRET",
        "CLIENT-SECRET-VALUE",
        "ACTOR-TOKEN-SECRET",
    ] {
        assert!(!rendered.contains(secret), "{secret} leaked into Debug");
    }
    // What must stay: the client id (RFC 6749 s2.2 makes it explicitly not a secret) and the
    // PRESENCE of the actor token, which is the difference between delegation and impersonation
    // and is the first thing anyone debugging this grant needs to see.
    assert!(rendered.contains("some-client"));
    assert!(rendered.contains("actor_token: Some(\"[redacted]\")"));
}

/// The response carries the issued token, so its `Debug` is redacted for the same reason.
#[test]
fn the_response_debug_prints_no_token() {
    let response = TokenExchangeResponse {
        access_token: "ISSUED-TOKEN-SECRET".to_string(),
        issued_token_type: TokenTypeIdentifier::AccessToken,
        token_type: TokenType::Bearer,
        expires_in: Some(3600),
        scope: Some("read".to_string()),
        refresh_token: None,
    };
    let rendered = format!("{response:?}");
    assert!(!rendered.contains("ISSUED-TOKEN-SECRET"));
    assert!(rendered.contains("Bearer"));
}

/// RFC 8693 section 4.1: a chain of delegation is expressed by NESTING, with the outermost claim
/// the current actor. The serialization has to keep that nesting, because flattening it would lose
/// which actor a consumer is required to authorize against.
#[test]
fn the_act_claim_nests_prior_actors_and_omits_what_is_absent() {
    let claim = ActClaim {
        sub: "current-actor".to_string(),
        client_id: Some("gateway".to_string()),
        act: Some(Box::new(ActClaim {
            sub: "earlier-actor".to_string(),
            client_id: None,
            act: None,
        })),
    };
    let json = serde_json::to_value(&claim).unwrap();
    assert_eq!(json["sub"], serde_json::json!("current-actor"));
    assert_eq!(json["act"]["sub"], serde_json::json!("earlier-actor"));
    assert!(
        json["act"].get("client_id").is_none(),
        "an absent optional claim is omitted, never null"
    );
    assert!(json["act"].get("act").is_none());
}
