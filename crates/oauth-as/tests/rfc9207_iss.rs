// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9207: the `iss` authorization response parameter.
//!
//! Why this exists at all. RFC 9700 section 4.4 names this as THE standard countermeasure to the
//! mix-up attack: a client that talks to several authorization servers otherwise has no way to
//! tell which one answered a given redirect, so an attacker who controls one AS can induce the
//! client to send a code issued by an honest AS to the attacker's token endpoint (or the reverse).
//! `iss` makes the answer self-identifying, and RFC 9207 section 2.4 puts the matching obligation
//! on the client to compare it against the issuer it started the flow with.
//!
//! RFC 9207 section 2 is specific about WHEN: the parameter is included "in the authorization
//! response", and section 2.2 spells out that this covers error responses too. That is why the
//! error-redirect cases below matter as much as the success case: an AS that only stamps `iss` on
//! success leaves the client unable to attribute a failure, which is the case an attacker steers
//! toward.

mod support;

use oauth_as::{
    AuthorizationError, AuthorizationRequest, AuthorizationServerMetadata, ErrorCode, ServerConfig,
};
use support::{public_client, server_with, ManualClock, PUBLIC_REDIRECT, RFC7636_VERIFIER};

/// The issuer `support::server_with` configures, and its percent-encoded form as it must appear in
/// a redirect query (`authorization.rs` encodes everything outside the RFC 3986 unreserved set).
const ISSUER: &str = "https://as.example";
const ISSUER_ENCODED: &str = "https%3A%2F%2Fas.example";

fn challenge() -> String {
    oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER)
}

fn good_request(challenge: &str) -> AuthorizationRequest<'static> {
    AuthorizationRequest {
        response_type: Some("code".into()),
        client_id: Some("public-app".into()),
        redirect_uri: Some(PUBLIC_REDIRECT.into()),
        scope: Some("read".into()),
        state: Some("opaque-state".into()),
        code_challenge: Some(challenge.to_string().into()),
        code_challenge_method: Some("S256".into()),
        ..Default::default()
    }
}

/// RFC 9207 s2: an AS supporting this specification MUST include `iss` in the authorization
/// response, and the value is its issuer identifier. This is the success half.
#[tokio::test]
async fn the_success_redirect_carries_the_issuer_identifier() {
    let srv = server_with(ManualClock::at_epoch(), vec![public_client()]).await;
    let c = challenge();

    let validated = srv
        .validate_authorization_request(&good_request(&c))
        .await
        .expect("a complete, valid request must validate");
    let response = srv
        .issue_authorization_code(&validated, "user-1")
        .await
        .expect("issuing a code for a validated request");

    let location = response.location(PUBLIC_REDIRECT);
    assert!(
        location.contains(&format!("iss={ISSUER_ENCODED}")),
        "RFC 9207 s2 requires iss in the authorization response, got {location}"
    );
    // The value is the issuer identifier itself, not a derived endpoint URL: RFC 9207 s2 ties it
    // to the same string as the RFC 8414 `issuer` metadata member.
    assert!(
        !location.contains("authorize"),
        "iss must be the issuer identifier, not the authorization endpoint: {location}"
    );
}

/// RFC 9207 s2 and s2.2: the parameter is returned in the authorization response REGARDLESS of
/// outcome. A user refusal (RFC 6749 s4.1.2.1 `access_denied`) is an authorization response, so it
/// carries `iss` too.
#[tokio::test]
async fn the_user_denial_redirect_carries_the_issuer_identifier() {
    let srv = server_with(ManualClock::at_epoch(), vec![public_client()]).await;
    let c = challenge();

    let validated = srv
        .validate_authorization_request(&good_request(&c))
        .await
        .unwrap();
    let location = validated.denied().location();

    assert!(
        location.contains("error=access_denied"),
        "the denial must still be the RFC 6749 s4.1.2.1 answer: {location}"
    );
    assert!(
        location.contains(&format!("iss={ISSUER_ENCODED}")),
        "RFC 9207 s2.2: error responses carry iss as well, got {location}"
    );
}

/// RFC 9207 s2.2 again, on the other error path: a request that fails validation AFTER the client
/// and redirect URI are trusted is reported by redirecting, and that redirect is an authorization
/// response.
#[tokio::test]
async fn a_redirected_validation_error_carries_the_issuer_identifier() {
    let srv = server_with(ManualClock::at_epoch(), vec![public_client()]).await;
    let c = challenge();
    let mut req = good_request(&c);
    // OAuth 2.1 removes the implicit grant, so this is `unsupported_response_type` reported to the
    // (already validated) redirect URI.
    req.response_type = Some("token".into());

    let err = srv
        .validate_authorization_request(&req)
        .await
        .expect_err("response_type=token must be refused");
    let redirect = match err {
        AuthorizationError::Redirect(r) => r,
        AuthorizationError::Direct(e) => panic!("expected a redirected error, got {e}"),
    };
    assert_eq!(redirect.error.error, ErrorCode::UnsupportedResponseType);
    let location = redirect.location();
    assert!(
        location.contains(&format!("iss={ISSUER_ENCODED}")),
        "RFC 9207 s2.2: a redirected error response carries iss, got {location}"
    );
}

/// RFC 9207 s2 says the value is the issuer identifier "as defined in [RFC8414]", i.e. the same
/// string the metadata document publishes as `issuer`. A host that configured a trailing slash must
/// not end up with two different spellings of its own identity, because RFC 9207 s2.4 has the
/// client compare them for EQUALITY.
#[tokio::test]
async fn the_iss_value_is_byte_identical_to_the_metadata_issuer() {
    let clock = ManualClock::at_epoch();
    let cfg = ServerConfig::new("https://as.example/", "https://as.example/device");
    let metadata_issuer = AuthorizationServerMetadata::from_config(&cfg).issuer;
    let srv = oauth_as::AuthorizationServer::with_clock(cfg, oauth_as::MemoryStorage::new(), clock);
    srv.register_client(public_client()).await.unwrap();

    let c = challenge();
    let validated = srv
        .validate_authorization_request(&good_request(&c))
        .await
        .unwrap();
    let response = srv
        .issue_authorization_code(&validated, "user-1")
        .await
        .unwrap();

    // Encoded the way the redirect builder encodes it: only `:` and `/` in an https issuer sit
    // outside the RFC 3986 unreserved set.
    let encoded = metadata_issuer.replace(':', "%3A").replace('/', "%2F");
    let location = response.location(PUBLIC_REDIRECT);
    assert!(
        location.contains(&format!("iss={encoded}")),
        "RFC 9207 s2.4 compares iss to the issuer identifier for equality, so the two spellings \
         must not differ: metadata says {metadata_issuer}, redirect says {location}"
    );
}

/// RFC 9207 s3 registers `authorization_response_iss_parameter_supported`, a boolean whose absence
/// (or `false`) tells a client the countermeasure is unavailable here. Because this server always
/// sends the parameter, the member must be present and true: a client cannot enforce section 2.4
/// against a server that will not say it does this.
#[test]
fn the_metadata_document_advertises_the_iss_parameter() {
    let cfg = ServerConfig::new(ISSUER, "https://as.example/device");
    let doc = AuthorizationServerMetadata::from_config(&cfg);
    let json = serde_json::to_value(&doc).unwrap();
    assert_eq!(
        json.get("authorization_response_iss_parameter_supported"),
        Some(&serde_json::json!(true)),
        "RFC 9207 s3: the member must be published, and true, for a server that sends iss"
    );
}

/// The one place `iss` is NOT delivered, and why that is right: RFC 6749 s4.1.2.1 forbids
/// redirecting when the client or the redirect URI cannot be validated, so there is no
/// authorization response for RFC 9207 s2 to apply to. Stamping the issuer onto a directly rendered
/// error would put it somewhere no client ever reads it, and reaching that error at all means the
/// AS has nowhere it may safely send anything.
#[tokio::test]
async fn an_unvalidatable_request_produces_no_authorization_response_at_all() {
    let srv = server_with(ManualClock::at_epoch(), vec![public_client()]).await;
    let c = challenge();
    let mut req = good_request(&c);
    req.client_id = Some("not-registered".into());

    let err = srv
        .validate_authorization_request(&req)
        .await
        .expect_err("an unknown client must be refused");
    assert!(
        matches!(err, AuthorizationError::Direct(_)),
        "an unknown client must not be answered by redirecting anywhere"
    );
}
