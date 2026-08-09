// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 6749 section 4.4: the client credentials grant, where the client acts on its own behalf
//! and its own authentication IS the authorization grant. As elsewhere in this crate, the
//! refusals are most of the point: who may use this grant at all (confidential clients only,
//! section 4.4) and what it must never hand back (a refresh token, section 4.4.3, or a subject)
//! matter more than the shape of a successful response.

mod support;

use oauth_as::{ClientId, ErrorCode, ScopeSet, TokenRequest};
use support::{
    client_credentials_client, confidential_client, device_only_client, server_with, ManualClock,
    CC_SECRET, CONFIDENTIAL_SECRET,
};

fn cc_request(secret: Option<&str>, scope: Option<&str>) -> TokenRequest {
    TokenRequest::ClientCredentials {
        client_id: ClientId::new("cc-app"),
        client_secret: secret.map(str::to_string),
        scope: scope.map(|s| ScopeSet::parse(s).unwrap()),
    }
}

/// RFC 6749 s4.4.3: a refresh token SHOULD NOT be issued for this grant, because the client can
/// simply present its own credentials again. And there is no resource owner, so no `sub`.
#[tokio::test]
async fn confidential_client_gets_a_token_with_no_refresh_token_and_no_subject() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![client_credentials_client()]).await;

    let token = srv
        .token(cc_request(Some(CC_SECRET), None))
        .await
        .expect("a registered confidential client with the right secret must succeed");

    assert!(
        token.refresh_token.is_none(),
        "RFC 6749 s4.4.3: client_credentials must not mint a refresh token"
    );
    assert_eq!(token.scope.as_deref(), Some("api:read api:write"));

    let record = srv
        .introspect(&token.access_token)
        .await
        .unwrap()
        .expect("the issued access token must be live");
    assert_eq!(
        record.subject, None,
        "there is no resource owner in this grant"
    );
}

/// RFC 6749 s4.4: this grant is for confidential clients. A public client cannot use it even when
/// its registration lists the grant, because "the client itself" has to be an identity someone
/// actually proved, and a public client has no secret to prove it with.
#[tokio::test]
async fn a_public_client_cannot_use_this_grant_even_if_registered_for_it() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(
        clock,
        vec![oauth_as::Client {
            client_id: ClientId::new("public-cc"),
            auth: oauth_as::ClientAuth::Public,
            grant_types: vec![oauth_as::GrantType::ClientCredentials],
            redirect_uris: vec![],
            allowed_scopes: ScopeSet::parse("read").unwrap(),
            default_scopes: ScopeSet::parse("read").unwrap(),
            name: None,
            registration: None,
        }],
    )
    .await;

    let err = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("public-cc"),
            client_secret: None,
            scope: None,
        })
        .await
        .expect_err("a public client must never be able to use client_credentials");
    assert_eq!(err.error, ErrorCode::InvalidClient);
}

/// A confidential client that IS authenticable but was not registered for this grant is refused
/// distinctly from an authentication failure: `unauthorized_client`, not `invalid_client`.
#[tokio::test]
async fn a_client_not_registered_for_the_grant_gets_unauthorized_client() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![device_only_client()]).await;

    let err = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("device-only"),
            client_secret: Some("s3cret-value-for-tests".to_string()),
            scope: None,
        })
        .await
        .expect_err("device-only is not registered for client_credentials");
    assert_eq!(err.error, ErrorCode::UnauthorizedClient);
}

/// A wrong secret is an authentication failure, judged before grant-type registration is even
/// consulted.
#[tokio::test]
async fn wrong_secret_gets_invalid_client() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![client_credentials_client()]).await;

    let err = srv
        .token(cc_request(Some("definitely-not-the-secret"), None))
        .await
        .expect_err("a wrong secret must not authenticate");
    assert_eq!(err.error, ErrorCode::InvalidClient);

    let err = srv
        .token(cc_request(None, None))
        .await
        .expect_err("a confidential client presenting no secret must not authenticate");
    assert_eq!(err.error, ErrorCode::InvalidClient);
}

/// RFC 6749 s3.3: an absent scope means the registration's default.
#[tokio::test]
async fn absent_scope_uses_the_registered_default() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![client_credentials_client()]).await;

    let token = srv.token(cc_request(Some(CC_SECRET), None)).await.unwrap();
    assert_eq!(token.scope.as_deref(), Some("api:read api:write"));
}

/// A scope narrower than the default is honoured exactly.
#[tokio::test]
async fn narrower_requested_scope_is_honoured() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![client_credentials_client()]).await;

    let token = srv
        .token(cc_request(Some(CC_SECRET), Some("api:read")))
        .await
        .unwrap();
    assert_eq!(token.scope.as_deref(), Some("api:read"));
}

/// A scope outside the client's ALLOWED set (not merely its default) is `invalid_scope`, even
/// when part of the request is legitimate.
#[tokio::test]
async fn scope_beyond_the_registration_is_invalid_scope() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![client_credentials_client()]).await;

    let err = srv
        .token(cc_request(
            Some(CC_SECRET),
            Some("api:read api:write api:superuser"),
        ))
        .await
        .expect_err("api:superuser was never registered for this client");
    assert_eq!(err.error, ErrorCode::InvalidScope);
}

/// A scope inside the allowed set but wider than the default (`api:admin`) is a legitimate
/// narrowing/selection request, not a widening violation: the registration's `allowed_scopes` is
/// the ceiling, not `default_scopes`.
#[tokio::test]
async fn scope_within_the_allowed_set_but_beyond_the_default_is_honoured() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![client_credentials_client()]).await;

    let token = srv
        .token(cc_request(Some(CC_SECRET), Some("api:admin")))
        .await
        .expect("api:admin is within allowed_scopes even though outside default_scopes");
    assert_eq!(token.scope.as_deref(), Some("api:admin"));
}

/// The issued token introspects correctly through the RFC 7662 wire surface, and in particular
/// carries no `sub` member at all (not merely a null one) since there is no resource owner.
#[tokio::test]
async fn issued_token_introspects_correctly_with_no_sub() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![client_credentials_client()]).await;

    let token = srv
        .token(cc_request(Some(CC_SECRET), Some("api:read")))
        .await
        .unwrap();

    let resp = srv
        .introspection_response(
            &ClientId::new("cc-app"),
            Some(CC_SECRET),
            &token.access_token,
        )
        .await
        .unwrap();
    assert!(resp.active);
    assert_eq!(resp.scope.as_deref(), Some("api:read"));
    assert_eq!(resp.client_id.as_deref(), Some("cc-app"));
    assert_eq!(resp.sub, None);
    assert_eq!(resp.token_type, Some(oauth_as::TokenType::Bearer));

    let value = serde_json::to_value(&resp).unwrap();
    assert!(
        value.as_object().unwrap().get("sub").is_none(),
        "a client_credentials token must not carry a sub member at all, got {value}"
    );
}

/// `confidential_client()` (used by the introspection and revocation suites) is ALSO registered
/// for client_credentials; this pins that it behaves identically through this endpoint rather
/// than being special-cased by client identity.
#[tokio::test]
async fn a_client_registered_for_multiple_grants_still_gets_no_refresh_token_here() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![confidential_client()]).await;

    let token = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            scope: None,
        })
        .await
        .expect("confidential-app is registered for client_credentials too");
    assert!(token.refresh_token.is_none());
}
