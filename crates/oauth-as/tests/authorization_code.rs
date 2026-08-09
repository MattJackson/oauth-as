// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The RFC 6749 section 4.1 authorization code grant under the OAuth 2.1 constraints: PKCE is
//! mandatory, redirect URIs match exactly, codes are single use, and a replayed code revokes what
//! it already minted.
//!
//! Most of this file is negative cases. An authorization endpoint that never refuses anything
//! passes every happy-path test ever written and is still catastrophically broken, so the refusals
//! are the part worth pinning.

mod support;

use oauth_as::server::UserApproval;
use std::time::Duration;

use oauth_as::{
    AuthorizationError, AuthorizationRequest, ClientId, CodeChallengeMethod, ErrorCode,
    TokenRequest,
};
use support::{
    device_only_client, public_client, server_with, two_redirect_client, ManualClock,
    PUBLIC_REDIRECT, RFC7636_VERIFIER, SECOND_REDIRECT,
};

fn challenge() -> String {
    oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER)
}

/// A complete, valid request from the public client.
fn good_request(challenge: &str) -> AuthorizationRequest<'static> {
    AuthorizationRequest {
        resource: Vec::new(),
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        response_type: Some("code".into()),
        client_id: Some("public-app".into()),
        redirect_uri: Some(PUBLIC_REDIRECT.into()),
        scope: Some("read write".into()),
        state: Some("opaque-state".into()),
        code_challenge: Some(challenge.to_string().into()),
        code_challenge_method: Some("S256".into()),
        #[cfg(feature = "consent")]
        acr_values: None,
        #[cfg(feature = "consent")]
        max_age: None,
    }
}

fn redeem(code: &str, verifier: &str) -> TokenRequest {
    TokenRequest::AuthorizationCode {
        client_id: ClientId::new("public-app"),
        client_secret: None,
        code: code.to_string(),
        redirect_uri: Some(PUBLIC_REDIRECT.to_string()),
        code_verifier: Some(verifier.to_string()),
    }
}

// ---------------------------------------------------------------- happy path

#[tokio::test]
async fn valid_request_issues_a_code_that_redeems_once() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![public_client()]).await;
    let c = challenge();

    let validated = srv
        .validate_authorization_request(&good_request(&c))
        .await
        .expect("a complete, valid request must validate");
    assert_eq!(validated.redirect_uri, PUBLIC_REDIRECT);
    assert_eq!(validated.code_challenge_method, CodeChallengeMethod::S256);

    let response = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .expect("issuing a code for a validated request");
    assert_eq!(
        response.state.as_deref(),
        Some("opaque-state"),
        "RFC 6749 s4.1.2: state is echoed back unmodified"
    );
    assert!(!response.code.is_empty());

    let issued = srv
        .token(redeem(&response.code, RFC7636_VERIFIER))
        .await
        .expect("the code must redeem with the matching verifier");
    assert!(!issued.access_token.is_empty());
    assert_eq!(issued.expires_in, 3600);
    assert_eq!(
        issued.scope.as_deref(),
        Some("read write"),
        "the granted scope is reported (RFC 6749 s5.1)"
    );

    // The token is real: introspection knows it and attributes it to the right subject.
    let introspected = srv.introspect(&issued.access_token).await.unwrap().unwrap();
    assert_eq!(introspected.subject.as_deref(), Some("user-1"));
}

/// The redirect URL is what the user agent actually follows, so its construction is part of the
/// protocol, not a formatting detail: the code and state must survive percent-encoding intact.
#[tokio::test]
async fn success_redirect_url_encodes_parameters() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;
    let c = challenge();
    let mut req = good_request(&c);
    req.state = Some("a b&c=d#e".into());

    let validated = srv.validate_authorization_request(&req).await.unwrap();
    let response = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .unwrap();
    let location = response.location(PUBLIC_REDIRECT);

    assert!(location.starts_with(&format!("{PUBLIC_REDIRECT}?")));
    assert!(
        location.contains("state=a%20b%26c%3Dd%23e"),
        "reserved characters in state must be percent-encoded, got {location}"
    );
    assert!(
        !location.contains('#') || location.contains("%23"),
        "an unencoded fragment marker would truncate the query"
    );
}

/// A redirect URI that already carries a query must gain the parameters, not lose them.
#[tokio::test]
async fn redirect_url_appends_to_an_existing_query() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;
    let c = challenge();
    let validated = srv
        .validate_authorization_request(&good_request(&c))
        .await
        .unwrap();
    let response = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .unwrap();

    let location = response.location("https://app.example/cb?tenant=acme");
    assert!(
        location.starts_with("https://app.example/cb?tenant=acme&"),
        "existing query must be preserved, got {location}"
    );
}

// -------------------------------------------------- errors that MUST NOT redirect

/// RFC 6749 s4.1.2.1: with an unvalidated client the AS MUST NOT redirect, because the redirect
/// target is exactly what an attacker would be trying to choose.
#[tokio::test]
async fn unknown_client_does_not_redirect() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;
    let c = challenge();
    let mut req = good_request(&c);
    req.client_id = Some("no-such-client".into());

    match srv.validate_authorization_request(&req).await {
        Err(AuthorizationError::Direct(e)) => assert_eq!(e.error, ErrorCode::InvalidRequest),
        other => panic!("an unknown client_id must not produce a redirect, got {other:?}"),
    }
}

/// A redirect URI that is not registered is the classic open-redirect vector; OAuth 2.1 requires
/// exact string matching and RFC 6749 s4.1.2.1 forbids redirecting to it to report the problem.
#[tokio::test]
async fn unregistered_redirect_uri_does_not_redirect() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;
    let c = challenge();
    let mut req = good_request(&c);
    req.redirect_uri = Some("https://attacker.example/steal".into());

    match srv.validate_authorization_request(&req).await {
        Err(AuthorizationError::Direct(_)) => {}
        other => panic!("an unregistered redirect_uri must not be redirected to, got {other:?}"),
    }
}

/// Exact match means exact: a trailing slash, a different case in the path, or an extra query
/// parameter is a different URI (OAuth 2.1 s4.1.3).
#[tokio::test]
async fn redirect_uri_matching_is_exact() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;
    let c = challenge();
    for near_miss in [
        "https://app.example/cb/",
        "https://app.example/CB",
        "https://app.example/cb?extra=1",
        "https://app.example/cb#frag",
        "http://app.example/cb",
    ] {
        let mut req = good_request(&c);
        req.redirect_uri = Some(near_miss.into());
        assert!(
            matches!(
                srv.validate_authorization_request(&req).await,
                Err(AuthorizationError::Direct(_))
            ),
            "{near_miss} must not match the registered URI"
        );
    }
}

/// With exactly one registered URI the request may omit it (RFC 6749 s3.1.2.3).
#[tokio::test]
async fn omitted_redirect_uri_uses_the_single_registration() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;
    let c = challenge();
    let mut req = good_request(&c);
    req.redirect_uri = None;

    let validated = srv.validate_authorization_request(&req).await.unwrap();
    assert_eq!(validated.redirect_uri, PUBLIC_REDIRECT);
}

/// With more than one registered URI the AS cannot guess, and guessing wrong is a token leak.
#[tokio::test]
async fn omitted_redirect_uri_with_multiple_registrations_is_refused_without_redirecting() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![two_redirect_client()]).await;
    let c = challenge();
    let mut req = good_request(&c);
    req.client_id = Some("multi-redirect".into());
    req.redirect_uri = None;

    match srv.validate_authorization_request(&req).await {
        Err(AuthorizationError::Direct(e)) => assert_eq!(e.error, ErrorCode::InvalidRequest),
        other => panic!("ambiguous redirect target must not be guessed, got {other:?}"),
    }
}

/// The second registered URI is equally valid when the request names it.
#[tokio::test]
async fn either_registered_redirect_uri_is_accepted_when_named() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![two_redirect_client()]).await;
    let c = challenge();
    let mut req = good_request(&c);
    req.client_id = Some("multi-redirect".into());
    req.redirect_uri = Some(SECOND_REDIRECT.into());
    req.scope = Some("read".into());

    let validated = srv.validate_authorization_request(&req).await.unwrap();
    assert_eq!(validated.redirect_uri, SECOND_REDIRECT);
}

// ------------------------------------------------------ errors that DO redirect

async fn redirect_error(req: &AuthorizationRequest<'_>) -> ErrorCode {
    let clock = ManualClock::at_epoch();
    let srv = server_with(
        clock,
        vec![public_client(), two_redirect_client(), device_only_client()],
    )
    .await;
    match srv.validate_authorization_request(req).await {
        Err(AuthorizationError::Redirect(r)) => r.error.error,
        other => panic!("expected a redirected error, got {other:?}"),
    }
}

/// OAuth 2.1 requires PKCE for the authorization code grant; a missing challenge is
/// `invalid_request` (RFC 7636 s4.4.1), never a silently granted code.
#[tokio::test]
async fn missing_pkce_challenge_is_invalid_request() {
    let c = challenge();
    let mut req = good_request(&c);
    req.code_challenge = None;
    req.code_challenge_method = None;
    assert_eq!(redirect_error(&req).await, ErrorCode::InvalidRequest);
}

/// `plain` is not implemented and is not advertised; accepting it would be a PKCE downgrade.
#[tokio::test]
async fn plain_pkce_method_is_refused() {
    let c = challenge();
    let mut req = good_request(&c);
    req.code_challenge_method = Some("plain".into());
    assert_eq!(redirect_error(&req).await, ErrorCode::InvalidRequest);

    // ... and so is an unknown method name.
    let mut req = good_request(&c);
    req.code_challenge_method = Some("S512".into());
    assert_eq!(redirect_error(&req).await, ErrorCode::InvalidRequest);
}

/// RFC 7636 s4.2 fixes the challenge shape; a malformed challenge cannot verify against any
/// verifier, so accepting it would issue a code that can never be redeemed.
#[tokio::test]
async fn malformed_code_challenge_is_refused() {
    let c = challenge();
    for bad in ["", "too-short", &"a".repeat(200), "not+base64url/at=all"] {
        let mut req = good_request(&c);
        req.code_challenge = Some(bad.to_string().into());
        assert_eq!(
            redirect_error(&req).await,
            ErrorCode::InvalidRequest,
            "challenge {bad:?} must be refused"
        );
    }
}

/// OAuth 2.1 removes the implicit grant, so `token` is not merely unsupported here, it is gone.
#[tokio::test]
async fn implicit_response_type_is_unsupported() {
    let c = challenge();
    let mut req = good_request(&c);
    req.response_type = Some("token".into());
    assert_eq!(
        redirect_error(&req).await,
        ErrorCode::UnsupportedResponseType
    );
}

#[tokio::test]
async fn missing_response_type_is_invalid_request() {
    let c = challenge();
    let mut req = good_request(&c);
    req.response_type = None;
    assert_eq!(redirect_error(&req).await, ErrorCode::InvalidRequest);
}

/// A client may not obtain, through the authorization endpoint, scope its registration forbids.
#[tokio::test]
async fn scope_beyond_the_registration_is_invalid_scope() {
    let c = challenge();
    let mut req = good_request(&c);
    req.scope = Some("read write admin superuser".into());
    assert_eq!(redirect_error(&req).await, ErrorCode::InvalidScope);
}

/// A client registered only for the device grant must not be able to start a code flow.
#[tokio::test]
async fn client_without_the_grant_is_unauthorized_client() {
    let c = challenge();
    let mut req = good_request(&c);
    req.client_id = Some("device-only".into());
    req.scope = Some("read".into());
    assert_eq!(redirect_error(&req).await, ErrorCode::UnauthorizedClient);
}

/// The user refusing consent is `access_denied` delivered to the client, not an error page.
#[tokio::test]
async fn denial_redirects_with_access_denied_and_the_state() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;
    let c = challenge();
    let validated = srv
        .validate_authorization_request(&good_request(&c))
        .await
        .unwrap();

    let denial = validated.denied();
    assert_eq!(denial.error.error, ErrorCode::AccessDenied);
    assert_eq!(denial.state.as_deref(), Some("opaque-state"));
    let location = denial.location();
    assert!(location.starts_with(PUBLIC_REDIRECT));
    assert!(location.contains("error=access_denied"));
    assert!(
        location.contains("state=opaque-state"),
        "RFC 6749 s4.1.2.1: state is echoed on the error redirect too"
    );
    assert!(
        !location.contains("code="),
        "a denial must not carry a code"
    );
}

// ------------------------------------------------------- redemption negatives

#[tokio::test]
async fn wrong_verifier_is_invalid_grant() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;
    let c = challenge();
    let validated = srv
        .validate_authorization_request(&good_request(&c))
        .await
        .unwrap();
    let response = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .unwrap();

    let err = srv
        .token(redeem(&response.code, &"z".repeat(43)))
        .await
        .expect_err("RFC 7636 s4.6: a verifier that does not match the challenge");
    assert_eq!(err.error, ErrorCode::InvalidGrant);
}

/// A verifier is REQUIRED once a challenge was recorded; omitting it is the downgrade PKCE
/// exists to prevent.
#[tokio::test]
async fn missing_verifier_is_invalid_grant() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;
    let c = challenge();
    let validated = srv
        .validate_authorization_request(&good_request(&c))
        .await
        .unwrap();
    let response = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .unwrap();

    let err = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("public-app"),
            client_secret: None,
            code: response.code,
            redirect_uri: Some(PUBLIC_REDIRECT.to_string()),
            code_verifier: None,
        })
        .await
        .expect_err("a recorded challenge makes code_verifier mandatory");
    assert_eq!(err.error, ErrorCode::InvalidGrant);
}

/// RFC 6749 s4.1.3: the redirect_uri presented at the token endpoint must be the one the code
/// was issued for.
#[tokio::test]
async fn mismatched_redirect_uri_at_redemption_is_invalid_grant() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;
    let c = challenge();
    let validated = srv
        .validate_authorization_request(&good_request(&c))
        .await
        .unwrap();
    let response = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .unwrap();

    let err = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("public-app"),
            client_secret: None,
            code: response.code,
            redirect_uri: Some("https://app.example/other".to_string()),
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await
        .expect_err("redirect_uri must match the authorization request");
    assert_eq!(err.error, ErrorCode::InvalidGrant);
}

/// A code issued to one client must be worthless to another, even a legitimately registered one.
#[tokio::test]
async fn cross_client_redemption_is_invalid_grant() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(
        clock,
        vec![public_client(), two_redirect_client(), device_only_client()],
    )
    .await;
    let c = challenge();
    let validated = srv
        .validate_authorization_request(&good_request(&c))
        .await
        .unwrap();
    let response = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .unwrap();

    let err = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("multi-redirect"),
            client_secret: None,
            code: response.code,
            redirect_uri: Some(PUBLIC_REDIRECT.to_string()),
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await
        .expect_err("a code belongs to the client it was issued to");
    assert_eq!(err.error, ErrorCode::InvalidGrant);
}

#[tokio::test]
async fn expired_code_is_invalid_grant() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![public_client()]).await;
    let c = challenge();
    let validated = srv
        .validate_authorization_request(&good_request(&c))
        .await
        .unwrap();
    let response = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .unwrap();

    clock.advance(Duration::from_secs(61));
    let err = srv
        .token(redeem(&response.code, RFC7636_VERIFIER))
        .await
        .expect_err("the default code lifetime is 60 seconds");
    assert_eq!(err.error, ErrorCode::InvalidGrant);
}

#[tokio::test]
async fn fabricated_code_is_invalid_grant() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;
    let err = srv
        .token(redeem("not-a-real-code", RFC7636_VERIFIER))
        .await
        .expect_err("an unknown code");
    assert_eq!(err.error, ErrorCode::InvalidGrant);
}

/// RFC 6749 s4.1.2 and RFC 9700 s4.1.1: a replayed code is not merely refused. Replay is
/// evidence the code leaked, so the tokens it already minted are revoked as well. Refusing the
/// replay while leaving the stolen access token live would miss the actual attack.
#[tokio::test]
async fn replayed_code_is_refused_and_revokes_what_it_minted() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;
    let c = challenge();
    let validated = srv
        .validate_authorization_request(&good_request(&c))
        .await
        .unwrap();
    let response = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .unwrap();

    let issued = srv
        .token(redeem(&response.code, RFC7636_VERIFIER))
        .await
        .unwrap();
    assert!(
        srv.introspect(&issued.access_token)
            .await
            .unwrap()
            .is_some(),
        "the first redemption's token is live"
    );

    let err = srv
        .token(redeem(&response.code, RFC7636_VERIFIER))
        .await
        .expect_err("a code is single use");
    assert_eq!(err.error, ErrorCode::InvalidGrant);

    assert!(
        srv.introspect(&issued.access_token)
            .await
            .unwrap()
            .is_none(),
        "replay must revoke the access token the code already minted (RFC 9700 s4.1.1)"
    );
    let refresh = issued.refresh_token.expect("a refresh token was issued");
    let err = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("public-app"),
            client_secret: None,
            refresh_token: refresh,
            scope: None,
        })
        .await
        .expect_err("replay must revoke the refresh chain too");
    assert_eq!(err.error, ErrorCode::InvalidGrant);
}

/// A third presentation, after the replay already burned the record, is still refused.
#[tokio::test]
async fn a_third_presentation_is_still_refused() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;
    let c = challenge();
    let validated = srv
        .validate_authorization_request(&good_request(&c))
        .await
        .unwrap();
    let response = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .unwrap();

    srv.token(redeem(&response.code, RFC7636_VERIFIER))
        .await
        .unwrap();
    for _ in 0..2 {
        let err = srv
            .token(redeem(&response.code, RFC7636_VERIFIER))
            .await
            .expect_err("still single use");
        assert_eq!(err.error, ErrorCode::InvalidGrant);
    }
}

/// Codes must not be guessable: two codes issued back to back share no structure.
#[tokio::test]
async fn codes_are_unpredictable() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;
    let c = challenge();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..8 {
        let validated = srv
            .validate_authorization_request(&good_request(&c))
            .await
            .unwrap();
        let r = srv
            .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
            .await
            .unwrap();
        assert!(
            r.code.len() >= 32,
            "at least 128 bits of entropy, hex coded"
        );
        assert!(seen.insert(r.code), "codes must never repeat");
    }
}
