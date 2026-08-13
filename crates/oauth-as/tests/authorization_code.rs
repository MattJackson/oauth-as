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
    AuthorizationRequest::from_pairs([
        ("response_type", "code".to_string()),
        ("client_id", "public-app".to_string()),
        ("redirect_uri", PUBLIC_REDIRECT.to_string()),
        ("scope", "read write".to_string()),
        ("state", "opaque-state".to_string()),
        ("code_challenge", challenge.to_string()),
        ("code_challenge_method", "S256".to_string()),
    ])
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
    // Not `!contains('#') || contains("%23")`, which is what this was: the assertion two lines up
    // already requires `%23` to be present, so the right half was always true and the whole
    // expression could not fail. A redirect that emitted a RAW `#` alongside the encoded one --
    // the exact truncation this is about -- passed.
    assert!(
        !location.contains('#'),
        "an unencoded fragment marker would truncate the query, and every reserved character in \
         `state` must already be percent-encoded: {location}"
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

/// A `code_verifier` that is too short to be worth checking must be refused, not merely hashed.
///
/// FOUND BY THE 0.9.1 AUDIT. RFC 7636 section 4.1 puts the verifier at 43 to 128 characters of the
/// unreserved set, and this crate shipped `pkce::verifier_is_valid` to say so — with no caller
/// outside its own tests. Redemption went straight to `verify_s256`, so the server validated every
/// challenge it MINTED (43 base64url characters, `plain` refused) and nothing the client PRESENTED.
///
/// Why the length is not cosmetic: section 7.1 notes the `code_challenge` travels in the
/// authorization request, so it reaches browser history, the `Referer` header and any proxy log on
/// the way. An attacker who holds a stolen code and the challenge that goes with it can brute force
/// a short verifier outright — six characters is a rounding error, not a search — and PKCE has
/// bought the flow nothing. A conforming client is unaffected: it could not have produced a
/// verifier this short without ignoring the section that defines the parameter.
#[tokio::test]
async fn a_code_verifier_below_the_rfc_7636_minimum_is_refused() {
    // A verifier the client actually used to derive its challenge, so the hash genuinely matches:
    // this test must fail on the LENGTH rule and on nothing else.
    const SHORT: &str = "abcdef";
    let short_challenge = oauth_as::pkce::code_challenge_s256(SHORT);

    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;
    let req = AuthorizationRequest::from_pairs([
        ("response_type", "code"),
        ("client_id", "public-app"),
        ("redirect_uri", PUBLIC_REDIRECT),
        ("scope", "read"),
        ("code_challenge", short_challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]);
    let validated = srv.validate_authorization_request(&req).await.unwrap();
    let issued = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .unwrap();

    let redeemed = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("public-app"),
            client_secret: None,
            code: issued.code,
            redirect_uri: Some(PUBLIC_REDIRECT.to_string()),
            code_verifier: Some(SHORT.to_string()),
        })
        .await;

    assert_eq!(
        redeemed.unwrap_err().error,
        ErrorCode::InvalidGrant,
        "a six character code_verifier hashed to the recorded challenge and was accepted, so the \
         RFC 7636 s4.1 bound is enforced nowhere and a stolen code plus the challenge from a proxy \
         log is redeemable"
    );
}

/// RFC 6749 section 3.1.2.3 lets an authorization request OMIT `redirect_uri` when the client has
/// exactly one registered, and section 4.1.3 then makes the token endpoint's copy of the parameter
/// REQUIRED only "if the `redirect_uri` parameter was included in the authorization request".
/// Conditional means conditional in both directions, and through 0.9.1 this endpoint required it
/// unconditionally: the authorize half deliberately supported the omission and filled the record
/// from the registration, and the token half then matched on `Some(u)` only, so `None` fell to the
/// catch-all and was refused — with a message blaming a mismatch that had not happened, which is
/// the answer that sends a developer to look at their registration for a bug that is not there.
#[tokio::test]
async fn a_code_from_a_request_that_omitted_redirect_uri_redeems_without_one() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;

    // No `redirect_uri`: the client has exactly one registered, so section 3.1.2.3 says this is a
    // complete request and the server fills it in.
    let challenge = challenge();
    let validated = srv
        .validate_authorization_request(&AuthorizationRequest::from_pairs([
            ("response_type", "code".to_string()),
            ("client_id", "public-app".to_string()),
            ("scope", "read".to_string()),
            ("code_challenge", challenge.clone()),
            ("code_challenge_method", "S256".to_string()),
        ]))
        .await
        .expect("RFC 6749 s3.1.2.3: one registered URI means the parameter may be omitted");
    assert_eq!(
        validated.redirect_uri, PUBLIC_REDIRECT,
        "the server fills the omitted parameter from the single registration"
    );

    let response = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .expect("the approved request mints a code");

    // The token request omits it too, which is exactly what section 4.1.3 permits. What is on
    // trial is that a TOKEN comes back, not merely that some call returned.
    let issued = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("public-app"),
            client_secret: None,
            code: response.code,
            redirect_uri: None,
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await
        .expect("RFC 6749 s4.1.3 makes the parameter conditional on the authorization request");
    assert!(!issued.access_token.is_empty());
}

/// The other direction, and the reason the fix above is not a weakening. A code minted for a
/// request that DID name its redirect URI still requires the parameter at the token endpoint, and
/// a code minted for a request that omitted it must not be redeemable as though the client had
/// chosen the address itself: the whole point of section 4.1.3 is that the two legs of one grant
/// agree about where the code was delivered.
#[tokio::test]
async fn the_parameter_is_still_required_when_the_authorization_request_sent_one() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;
    let challenge = challenge();

    // Named at authorize time -> required at token time.
    let validated = srv
        .validate_authorization_request(&good_request(&challenge))
        .await
        .unwrap();
    let response = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .unwrap();
    let refused = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("public-app"),
            client_secret: None,
            code: response.code,
            redirect_uri: None,
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await
        .expect_err("s4.1.3 makes it REQUIRED when the authorization request included it");
    assert_eq!(refused.error, ErrorCode::InvalidGrant);

    // Omitted at authorize time -> naming THE RECORDED ONE at token time is still a match. The
    // comparison did not move: `Some` is still checked for equality against what the code records,
    // and only the ABSENCE of the parameter is now conditional. A client that omits at authorize
    // and sends the registered URI at token time has said nothing false.
    let validated = srv
        .validate_authorization_request(&AuthorizationRequest::from_pairs([
            ("response_type", "code".to_string()),
            ("client_id", "public-app".to_string()),
            ("scope", "read".to_string()),
            ("code_challenge", challenge.clone()),
            ("code_challenge_method", "S256".to_string()),
        ]))
        .await
        .unwrap();
    let response = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .unwrap();
    let issued = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("public-app"),
            client_secret: None,
            code: response.code,
            redirect_uri: Some(PUBLIC_REDIRECT.to_string()),
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await;
    assert!(
        issued.is_ok(),
        "presenting the URI the code actually records is still a match, whichever way the record \
         obtained it"
    );
}

// ------------------------------------------------- the 0.9.0 upgrade path, for the grant instant

/// Round-trip a record through JSON with one key DELETED, which is exactly the payload a 0.9.0 node
/// writes: the field did not exist in that release, so it was never serialized.
fn as_written_by_0_9_0<T: serde::Serialize + serde::de::DeserializeOwned>(
    value: &T,
    drop_key: &str,
) -> T {
    let mut json = serde_json::to_value(value).expect("the record serializes");
    assert!(
        json.as_object_mut()
            .expect("records serialize as JSON objects")
            .remove(drop_key)
            .is_some(),
        "the key {drop_key} must be present to begin with, or this test removes nothing"
    );
    serde_json::from_value(json).expect(
        "a 0.9.0 payload must still deserialize; without a serde default every record that release \
         wrote becomes unreadable the moment this one starts, which is a server_error per request \
         on a patch bump",
    )
}

/// THE UPGRADE PATH, which is the half of the 0.9.1 resurrection work no migration can cover.
///
/// `IssuedToken::grant_established_at` and `RefreshTokenRecord::grant_established_at` are new in
/// 0.9.1 and both persisted, so a record a 0.9.0 node wrote — or is still writing, during a rolling
/// upgrade, after the Postgres backfill has already run — carries no such key. Two things then
/// matter and they pull in opposite directions:
///
/// 1. The read must not FAIL. Without a serde default it does.
/// 2. The value it defaults to must be the FAIL-CLOSED one. A barrier refuses a grant established
///    at or before the revocation, so the epoch is refused by every barrier that could ever have
///    been recorded. A far-future default would deserialize just as happily and ADMIT every 0.9.0
///    record, which is the resurrection this release exists to close, reintroduced through the
///    upgrade path.
///
/// So the assertion is not that it deserializes. It is that what comes back is REFUSED by a
/// standing revocation, with a same-shaped record whose instant POSTDATES the revocation admitted
/// alongside it — so neither a far-future default nor a barrier that refuses everything
/// unconditionally could satisfy this test.
#[tokio::test]
async fn a_token_record_from_0_9_0_dates_from_the_epoch_and_stays_revoked() {
    use oauth_as::store::{RevocationWindow, Storage};
    use oauth_as::{IssuedToken, MemoryStorage, RefreshTokenRecord, ScopeSet};
    use std::time::UNIX_EPOCH;

    let revoked_at = UNIX_EPOCH + Duration::from_secs(100);
    let after = revoked_at + Duration::from_secs(1);
    let window = RevocationWindow {
        recorded_at: revoked_at,
        // A real deadline, and `recorded_at` a genuine instant BETWEEN the two record instants
        // below: a far-future `recorded_at` refuses every grant unconditionally, and this test
        // would then pass with no comparison having happened at all.
        until: revoked_at + Duration::from_secs(100_000),
    };
    let client_id = ClientId::new("public-app");

    // A CLIENT barrier (RFC 7592 s2.3 deletion) rather than a family one, deliberately: a
    // `TokenFamily` barrier refuses its family outright, by identity, so it could not tell an
    // epoch-dated record from a fresh one and this test would prove nothing about the default. The
    // `Client` and `Consent` scopes are the two that ADMIT a grant established after the
    // revocation, which is exactly the comparison on trial here.
    let store = MemoryStorage::new();
    store.delete_client(&client_id, window).await.unwrap();

    let mut token = IssuedToken::new(
        "at-1",
        client_id.clone(),
        Some("user-1".to_string()),
        ScopeSet::parse("read").unwrap(),
        after,
        after + Duration::from_secs(3600),
    );
    token.family_id = Some("fam-1".to_string());
    // Established AFTER the revocation, so the unmodified record is the CONTROL: the barrier must
    // admit it, and the one below differs from it in exactly the missing key.
    token.grant_established_at = after;
    let control = token.clone();
    let old = as_written_by_0_9_0(&token, "grant_established_at");
    assert_eq!(
        old.grant_established_at, UNIX_EPOCH,
        "a record with no stated grant instant must date from before every barrier, not after one"
    );
    assert!(
        store.put_token(old).await.unwrap().is_refused(),
        "a 0.9.0 access token in a revoked family must stay revoked across the upgrade"
    );
    assert!(
        !store.put_token(control).await.unwrap().is_refused(),
        "the same record with an instant AFTER the revocation is admitted, so the refusal above is \
         the instant comparison and not a barrier that refuses everything"
    );

    let store = MemoryStorage::new();
    store.delete_client(&client_id, window).await.unwrap();

    let mut chain = RefreshTokenRecord::new(
        "rt-1",
        client_id.clone(),
        Some("user-1".to_string()),
        ScopeSet::parse("read").unwrap(),
        "fam-2",
    );
    chain.grant_established_at = after;
    let control = chain.clone();
    let old = as_written_by_0_9_0(&chain, "grant_established_at");
    assert_eq!(old.grant_established_at, UNIX_EPOCH);
    assert!(
        store.put_refresh_token(old).await.unwrap().is_refused(),
        "a 0.9.0 refresh chain in a revoked family must stay revoked across the upgrade"
    );
    assert!(
        !store.put_refresh_token(control).await.unwrap().is_refused(),
        "and one established after the revocation is still a new grant"
    );
}

/// The same upgrade question for `AuthorizationCodeRecord::issued_at`, which reaches a barrier by a
/// different route and therefore has to be asserted at the endpoint rather than at the store: the
/// code's instant is what redemption carries into the token it mints
/// (`IssuedToken::grant_established_at`), and it is THAT write a standing barrier refuses.
///
/// So the user-visible outcome is the one pinned here: a code a 0.9.0 node wrote, redeemed after
/// the upgrade against a consent the user has since withdrawn, yields no token. With a far-future
/// default it would yield one, and the withdrawal would have been undone by an upgrade.
#[cfg(feature = "consent")]
#[tokio::test]
async fn a_0_9_0_authorization_code_redeems_into_nothing_when_a_withdrawal_stands() {
    use oauth_as::store::{RevocationWindow, Storage};
    use oauth_as::{AuthorizationCodeRecord, ConsentRecord, ScopeSet};

    async fn redeem_a_code_dated(
        issued_at_key_present: bool,
        issued_at: std::time::SystemTime,
    ) -> Result<oauth_as::TokenResponse, oauth_as::ErrorResponse> {
        let clock = ManualClock::at_epoch();
        let now = <ManualClock as oauth_as::Clock>::now(&clock);
        let revoked_at = now - Duration::from_secs(60);
        let srv = server_with(clock, vec![public_client()]).await;

        let consent = ConsentRecord {
            consent_id: "consent-1".into(),
            client_id: ClientId::new("public-app"),
            subject: "user-1".into(),
            scope: ScopeSet::parse("read").unwrap(),
            resource: Vec::new(),
            granted_at: revoked_at - Duration::from_secs(60),
            authentication: None,
        };
        srv.store().put_consent(consent).await.unwrap();
        srv.store()
            .revoke_consent(
                "consent-1",
                RevocationWindow {
                    recorded_at: revoked_at,
                    until: now + Duration::from_secs(100_000),
                },
            )
            .await
            .unwrap();

        let mut code = AuthorizationCodeRecord::new(
            "code-1",
            ClientId::new("public-app"),
            PUBLIC_REDIRECT,
            ScopeSet::parse("read").unwrap(),
            "user-1",
            challenge(),
            now + Duration::from_secs(60),
        );
        code.issued_at = issued_at;
        let code = if issued_at_key_present {
            code
        } else {
            let stripped: AuthorizationCodeRecord = as_written_by_0_9_0(&code, "issued_at");
            assert_eq!(
                stripped.issued_at,
                std::time::UNIX_EPOCH,
                "a code with no stated decision instant must date from before every barrier"
            );
            stripped
        };
        srv.store().put_authorization_code(code).await.unwrap();

        srv.token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("public-app"),
            client_secret: None,
            code: "code-1".to_string(),
            redirect_uri: Some(PUBLIC_REDIRECT.to_string()),
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await
    }

    let clock = ManualClock::at_epoch();
    let now = <ManualClock as oauth_as::Clock>::now(&clock);
    let after_the_withdrawal = now - Duration::from_secs(30);

    let refused = redeem_a_code_dated(false, after_the_withdrawal)
        .await
        .expect_err(
            "a 0.9.0 code carries no decision instant, so it dates from the epoch and the \
             withdrawal still refuses what it would mint",
        );
    assert_eq!(refused.error, ErrorCode::InvalidGrant);

    // The CONTROL, differing only in that the key survived: a decision made after the withdrawal is
    // a new one and must still be served. Without this the test above would pass with a barrier
    // that refuses everything, which is not the property being pinned.
    let issued = redeem_a_code_dated(true, after_the_withdrawal)
        .await
        .expect("a code whose decision postdates the withdrawal is a new grant and is served");
    assert!(!issued.access_token.is_empty());
}

// ------------------------------------------------------------- the authorization endpoint's bound

/// The authorization endpoint had NO throttle seam at all, and it is the one endpoint that takes no
/// credential: RFC 9700 section 4.13's credential-stuffing argument does not reach it, so nothing
/// bounded it. What a deployment is bounding here is work and STORAGE — every request costs a
/// `get_client`, and an approved one WRITES an authorization code record that nothing but
/// `Storage::sweep_expired` ever reclaims.
///
/// TWO CHARGES on one completed flow, deliberately: the validation is the read and the issuance is
/// the write, and a limiter that charged the second to the first would let a caller who validated
/// once go on issuing for free — which is the half that actually grows the store. So both are
/// asserted, and separately.
#[tokio::test]
async fn the_authorization_endpoint_is_throttled_at_validation_and_again_at_issuance() {
    use oauth_as::events::{Attempt, RateLimitDecision, RateLimiter};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Allows the first `allow_first` authorization-request attempts and denies afterwards, so the
    /// test can put the boundary exactly between the two charge points.
    struct Counting {
        seen: Arc<AtomicUsize>,
        allow_first: usize,
    }
    impl RateLimiter for Counting {
        fn check(&self, attempt: Attempt<'_>) -> RateLimitDecision {
            match attempt {
                Attempt::AuthorizationRequest { .. } => {
                    let n = self.seen.fetch_add(1, Ordering::SeqCst);
                    if n < self.allow_first {
                        RateLimitDecision::Allow
                    } else {
                        RateLimitDecision::Deny
                    }
                }
                _ => RateLimitDecision::Allow,
            }
        }
    }

    // ZERO allowed: the validation itself is refused, before the store is touched, and NOT by a
    // redirect — neither the client nor the redirect URI has been validated yet, so there is no
    // address this server may safely send anything to (RFC 6749 s4.1.2.1).
    let seen = Arc::new(AtomicUsize::new(0));
    let srv = server_with(ManualClock::at_epoch(), vec![public_client()])
        .await
        .with_rate_limiter(Box::new(Counting {
            seen: seen.clone(),
            allow_first: 0,
        }));
    let c = challenge();
    match srv.validate_authorization_request(&good_request(&c)).await {
        Err(AuthorizationError::Direct(e)) => {
            assert_eq!(e.error, ErrorCode::TemporarilyUnavailable)
        }
        other => {
            panic!("a throttled authorization request must be refused directly, got {other:?}")
        }
    }
    assert_eq!(
        seen.load(Ordering::SeqCst),
        1,
        "the endpoint must consult the limiter at all"
    );

    // ONE allowed: validation goes through, and the ISSUANCE is charged separately and refused.
    // This is the assertion that would pass vacuously if only one charge existed.
    let seen = Arc::new(AtomicUsize::new(0));
    let srv = server_with(ManualClock::at_epoch(), vec![public_client()])
        .await
        .with_rate_limiter(Box::new(Counting {
            seen: seen.clone(),
            allow_first: 1,
        }));
    let validated = srv
        .validate_authorization_request(&good_request(&c))
        .await
        .expect("the first attempt is allowed");
    match srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
    {
        // A REDIRECT here, unlike above: by this point the redirect URI is validated, so the error
        // goes back to the client carrying the state that lets it correlate.
        Err(AuthorizationError::Redirect(r)) => {
            assert_eq!(r.error.error, ErrorCode::TemporarilyUnavailable);
            assert_eq!(r.state.as_deref(), Some("opaque-state"));
        }
        other => panic!("the WRITE must be charged separately from the read, got {other:?}"),
    }
    assert_eq!(
        seen.load(Ordering::SeqCst),
        2,
        "issuance must be a second charge, not a free ride on the validation's"
    );

    // And with both allowed, a code is actually minted: the throttle is a bound, not a wall.
    let seen = Arc::new(AtomicUsize::new(0));
    let srv = server_with(ManualClock::at_epoch(), vec![public_client()])
        .await
        .with_rate_limiter(Box::new(Counting {
            seen: seen.clone(),
            allow_first: 2,
        }));
    let validated = srv
        .validate_authorization_request(&good_request(&c))
        .await
        .unwrap();
    let response = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .expect("within the budget the endpoint works exactly as it did before");
    assert!(!response.code.is_empty());
}

/// TWO WAYS OF CREATING A CLIENT DISAGREED ABOUT WHAT A REDIRECT URI MAY BE, and the permissive one
/// was `register_client` — the direct API, which a default build has and which RFC 7591 dynamic
/// registration (optional, and layered on top of this one) does not replace.
///
/// The failure it produced surfaced three layers from its cause. A registered URI containing a
/// space passes the authorization endpoint's exact-string match, the host's resolver approves, the
/// authorization code is MINTED AND PERSISTED, and only then does building the `Location` header
/// fail: the user gets a 500, the client is never reached, the code sits in storage until it
/// expires, and every retry does it again. So the whole flow is driven here rather than just the
/// registration call, because that sequence is the reason the check is worth having.
#[tokio::test]
async fn a_redirect_uri_the_authorization_endpoint_could_never_reproduce_is_not_registerable() {
    use oauth_as::{Client, ClientAuth, MemoryStorage, ScopeSet, ServerConfig, Storage};

    fn client_with(redirect_uri: &str) -> Client {
        Client {
            client_id: ClientId::new("bad-uri-app"),
            auth: ClientAuth::Public,
            grant_types: vec![oauth_as::GrantType::AuthorizationCode],
            redirect_uris: vec![redirect_uri.to_string()],
            allowed_scopes: ScopeSet::parse("read").unwrap(),
            default_scopes: ScopeSet::parse("read").unwrap(),
            name: None,
            registration: None,
        }
    }

    let srv = oauth_as::AuthorizationServer::with_clock(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        MemoryStorage::new(),
        ManualClock::at_epoch(),
    );

    for bad in [
        // A space: legal in a Rust `String`, illegal in a URI, and the exact value that used to
        // fail at header construction after a code had already been written.
        "https://app.example/cb?next=a b",
        // RFC 6749 s3.1.2: the URI MUST NOT include a fragment.
        "https://app.example/cb#frag",
        // RFC 6749 s3.1.2: the URI MUST be absolute.
        "/cb",
    ] {
        let refused = srv
            .register_client(client_with(bad))
            .await
            .expect_err("a redirect_uri this server can never match must not be registerable");
        assert!(
            refused.to_string().contains(bad),
            "the operator who just supplied the value needs to see WHICH one: {refused}"
        );
        assert!(
            srv.store()
                .get_client(&ClientId::new("bad-uri-app"))
                .await
                .unwrap()
                .is_none(),
            "a refused registration must leave no row behind, or the next start-up reads it back"
        );
    }

    // The flow the refusal replaces. With the registration refused there is nothing to authorize
    // against, so the failure now happens at start-up rather than after a code has been minted and
    // orphaned in storage.
    let c = challenge();
    match srv
        .validate_authorization_request(&AuthorizationRequest::from_pairs([
            ("response_type", "code".to_string()),
            ("client_id", "bad-uri-app".to_string()),
            (
                "redirect_uri",
                "https://app.example/cb?next=a b".to_string(),
            ),
            ("scope", "read".to_string()),
            ("code_challenge", c),
            ("code_challenge_method", "S256".to_string()),
        ]))
        .await
    {
        Err(AuthorizationError::Direct(e)) => assert_eq!(e.error, ErrorCode::InvalidRequest),
        other => panic!("nothing was registered, so nothing may be authorized: {other:?}"),
    }

    // And a well-formed one still registers, so this is a rule rather than a wall.
    srv.register_client(client_with("https://app.example/cb"))
        .await
        .expect("a conforming redirect_uri is unaffected");
}
