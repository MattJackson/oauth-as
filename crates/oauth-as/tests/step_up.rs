// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! RFC 9470 step-up authentication, driven through the crate's public API.
//!
//! The whole exchange, and what each end of it is responsible for:
//!
//! 1. a resource server receives a valid token, decides the operation needs a stronger or fresher
//!    login than the token reflects, and challenges with `insufficient_user_authentication` plus
//!    `acr_values` and/or `max_age` (s3). This crate can BUILD that challenge but never sends one:
//!    it is not a resource server.
//! 2. the client repeats its authorization request carrying those two parameters (s4).
//! 3. the authorization server acts on them and reports what it did as `auth_time` and `acr` (s5).
//!
//! Step 3 is where this library's boundary is, and it is the reason most of this suite is about
//! REFUSALS. The library cannot authenticate anybody: the HOST reports when and how it did, and the
//! library records that report and ENFORCES the request against it. So the failure this suite is
//! built around is an authorization server that satisfies a step-up challenge it never actually
//! stepped up for, which is what would happen if an unreported authentication, or a stale one, or
//! one of the wrong class, were quietly allowed to mint a code. Each of those has a test whose
//! assertion is that NOTHING was issued.
//!
//! The second failure it guards is subtler and lives in the refresh path: an `auth_time` that got
//! restamped on rotation would let any client defeat any `max_age` by refreshing, and the token
//! would carry a freshness the user never performed.
#![cfg(feature = "consent")]

mod support;

use oauth_as::server::UserApproval;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::{
    Authentication, AuthenticationRequirement, AuthorizationError, AuthorizationRequest, ClientId,
    ErrorCode, ScopeSet, TokenRequest,
};
use support::{
    confidential_client, ManualClock, CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET, RFC7636_VERIFIER,
};

const APP: &str = "confidential-app";
/// The instant `ManualClock::at_epoch` starts at, so a test can name an `auth_time` relative to it.
const NOW: u64 = 1_700_000_000;

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// The authorization request a challenged client repeats, built through the real query parser so
/// this fixture cannot drift from what an actual request looks like.
fn request<'a>(challenge: &'a str) -> AuthorizationRequest<'a> {
    AuthorizationRequest::from_pairs([
        ("response_type", "code"),
        ("client_id", APP),
        ("redirect_uri", CONFIDENTIAL_REDIRECT),
        ("scope", "read"),
        ("state", "step-up-state"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ])
}

/// The parameters a client would put on the authorization request after being challenged.
fn requirement(acr_values: Option<&str>, max_age: Option<&str>) -> AuthenticationRequirement {
    let mut pairs: Vec<(&str, &str)> = vec![("client_id", APP)];
    if let Some(a) = acr_values {
        pairs.push(("acr_values", a));
    }
    if let Some(m) = max_age {
        pairs.push(("max_age", m));
    }
    AuthenticationRequirement::from_pairs(pairs).expect("well-formed step-up parameters")
}

/// Run one authorization request through validation and code issuance, with whatever the host says
/// it did about authenticating the user.
async fn authorize<S: oauth_as::Storage>(
    srv: &oauth_as::AuthorizationServer<S, ManualClock>,
    requirement: &AuthenticationRequirement,
    authentication: Option<&Authentication>,
) -> Result<oauth_as::AuthorizationResponse, AuthorizationError> {
    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let validated = srv
        .validate_authorization_request(&request(&challenge))
        .await
        .expect("the request itself is well formed");
    srv.issue_authorization_code_with_authentication(
        UserApproval::granted(&validated, "user-1"),
        requirement,
        authentication,
    )
    .await
}

/// The error code carried on a redirect refusal, or a panic naming what came back instead.
fn redirect_error(err: AuthorizationError) -> ErrorCode {
    match err {
        AuthorizationError::Redirect(r) => r.error.error,
        other => panic!("expected a redirect refusal, got {other:?}"),
    }
}

// ---------------------------------------------------------------- the refusals that must happen

/// THE FAILURE THIS SUITE EXISTS FOR. A host that reports no authentication must not satisfy a
/// step-up request. If it did, every deployment that had not wired the reporter would silently
/// answer every challenge a resource server ever sent, with a token that proves nothing.
#[tokio::test]
async fn a_request_with_no_reported_authentication_is_refused() {
    let srv = support::server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;

    let err = authorize(&srv, &requirement(None, Some("300")), None)
        .await
        .expect_err("a max_age request with nothing reported must be refused");

    assert_eq!(
        redirect_error(err),
        ErrorCode::InsufficientUserAuthentication
    );
    let err = authorize(&srv, &requirement(Some("phr"), None), None)
        .await
        .expect_err("an acr_values request with nothing reported must be refused");
    assert_eq!(
        redirect_error(err),
        ErrorCode::InsufficientUserAuthentication
    );
}

/// An authentication older than the requested `max_age` is refused, and NOTHING is minted: no code
/// exists to be redeemed afterwards. A server that issued the code and merely omitted `auth_time`
/// would leave the resource server no better off than before it challenged.
///
/// HOW "NOTHING WAS MINTED" IS ACTUALLY CHECKED. It cannot be checked by making a second, DIFFERENT
/// request and watching that one succeed — which is what this test used to do, under a comment
/// saying "Nothing was issued". That second request proves the fixture works and says nothing
/// whatever about whether the refused one wrote a record; the test passed either way.
///
/// The store is the only witness, so the store is what answers. `FaultStorage` is set to fail
/// EVERY `put_authorization_code`, which turns "a code was written" into an observable event: if
/// the refusal came after the write, the write's failure is what the caller would see, and the
/// answer would not be `insufficient_user_authentication`. Getting the step-up refusal back means
/// the code path never reached the store at all.
#[tokio::test]
async fn an_authentication_older_than_max_age_is_refused_and_mints_nothing() {
    let srv =
        support::fault_server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    srv.store()
        .fail_put_authorization_code
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let stale = Authentication::at(at(NOW - 3_600));

    let err = authorize(&srv, &requirement(None, Some("300")), Some(&stale))
        .await
        .expect_err("an hour-old login does not satisfy max_age=300");

    assert_eq!(
        redirect_error(err),
        ErrorCode::InsufficientUserAuthentication,
        "the refusal must be the step-up one; a store error here would mean a code was written \
         before the requirement was checked"
    );

    // The control, on a store that works: the fixture really can mint, so the refusal above is the
    // requirement doing its job rather than the harness being broken.
    let working = support::server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let fresh = Authentication::at(at(NOW - 60));
    let ok = authorize(&working, &requirement(None, Some("300")), Some(&fresh))
        .await
        .expect("a one-minute-old login satisfies max_age=300");
    assert!(!ok.code.is_empty());
}

/// `max_age=0` means re-authenticate NOW. It must not be read as an absent parameter, which is the
/// reading that turns the strongest possible request into no request at all.
#[tokio::test]
async fn max_age_zero_demands_an_authentication_at_this_instant() {
    let srv = support::server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;

    let a_second_ago = Authentication::at(at(NOW - 1));
    let err = authorize(&srv, &requirement(None, Some("0")), Some(&a_second_ago))
        .await
        .expect_err("max_age=0 is not satisfied by a login one second old");
    assert_eq!(
        redirect_error(err),
        ErrorCode::InsufficientUserAuthentication
    );

    let just_now = Authentication::at(at(NOW));
    authorize(&srv, &requirement(None, Some("0")), Some(&just_now))
        .await
        .expect("max_age=0 is satisfied by an authentication at this instant");
}

/// An `acr` the request did not ask for is refused, and one it did ask for is honoured. RFC 9470 s4
/// makes `acr_values` an ordered preference, so ANY of the listed classes is enough.
#[tokio::test]
async fn only_a_requested_acr_satisfies_the_request() {
    let srv = support::server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let want = requirement(Some("urn:acr:phr urn:acr:mfa"), None);

    let password = Authentication::at(at(NOW)).with_acr("urn:acr:pwd");
    let err = authorize(&srv, &want, Some(&password))
        .await
        .expect_err("a password login does not satisfy a request for phr or mfa");
    assert_eq!(
        redirect_error(err),
        ErrorCode::InsufficientUserAuthentication
    );

    let second_choice = Authentication::at(at(NOW)).with_acr("urn:acr:mfa");
    authorize(&srv, &want, Some(&second_choice))
        .await
        .expect("the second listed class is still one of the requested classes");
}

/// A refusal goes back to the CLIENT at its validated redirect URI (RFC 6749 s4.1.2.1), carrying
/// the state it sent, because the client is the party that asked the question and the party that
/// has to decide whether to send the user back to log in. It is not a page rendered at the AS.
///
/// THE REFUSED REQUEST REPORTS AN AUTHENTICATION, of the wrong class. With `None` there was no
/// `auth_time` and no `acr` anywhere in the process, so the "nothing leaked" assertion at the end
/// had nothing it could have caught: it was asserting that a value which did not exist was not
/// present. A password login refused for not being `phr` is the case where the server HOLDS both
/// values and must still not put them in the query.
#[tokio::test]
async fn a_step_up_refusal_is_a_redirect_carrying_state_and_iss() {
    let srv = support::server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;

    let password = Authentication::at(at(NOW)).with_acr("urn:acr:pwd");
    let err = authorize(&srv, &requirement(Some("phr"), None), Some(&password))
        .await
        .expect_err("refused");

    match err {
        AuthorizationError::Redirect(r) => {
            assert_eq!(r.redirect_uri, CONFIDENTIAL_REDIRECT);
            assert_eq!(r.state.as_deref(), Some("step-up-state"));
            // RFC 9207 s2: every authorization response names its author, refusals included.
            assert_eq!(r.iss, "https://as.example");
            let location = r.location();
            assert!(
                location.contains("error=insufficient_user_authentication"),
                "{location}"
            );
            // The client is not told when the user last logged in, or which acr they hold. Both
            // exist on this request, so both are values the redirect could have leaked.
            assert!(!location.contains("1700"), "{location}");
            assert!(!location.contains("pwd"), "{location}");
        }
        other => panic!("expected a redirect refusal, got {other:?}"),
    }
}

/// An ordinary authorization request, which carries neither parameter, is completely unaffected by
/// this feature whether or not the host reports anything. A host that has not adopted step-up must
/// not find its existing flows refused.
#[tokio::test]
async fn a_request_with_no_step_up_parameters_is_unaffected() {
    let srv = support::server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;

    authorize(&srv, &AuthenticationRequirement::none(), None)
        .await
        .expect("an ordinary request with nothing reported still works");
}

// ---------------------------------------------------------------- what the token then reports

/// RFC 9470 s6.2: the token that comes out of a satisfied step-up REPORTS the authentication behind
/// it, through RFC 7662 introspection, so the resource server that sent the challenge can check the
/// answer rather than taking the client's word for it. (Section 5 is the AUTHORIZATION RESPONSE;
/// section 6 is where the authentication information is conveyed, 6.1 in a JWT and 6.2 here.)
#[tokio::test]
async fn the_issued_token_reports_auth_time_and_acr_to_introspection() {
    let srv = support::server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let auth = Authentication::at(at(NOW - 30)).with_acr("urn:acr:mfa");
    let response = authorize(
        &srv,
        &requirement(Some("urn:acr:mfa"), Some("300")),
        Some(&auth),
    )
    .await
    .expect("issued");

    let issued = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new(APP),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            code: response.code,
            redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await
        .unwrap();

    let introspected = srv
        .introspection_response(
            &ClientId::new(APP),
            Some(CONFIDENTIAL_SECRET),
            &issued.access_token,
        )
        .await
        .unwrap();
    assert_eq!(introspected.auth_time, Some(NOW - 30));
    assert_eq!(introspected.acr.as_deref(), Some("urn:acr:mfa"));
}

/// A grant with no reported authentication reports NEITHER member, rather than reporting a null or
/// the issuance instant. A resource server reading `auth_time` off a token whose authentication
/// nobody described would be checking a freshness this server never witnessed.
#[tokio::test]
async fn a_token_from_an_unreported_grant_reports_neither_member() {
    let srv = support::server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let issued = support::mint_code_token(
        &srv,
        APP,
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;

    let introspected = srv
        .introspection_response(
            &ClientId::new(APP),
            Some(CONFIDENTIAL_SECRET),
            &issued.access_token,
        )
        .await
        .unwrap();
    assert_eq!(introspected.auth_time, None);
    assert_eq!(introspected.acr, None);
    // Omitted from the wire document too, not sent as null: RFC 7662 s2.2 lets a server omit what
    // it does not know, and a `null` reads to a careless resource server as a checked value.
    let json = serde_json::to_string(&introspected).unwrap();
    assert!(!json.contains("auth_time"), "{json}");
    assert!(!json.contains("acr"), "{json}");
}

/// THE REFRESH ATTACK. A rotation is not a new authentication: the user is not present and nothing
/// has been proven again. An `auth_time` restamped on refresh would let any client defeat any
/// `max_age` simply by refreshing, and hand a resource server a token claiming a freshness that
/// never happened.
#[tokio::test]
async fn refreshing_does_not_restamp_auth_time() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock.clone(), vec![confidential_client()]).await;
    let auth = Authentication::at(at(NOW));
    let response = authorize(&srv, &requirement(None, Some("300")), Some(&auth))
        .await
        .expect("issued");
    let first = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new(APP),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            code: response.code,
            redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await
        .unwrap();

    // An hour later, the client refreshes.
    clock.advance(Duration::from_secs(3_600));
    let refreshed = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new(APP),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            refresh_token: first.refresh_token.expect("a refresh token"),
            scope: None,
        })
        .await
        .unwrap();

    let introspected = srv
        .introspection_response(
            &ClientId::new(APP),
            Some(CONFIDENTIAL_SECRET),
            &refreshed.access_token,
        )
        .await
        .unwrap();
    assert_eq!(
        introspected.auth_time,
        Some(NOW),
        "the refresh restamped auth_time, so max_age can be defeated by refreshing"
    );
}

/// The RFC 9470 s3 challenge and the s4 request that answers it have to agree on the spelling of
/// two parameters. This drives one full round trip through both halves of this crate's surface, so
/// a change to either spelling breaks here rather than in a deployment.
#[tokio::test]
async fn a_challenge_this_crate_builds_parses_back_into_the_requirement_it_asked_for() {
    let challenge = oauth_as::step_up_challenge(
        "Bearer",
        &["urn:acr:phr".into()],
        Some(Duration::from_secs(120)),
    );

    // What a client does with the challenge: lift the two parameters onto its authorization
    // request. Parsed here out of the challenge text, so the test cannot silently drift from it.
    let acr = between(&challenge, "acr_values=\"", "\"").expect("acr_values in the challenge");
    let max_age = between(&challenge, "max_age=\"", "\"").expect("max_age in the challenge");
    let parsed = AuthenticationRequirement::from_pairs([("acr_values", acr), ("max_age", max_age)])
        .expect("the challenge's own parameters must parse");

    assert_eq!(parsed.acr_values, vec![Box::<str>::from("urn:acr:phr")]);
    assert_eq!(parsed.max_age, Some(Duration::from_secs(120)));

    let srv = support::server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let satisfying = Authentication::at(at(NOW - 60)).with_acr("urn:acr:phr");
    authorize(&srv, &parsed, Some(&satisfying))
        .await
        .expect("the authentication the challenge asked for satisfies the request it produced");
}

fn between<'a>(haystack: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let from = haystack.find(start)? + start.len();
    let rest = &haystack[from..];
    Some(&rest[..rest.find(end)?])
}

/// The step-up parameters do not widen anything. A client cannot use `acr_values` to obtain scope
/// its registration does not permit, and a satisfied step-up grants exactly what was asked for.
#[tokio::test]
async fn a_satisfied_step_up_grants_no_more_than_the_request_asked_for() {
    let srv = support::server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let auth = Authentication::at(at(NOW)).with_acr("urn:acr:phr");
    let response = authorize(&srv, &requirement(Some("urn:acr:phr"), None), Some(&auth))
        .await
        .expect("issued");
    let issued = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new(APP),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            code: response.code,
            redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await
        .unwrap();
    assert_eq!(
        issued.scope.as_deref(),
        Some("read"),
        "a step-up request granted scope the authorization request never asked for"
    );
    let _ = ScopeSet::parse("read").unwrap();
}
