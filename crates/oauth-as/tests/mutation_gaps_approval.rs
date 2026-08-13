// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Survivors of a whole-crate `cargo mutants --all-features` sweep that sit on the issuance path:
//! [`oauth_as::server::UserApproval`], the RFC 9470 step-up parameters as they arrive on the QUERY
//! string, and the authentication a grant carries forward.
//!
//! These are outside the three modules the sweep was scoped to, and they are here because of what
//! they touch rather than where they live. `UserApproval` is the only thing this crate will mint an
//! authorization code from, so the subject it names is the subject of every token that code
//! produces; and the step-up parameters are the mechanism by which a resource server that has
//! already refused a token asks for a stronger one.
//!
//! The step-up pair is the one to read first, because the sweep found the SAME defect the crate
//! had already fixed once. `src/server.rs` carries a comment recording that `acr_values` and
//! `max_age` were once dropped entirely on the RFC 9126 and RFC 9101 paths, "which disabled
//! step-up for every PAR and JAR deployment". The mutants below show the plain query-string path
//! was one deleted match arm away from exactly that, with nothing to catch it: the existing
//! step-up suite builds its [`oauth_as::AuthenticationRequirement`] through a SEPARATE parser
//! (`AuthenticationRequirement::from_pairs`) and so never exercises the two arms in
//! `AuthorizationRequest::from_pairs` that a real query string goes through.

#![cfg(feature = "consent")]

mod support;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::server::UserApproval;
use oauth_as::{Authentication, AuthorizationRequest, ClientId, ErrorCode, Storage, TokenRequest};
use support::{
    confidential_client, ManualClock, CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET, RFC7636_VERIFIER,
};

const APP: &str = "confidential-app";
const NOW: u64 = 1_700_000_000;

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// An authorization request built the way a browser sends one: one flat list of query pairs
/// through the crate's own parser. That is the whole point of these tests, so it is never
/// short-circuited.
fn query<'a>(challenge: &'a str, extra: &[(&'a str, &'a str)]) -> AuthorizationRequest<'a> {
    let mut pairs: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("client_id", APP),
        ("redirect_uri", CONFIDENTIAL_REDIRECT),
        ("scope", "read"),
        ("state", "query-state"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ];
    pairs.extend_from_slice(extra);
    AuthorizationRequest::from_pairs(pairs)
}

// ------------------------------------------------------- the step-up parameters on the query

/// SURVIVORS: `authorization.rs delete match arm "acr_values"` and
/// `delete match arm "max_age"`, both in `AuthorizationRequest::from_pairs`.
///
/// Deleting either arm does not fail closed. The parameter falls through to the `_ => continue`
/// that exists for the members this server does not model, so the request parses cleanly with the
/// step-up parameter simply absent, and `AuthenticationRequirement::from_request` then derives a
/// requirement of NONE.
///
/// The consequence is the exact failure RFC 9470 exists to prevent, and the crate has already been
/// bitten by it once on the PAR and JAR paths. A resource server refuses a token with
/// `insufficient_user_authentication`; the client repeats its authorization request carrying
/// `max_age=0`, which means "re-authenticate this user NOW"; and the server mints a code against
/// the very session it was told to replace. Nobody sees an error. The client believes it complied,
/// the resource server believes the user re-authenticated, and the token says nothing either way.
///
/// The existing step-up suite cannot see it: it builds its requirement through
/// `AuthenticationRequirement::from_pairs`, a different parser, so the two arms that a real query
/// string passes through were never exercised.
#[tokio::test]
async fn the_step_up_parameters_survive_the_query_string_parser() {
    let srv = support::server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);

    // max_age=0 on the query: re-authenticate now. A login one second old does not satisfy it.
    let validated = srv
        .validate_authorization_request(&query(&challenge, &[("max_age", "0")]))
        .await
        .expect("the request is well formed");
    let a_second_ago = Authentication::at(at(NOW - 1));
    let err = srv
        .issue_authorization_code_with_authentication(
            UserApproval::granted(&validated, "user-1"),
            &validated.authentication_requirement,
            Some(&a_second_ago),
        )
        .await
        .expect_err(
            "max_age=0 arriving on the query string must be honoured, or a client answering an \
             insufficient_user_authentication challenge is handed a code minted against the \
             session it was told to replace",
        );
    assert!(
        matches!(
            err,
            oauth_as::AuthorizationError::Redirect(ref r)
                if r.error.error == ErrorCode::InsufficientUserAuthentication
        ),
        "expected RFC 9470 s3 insufficient_user_authentication, got {err:?}"
    );

    // acr_values on the query: a class the request did not ask for does not satisfy it.
    let validated = srv
        .validate_authorization_request(&query(&challenge, &[("acr_values", "urn:acr:phr")]))
        .await
        .expect("the request is well formed");
    let password = Authentication::at(at(NOW)).with_acr("urn:acr:pwd");
    let err = srv
        .issue_authorization_code_with_authentication(
            UserApproval::granted(&validated, "user-1"),
            &validated.authentication_requirement,
            Some(&password),
        )
        .await
        .expect_err("acr_values on the query string must be honoured");
    assert!(
        matches!(
            err,
            oauth_as::AuthorizationError::Redirect(ref r)
                if r.error.error == ErrorCode::InsufficientUserAuthentication
        ),
        "expected RFC 9470 s3 insufficient_user_authentication, got {err:?}"
    );

    // And the requirement is genuinely satisfiable, so the assertions above are not passing
    // because every request is refused.
    let strong = Authentication::at(at(NOW)).with_acr("urn:acr:phr");
    srv.issue_authorization_code_with_authentication(
        UserApproval::granted(&validated, "user-1"),
        &validated.authentication_requirement,
        Some(&strong),
    )
    .await
    .expect("the requested authentication class satisfies the request");
}

// ------------------------------------------------------- UserApproval

/// SURVIVORS: `server.rs replace UserApproval<'a>::subject -> &str with
/// ""` and `with "xyzzy"`.
///
/// [`UserApproval::subject`] is a public accessor with no caller inside this crate: issuance
/// destructures the value rather than going through it, which is exactly why nothing constrained
/// it. It is not decoration, though. It is the only way a host can read back WHO it is about to
/// mint for, and the module's own documentation presents the approval as the thing a host writes
/// deliberately, which means a host logging or displaying the approval reads this.
///
/// A constant here is a false audit record: the log says a code was issued for `""` (or, worse,
/// for a plausible-looking name that belongs to nobody) while the token that came out carries the
/// real user. The two records disagree and the wrong one is the one an investigation reads.
#[tokio::test]
async fn the_approval_reports_the_subject_it_was_given() {
    let srv = support::server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let validated = srv
        .validate_authorization_request(&query(&challenge, &[]))
        .await
        .expect("the request is well formed");

    let approval = UserApproval::granted(&validated, "user-1");
    assert_eq!(
        approval.subject(),
        "user-1",
        "the approval must report the subject it was constructed with: a host reads this to log \
         or display who it is minting for, and a constant makes that record disagree with the \
         token that is actually issued"
    );
    // A second subject, so the accessor cannot be passing by returning one hard-coded name.
    let other = UserApproval::granted(&validated, "user-2");
    assert_eq!(other.subject(), "user-2");

    // And it agrees with what is actually minted, which is the disagreement the mutation creates.
    let response = srv
        .issue_authorization_code(UserApproval::granted(&validated, "user-1"))
        .await
        .expect("issuing for a validated request");
    let issued = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new(APP),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            code: response.code.clone(),
            redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await
        .expect("the code redeems");
    let introspected = srv.introspect(&issued.access_token).await.unwrap().unwrap();
    assert_eq!(
        introspected.subject.as_deref(),
        Some(approval.subject()),
        "what the approval reports and what the token carries must be the same person"
    );
}

/// SURVIVOR: `server.rs replace <impl fmt::Debug for
/// UserApproval<'_>>::fmt -> fmt::Result with Ok(Default::default())`.
///
/// The hand-written `Debug` exists to keep a user identifier out of whatever caught a `{:?}` while
/// leaving the REQUEST visible, because the request is the whole of what anybody debugging an
/// issuance needs. Replacing the body with a silent `Ok(())` renders the approval as the empty
/// string and nothing failed, which means the redaction had never been asserted: an edit that
/// printed the subject verbatim would have been equally invisible.
#[tokio::test]
async fn the_approval_debug_keeps_the_request_and_redacts_the_user() {
    let srv = support::server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let validated = srv
        .validate_authorization_request(&query(&challenge, &[]))
        .await
        .expect("the request is well formed");

    let rendered = format!(
        "{:?}",
        UserApproval::granted(&validated, "alice@example.com")
    );
    assert!(
        !rendered.contains("alice@example.com"),
        "a resource owner's identifier must not reach a debug format: {rendered}"
    );
    assert!(
        rendered.contains("[redacted]"),
        "the subject is redacted rather than dropped, so a reader can tell there is one: \
         {rendered}"
    );
    assert!(
        rendered.contains("UserApproval") && rendered.contains(APP),
        "WHICH request is being approved stays visible, because that is what anybody debugging an \
         issuance is looking for: {rendered}"
    );
}

// ------------------------------------------------------- the authentication a grant carries

/// SURVIVORS: `server.rs replace GrantedAuthentication::from_code ->
/// Self with Default::default()` and `... from_refresh ...`.
///
/// These two carry the host's authentication report from the record a grant rests on onto the
/// token that grant mints: from the authorization code at first issuance, and from the refresh
/// record across every rotation. Replaced with the default, the report is dropped and the issued
/// token carries no `auth_time` and no `acr`.
///
/// That is RFC 9470 failing in the direction that cannot be seen from the token endpoint. The
/// step-up refusal still works, because it is checked at ISSUANCE against the requirement; what is
/// lost is the evidence on the token afterwards. The resource server that challenged in the first
/// place introspects the new token, finds nothing saying the user re-authenticated, and challenges
/// again. The client repeats the whole step-up dance, satisfies it again, and gets another token
/// that proves nothing: a loop with no error in it anywhere.
///
/// `from_refresh` is the more consequential of the two. RFC 9470 section 6.2 defines the CHANNEL —
/// the `auth_time` and `acr` an introspecting caller reads — and it does not mandate what a
/// rotation does with them; the mandate here is this crate's. A rotation is not a new
/// authentication, so the chain has to carry the ORIGINAL one, and a default drops it on the first
/// refresh a long-lived session performs, leaving that channel to answer a step-up challenge with
/// silence.
#[tokio::test]
async fn the_authentication_a_grant_rests_on_reaches_the_tokens_it_mints() {
    let srv = support::server_with(ManualClock::at_epoch(), vec![confidential_client()]).await;
    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let validated = srv
        .validate_authorization_request(&query(&challenge, &[("acr_values", "urn:acr:phr")]))
        .await
        .expect("the request is well formed");

    let strong = Authentication::at(at(NOW)).with_acr("urn:acr:phr");
    let response = srv
        .issue_authorization_code_with_authentication(
            UserApproval::granted(&validated, "user-1"),
            &validated.authentication_requirement,
            Some(&strong),
        )
        .await
        .expect("a phr login satisfies a phr request");

    let issued = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new(APP),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            code: response.code.clone(),
            redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await
        .expect("the code redeems");

    // FROM THE CODE. The token the code minted carries what the host reported at approval.
    let stored = srv
        .store()
        .get_token(&issued.access_token)
        .await
        .unwrap()
        .expect("the token is in the store");
    let carried = stored.authentication.as_deref().expect(
        "the access token minted from an authorization code must carry the authentication the \
             host reported: without it the resource server that sent the RFC 9470 challenge finds \
             nothing on the new token saying the user re-authenticated, and challenges again",
    );
    assert_eq!(carried.auth_time, at(NOW));
    assert_eq!(carried.acr.as_deref(), Some("urn:acr:phr"));

    // FROM THE REFRESH RECORD. A rotation is not a new authentication, so the chain carries the
    // original one forward rather than forgetting it, and RFC 9470 s6.2 is the channel that then
    // has something to report.
    let refresh_token = issued
        .refresh_token
        .clone()
        .expect("the code grant issues a refresh token");
    let rotated = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new(APP),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            refresh_token,
            scope: None,
        })
        .await
        .expect("the refresh token rotates");
    let stored = srv
        .store()
        .get_token(&rotated.access_token)
        .await
        .unwrap()
        .expect("the rotated token is in the store");
    let carried = stored.authentication.as_deref().expect(
        "a rotation must carry the ORIGINAL authentication forward, or the RFC 9470 s6.2 channel \
         has nothing to report: dropping it on \
         the first refresh means a long-lived session silently stops being able to prove how its \
         user logged in",
    );
    assert_eq!(carried.auth_time, at(NOW));
    assert_eq!(carried.acr.as_deref(), Some("urn:acr:phr"));
}
