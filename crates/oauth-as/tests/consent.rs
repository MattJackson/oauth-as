// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Consent records and consent WITHDRAWAL, driven through the crate's public API.
//!
//! The failure mode this suite exists to catch, and the one every other test here is arranged
//! around, is a withdrawal that leaves tokens alive. That failure is worse than having no
//! withdrawal at all: a user who clicks "remove this application" and is shown a confirmation has
//! been told something stopped, and if the access token in the attacker's (or merely the ex
//! employee's) hand still works for another hour, the server has lied to the person it exists to
//! protect. So the assertions here are not "the record is gone"; they are "the token no longer
//! works", checked through RFC 7662 introspection and through the token endpoint, which is what an
//! attacker would actually use.
//!
//! The second thing pinned here is that a consent is BROADER than a refresh family. The family is
//! what RFC 9700 s4.14.2 revokes on reuse detection, and one client acting for one user
//! accumulates families: every trip through the authorization endpoint mints another. A withdrawal
//! that killed the newest family and left the rest is the same silent failure one level up, so
//! `withdrawal_reaches_every_family_the_consent_ever_produced` drives two complete, independent
//! grants before withdrawing once.
//!
//! And the third: withdrawal must not be a weapon. A consent belongs to one (client, subject)
//! pair, so withdrawing it must leave another user's grant to the same client, and the same user's
//! grant to another client, completely untouched. "Any user can end any other user's sessions" is
//! a denial of service, not a feature.
#![cfg(feature = "consent")]

mod support;

use std::sync::Mutex;
use std::time::{Duration, UNIX_EPOCH};

use oauth_as::{
    Authentication, ClientId, Event, EventSink, IntrospectionResponse, ScopeSet, Storage,
    TokenRequest, TokenTypeHint,
};
use support::{
    confidential_client, mint_code_token, other_confidential_client, ManualClock,
    CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET, OTHER_CONFIDENTIAL_SECRET, OTHER_REDIRECT,
};

const APP: &str = "confidential-app";
/// The secret  is registered with; it is a confidential client, so a
/// device poll has to authenticate.
const DEVICE_ONLY_SECRET: &str = "s3cret-value-for-tests";

fn scopes(s: &str) -> ScopeSet {
    ScopeSet::parse(s).unwrap()
}

/// Whether the access token still answers RFC 7662 introspection as active. This is the question a
/// resource server asks, so it is the question these tests ask.
async fn still_live<S: Storage>(
    srv: &oauth_as::AuthorizationServer<S, ManualClock>,
    access_token: &str,
) -> bool {
    srv.introspection_response(&ClientId::new(APP), Some(CONFIDENTIAL_SECRET), access_token)
        .await
        .unwrap()
        != IntrospectionResponse::inactive()
}

/// An event sink that keeps what it is told, so the audit half of a withdrawal can be asserted.
#[derive(Default)]
struct Recorder(Mutex<Vec<String>>);

impl EventSink for Recorder {
    fn on_event(&self, event: Event<'_>) {
        if let Event::ConsentWithdrawn {
            client_id,
            subject,
            records_revoked,
        } = event
        {
            self.0
                .lock()
                .unwrap()
                .push(format!("{client_id}/{subject}/{records_revoked}"));
        }
    }
}

// ------------------------------------------------------------------ the point of the feature

/// THE TEST THIS SUITE EXISTS FOR. A user withdraws consent; every token that consent produced
/// must be dead, immediately, as seen from the outside.
///
/// Both halves are checked the way an attacker would use them: the access token through RFC 7662
/// introspection, and the refresh token through the token endpoint, because a refresh token that
/// still mints new access tokens makes the withdrawal purely cosmetic.
#[tokio::test]
async fn withdrawal_kills_the_access_and_refresh_tokens_it_produced() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock, vec![confidential_client()]).await;
    let issued = mint_code_token(
        &srv,
        APP,
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    let refresh_token = issued.refresh_token.clone().expect("a refresh token");
    let consent = srv
        .record_consent(&ClientId::new(APP), "user-1", &scopes("read"), &[], None)
        .await
        .unwrap();
    assert!(still_live(&srv, &issued.access_token).await);

    let revoked = srv.withdraw_consent(&consent.consent_id).await.unwrap();

    assert!(revoked >= 2, "the cascade removed only {revoked} records");
    assert!(
        !still_live(&srv, &issued.access_token).await,
        "the access token is still live after the user withdrew consent"
    );
    let refreshed = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new(APP),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            refresh_token,
            scope: None,
        })
        .await;
    assert!(
        refreshed.is_err(),
        "the refresh token still mints tokens after the user withdrew consent"
    );
    assert_eq!(
        refreshed.unwrap_err().error,
        oauth_as::ErrorCode::InvalidGrant
    );
}

/// A consent is a BROADER unit than a refresh family. Two complete, independent trips through the
/// authorization endpoint produce two families; one withdrawal must end both.
///
/// This is the case a family-based revocation gets wrong while looking correct in a single-grant
/// test: it kills the newest chain, the user sees the application disappear from their list, and
/// last month's tokens go on working.
#[tokio::test]
async fn withdrawal_reaches_every_family_the_consent_ever_produced() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock.clone(), vec![confidential_client()]).await;
    let first = mint_code_token(
        &srv,
        APP,
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    clock.advance(Duration::from_secs(60));
    let second = mint_code_token(
        &srv,
        APP,
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    // Two grants, two families: the premise of the test.
    let first_record = srv.introspect(&first.access_token).await.unwrap().unwrap();
    let second_record = srv.introspect(&second.access_token).await.unwrap().unwrap();
    assert_ne!(
        first_record.family_id, second_record.family_id,
        "fixture is not exercising two families"
    );

    let consent = srv
        .record_consent(&ClientId::new(APP), "user-1", &scopes("read"), &[], None)
        .await
        .unwrap();
    srv.withdraw_consent(&consent.consent_id).await.unwrap();

    assert!(
        !still_live(&srv, &first.access_token).await,
        "the OLDER grant survived the withdrawal: this is family-scoped revocation wearing a \
         consent's name"
    );
    assert!(!still_live(&srv, &second.access_token).await);
}

/// An authorization code that has been issued but not yet redeemed is a grant IN FLIGHT. Left
/// behind, it mints a token seconds after the user said stop, which is the withdrawal failing in
/// the way nobody notices until it matters.
#[tokio::test]
async fn withdrawal_kills_an_authorization_code_that_has_not_been_redeemed_yet() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock, vec![confidential_client()]).await;
    let challenge = oauth_as::pkce::code_challenge_s256(support::RFC7636_VERIFIER);
    // Built through the real query parser rather than as a struct literal, so this fixture cannot
    // drift from what an actual request looks like.
    let request = oauth_as::AuthorizationRequest::from_pairs([
        ("response_type", "code"),
        ("client_id", APP),
        ("redirect_uri", CONFIDENTIAL_REDIRECT),
        ("scope", "read"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]);
    let validated = srv.validate_authorization_request(&request).await.unwrap();
    let response = srv
        .issue_authorization_code(&validated, "user-1")
        .await
        .unwrap();
    let consent = srv
        .record_consent(&ClientId::new(APP), "user-1", &scopes("read"), &[], None)
        .await
        .unwrap();

    srv.withdraw_consent(&consent.consent_id).await.unwrap();

    let redeemed = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new(APP),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            code: response.code,
            redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
            code_verifier: Some(support::RFC7636_VERIFIER.to_string()),
        })
        .await;
    assert_eq!(
        redeemed.unwrap_err().error,
        oauth_as::ErrorCode::InvalidGrant,
        "an authorization code outlived the consent it was issued under"
    );
}

/// A device grant the user has APPROVED but the device has not polled for yet is the same problem
/// as an unredeemed code: RFC 8628 s3.4 lets the device redeem it on its next poll.
#[tokio::test]
async fn withdrawal_kills_an_approved_device_grant_the_device_has_not_polled_for() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock, vec![support::device_only_client()]).await;
    let auth = srv
        .device_authorization(
            &ClientId::new("device-only"),
            Some(DEVICE_ONLY_SECRET),
            None,
        )
        .await
        .unwrap();
    srv.approve_device(&auth.user_code, "user-1").await.unwrap();
    let consent = srv
        .record_consent(
            &ClientId::new("device-only"),
            "user-1",
            &scopes("read"),
            &[],
            None,
        )
        .await
        .unwrap();

    srv.withdraw_consent(&consent.consent_id).await.unwrap();

    let polled = srv
        .token(TokenRequest::DeviceCode {
            client_id: ClientId::new("device-only"),
            client_secret: Some(DEVICE_ONLY_SECRET.to_string()),
            device_code: auth.device_code,
        })
        .await;
    assert_eq!(
        polled.unwrap_err().error,
        oauth_as::ErrorCode::InvalidGrant,
        "an approved device grant outlived the consent that approved it"
    );
}

// ------------------------------------------------------------------ withdrawal is not a weapon

/// A consent belongs to one (client, subject) pair. Withdrawing one user's must leave another
/// user's grant to the SAME client working: "any user can end any other user's session" is a
/// denial of service.
#[tokio::test]
async fn withdrawal_does_not_touch_another_users_grant_to_the_same_client() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock, vec![confidential_client()]).await;
    let mine = mint_code_token(
        &srv,
        APP,
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    let theirs = mint_code_token(
        &srv,
        APP,
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-2",
    )
    .await;
    let consent = srv
        .record_consent(&ClientId::new(APP), "user-1", &scopes("read"), &[], None)
        .await
        .unwrap();

    srv.withdraw_consent(&consent.consent_id).await.unwrap();

    assert!(!still_live(&srv, &mine.access_token).await);
    assert!(
        still_live(&srv, &theirs.access_token).await,
        "withdrawing one user's consent revoked another user's tokens"
    );
}

/// And the other axis: the same user's grant to a DIFFERENT client survives. A user removing one
/// application has not removed the rest.
#[tokio::test]
async fn withdrawal_does_not_touch_the_same_users_grant_to_another_client() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(
        clock,
        vec![confidential_client(), other_confidential_client()],
    )
    .await;
    let here = mint_code_token(
        &srv,
        APP,
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    let elsewhere = mint_code_token(
        &srv,
        "other-app",
        Some(OTHER_CONFIDENTIAL_SECRET),
        OTHER_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    let consent = srv
        .record_consent(&ClientId::new(APP), "user-1", &scopes("read"), &[], None)
        .await
        .unwrap();

    srv.withdraw_consent(&consent.consent_id).await.unwrap();

    assert!(!still_live(&srv, &here.access_token).await);
    let other_still_live = srv
        .introspection_response(
            &ClientId::new("other-app"),
            Some(OTHER_CONFIDENTIAL_SECRET),
            &elsewhere.access_token,
        )
        .await
        .unwrap();
    assert_ne!(
        other_still_live,
        IntrospectionResponse::inactive(),
        "withdrawing consent for one client revoked another client's tokens for the same user"
    );
}

/// A client-only token (RFC 6749 s4.4) belongs to no resource owner, so no user's withdrawal
/// reaches it. Killing it would take a service offline because an unrelated human clicked a button.
#[tokio::test]
async fn withdrawal_does_not_touch_a_client_credentials_token() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock, vec![confidential_client()]).await;
    let service = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new(APP),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            scope: None,
        })
        .await
        .unwrap();
    let consent = srv
        .record_consent(&ClientId::new(APP), "user-1", &scopes("read"), &[], None)
        .await
        .unwrap();

    srv.withdraw_consent(&consent.consent_id).await.unwrap();

    assert!(
        still_live(&srv, &service.access_token).await,
        "a user's withdrawal revoked a client-only token that names no user"
    );
}

/// Withdrawing twice, or withdrawing something that never existed, is success answering 0. A user
/// who clicks twice has not made a mistake, and an unknown identifier must not be distinguishable
/// from a known one by its error.
#[tokio::test]
async fn withdrawal_is_idempotent_and_unknown_ids_are_not_an_error() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock, vec![confidential_client()]).await;
    mint_code_token(
        &srv,
        APP,
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    let consent = srv
        .record_consent(&ClientId::new(APP), "user-1", &scopes("read"), &[], None)
        .await
        .unwrap();

    assert!(srv.withdraw_consent(&consent.consent_id).await.unwrap() > 0);
    assert_eq!(srv.withdraw_consent(&consent.consent_id).await.unwrap(), 0);
    assert_eq!(srv.withdraw_consent("no-such-consent").await.unwrap(), 0);
}

// ------------------------------------------------------------------ the record itself

/// A user has to be able to SEE what they granted, which is the other half of why this feature
/// exists. One entry per client, carrying what that client may do.
#[tokio::test]
async fn a_user_can_see_every_consent_they_have_granted() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(
        clock,
        vec![confidential_client(), other_confidential_client()],
    )
    .await;
    srv.record_consent(
        &ClientId::new(APP),
        "user-1",
        &scopes("read write"),
        &[],
        None,
    )
    .await
    .unwrap();
    srv.record_consent(
        &ClientId::new("other-app"),
        "user-1",
        &scopes("read"),
        &["https://rs.example/".to_string()],
        None,
    )
    .await
    .unwrap();
    srv.record_consent(&ClientId::new(APP), "user-2", &scopes("read"), &[], None)
        .await
        .unwrap();

    let mut mine = srv.consents_for_subject("user-1").await.unwrap();
    mine.sort_by(|a, b| a.client_id.as_str().cmp(b.client_id.as_str()));
    assert_eq!(mine.len(), 2);
    assert_eq!(mine[0].client_id.as_str(), APP);
    assert_eq!(mine[0].scope, scopes("read write"));
    assert_eq!(mine[1].client_id.as_str(), "other-app");
    assert_eq!(mine[1].resource, vec!["https://rs.example/".to_string()]);
    // Another user's consent to the same client is a different record and is not listed here.
    assert_eq!(srv.consents_for_subject("user-2").await.unwrap().len(), 1);
    assert!(srv.consents_for_subject("nobody").await.unwrap().is_empty());
}

/// Approving something further WIDENS the existing consent rather than making a second one: one
/// relationship, one row, one thing to withdraw. The identifier survives, so a link a user is
/// looking at does not stop working because they approved another scope in another tab.
#[tokio::test]
async fn a_second_approval_widens_the_same_consent() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock.clone(), vec![confidential_client()]).await;
    let first = srv
        .record_consent(&ClientId::new(APP), "user-1", &scopes("read"), &[], None)
        .await
        .unwrap();
    clock.advance(Duration::from_secs(3600));
    let second = srv
        .record_consent(
            &ClientId::new(APP),
            "user-1",
            &scopes("write"),
            &["https://rs.example/".to_string()],
            None,
        )
        .await
        .unwrap();

    assert_eq!(first.consent_id, second.consent_id);
    assert_eq!(first.granted_at, second.granted_at, "granted_at moved");
    assert_eq!(second.scope, scopes("read write"));
    assert_eq!(second.resource, vec!["https://rs.example/".to_string()]);
    assert_eq!(srv.consents_for_subject("user-1").await.unwrap().len(), 1);
}

/// Remembered consent is scoped to the pair. This is what the HTTP layer hands the host's consent
/// resolver, so a wrong answer here is a prompt skipped for a client the user never approved.
#[tokio::test]
async fn remembered_consent_is_per_client_and_per_user() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(
        clock,
        vec![confidential_client(), other_confidential_client()],
    )
    .await;
    srv.record_consent(&ClientId::new(APP), "user-1", &scopes("read"), &[], None)
        .await
        .unwrap();

    let remembered = srv
        .remembered_consent(&ClientId::new(APP), "user-1")
        .await
        .unwrap()
        .expect("the consent just recorded");
    assert!(remembered.covers(&scopes("read"), &[]));
    assert!(!remembered.covers(&scopes("read write"), &[]));

    assert!(srv
        .remembered_consent(&ClientId::new(APP), "user-2")
        .await
        .unwrap()
        .is_none());
    assert!(srv
        .remembered_consent(&ClientId::new("other-app"), "user-1")
        .await
        .unwrap()
        .is_none());
}

/// The most recent authentication replaces the previous one, because it is what an RFC 9470
/// `max_age` on the NEXT request has to be measured against. A host that reports nothing this time
/// leaves the previous report standing: "did not say" is not "no longer authenticated".
#[tokio::test]
async fn the_latest_authentication_replaces_the_previous_one_and_silence_does_not() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock, vec![confidential_client()]).await;
    let early = UNIX_EPOCH + Duration::from_secs(1_000);
    let later = UNIX_EPOCH + Duration::from_secs(2_000);

    srv.record_consent(
        &ClientId::new(APP),
        "user-1",
        &scopes("read"),
        &[],
        Some(Authentication::at(early).with_acr("pwd")),
    )
    .await
    .unwrap();
    let after_stronger = srv
        .record_consent(
            &ClientId::new(APP),
            "user-1",
            &scopes("read"),
            &[],
            Some(Authentication::at(later).with_acr("mfa")),
        )
        .await
        .unwrap();
    let auth = after_stronger.authentication.expect("an authentication");
    assert_eq!(auth.auth_time, later);
    assert_eq!(auth.acr.as_deref(), Some("mfa"));

    let after_silence = srv
        .record_consent(&ClientId::new(APP), "user-1", &scopes("read"), &[], None)
        .await
        .unwrap();
    let auth = after_silence.authentication.expect("the previous report");
    assert_eq!(auth.auth_time, later, "silence erased the report");
}

/// The cascade is not silent. RFC 9700 s4.14.2's revocations are observable through
/// [`EventSink`] precisely because a revocation nobody can see is one nobody investigates, and a
/// consent withdrawal logs a client out of an account it was working with, so a host will be asked
/// about it.
#[tokio::test]
async fn withdrawal_is_reported_to_the_event_sink_with_what_it_removed() {
    let clock = ManualClock::at_epoch();
    let recorder = std::sync::Arc::new(Recorder::default());
    let srv = support::server_with(clock, vec![confidential_client()])
        .await
        .with_event_sink(Box::new(RecorderHandle(recorder.clone())));
    mint_code_token(
        &srv,
        APP,
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    let consent = srv
        .record_consent(&ClientId::new(APP), "user-1", &scopes("read"), &[], None)
        .await
        .unwrap();

    let revoked = srv.withdraw_consent(&consent.consent_id).await.unwrap();

    let seen = recorder.0.lock().unwrap().clone();
    assert_eq!(seen, vec![format!("confidential-app/user-1/{revoked}")]);
    // Withdrawing something already gone revokes nothing and says nothing.
    srv.withdraw_consent(&consent.consent_id).await.unwrap();
    assert_eq!(recorder.0.lock().unwrap().len(), 1);
}

/// A shared handle, so the test can read what the sink recorded after the server has taken it.
struct RecorderHandle(std::sync::Arc<Recorder>);

impl EventSink for RecorderHandle {
    fn on_event(&self, event: Event<'_>) {
        self.0.on_event(event);
    }
}

/// RFC 7592 s2.3 deletes a registration and everything it holds. A consent naming a client that no
/// longer exists would show a user an application they cannot revoke, on a registration nothing can
/// reach.
#[tokio::test]
async fn deleting_a_client_takes_its_consents_with_it() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock, vec![confidential_client()]).await;
    srv.record_consent(&ClientId::new(APP), "user-1", &scopes("read"), &[], None)
        .await
        .unwrap();
    assert_eq!(srv.consents_for_subject("user-1").await.unwrap().len(), 1);

    assert!(srv
        .store()
        .delete_client(&ClientId::new(APP))
        .await
        .unwrap());

    assert!(srv.consents_for_subject("user-1").await.unwrap().is_empty());
}

/// A revoked ACCESS token is not a withdrawn consent, and must not read as one. RFC 7009 revocation
/// is the client saying "I am done with this string"; withdrawal is the user saying "you may not
/// act for me". Conflating them would make a client able to erase its own consent record and so
/// disappear from the user's list without the user doing anything.
#[tokio::test]
async fn revoking_a_token_does_not_withdraw_the_consent() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock, vec![confidential_client()]).await;
    let issued = mint_code_token(
        &srv,
        APP,
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    srv.record_consent(&ClientId::new(APP), "user-1", &scopes("read"), &[], None)
        .await
        .unwrap();

    srv.revoke(
        &ClientId::new(APP),
        Some(CONFIDENTIAL_SECRET),
        &issued.access_token,
        Some(TokenTypeHint::AccessToken),
    )
    .await
    .unwrap();

    assert_eq!(srv.consents_for_subject("user-1").await.unwrap().len(), 1);
}
