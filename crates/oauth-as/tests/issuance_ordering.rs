// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! WHAT IS STILL DETECTABLE WHEN A REDEMPTION DIES HALF WAY THROUGH.
//!
//! Two redemptions in this server destroy a credential and mint replacements: the authorization
//! code grant (RFC 6749 section 4.1.3) and refresh rotation (OAuth 2.1 draft section 6.1). Both
//! begin with an ATOMIC TAKE, which is what makes them single use under concurrency, and both then
//! have to write a record saying the taken credential was spent, because that record IS the reuse
//! and replay alarm: RFC 6749 section 4.1.2, RFC 9700 sections 4.1.1 and 4.14.2 all require a
//! second presentation to be recognised as evidence rather than as an unknown string.
//!
//! `Storage` has no transaction, so those steps cannot be made atomic with each other. What CAN be
//! chosen is the ORDER, and the order decides which way the sequence fails when the store is flaky.
//! Minting first and recording spent-ness afterwards fails OPEN: the alarm for that family is
//! disarmed, permanently and silently, at exactly the moment the deployment's storage is misbehaving.
//! Recording spent-ness first fails CLOSED: the client is locked out and re-authenticates, which is
//! an inconvenience rather than a compromise-detection capability going offline.
//!
//! These tests fail the ISSUANCE half (`put_token`, the first write `issue` makes) and then present
//! the taken credential a second time. The alarm must still fire.

mod support;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use oauth_as::server::UserApproval;
use oauth_as::{
    AuthorizationRequest, AuthorizationServer, ClientId, ErrorCode, Event, EventSink, Storage,
    TokenRequest,
};

use support::{
    confidential_client, fault_server_with, ManualClock, CONFIDENTIAL_REDIRECT,
    CONFIDENTIAL_SECRET, RFC7636_VERIFIER,
};

/// Only the two compromise events matter here, and only that they FIRED: their fields are already
/// on trial in `tests/containment_truth.rs`.
#[derive(Default)]
struct Sink {
    replays: Mutex<usize>,
    reuses: Mutex<usize>,
}

impl EventSink for Sink {
    fn on_event(&self, event: Event<'_>) {
        match event {
            Event::AuthorizationCodeReplayDetected { .. } => {
                *self.replays.lock().unwrap_or_else(|e| e.into_inner()) += 1
            }
            Event::RefreshTokenReuseDetected { .. } => {
                *self.reuses.lock().unwrap_or_else(|e| e.into_inner()) += 1
            }
            _ => {}
        }
    }
}

struct SinkHandle(Arc<Sink>);

impl EventSink for SinkHandle {
    fn on_event(&self, event: Event<'_>) {
        self.0.on_event(event)
    }
}

/// Mint an authorization code and STOP: the suites here need a live, unredeemed code, which every
/// shared fixture consumes on the way to a token.
async fn issue_code<S: Storage>(
    srv: &AuthorizationServer<S, ManualClock>,
    client_id: &str,
    redirect_uri: &str,
    subject: &str,
) -> String {
    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let req = AuthorizationRequest {
        resource: Vec::new(),
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        response_type: Some("code".to_string().into()),
        client_id: Some(client_id.to_string().into()),
        redirect_uri: Some(redirect_uri.to_string().into()),
        scope: Some("read".to_string().into()),
        state: None,
        code_challenge: Some(challenge.into()),
        code_challenge_method: Some("S256".to_string().into()),
        #[cfg(feature = "consent")]
        acr_values: None,
        #[cfg(feature = "consent")]
        max_age: None,
    };
    let validated = srv
        .validate_authorization_request(&req)
        .await
        .expect("fixture authorization request must validate");
    srv.issue_authorization_code(UserApproval::granted(&validated, subject))
        .await
        .expect("fixture code issuance must succeed")
        .code
}

/// RFC 6749 section 4.1.2 and RFC 9700 section 4.1.1: a code presented twice is evidence it leaked.
///
/// The first redemption here reaches issuance and the store kills it there. The code has already
/// been taken by then, so if the `Consumed` record is only written AFTER a successful issuance,
/// this code is now absent from the store entirely and its replay reads as a typo. The client's
/// lockout is the correct and acceptable half of that failure; losing the alarm is not.
#[tokio::test]
async fn a_code_whose_issuance_failed_is_still_recognised_as_replayed() {
    let sink = Arc::new(Sink::default());
    let srv = fault_server_with(ManualClock::at_epoch(), vec![confidential_client()])
        .await
        .with_event_sink(Box::new(SinkHandle(sink.clone())));

    let code = issue_code(&srv, "confidential-app", CONFIDENTIAL_REDIRECT, "alice").await;

    srv.store().fail_put_token.store(true, Ordering::SeqCst);
    let redeem = |code: String| {
        srv.token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            code,
            redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
    };
    assert_eq!(
        redeem(code.clone()).await.unwrap_err().error,
        ErrorCode::ServerError,
        "the store refused to persist the access token, so nothing was issued"
    );

    // The store recovers. Whoever holds the code now presents it.
    srv.store().fail_put_token.store(false, Ordering::SeqCst);
    let replay = redeem(code).await.unwrap_err();
    assert_eq!(replay.error, ErrorCode::InvalidGrant, "a replay is refused");
    assert_eq!(
        *sink.replays.lock().unwrap(),
        1,
        "the replay alarm must survive a failed issuance: without the consumed record the second \
         presentation of a leaked code is indistinguishable from a typo, and RFC 9700 s4.1.1's \
         detection is off for this grant permanently and silently"
    );
}

/// OAuth 2.1 draft section 6.1 and RFC 9700 section 4.14.2: a superseded refresh token presented
/// again means two parties hold it, and the whole family must die.
///
/// Same shape as the code test above. The rotation takes the token atomically, issuance fails, and
/// the question is whether the `Spent` record that arms reuse detection for this family was written
/// before that failure or after it.
#[tokio::test]
async fn a_refresh_token_whose_rotation_failed_is_still_recognised_as_reused() {
    let sink = Arc::new(Sink::default());
    let srv = fault_server_with(ManualClock::at_epoch(), vec![confidential_client()])
        .await
        .with_event_sink(Box::new(SinkHandle(sink.clone())));

    let issued = support::mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "alice",
    )
    .await;
    let first = issued.refresh_token.expect("the fixture issues a chain");

    srv.store().fail_put_token.store(true, Ordering::SeqCst);
    let rotate = |refresh_token: String| {
        srv.token(TokenRequest::RefreshToken {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            refresh_token,
            scope: None,
        })
    };
    assert_eq!(
        rotate(first.clone()).await.unwrap_err().error,
        ErrorCode::ServerError,
        "the store refused to persist the new access token, so nothing was issued"
    );

    srv.store().fail_put_token.store(false, Ordering::SeqCst);
    let reuse = rotate(first).await.unwrap_err();
    assert_eq!(reuse.error, ErrorCode::InvalidGrant, "a reuse is refused");
    assert_eq!(
        *sink.reuses.lock().unwrap(),
        1,
        "the reuse alarm must survive a failed rotation: with no Spent record the presented token \
         is an unknown string, so RFC 9700 s4.14.2 detection is off for this family permanently"
    );
}
