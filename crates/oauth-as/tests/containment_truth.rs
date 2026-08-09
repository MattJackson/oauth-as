// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! WHAT THE AUDIT SINK IS TOLD WHEN THE CONTAINMENT RESPONSE ITSELF FAILS.
//!
//! Two paths in this server react to evidence by DESTROYING credentials: the authorization-code
//! replay branch (RFC 6749 section 4.1.2, RFC 9700 section 4.1.1) and RFC 7009 revocation's cascade
//! to the rest of the grant (section 2.1). Both of them talk to the host's store, and a store can
//! fail.
//!
//! The wire cannot carry that news. A replayed code gets `invalid_grant` whether or not the
//! revocation worked, because the party being answered is the one holding a leaked code, and a
//! revocation endpoint that turned a completed revocation into a 503 would tell an honest client
//! that nothing happened when the token it named is already gone. So THE AUDIT EVENT IS THE ONLY
//! SIGNAL A DEPLOYMENT GETS, and an event that claims containment it did not achieve is worse than
//! no event at all: it is the thing an operator reads while deciding not to investigate.
//!
//! These tests fail the store underneath each containment step and assert on what the sink is told.

mod support;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use oauth_as::{ClientId, ErrorCode, Event, EventSink, ScopeSet, TokenRequest, TokenTypeHint};

use support::{fault_server_with, ManualClock, CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET};

/// Records the two containment events in full, since it is their FIELDS that are on trial here and
/// not merely that they fired.
#[derive(Default)]
struct Sink {
    replays: Mutex<Vec<(bool, bool)>>,
    revocations: Mutex<Vec<(TokenTypeHint, bool)>>,
}

impl EventSink for Sink {
    fn on_event(&self, event: Event<'_>) {
        match event {
            Event::AuthorizationCodeReplayDetected {
                tokens_revoked,
                containment_failed,
                ..
            } => self
                .replays
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((tokens_revoked, containment_failed)),
            Event::TokenRevoked {
                token_type,
                cascade_failed,
                ..
            } => self
                .revocations
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((token_type, cascade_failed)),
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

/// A code that was redeemed once and is now presented again, with the store rigged to fail the
/// step named by `rig`.
async fn replay_with_broken_store(rig: fn(&support::FaultStorage)) -> Arc<Sink> {
    let clock = ManualClock::at_epoch();
    let sink = Arc::new(Sink::default());
    let srv = fault_server_with(clock, vec![support::confidential_client()])
        .await
        .with_event_sink(Box::new(SinkHandle(sink.clone())));

    let (_issued, code) = support::mint_code_token_keeping_code(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "alice",
    )
    .await;

    rig(srv.store());

    let replay = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            code,
            redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
            code_verifier: Some(support::RFC7636_VERIFIER.to_string()),
        })
        .await;
    assert_eq!(
        replay.unwrap_err().error,
        ErrorCode::InvalidGrant,
        "the WIRE answer to a replayed code is invalid_grant however badly the store is behaving"
    );
    sink
}

/// The baseline: with a healthy store, the event says the containment worked, and says so honestly.
#[tokio::test]
async fn a_successful_containment_reports_success() {
    let sink = replay_with_broken_store(|_| {}).await;
    let replays = sink.replays.lock().unwrap();
    assert_eq!(replays.len(), 1, "one replay, one event");
    assert_eq!(
        replays[0],
        (true, false),
        "tokens were revoked and nothing failed"
    );
}

/// THE FINDING. The family revocation's `Result` was discarded and `tokens_revoked: true` was set
/// unconditionally, so a store that failed at the exact moment the server was responding to a
/// detected compromise reported a clean containment to the operator. The attacker's refresh chain
/// is still live and the audit log says it is not.
#[tokio::test]
async fn a_failed_family_revocation_must_not_be_reported_as_tokens_revoked() {
    let sink = replay_with_broken_store(|store| {
        store.fail_revoke_token_family.store(true, Ordering::SeqCst);
    })
    .await;
    let replays = sink.replays.lock().unwrap();
    assert_eq!(replays.len(), 1);
    let (tokens_revoked, containment_failed) = replays[0];
    assert!(
        !tokens_revoked,
        "nothing was revoked: the store refused the family revocation"
    );
    assert!(
        containment_failed,
        "the operator must be told the compromise response did not complete"
    );
}

/// The fallback leg: no reachable refresh chain, so the access token the code minted is deleted by
/// name. That delete was fire-and-forget, and a failure left the compromised access token live for
/// its whole TTL with nothing anywhere recording it.
#[tokio::test]
async fn a_failed_access_token_deletion_must_be_reported() {
    let sink = replay_with_broken_store(|store| {
        // No refresh chain to reach a family through, so the fallback delete is the containment.
        store.fail_get_refresh.store(true, Ordering::SeqCst);
        store.fail_delete_token.store(true, Ordering::SeqCst);
    })
    .await;
    let replays = sink.replays.lock().unwrap();
    assert_eq!(replays.len(), 1);
    assert_eq!(
        replays[0],
        (false, true),
        "nothing was revoked and the failure has to show"
    );
}

/// Putting the CONSUMED record back is what makes replay detection work more than once. It was
/// fire-and-forget too: if it fails the record is gone, and the NEXT presentation of the same code
/// reads as an unknown code, which is the answer a typo gets. The compromise stops being visible.
#[tokio::test]
async fn a_failed_replay_record_restore_must_be_reported() {
    let sink = replay_with_broken_store(|store| {
        store
            .fail_put_authorization_code
            .store(true, Ordering::SeqCst);
    })
    .await;
    let replays = sink.replays.lock().unwrap();
    assert_eq!(replays.len(), 1);
    assert!(
        replays[0].1,
        "losing the consumed record loses the evidence, so the event must say so"
    );
}

/// RFC 7009 section 2.1's SHOULD: revoking a refresh token also invalidates the access tokens of
/// the same grant. The cascade is deliberately non-fatal (see the comment at the call site), but it
/// fired `TokenRevoked` unconditionally, so an operator could not tell a complete revocation from a
/// partial one.
#[tokio::test]
async fn a_failed_revocation_cascade_must_be_reported() {
    let clock = ManualClock::at_epoch();
    let sink = Arc::new(Sink::default());
    let srv = fault_server_with(clock, vec![support::confidential_client()])
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
    let refresh = issued.refresh_token.expect("the fixture issues a chain");

    srv.store()
        .fail_revoke_token_family
        .store(true, Ordering::SeqCst);
    srv.revoke(
        &ClientId::new("confidential-app"),
        Some(CONFIDENTIAL_SECRET),
        &refresh,
        Some(TokenTypeHint::RefreshToken),
    )
    .await
    .expect("section 2.2: the presented token is gone, so the answer is still success");

    let revocations = sink.revocations.lock().unwrap();
    assert_eq!(revocations.len(), 1);
    assert_eq!(
        revocations[0],
        (TokenTypeHint::RefreshToken, true),
        "the presented token was revoked; the cascade to the grant was not, and that has to show"
    );
}

/// A healthy cascade reports no failure, so the field above is not simply always true.
#[tokio::test]
async fn a_successful_revocation_cascade_reports_no_failure() {
    let clock = ManualClock::at_epoch();
    let sink = Arc::new(Sink::default());
    let srv = fault_server_with(clock, vec![support::confidential_client()])
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
    let refresh = issued.refresh_token.unwrap();
    srv.revoke(
        &ClientId::new("confidential-app"),
        Some(CONFIDENTIAL_SECRET),
        &refresh,
        None,
    )
    .await
    .unwrap();

    let revocations = sink.revocations.lock().unwrap();
    assert_eq!(revocations[0], (TokenTypeHint::RefreshToken, false));
}

/// A code presented by the WRONG client is put back, because destroying it would hand any third
/// party a free denial of service against the legitimate client. That restore was fire-and-forget:
/// if the store refuses it, a live code belonging to an honest client is destroyed and the server
/// answers as though it had merely refused a stranger. The failure has to reach somebody.
#[tokio::test]
async fn a_failed_code_restore_after_a_client_mismatch_is_not_silent() {
    let clock = ManualClock::at_epoch();
    let srv = fault_server_with(
        clock,
        vec![support::confidential_client(), support::public_client()],
    )
    .await;

    let challenge = oauth_as::pkce::code_challenge_s256(support::RFC7636_VERIFIER);
    let req = oauth_as::AuthorizationRequest {
        resource: Vec::new(),
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        response_type: Some("code".to_string().into()),
        client_id: Some("confidential-app".to_string().into()),
        redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string().into()),
        scope: Some("read".to_string().into()),
        state: None,
        code_challenge: Some(challenge.into()),
        code_challenge_method: Some("S256".to_string().into()),
        #[cfg(feature = "consent")]
        acr_values: None,
        #[cfg(feature = "consent")]
        max_age: None,
    };
    let validated = srv.validate_authorization_request(&req).await.unwrap();
    let response = srv
        .issue_authorization_code(oauth_as::server::UserApproval::granted(&validated, "alice"))
        .await
        .unwrap();

    srv.store()
        .fail_put_authorization_code
        .store(true, Ordering::SeqCst);

    // A different, registered client presents the code. The ownership check refuses it, and the
    // restore of the honest client's code is what fails.
    let outcome = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("public-app"),
            client_secret: None,
            code: response.code.clone(),
            redirect_uri: Some(support::PUBLIC_REDIRECT.to_string()),
            code_verifier: Some(support::RFC7636_VERIFIER.to_string()),
        })
        .await;
    assert_eq!(
        outcome.unwrap_err().error,
        ErrorCode::ServerError,
        "a storage failure that destroyed a live code must not be answered as a plain refusal"
    );

    // Sanity: the fixture really did make the code unrecoverable, which is what makes the loud
    // answer the only signal there is.
    srv.store()
        .fail_put_authorization_code
        .store(false, Ordering::SeqCst);
    let honest = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            code: response.code,
            redirect_uri: Some(CONFIDENTIAL_REDIRECT.to_string()),
            code_verifier: Some(support::RFC7636_VERIFIER.to_string()),
        })
        .await;
    assert_eq!(honest.unwrap_err().error, ErrorCode::InvalidGrant);
    let _ = ScopeSet::empty();
}
