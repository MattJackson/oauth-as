// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! WHAT THE WIRE SAYS WHEN RESTORING A STRANGER'S PUSHED REQUEST FAILS.
//!
//! RFC 9126 section 7.5 is request URI swapping: a handle issued to one client presented by
//! another. The refusal is only half the answer. The record has already been removed by the atomic
//! take that resolves it, so it has to go BACK, or refusing the swap has bought a denial of service
//! against the rightful owner instead of preventing one.
//!
//! That write can fail, and the answer then is NOT the ordinary refusal. `invalid_request_uri`
//! would report a live handle's destruction as the routine rejection it is not: the honest client
//! would arrive a moment later, be told `invalid_request_uri` as well, and nobody would ever
//! connect the two. The authorization code path in `src/server.rs` argues exactly this and
//! propagates; this file holds the RFC 9126 path to the same standard.

#![cfg(feature = "par")]

mod support;

use std::sync::atomic::Ordering;

use oauth_as::{
    AuthorizationError, AuthorizationServer, Client, ClientAuth, ClientId, ErrorCode, GrantType,
    ParConfig, ScopeSet, ServerConfig,
};

use support::{FaultStorage, ManualClock};

fn client(id: &str) -> Client {
    Client {
        client_id: ClientId::new(id),
        auth: ClientAuth::ConfidentialSecret {
            secret: format!("{id}-secret"),
        },
        grant_types: vec![GrantType::AuthorizationCode],
        redirect_uris: vec![format!("https://{id}.example/cb")],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

async fn server() -> AuthorizationServer<FaultStorage, ManualClock> {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.par = Some(Box::new(ParConfig::new()));
    let srv = AuthorizationServer::with_clock(cfg, FaultStorage::new(), ManualClock::at_epoch());
    srv.register_client(client("app")).await.unwrap();
    srv.register_client(client("other")).await.unwrap();
    srv
}

async fn push(srv: &AuthorizationServer<FaultStorage, ManualClock>) -> String {
    let challenge = oauth_as::pkce::code_challenge_s256(support::RFC7636_VERIFIER);
    srv.pushed_authorization_request(
        &ClientId::new("app"),
        Some("app-secret"),
        &[
            ("response_type", "code"),
            ("client_id", "app"),
            ("redirect_uri", "https://app.example/cb"),
            ("scope", "read"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ],
    )
    .await
    .expect("a well-formed pushed request is accepted")
    .request_uri
}

/// The baseline, so the failure case below is read against a known-good answer: a swap is refused
/// with `invalid_request_uri` and the rightful owner's handle still works.
#[tokio::test]
async fn a_swap_is_refused_and_the_owners_handle_survives() {
    let srv = server().await;
    let request_uri = push(&srv).await;

    let refused = srv
        .validate_pushed_authorization_request("other", &request_uri)
        .await
        .expect_err("RFC 9126 s7.5: a handle issued to `app` is not `other`'s to use");
    match refused {
        AuthorizationError::Direct(e) => assert_eq!(e.error, ErrorCode::InvalidRequestUri),
        other => panic!("expected a direct refusal, got {other:?}"),
    }

    srv.validate_pushed_authorization_request("app", &request_uri)
        .await
        .expect("the rightful owner's handle must survive a stranger's attempt on it");
}

/// The one that was silent. With the restore discarded, this answered `invalid_request_uri`: the
/// same thing it says to any stranger with a made-up handle, while an honest client's live pushed
/// request had just been destroyed and nothing anywhere recorded it.
#[tokio::test]
async fn a_restore_that_fails_is_reported_as_a_server_error_not_as_a_refusal() {
    let srv = server().await;
    let request_uri = push(&srv).await;

    srv.store()
        .fail_put_pushed_request
        .store(true, Ordering::SeqCst);
    let refused = srv
        .validate_pushed_authorization_request("other", &request_uri)
        .await
        .expect_err("the swap is refused either way");
    match refused {
        AuthorizationError::Direct(e) => assert_eq!(
            e.error,
            ErrorCode::ServerError,
            "the handle has been destroyed by a stranger's request and the store refused to put \
             it back; answering `invalid_request_uri` would report that as the routine refusal it \
             is not, and the party in front of us is not the one who was harmed"
        ),
        other => panic!("expected a direct refusal, got {other:?}"),
    }

    // And the damage the answer is reporting is real: the owner's handle is gone.
    srv.store()
        .fail_put_pushed_request
        .store(false, Ordering::SeqCst);
    srv.validate_pushed_authorization_request("app", &request_uri)
        .await
        .expect_err(
            "the handle really was lost, which is why the answer above must not be a \
                     routine refusal",
        );
}
