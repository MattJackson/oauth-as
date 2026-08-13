// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Narrowing a registration must reach the grants that registration already produced.
//!
//! `Client::allowed_scopes` is documented as "the scopes this client may ever be granted". That is
//! a promise about the FUTURE of every live grant, not only about the next authorization request,
//! and a refresh chain is where the difference bites: `ServerConfig::refresh_token_ttl` defaults to
//! `None`, which its own documentation describes as no time expiry at all, so a chain minted under
//! a wide registration outlives every narrowing an operator performs afterwards.
//!
//! FOUND BY THE 0.9.1 AUDIT. The registration ceiling was applied at `device_authorization` and at
//! `client_credentials` and nowhere else: neither the code grant's redemption nor a rotation
//! consulted it, so the only ceiling on a rotation was the record's own scope. An operator who
//! discovered a client should never have held a scope, narrowed the registration, and confirmed
//! the change, kept minting that scope on every rotation, indefinitely, with no event saying so.
//! The only thing that actually stopped it was `delete_client` or a per-family revocation the
//! operator has no list of.
//!
//! A code (60s) and a device grant (600s) have the same gap for their own lifetimes; those windows
//! are short and self-closing, and this file does not pretend otherwise. The chain is the one that
//! never closes.

mod support;

use oauth_as::{Client, ClientId, ErrorCode, ScopeSet, TokenRequest};
use support::{
    confidential_client, mint_code_token, ManualClock, CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET,
};

/// Re-register the confidential client with a narrower ceiling, the way an operator correcting an
/// over-broad registration would.
fn narrowed_to(scopes: &str) -> Client {
    Client {
        allowed_scopes: ScopeSet::parse(scopes).unwrap(),
        ..confidential_client()
    }
}

#[tokio::test]
async fn a_rotation_cannot_carry_a_scope_the_registration_no_longer_allows() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock, vec![confidential_client()]).await;

    // A grant taken out while the registration still allowed both scopes.
    let issued = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read write",
        "user-1",
    )
    .await;
    let refresh = issued.refresh_token.expect("the code grant issues a chain");

    // The operator narrows the registration. Nothing else happens: no deletion, no revocation, no
    // list of families to walk — which is the whole point, because that list is what an operator
    // does not have.
    srv.register_client(narrowed_to("read")).await.unwrap();

    let rotated = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            refresh_token: refresh,
            scope: None,
        })
        .await;

    assert_eq!(
        rotated.unwrap_err().error,
        ErrorCode::InvalidScope,
        "a refresh chain kept minting a scope the registration no longer allows; with the default \
         `refresh_token_ttl: None` that is forever, and narrowing a registration is the control an \
         operator is told to reach for"
    );
}

/// The other half, and the reason the check is a subset test rather than a deletion: narrowing to
/// something the grant still fits inside must leave the chain working.
///
/// Without this, "re-apply the ceiling" could be implemented as "refuse any rotation after any
/// registration edit", which would turn every metadata change — a new redirect URI, a renamed
/// client — into a mass logout.
#[tokio::test]
async fn a_rotation_inside_the_narrowed_ceiling_still_works() {
    let clock = ManualClock::at_epoch();
    let srv = support::server_with(clock, vec![confidential_client()]).await;

    let issued = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    let refresh = issued.refresh_token.expect("the code grant issues a chain");

    // The ceiling moves, but not past this grant.
    srv.register_client(narrowed_to("read")).await.unwrap();

    let rotated = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            refresh_token: refresh,
            scope: None,
        })
        .await
        .expect("a grant inside the new ceiling must keep rotating");
    assert_eq!(rotated.scope.as_deref(), Some("read"));
}
