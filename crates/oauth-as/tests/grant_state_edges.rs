// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Edges of the grant state machines that the rest of the suite walks past.
//!
//! Every test here exists because mutation testing showed the behaviour it pins could be removed
//! from `src/server.rs` or `src/store.rs` without a single test failing. They are not obscure
//! corners: they include a registration shape a real deployment produces (a client with no
//! registered redirect URI), the revocation half of replay detection for a grant that minted no
//! refresh chain, the retention deadline that is the ONLY thing keeping a spent refresh record
//! reclaimable, and the timestamps RFC 7662 introspection reports.

mod support;

use std::time::Duration;

use oauth_as::store::Storage;
use oauth_as::Clock;
use oauth_as::{
    AuthorizationError, AuthorizationRequest, AuthorizationServer, Client, ClientAuth, ClientId,
    ErrorCode, GrantType, IssuedToken, MemoryStorage, RefreshTokenRecord, RefreshTokenState,
    ScopeSet, ServerConfig, TokenRequest, TokenTypeHint,
};

use support::{
    confidential_client, fault_server_with, mint_code_token, mint_code_token_keeping_code,
    public_client, server_with, ManualClock, CONFIDENTIAL_REDIRECT, CONFIDENTIAL_SECRET,
    PUBLIC_REDIRECT, RFC7636_VERIFIER,
};

// ------------------------------------------------- a client with no registered redirect URI

/// A confidential client registered for grants that need no browser redirect at all (device code,
/// client credentials) legitimately has an EMPTY `redirect_uris` list. It is also, wrongly,
/// registered for the authorization code grant here, which is exactly the misconfiguration this
/// test is about.
fn no_redirect_client() -> Client {
    Client {
        client_id: ClientId::new("no-redirect-app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: "no-redirect-secret".into(),
        },
        grant_types: vec![GrantType::AuthorizationCode, GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// RFC 6749 section 3.1.2.3 lets a request omit `redirect_uri` only when there is exactly one
/// registration to mean. With NONE registered there is nothing to mean, and the server must refuse
/// WITHOUT redirecting: RFC 6749 section 4.1.2.1 forbids redirecting an error when the redirect
/// target has not been validated, and here there is no target at all.
///
/// The failure mode this pins is specific. Collapsing the "no registrations" case into the
/// "several registrations" case still produces `invalid_request`, so an assertion on the error code
/// alone cannot tell them apart. The description is what tells an operator that the CLIENT
/// REGISTRATION is wrong rather than the request, so it is asserted too.
#[tokio::test]
async fn a_client_with_no_registered_redirect_uri_is_refused_without_redirecting() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![no_redirect_client()]).await;
    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let req = AuthorizationRequest {
        resource: Vec::new(),
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        response_type: Some("code".into()),
        client_id: Some("no-redirect-app".into()),
        // Omitted, which is the only way to reach the branch: naming one would fail the exact-match
        // check first, since there is nothing registered to match.
        redirect_uri: None,
        scope: None,
        state: Some("s".into()),
        code_challenge: Some(challenge.into()),
        code_challenge_method: Some("S256".into()),
    };

    match srv.validate_authorization_request(&req).await {
        Err(AuthorizationError::Direct(e)) => {
            assert_eq!(e.error, ErrorCode::InvalidRequest);
            assert_eq!(
                e.error_description.as_deref(),
                Some("client has no registered redirect_uri"),
                "an empty registration is a different defect from an ambiguous one, and the \
                 description is the only thing that distinguishes them"
            );
        }
        other => panic!("expected a non-redirecting refusal, got {other:?}"),
    }
}

/// The neighbouring case, so the two cannot be collapsed into one another from the other side: with
/// SEVERAL registrations the server would be guessing where to send a credential, and a wrong guess
/// is the whole attack (RFC 6749 section 3.1.2.3).
#[tokio::test]
async fn several_registered_redirect_uris_require_the_request_to_name_one() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![support::two_redirect_client()]).await;
    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let req = AuthorizationRequest {
        resource: Vec::new(),
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        response_type: Some("code".into()),
        client_id: Some("multi-redirect".into()),
        redirect_uri: None,
        scope: None,
        state: None,
        code_challenge: Some(challenge.into()),
        code_challenge_method: Some("S256".into()),
    };

    match srv.validate_authorization_request(&req).await {
        Err(AuthorizationError::Direct(e)) => {
            assert_eq!(e.error, ErrorCode::InvalidRequest);
            assert_eq!(
                e.error_description.as_deref(),
                Some("redirect_uri is required when several are registered")
            );
        }
        other => panic!("expected a non-redirecting refusal, got {other:?}"),
    }
}

// --------------------------------------------- replay revocation with no refresh chain to reach

/// A confidential client registered for the authorization code grant but NOT for `refresh_token`,
/// so its code redemptions mint an access token and nothing else.
fn code_only_client() -> Client {
    Client {
        client_id: ClientId::new("code-only-app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: "code-only-secret".into(),
        },
        grant_types: vec![GrantType::AuthorizationCode],
        redirect_uris: vec![PUBLIC_REDIRECT.to_string()],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// RFC 6749 section 4.1.2 and RFC 9700 section 4.1.1: a replayed authorization code is evidence the
/// code leaked, so the tokens it already minted must be REVOKED, not merely the replay refused.
/// Refusing the replay alone leaves the attacker's stolen access token live for its full lifetime.
///
/// This pins the branch for a grant with NO refresh chain, which is the case where the recorded
/// access token has to be revoked by name because there is no family to revoke it through. It is a
/// real registration shape, not a contrived one: a client not registered for `refresh_token` gets
/// exactly this, and RFC 6749 section 4.4.3's client-credentials advice ("simply request another
/// token") is the same reasoning applied to a different grant.
#[tokio::test]
async fn replaying_a_code_that_minted_no_refresh_chain_still_revokes_its_access_token() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![code_only_client()]).await;

    let (issued, code) = mint_code_token_keeping_code(
        &srv,
        "code-only-app",
        Some("code-only-secret"),
        PUBLIC_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    assert!(
        issued.refresh_token.is_none(),
        "test setup: this client must not be registered for the refresh_token grant"
    );
    assert!(
        srv.introspect(&issued.access_token)
            .await
            .unwrap()
            .is_some(),
        "test setup: the minted access token must start out live"
    );

    // THE REPLAY. The same client presents the same code a second time.
    let err = srv
        .token(TokenRequest::AuthorizationCode {
            client_id: ClientId::new("code-only-app"),
            client_secret: Some("code-only-secret".to_string()),
            code,
            redirect_uri: Some(PUBLIC_REDIRECT.to_string()),
            code_verifier: Some(RFC7636_VERIFIER.to_string()),
        })
        .await
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidGrant);

    assert!(
        srv.introspect(&issued.access_token)
            .await
            .unwrap()
            .is_none(),
        "the access token the replayed code minted must be revoked, not left live"
    );
}

// ------------------------------------------------- retention deadline on a rotated refresh token

/// The retention deadline that makes reuse detection survivable for a chain with no absolute
/// expiry.
///
/// A rotated refresh token is RETAINED in the `Spent` state rather than deleted, because a deleted
/// token makes a later presentation indistinguishable from a typo and RFC 9700 section 4.14.2's
/// reuse remedy then never fires. But a chain configured with no absolute lifetime
/// (`refresh_token_ttl: None`, this crate's default) would make every superseded link IMMORTAL,
/// since `Storage::sweep_expired` may only reclaim a refresh record that has an `expires_at`. The
/// server therefore stamps a spent record from a never-expiring chain with
/// `now + refresh_reuse_window`.
///
/// Both halves are pinned here, because each fails differently: without the stamp the store grows
/// without bound at attacker pace, and with the stamp computed backwards the record is already dead
/// when it is written, which silently disables reuse detection from the first rotation onward.
#[tokio::test]
async fn a_rotated_token_from_a_never_expiring_chain_gets_a_retention_deadline() {
    let clock = ManualClock::at_epoch();
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    assert!(
        cfg.refresh_token_ttl.is_none(),
        "test setup: this pins the no-absolute-lifetime chain, which is the default"
    );
    let reuse_window = cfg.refresh_reuse_window;
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), clock.clone());
    srv.register_client(confidential_client()).await.unwrap();

    let first = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    let first_refresh = first.refresh_token.expect("chain must start");
    assert_eq!(
        srv.store()
            .get_refresh_token(&first_refresh)
            .await
            .unwrap()
            .unwrap()
            .expires_at,
        None,
        "test setup: the live link of a never-expiring chain carries no expiry"
    );

    srv.token(TokenRequest::RefreshToken {
        client_id: ClientId::new("confidential-app"),
        client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
        refresh_token: first_refresh.clone(),
        scope: None,
    })
    .await
    .unwrap();

    let spent = srv
        .store()
        .get_refresh_token(&first_refresh)
        .await
        .unwrap()
        .expect("a rotated token is retained so its reuse can be recognised");
    assert_eq!(spent.state, RefreshTokenState::Spent);
    assert_eq!(
        spent.expires_at,
        Some(clock.now() + reuse_window),
        "a spent link of a never-expiring chain must be stamped with a retention deadline, in the \
         FUTURE, or it is either immortal or already dead"
    );

    // The deadline is what lets the host reclaim it, and not a moment before. (The counts are not
    // asserted here: an ordinary sweep this far in the future also reaps the access tokens and the
    // consumed authorization code, which is not what this test is about.)
    let just_before = clock.now() + reuse_window - Duration::from_secs(1);
    srv.store().sweep_expired(just_before).await.unwrap();
    assert!(
        srv.store()
            .get_refresh_token(&first_refresh)
            .await
            .unwrap()
            .is_some(),
        "the retained record must survive its whole retention window: that window IS the reuse \
         detection"
    );

    srv.store()
        .sweep_expired(clock.now() + reuse_window)
        .await
        .unwrap();
    assert!(
        srv.store()
            .get_refresh_token(&first_refresh)
            .await
            .unwrap()
            .is_none(),
        "at its retention deadline the spent record must become reclaimable, or a chain with no \
         absolute lifetime leaves an immortal record behind on every rotation"
    );
}

/// The other side of the same rule: when the chain DOES have an absolute lifetime, rotation carries
/// it across unchanged rather than sliding it forward. RFC 6749 section 6 gives the AS the choice
/// of refresh lifetime; this crate's stated choice is an ABSOLUTE chain lifetime, and a rotation
/// that recomputed the expiry from `now` would turn it into a sliding one that never ends.
#[tokio::test]
async fn a_configured_chain_lifetime_is_absolute_and_does_not_slide_on_rotation() {
    let clock = ManualClock::at_epoch();
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let chain_ttl = Duration::from_secs(7 * 24 * 60 * 60);
    cfg.refresh_token_ttl = Some(chain_ttl);
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), clock.clone());
    srv.register_client(confidential_client()).await.unwrap();

    let issued_at = clock.now();
    let first = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    let first_refresh = first.refresh_token.expect("chain must start");
    assert_eq!(
        srv.store()
            .get_refresh_token(&first_refresh)
            .await
            .unwrap()
            .unwrap()
            .expires_at,
        Some(issued_at + chain_ttl),
        "a configured chain lifetime must be stamped forward from issuance, not backward"
    );

    // Rotate a day later. The replacement must inherit the ORIGINAL deadline.
    clock.advance(Duration::from_secs(24 * 60 * 60));
    let second = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            refresh_token: first_refresh,
            scope: None,
        })
        .await
        .unwrap();
    let second_refresh = second
        .refresh_token
        .expect("rotation must issue a replacement");
    assert_eq!(
        srv.store()
            .get_refresh_token(&second_refresh)
            .await
            .unwrap()
            .unwrap()
            .expires_at,
        Some(issued_at + chain_ttl),
        "rotation must carry the original absolute deadline, never restart it from now"
    );

    // And the chain really does die at that deadline rather than living on through rotations.
    clock.advance(chain_ttl);
    let err = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("confidential-app"),
            client_secret: Some(CONFIDENTIAL_SECRET.to_string()),
            refresh_token: second_refresh,
            scope: None,
        })
        .await
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidGrant);
    assert_eq!(
        err.error_description.as_deref(),
        Some("refresh token chain expired")
    );
}

// ------------------------------------------------------------- RFC 7662 introspection timestamps

/// RFC 7662 section 2.2 defines `exp` and `iat` as seconds since the Unix epoch, describing THIS
/// token: `iat` is when it was issued and `exp` is when it dies. Asserting only that they are
/// present (which the rest of the suite does) cannot tell a correct conversion from one that
/// answers a constant, so both are pinned to the exact instants the server's own clock and
/// configured lifetime imply.
#[tokio::test]
async fn introspection_reports_the_actual_issuance_and_expiry_instants() {
    let clock = ManualClock::at_epoch();
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let ttl = cfg.access_token_ttl;
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), clock.clone());
    srv.register_client(confidential_client()).await.unwrap();

    let issued_at = clock.now();
    let token = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;

    let expected_iat = issued_at
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expected_exp = (issued_at + ttl)
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        expected_iat > 0 && expected_exp > expected_iat,
        "test setup: the fixture clock must be well past the epoch"
    );

    let resp = srv
        .introspection_response(
            &ClientId::new("confidential-app"),
            Some(CONFIDENTIAL_SECRET),
            &token.access_token,
        )
        .await
        .unwrap();
    assert!(resp.active);
    assert_eq!(
        resp.iat,
        Some(expected_iat),
        "iat must be the instant the token was issued, in epoch seconds"
    );
    assert_eq!(
        resp.exp,
        Some(expected_exp),
        "exp must be iat plus the configured access token lifetime"
    );
}

// ---------------------------------------------------------------- RFC 7009 token_type_hint order

/// RFC 7009 section 2.1: `token_type_hint` is an optimisation. The server SHOULD look in the hinted
/// store FIRST, and MUST keep looking if the hint turns out to be wrong.
///
/// The outcome is deliberately the same either way, which is precisely why this needs its own
/// observation: a server that ignored the hint entirely would pass every other revocation test in
/// this suite. What the hint actually buys is one avoided lookup on the common (correct) hint, so
/// the ORDER of the lookups is the behaviour, and the order is what is asserted.
#[tokio::test]
async fn the_token_type_hint_decides_which_lookup_runs_first() {
    let clock = ManualClock::at_epoch();
    let srv = fault_server_with(clock, vec![confidential_client()]).await;
    let token = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-1",
    )
    .await;
    let refresh = token.refresh_token.clone().expect("chain must start");

    // Hint says access token, and it is one: the access lookup runs first and answers, so the
    // refresh store is never consulted at all.
    srv.store().take_lookup_order();
    srv.revoke(
        &ClientId::new("confidential-app"),
        Some(CONFIDENTIAL_SECRET),
        &token.access_token,
        Some(TokenTypeHint::AccessToken),
    )
    .await
    .unwrap();
    assert_eq!(
        srv.store().take_lookup_order(),
        vec!["get_token"],
        "a correct access_token hint must consult the access store first, and then stop"
    );

    // No hint: the refresh store is consulted first (this crate's documented default order).
    srv.store().take_lookup_order();
    srv.revoke(
        &ClientId::new("confidential-app"),
        Some(CONFIDENTIAL_SECRET),
        &refresh,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        srv.store().take_lookup_order(),
        vec!["get_refresh_token"],
        "with no hint the refresh store is consulted first"
    );

    // A WRONG hint must not stop the search: section 2.1 requires the server to keep looking, so
    // both stores are consulted, hinted one first, and the token is still revoked.
    let second = mint_code_token(
        &srv,
        "confidential-app",
        Some(CONFIDENTIAL_SECRET),
        CONFIDENTIAL_REDIRECT,
        "read",
        "user-2",
    )
    .await;
    let second_refresh = second.refresh_token.expect("chain must start");
    srv.store().take_lookup_order();
    srv.revoke(
        &ClientId::new("confidential-app"),
        Some(CONFIDENTIAL_SECRET),
        &second_refresh,
        Some(TokenTypeHint::AccessToken),
    )
    .await
    .unwrap();
    assert_eq!(
        srv.store().take_lookup_order(),
        vec!["get_token", "get_refresh_token"],
        "a wrong hint costs one extra lookup and nothing else: the search must continue"
    );
    assert!(
        srv.store()
            .get_refresh_token(&second_refresh)
            .await
            .unwrap()
            .is_none(),
        "a wrong hint must not stop the token from being revoked"
    );
}

// -------------------------------------------------------------- family revocation, counted

/// RFC 9700 section 4.14.2's remedy revokes "the tokens issued for that authorization grant", and
/// [`oauth_as::Storage::revoke_token_family`] reports HOW MANY records that was. The count is part
/// of the trait's contract (a host implementing this against a real database returns its own
/// affected-row count), and a host has no other way to log or alarm on the size of a compromise, so
/// it must be the real number rather than a plausible-looking one.
#[tokio::test]
async fn revoke_token_family_reports_the_number_of_records_it_removed() {
    let store = MemoryStorage::new();
    let now = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    let token = |name: &str, family: Option<&str>| IssuedToken {
        #[cfg(feature = "dpop")]
        jkt: None,
        #[cfg(feature = "mtls")]
        x5t_s256: None,
        resource: Vec::new(),
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        access_token: name.to_string(),
        client_id: ClientId::new("app"),
        subject: Some("user-1".to_string()),
        scope: ScopeSet::parse("read").unwrap(),
        issued_at: now,
        expires_at: now + Duration::from_secs(3600),
        family_id: family.map(str::to_string),
        #[cfg(feature = "consent")]
        authentication: None,
    };
    let refresh = |name: &str, family: &str| RefreshTokenRecord {
        #[cfg(feature = "dpop")]
        jkt: None,
        #[cfg(feature = "mtls")]
        x5t_s256: None,
        resource: Vec::new(),
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        refresh_token: name.to_string(),
        client_id: ClientId::new("app"),
        subject: Some("user-1".to_string()),
        scope: ScopeSet::parse("read").unwrap(),
        expires_at: None,
        family_id: family.to_string(),
        state: RefreshTokenState::Active,
        #[cfg(feature = "consent")]
        authentication: None,
    };

    // Three records in the doomed family (two access tokens minted along the chain, one refresh
    // link), and three that must be untouched: another family's pair, and a family-less token from
    // a client-credentials grant.
    store
        .put_token(token("at-1", Some("doomed")))
        .await
        .unwrap();
    store
        .put_token(token("at-2", Some("doomed")))
        .await
        .unwrap();
    store
        .put_refresh_token(refresh("rt-1", "doomed"))
        .await
        .unwrap();
    store
        .put_token(token("at-other", Some("other")))
        .await
        .unwrap();
    store
        .put_refresh_token(refresh("rt-other", "other"))
        .await
        .unwrap();
    store.put_token(token("at-none", None)).await.unwrap();

    assert_eq!(
        store.revoke_token_family("doomed").await.unwrap(),
        3,
        "the count must be the records actually removed, across BOTH token kinds"
    );

    for gone in ["at-1", "at-2"] {
        assert!(store.get_token(gone).await.unwrap().is_none());
    }
    assert!(store.get_refresh_token("rt-1").await.unwrap().is_none());
    for survivor in ["at-other", "at-none"] {
        assert!(
            store.get_token(survivor).await.unwrap().is_some(),
            "{survivor} belongs to a different grant and must be untouched"
        );
    }
    assert!(store.get_refresh_token("rt-other").await.unwrap().is_some());

    // Idempotent, and honest about having removed nothing: this runs on evidence of compromise and
    // must not be turned into an error (or a fictional count) by a concurrent revocation.
    assert_eq!(store.revoke_token_family("doomed").await.unwrap(), 0);
    assert_eq!(store.revoke_token_family("never-existed").await.unwrap(), 0);
}

/// A guard on the fixture the rest of this file leans on: `public_client` really is public, so the
/// confidential-only paths above are testing what they claim to be.
#[tokio::test]
async fn the_public_fixture_client_cannot_authenticate_with_a_secret() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![public_client()]).await;
    let err = srv
        .introspection_response(&ClientId::new("public-app"), Some("anything"), "some-token")
        .await
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidClient);
}
