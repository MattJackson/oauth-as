// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Bounded storage, and unique user codes.
//!
//! Two separate problems, both about a store that only ever grows or only ever overwrites.
//!
//! EVICTION. Consumed authorization codes are written back and kept on purpose, expired access
//! tokens are never deleted, and abandoned device grants sit until something asks for them. None
//! of that is wrong on its own, but the `Storage` trait offered no sweep operation, so a host
//! could not write a generic reaper even though `AuthorizationServer::store()` advertised the
//! seam "for host-side administration (listing, sweeping)". Meanwhile RFC 8628 section 3.1 lets
//! any client that may use the device grant allocate a grant per request, so the growth is
//! attacker-paced, not user-paced.
//!
//! UNIQUENESS. RFC 8628 section 6.1 sizes the user code for a human to type, which is exactly why
//! it is short enough to collide. The birthday bound over the 20-symbol alphabet at the default 8
//! symbols is in the low hundreds of thousands of concurrent live grants, and a collision that is
//! silently accepted does not merely lose one grant: it corrupts the index for both, because
//! taking the older grant removes an index entry that now names the newer one.
//!
//! Section 6.1 also states plainly that the code's entropy is adequate ONLY in combination with
//! rate limiting of code entry, which this library does not and cannot do.

mod support;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::{
    AuthorizationCodeRecord, AuthorizationCodeState, AuthorizationServer, ClientId,
    CodeChallengeMethod, DeviceGrant, DeviceGrantState, ErrorCode, IssuedToken, MemoryStorage,
    RefreshTokenRecord, RefreshTokenState, ScopeSet, ServerConfig, Storage,
};
use support::{device_only_client, fault_server_with, ManualClock};

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn scope() -> ScopeSet {
    ScopeSet::parse("read").unwrap()
}

fn device_grant(device_code: &str, user_code: &str, expires_at: SystemTime) -> DeviceGrant {
    DeviceGrant {
        device_code: device_code.to_string(),
        user_code: user_code.to_string(),
        client_id: ClientId::new("some-client"),
        scope: scope(),
        state: DeviceGrantState::Pending,
        created_at: now(),
        expires_at,
        interval: Duration::from_secs(5),
        last_poll_at: None,
    }
}

fn authorization_code(code: &str, expires_at: SystemTime) -> AuthorizationCodeRecord {
    AuthorizationCodeRecord {
        code: code.to_string(),
        client_id: ClientId::new("some-client"),
        redirect_uri: "https://app.example/cb".into(),
        scope: scope(),
        subject: "user-1".into(),
        code_challenge: "x".repeat(43),
        code_challenge_method: CodeChallengeMethod::S256,
        expires_at,
        state: AuthorizationCodeState::Consumed {
            access_token: "at".into(),
            refresh_token: None,
        },
    }
}

fn access_token(token: &str, expires_at: SystemTime) -> IssuedToken {
    IssuedToken {
        access_token: token.to_string(),
        client_id: ClientId::new("some-client"),
        subject: Some("user-1".into()),
        scope: scope(),
        issued_at: now(),
        expires_at,
        family_id: None,
    }
}

fn refresh_token(token: &str, expires_at: Option<SystemTime>) -> RefreshTokenRecord {
    RefreshTokenRecord {
        refresh_token: token.to_string(),
        client_id: ClientId::new("some-client"),
        subject: Some("user-1".into()),
        scope: scope(),
        expires_at,
        family_id: "family-1".into(),
        state: RefreshTokenState::Active,
    }
}

/// The eviction seam a host needs in order to keep the store bounded. Without it, every record
/// this crate writes is the host's problem forever, and a host with a shared store has no legal
/// way to tell which rows are dead: the expiry rules live here, not there.
#[tokio::test]
async fn sweep_expired_removes_exactly_the_dead_records() {
    let store = MemoryStorage::new();
    let dead = now();
    let live = now() + Duration::from_secs(600);

    store
        .put_device_grant(device_grant("dc-dead", "AAAA-AAAA", dead))
        .await
        .unwrap();
    store
        .put_device_grant(device_grant("dc-live", "BBBB-BBBB", live))
        .await
        .unwrap();
    store
        .put_authorization_code(authorization_code("code-dead", dead))
        .await
        .unwrap();
    store
        .put_authorization_code(authorization_code("code-live", live))
        .await
        .unwrap();
    store
        .put_token(access_token("at-dead", dead))
        .await
        .unwrap();
    store
        .put_token(access_token("at-live", live))
        .await
        .unwrap();
    store
        .put_refresh_token(refresh_token("rt-dead", Some(dead)))
        .await
        .unwrap();
    store
        .put_refresh_token(refresh_token("rt-live", Some(live)))
        .await
        .unwrap();
    // A chain with no absolute expiry is not dead and must survive any sweep.
    store
        .put_refresh_token(refresh_token("rt-forever", None))
        .await
        .unwrap();

    let removed = store.sweep_expired(now()).await.unwrap();
    assert_eq!(
        removed, 4,
        "exactly the four records at or past their expiry instant are dead"
    );

    assert!(store.get_device_grant("dc-dead").await.unwrap().is_none());
    assert!(store.get_device_grant("dc-live").await.unwrap().is_some());
    assert!(store
        .take_authorization_code("code-dead")
        .await
        .unwrap()
        .is_none());
    assert!(store
        .take_authorization_code("code-live")
        .await
        .unwrap()
        .is_some());
    assert!(store.get_token("at-dead").await.unwrap().is_none());
    assert!(store.get_token("at-live").await.unwrap().is_some());
    assert!(store.get_refresh_token("rt-dead").await.unwrap().is_none());
    assert!(store.get_refresh_token("rt-live").await.unwrap().is_some());
    assert!(store
        .get_refresh_token("rt-forever")
        .await
        .unwrap()
        .is_some());

    // The user-code index must go with the grant, or the sweep leaks the very entries it was
    // meant to reclaim (and leaves a lookup pointing at nothing).
    assert!(store
        .find_device_grant_by_user_code("AAAAAAAA")
        .await
        .unwrap()
        .is_none());
    assert!(store
        .find_device_grant_by_user_code("BBBBBBBB")
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        store.sweep_expired(now()).await.unwrap(),
        0,
        "a second sweep at the same instant has nothing left to do"
    );
}

/// RFC 8628 section 6.1: the user code is the credential a human types, so two live grants sharing
/// one is not a display nuisance, it is two different devices answering to one code. The store
/// must refuse the second write rather than silently repoint the index, because the losing grant
/// then becomes unapprovable AND takes the winner's index entry with it when it is reaped.
#[tokio::test]
async fn put_device_grant_refuses_a_user_code_owned_by_another_device_code() {
    let store = MemoryStorage::new();
    let live = now() + Duration::from_secs(600);
    store
        .put_device_grant(device_grant("dc-1", "AAAA-AAAA", live))
        .await
        .unwrap();

    store
        .put_device_grant(device_grant("dc-2", "AAAA-AAAA", live))
        .await
        .expect_err("a user code already indexed for a different device_code must be refused");

    // The first grant is untouched: a refused write must not be a partial write.
    let found = store
        .find_device_grant_by_user_code("AAAAAAAA")
        .await
        .unwrap()
        .expect("the original grant still owns the code");
    assert_eq!(found.device_code, "dc-1");
    assert!(
        store.get_device_grant("dc-2").await.unwrap().is_none(),
        "the refused grant must not have been stored under its device_code either"
    );

    // Re-putting the SAME device_code with the same user code is an upsert, not a collision:
    // that is how the server records a state transition.
    store
        .put_device_grant(device_grant("dc-1", "AAAA-AAAA", live))
        .await
        .expect("upserting the same grant must still work");
}

/// If the store refuses a collision, the server must not turn that into a 500-shaped surprise on
/// the first unlucky draw: it retries, and only a run of collisions that cannot plausibly be
/// chance becomes `server_error` (RFC 6749 section 5.2). Here every lookup reports a hit, so the
/// bounded retry loop must terminate and report rather than spin forever.
#[tokio::test]
async fn device_authorization_gives_up_cleanly_when_user_codes_keep_colliding() {
    let clock = ManualClock::at_epoch();
    let srv = fault_server_with(clock, vec![device_only_client()]).await;
    srv.store()
        .collide_user_codes
        .store(true, std::sync::atomic::Ordering::SeqCst);

    let err = srv
        .device_authorization(
            &ClientId::new("device-only"),
            Some("s3cret-value-for-tests"),
            None,
        )
        .await
        .expect_err("an endless run of collisions must not be answered with a duplicate code");
    assert_eq!(err.error, ErrorCode::ServerError);
}

/// A user code shorter than the RFC 8628 section 6.1 example shape is not a tuning choice, it is a
/// broken deployment: 4 symbols is about 160,000 possibilities, guessable in seconds against an
/// endpoint the library cannot rate limit, and 0 symbols makes every grant collide on the empty
/// string. The floor is enforced where the code is generated, so a host cannot configure its way
/// under it.
#[tokio::test]
async fn user_code_length_is_clamped_to_the_documented_floor() {
    for configured in [0usize, 1, 4, 7] {
        let clock = ManualClock::at_epoch();
        let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
        cfg.user_code_length = configured;
        cfg.include_verification_uri_complete = false;
        let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), clock);
        srv.register_client(device_only_client()).await.unwrap();

        let resp = srv
            .device_authorization(
                &ClientId::new("device-only"),
                Some("s3cret-value-for-tests"),
                None,
            )
            .await
            .unwrap();
        let symbols = resp.user_code.chars().filter(|c| *c != '-').count();
        assert!(
            symbols >= 8,
            "user_code_length {configured} must be raised to the floor, got {symbols} symbols \
             in {}",
            resp.user_code
        );
    }
}
