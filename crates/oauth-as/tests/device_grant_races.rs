// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! LOST UPDATES on the RFC 8628 device grant, reproduced as an actual interleaving.
//!
//! Three actors touch one `DeviceGrant` record: the DEVICE polling the token endpoint, and the
//! USER approving or denying at the host's verification UI. Every one of those paths was a
//! read-modify-write with a blind `put_device_grant` at the end, so whichever wrote last won and
//! the other party's change was reverted with no error anywhere.
//!
//! The dangerous direction is not symmetric. A lost poll timestamp costs one extra `slow_down`.
//! A lost DECISION is a user's "no" being thrown away, or a user's "yes" being thrown away and the
//! device hanging. That asymmetry is what these tests pin.
//!
//! WHY THIS IS AN INTERLEAVE AND NOT TWO SEQUENTIAL CALLS. Calling `device_token` and then
//! `approve_device` proves nothing: the bug only exists in the window BETWEEN one caller's read
//! and its write. The store below opens that window on demand: the first gated read parks inside
//! the store until the test releases it, so the second actor's whole read-modify-write completes
//! against the real store while the first actor still holds a stale snapshot. Both futures run on
//! one `current_thread` runtime and the handoff is a counter plus `yield_now`, so there is no
//! sleeping, no thread scheduling and no flake: the interleaving is the same on every run.

mod support;

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::{
    AuthorizationCodeRecord, AuthorizationServer, Client, ClientAuth, ClientId, DeviceGrant,
    DeviceGrantState, ErrorCode, GrantType, IssuedToken, MemoryStorage, RefreshTokenRecord,
    ScopeSet, ServerConfig, Storage, StorageError, TokenRequest,
};

use support::ManualClock;

/// The handoff between the two interleaved tasks. `phase` is the whole of the protocol:
///
/// - 0: nobody has parked yet.
/// - 1: the gated reader is parked inside the store, holding a snapshot that is about to go stale.
/// - 2: the other actor has finished its own read-modify-write; the parked reader may proceed.
struct Gate {
    phase: AtomicU8,
    armed: AtomicBool,
}

impl Gate {
    /// DISARMED at construction, and armed by hand once the fixture is in place. Setting a grant up
    /// goes through the store too (`device_authorization` asks the user-code index whether the code
    /// it generated is free), so a gate that armed itself would park the fixture rather than the
    /// call under test, with nobody left to release it.
    fn new() -> Self {
        Gate {
            phase: AtomicU8::new(0),
            armed: AtomicBool::new(false),
        }
    }

    /// Arm for exactly one read, from a clean phase.
    fn arm(&self) {
        self.phase.store(0, Ordering::SeqCst);
        self.armed.store(true, Ordering::SeqCst);
    }
}

/// Park the caller inside the store on the FIRST gated read only, and only until phase 2.
///
/// `yield_now` rather than a sleep or a channel: the suite's tokio has `rt` and `macros` and
/// nothing else, and a yield loop on a `current_thread` runtime is a deterministic handoff rather
/// than a timing hope.
async fn park(gate: &Gate) {
    if !gate.armed.swap(false, Ordering::SeqCst) {
        return;
    }
    gate.phase.store(1, Ordering::SeqCst);
    while gate.phase.load(Ordering::SeqCst) != 2 {
        tokio::task::yield_now().await;
    }
}

/// Wait for the gated reader to be parked, so the second actor runs strictly inside the window.
async fn await_parked(gate: &Gate) {
    while gate.phase.load(Ordering::SeqCst) != 1 {
        tokio::task::yield_now().await;
    }
}

/// Which read the gate is attached to. The poll path reads by DEVICE code; the verification UI
/// reads by USER code, so the two races need the window opened in different places.
#[derive(Clone, Copy, PartialEq, Eq)]
enum GateOn {
    DeviceCode,
    UserCode,
}

/// A [`Storage`] that delegates everything to [`MemoryStorage`] and parks exactly one read.
struct RacyStorage {
    inner: MemoryStorage,
    gate: Arc<Gate>,
    on: GateOn,
}

impl Storage for RacyStorage {
    async fn get_client(&self, client_id: &ClientId) -> Result<Option<Arc<Client>>, StorageError> {
        self.inner.get_client(client_id).await
    }

    async fn put_client(&self, client: Client) -> Result<(), StorageError> {
        self.inner.put_client(client).await
    }

    async fn compare_and_swap_client(
        &self,
        expected: &Client,
        updated: Client,
    ) -> Result<bool, StorageError> {
        self.inner.compare_and_swap_client(expected, updated).await
    }

    async fn delete_client(
        &self,
        client_id: &ClientId,
        window: oauth_as::store::RevocationWindow,
    ) -> Result<bool, StorageError> {
        self.inner.delete_client(client_id, window).await
    }

    async fn put_device_grant(&self, grant: DeviceGrant) -> Result<(), StorageError> {
        self.inner.put_device_grant(grant).await
    }

    async fn get_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        let found = self.inner.get_device_grant(device_code).await;
        if self.on == GateOn::DeviceCode {
            park(&self.gate).await;
        }
        found
    }

    async fn find_device_grant_by_user_code(
        &self,
        normalized_user_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        let found = self
            .inner
            .find_device_grant_by_user_code(normalized_user_code)
            .await;
        if self.on == GateOn::UserCode {
            park(&self.gate).await;
        }
        found
    }

    async fn take_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        self.inner.take_device_grant(device_code).await
    }

    // The compare-and-swap the fix relies on MUST reach the atomic implementation underneath
    // rather than the trait's read-then-write default, or this wrapper would reintroduce exactly
    // the race it exists to demonstrate.
    async fn compare_and_swap_device_grant(
        &self,
        expected: &DeviceGrantState,
        updated: DeviceGrant,
    ) -> Result<bool, StorageError> {
        self.inner
            .compare_and_swap_device_grant(expected, updated)
            .await
    }

    async fn put_authorization_code(
        &self,
        record: AuthorizationCodeRecord,
    ) -> Result<(), StorageError> {
        self.inner.put_authorization_code(record).await
    }

    async fn compare_and_swap_authorization_code(
        &self,
        expected: &oauth_as::authorization::AuthorizationCodeState,
        updated: AuthorizationCodeRecord,
    ) -> Result<bool, StorageError> {
        self.inner
            .compare_and_swap_authorization_code(expected, updated)
            .await
    }

    async fn take_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCodeRecord>, StorageError> {
        self.inner.take_authorization_code(code).await
    }

    #[cfg(feature = "par")]
    async fn put_pushed_authorization_request(
        &self,
        record: oauth_as::PushedAuthorizationRequest,
    ) -> Result<oauth_as::store::WriteOutcome, StorageError> {
        self.inner.put_pushed_authorization_request(record).await
    }

    #[cfg(feature = "par")]
    async fn take_pushed_authorization_request(
        &self,
        request_uri: &str,
    ) -> Result<Option<oauth_as::PushedAuthorizationRequest>, StorageError> {
        self.inner
            .take_pushed_authorization_request(request_uri)
            .await
    }

    async fn put_token(
        &self,
        token: IssuedToken,
    ) -> Result<oauth_as::store::WriteOutcome, StorageError> {
        self.inner.put_token(token).await
    }

    async fn get_token(
        &self,
        access_token: &str,
    ) -> Result<Option<Arc<IssuedToken>>, StorageError> {
        self.inner.get_token(access_token).await
    }

    async fn delete_token(&self, access_token: &str) -> Result<(), StorageError> {
        self.inner.delete_token(access_token).await
    }

    async fn put_refresh_token(
        &self,
        record: RefreshTokenRecord,
    ) -> Result<oauth_as::store::WriteOutcome, StorageError> {
        self.inner.put_refresh_token(record).await
    }

    async fn get_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<Arc<RefreshTokenRecord>>, StorageError> {
        self.inner.get_refresh_token(refresh_token).await
    }

    async fn take_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshTokenRecord>, StorageError> {
        self.inner.take_refresh_token(refresh_token).await
    }

    async fn revoke_token_family(
        &self,
        family_id: &str,
        window: oauth_as::store::RevocationWindow,
    ) -> Result<u64, StorageError> {
        self.inner.revoke_token_family(family_id, window).await
    }

    #[cfg(feature = "consent")]
    async fn put_consent(&self, record: oauth_as::ConsentRecord) -> Result<(), StorageError> {
        self.inner.put_consent(record).await
    }

    #[cfg(feature = "consent")]
    async fn get_consent(
        &self,
        consent_id: &str,
    ) -> Result<Option<Arc<oauth_as::ConsentRecord>>, StorageError> {
        self.inner.get_consent(consent_id).await
    }

    #[cfg(feature = "consent")]
    async fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> Result<Option<Arc<oauth_as::ConsentRecord>>, StorageError> {
        self.inner.find_consent(client_id, subject).await
    }

    #[cfg(feature = "consent")]
    async fn consents_for_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<Arc<oauth_as::ConsentRecord>>, StorageError> {
        self.inner.consents_for_subject(subject).await
    }

    #[cfg(feature = "consent")]
    async fn compare_and_swap_consent(
        &self,
        expected: Option<&oauth_as::ConsentRecord>,
        updated: oauth_as::ConsentRecord,
    ) -> Result<bool, StorageError> {
        self.inner.compare_and_swap_consent(expected, updated).await
    }

    #[cfg(feature = "consent")]
    async fn revoke_consent(
        &self,
        consent_id: &str,
        window: oauth_as::store::RevocationWindow,
    ) -> Result<u64, StorageError> {
        self.inner.revoke_consent(consent_id, window).await
    }

    #[cfg(any(feature = "client-assertion", feature = "dpop"))]
    async fn claim_replay_id(
        &self,
        id: &str,
        expires_at: SystemTime,
    ) -> Result<bool, StorageError> {
        self.inner.claim_replay_id(id, expires_at).await
    }

    async fn sweep_expired(&self, now: SystemTime) -> Result<u64, StorageError> {
        self.inner.sweep_expired(now).await
    }
}

fn device_client() -> Client {
    Client {
        client_id: ClientId::new("racy-device"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::DeviceCode],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

async fn racy_server(
    gate: Arc<Gate>,
    on: GateOn,
) -> (AuthorizationServer<RacyStorage, ManualClock>, ManualClock) {
    let clock = ManualClock::at_epoch();
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let srv = AuthorizationServer::with_clock(
        cfg,
        RacyStorage {
            inner: MemoryStorage::new(),
            gate,
            on,
        },
        clock.clone(),
    );
    srv.register_client(device_client()).await.unwrap();
    (srv, clock)
}

/// The state a grant is actually in, read straight out of the store.
async fn stored_state<S: Storage>(
    srv: &AuthorizationServer<S, ManualClock>,
    device_code: &str,
) -> Option<DeviceGrantState> {
    srv.store()
        .get_device_grant(device_code)
        .await
        .unwrap()
        .map(|g| g.state)
}

/// THE ATTACK, and the worst of the three: a poll that started while the grant was pending lands
/// its write AFTER the user has said NO, and puts the grant back to `Pending`. The refusal the
/// user gave is gone, the verification UI reported success, and the next poll is told to keep
/// waiting: the device goes on to be approved by whoever gets to the code next.
#[tokio::test]
async fn a_poll_must_not_revert_a_denial_it_raced() {
    let gate = Arc::new(Gate::new());
    let (srv, _clock) = racy_server(gate.clone(), GateOn::DeviceCode).await;

    let authorized = srv
        .device_authorization(&ClientId::new("racy-device"), None, None)
        .await
        .unwrap();
    let device_code = authorized.device_code.clone();
    let user_code = authorized.user_code.clone();
    gate.arm();

    // The poll: parks inside `get_device_grant` holding a `Pending` snapshot.
    let poll = async {
        srv.token(TokenRequest::DeviceCode {
            client_id: ClientId::new("racy-device"),
            client_secret: None,
            device_code: device_code.clone(),
        })
        .await
    };
    // The user: denies, entirely inside the poll's read-to-write window.
    let user = async {
        await_parked(&gate).await;
        let outcome = srv.deny_device(&user_code).await;
        gate.phase.store(2, Ordering::SeqCst);
        outcome
    };

    let (poll_outcome, deny_outcome) = tokio::join!(poll, user);
    deny_outcome.expect("the user's refusal must be recorded");
    assert_eq!(
        poll_outcome.unwrap_err().error,
        ErrorCode::AuthorizationPending,
        "the poll read a pending grant, so pending is the honest answer to it"
    );

    assert_eq!(
        stored_state(&srv, &device_code).await,
        Some(DeviceGrantState::Denied),
        "a poll must never write over a decision: the user said no and it has to stay no"
    );
}

/// The same window, the other decision: an approval the user really gave is reverted by a poll
/// that raced it, so the device hangs and the user is asked again for something they already did.
#[tokio::test]
async fn a_poll_must_not_revert_an_approval_it_raced() {
    let gate = Arc::new(Gate::new());
    let (srv, _clock) = racy_server(gate.clone(), GateOn::DeviceCode).await;

    let authorized = srv
        .device_authorization(&ClientId::new("racy-device"), None, None)
        .await
        .unwrap();
    let device_code = authorized.device_code.clone();
    let user_code = authorized.user_code.clone();
    gate.arm();

    let poll = async {
        srv.token(TokenRequest::DeviceCode {
            client_id: ClientId::new("racy-device"),
            client_secret: None,
            device_code: device_code.clone(),
        })
        .await
    };
    let user = async {
        await_parked(&gate).await;
        let outcome = srv.approve_device(&user_code, "alice").await;
        gate.phase.store(2, Ordering::SeqCst);
        outcome
    };

    let (poll_outcome, approve_outcome) = tokio::join!(poll, user);
    approve_outcome.expect("the user's approval must be recorded");
    assert!(
        poll_outcome.is_err(),
        "the racing poll read a pending grant"
    );

    assert_eq!(
        stored_state(&srv, &device_code).await,
        Some(DeviceGrantState::Approved {
            subject: "alice".to_string()
        }),
        "the approval must survive the poll that raced it"
    );
}

/// A SLOW_DOWN poll writes too: it bumps the interval and restamps the poll clock. That write went
/// through the same blind put, so a decision landing in ITS window was reverted as well, and this
/// one is reachable by a device that simply polls faster than it was told to.
#[tokio::test]
async fn a_slow_down_poll_must_not_revert_a_denial_it_raced() {
    let gate = Arc::new(Gate::new());
    let (srv, _clock) = racy_server(gate.clone(), GateOn::DeviceCode).await;

    let authorized = srv
        .device_authorization(&ClientId::new("racy-device"), None, None)
        .await
        .unwrap();
    let device_code = authorized.device_code.clone();
    let user_code = authorized.user_code.clone();
    gate.arm();

    // First poll: sets `last_poll_at`. Ungated, so the gate is armed only afterwards, for the
    // poll that actually takes the `slow_down` branch and its write.
    gate.armed.store(false, Ordering::SeqCst);
    let first = srv
        .token(TokenRequest::DeviceCode {
            client_id: ClientId::new("racy-device"),
            client_secret: None,
            device_code: device_code.clone(),
        })
        .await;
    assert_eq!(first.unwrap_err().error, ErrorCode::AuthorizationPending);
    gate.arm();

    // Second poll, immediately: too fast, so it takes the `slow_down` branch and its write.
    let poll = async {
        srv.token(TokenRequest::DeviceCode {
            client_id: ClientId::new("racy-device"),
            client_secret: None,
            device_code: device_code.clone(),
        })
        .await
    };
    let user = async {
        await_parked(&gate).await;
        let outcome = srv.deny_device(&user_code).await;
        gate.phase.store(2, Ordering::SeqCst);
        outcome
    };

    let (poll_outcome, deny_outcome) = tokio::join!(poll, user);
    deny_outcome.expect("the user's refusal must be recorded");
    assert_eq!(
        poll_outcome.unwrap_err().error,
        ErrorCode::SlowDown,
        "the pacing verdict was computed from a real read and still stands"
    );

    assert_eq!(
        stored_state(&srv, &device_code).await,
        Some(DeviceGrantState::Denied),
        "a slow_down write is still a write, and it must not carry a stale state with it"
    );
}

/// Two verification-UI actions on one user code. Without a compare-and-swap both read `Pending`,
/// both write, and the LAST one wins by accident. FIRST DECISION WINS is the rule, and the loser
/// gets the same `NotPending` it would have got had it arrived a moment later.
#[tokio::test]
async fn an_approval_must_not_overwrite_a_denial_that_landed_first() {
    let gate = Arc::new(Gate::new());
    let (srv, _clock) = racy_server(gate.clone(), GateOn::UserCode).await;

    let authorized = srv
        .device_authorization(&ClientId::new("racy-device"), None, None)
        .await
        .unwrap();
    let device_code = authorized.device_code.clone();
    let user_code = authorized.user_code.clone();
    gate.arm();

    // The approval parks holding a `Pending` snapshot.
    let approve = async { srv.approve_device(&user_code, "alice").await };
    // The denial runs to completion inside that window.
    let deny = async {
        await_parked(&gate).await;
        let outcome = srv.deny_device(&user_code).await;
        gate.phase.store(2, Ordering::SeqCst);
        outcome
    };

    let (approve_outcome, deny_outcome) = tokio::join!(approve, deny);
    deny_outcome.expect("the denial got there first and must stand");
    assert!(
        matches!(
            approve_outcome,
            Err(oauth_as::DeviceApprovalError::NotPending)
        ),
        "the losing decision must be told it lost, not silently applied: got {approve_outcome:?}"
    );

    assert_eq!(
        stored_state(&srv, &device_code).await,
        Some(DeviceGrantState::Denied),
        "first decision wins"
    );
}

/// The pacing write is allowed to be LOST, and this pins that the trade was made deliberately: a
/// poll whose compare-and-swap misses drops its own timestamp rather than writing over the
/// decision. Nothing in RFC 8628 is broken by that, because the next poll simply reads the
/// decision instead.
#[tokio::test]
async fn a_lost_poll_timestamp_is_the_acceptable_half_of_the_trade() {
    let gate = Arc::new(Gate::new());
    let (srv, clock) = racy_server(gate.clone(), GateOn::DeviceCode).await;

    let authorized = srv
        .device_authorization(&ClientId::new("racy-device"), None, None)
        .await
        .unwrap();
    let device_code = authorized.device_code.clone();
    let user_code = authorized.user_code.clone();
    gate.arm();

    let poll = async {
        srv.token(TokenRequest::DeviceCode {
            client_id: ClientId::new("racy-device"),
            client_secret: None,
            device_code: device_code.clone(),
        })
        .await
    };
    let user = async {
        await_parked(&gate).await;
        let outcome = srv.approve_device(&user_code, "alice").await;
        gate.phase.store(2, Ordering::SeqCst);
        outcome
    };
    let (_, approve_outcome) = tokio::join!(poll, user);
    approve_outcome.unwrap();

    // The next well-paced poll redeems the approval that survived.
    clock.advance(Duration::from_secs(10));
    let issued = srv
        .token(TokenRequest::DeviceCode {
            client_id: ClientId::new("racy-device"),
            client_secret: None,
            device_code: device_code.clone(),
        })
        .await
        .expect("the surviving approval must be redeemable");
    assert!(!issued.access_token.is_empty());
    assert_eq!(
        stored_state(&srv, &device_code).await,
        None,
        "redemption consumes the grant"
    );
}

/// The compare-and-swap primitive itself, on the reference store, without the server on top:
/// a swap against the wrong expectation must write NOTHING and say so.
#[tokio::test]
async fn compare_and_swap_refuses_a_stale_expectation_and_writes_nothing() {
    let store = MemoryStorage::new();
    let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let grant = DeviceGrant {
        device_code: "dc".to_string(),
        user_code: "WDJB-MJHT".to_string(),
        client_id: ClientId::new("racy-device"),
        scope: ScopeSet::parse("read").unwrap(),
        state: DeviceGrantState::Denied,
        created_at: now,
        expires_at: now + Duration::from_secs(600),
        interval: Duration::from_secs(5),
        last_poll_at: None,
    };
    store.put_device_grant(grant.clone()).await.unwrap();

    let mut stale = grant.clone();
    stale.state = DeviceGrantState::Approved {
        subject: "mallory".to_string(),
    };
    let swapped = store
        .compare_and_swap_device_grant(&DeviceGrantState::Pending, stale)
        .await
        .unwrap();
    assert!(!swapped, "the record is Denied, not Pending");
    assert_eq!(
        store.get_device_grant("dc").await.unwrap().unwrap().state,
        DeviceGrantState::Denied,
        "a refused swap must leave the record exactly as it was"
    );

    // And the matching expectation does write.
    let mut next = grant.clone();
    next.last_poll_at = Some(now);
    assert!(store
        .compare_and_swap_device_grant(&DeviceGrantState::Denied, next)
        .await
        .unwrap());
    assert_eq!(
        store
            .get_device_grant("dc")
            .await
            .unwrap()
            .unwrap()
            .last_poll_at,
        Some(now)
    );

    // A record that is GONE cannot be swapped back into existence: redemption already took it.
    store.take_device_grant("dc").await.unwrap();
    assert!(!store
        .compare_and_swap_device_grant(&DeviceGrantState::Denied, grant)
        .await
        .unwrap());
    assert!(store.get_device_grant("dc").await.unwrap().is_none());
}
