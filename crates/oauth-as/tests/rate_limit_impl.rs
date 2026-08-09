// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The SHIPPED rate limiter ([`oauth_as::FixedWindowRateLimiter`]) under the attack it exists to
//! stop, driven through the real server rather than through the seam.
//!
//! # The attack
//!
//! RFC 8628 section 5.1 makes the device user code's entropy adequate only IN COMBINATION WITH
//! rate limiting of user code entry. This crate's default code is
//! [`oauth_as::MIN_USER_CODE_LENGTH`] symbols over a 20-symbol alphabet, about 2^34.6, and
//! [`oauth_as::AuthorizationServer::approve_device`] answers "is this a live code" for anyone who
//! asks. Unthrottled, an attacker sprays codes at the verification endpoint; a hit binds a
//! STRANGER'S DEVICE TO THE ATTACKER'S ACCOUNT, because the attacker is the one supplying the
//! `subject`. The pool of concurrently live grants multiplies their odds: they do not need to hit
//! one particular code, only SOME live code.
//!
//! `tests/rate_limit.rs` pins that the SEAM exists and that the server asks it. This file pins that
//! the crate SHIPS something to put in the seam, that its defaults actually refuse the spray, and
//! that a legitimate user is not locked out forever by it.
//!
//! # Why this file carries its own fixtures
//!
//! It deliberately does not use `tests/support`. The gate here is about what a host gets from
//! `FixedWindowRateLimiter` alone, so the server under test is built from nothing but this crate's
//! public API, exactly as a host would build it.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::{
    Attempt, AttemptOutcome, AuthorizationServer, Client, ClientAuth, ClientId, Clock,
    DeviceApprovalError, ErrorCode, FixedWindowRateLimiter, GrantType, MemoryStorage,
    RateLimitConfig, RateLimitDecision, RateLimiter, ScopeSet, ServerConfig, TokenRequest,
};

const DEVICE_SECRET: &str = "s3cret-value-for-tests";
const OTHER_SECRET: &str = "other-secret-for-tests";

/// A clock that never moves, so nothing in these tests expires while the WALL clock the limiter
/// reads is advancing. The two are deliberately independent: the limiter's window is real elapsed
/// time (a throttle a host could fast-forward by lying about the time would not be a throttle),
/// while grant expiry is the server's own injected clock.
#[derive(Clone)]
struct FrozenClock;

impl Clock for FrozenClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }
}

fn device_client() -> Client {
    Client {
        client_id: ClientId::new("device-only"),
        auth: ClientAuth::ConfidentialSecret {
            secret: DEVICE_SECRET.into(),
        },
        grant_types: vec![GrantType::DeviceCode],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

fn other_client() -> Client {
    Client {
        client_id: ClientId::new("other-app"),
        auth: ClientAuth::ConfidentialSecret {
            secret: OTHER_SECRET.into(),
        },
        grant_types: vec![GrantType::ClientCredentials],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

/// A limiter shared between the test and the server. `Box<dyn RateLimiter>` moves ownership into
/// the server, so a test that wants to inspect the limiter afterwards needs a handle to it; this
/// is the same shape `tests/rate_limit.rs` uses for its own fakes.
struct Shared(Arc<FixedWindowRateLimiter>);

impl RateLimiter for Shared {
    fn check(&self, attempt: Attempt<'_>) -> RateLimitDecision {
        self.0.check(attempt)
    }

    fn record(&self, attempt: Attempt<'_>, outcome: AttemptOutcome) {
        self.0.record(attempt, outcome);
    }
}

async fn server_with(
    limiter: Arc<FixedWindowRateLimiter>,
) -> AuthorizationServer<MemoryStorage, FrozenClock> {
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), FrozenClock)
        .with_rate_limiter(Box::new(Shared(limiter)));
    srv.register_client(device_client()).await.unwrap();
    srv.register_client(other_client()).await.unwrap();
    srv
}

/// Spray wrong codes until the limiter refuses, and answer how many got through first.
async fn wrong_codes_accepted(
    srv: &AuthorizationServer<MemoryStorage, FrozenClock>,
    prefix: &str,
    ceiling: usize,
) -> usize {
    let mut allowed = 0;
    for i in 0..ceiling {
        // Guesses that are certainly wrong: the crate's user code alphabet is
        // `BCDFGHJKLMNPQRSTVWXZ`, so a code containing `A` or a digit can never be a live one.
        let guess = format!("{prefix}{:04}", i % 10_000);
        match srv.approve_device(&guess, "attacker").await {
            Err(DeviceApprovalError::RateLimited) => return allowed,
            Err(DeviceApprovalError::UnknownUserCode) => allowed += 1,
            other => panic!("guess {i} produced an unexpected answer: {other:?}"),
        }
    }
    panic!("the limiter never refused: {allowed} wrong codes went through unthrottled");
}

/// THE GATE. A brute-force loop against `approve_device` must be REFUSED once the window's budget
/// is spent, and must RESUME once the window rolls.
///
/// The window is shortened to 200ms so the roll is observable without a 60 second test; the budget
/// is left at the shipped DEFAULT, because the number a host inherits by writing one line is
/// exactly the number this gate has to be about. With the default weights a wrong code costs
/// `1 + 9 = 10` against a 200-unit budget, so 20 wrong codes fit in a window and the twenty-first
/// is refused.
///
/// A fixed window anchored at construction makes the roll deterministic rather than a race:
/// sleeping longer than one whole window always crosses at least one boundary, whatever phase the
/// test started in.
#[tokio::test]
async fn a_brute_force_run_at_approve_device_is_refused_and_then_resumes() {
    let limiter = Arc::new(FixedWindowRateLimiter::with_config(
        RateLimitConfig::default().with_window(Duration::from_millis(200)),
    ));
    let srv = server_with(limiter.clone()).await;

    assert_eq!(
        wrong_codes_accepted(&srv, "AAAA", 200).await,
        20,
        "an unthrottled verification endpoint is an RFC 8628 section 5.1 defect: the shipped \
         limiter must refuse the spray after the default budget of 20 wrong codes per window"
    );

    // Still refused inside the same window, so the refusal is a budget and not a hiccup.
    assert_eq!(
        srv.approve_device("AAAA9999", "attacker").await,
        Err(DeviceApprovalError::RateLimited),
        "the budget is spent for the rest of the window"
    );

    // The window rolls, and the endpoint is usable again: a throttle that never lifts is an
    // outage, not a defence. A legitimate user typing a correct code now must get through.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let auth = srv
        .device_authorization(&ClientId::new("device-only"), Some(DEVICE_SECRET), None)
        .await
        .expect("the device's own client authentication has its own, separate budget");
    srv.approve_device(&auth.user_code, "real-user")
        .await
        .expect("the window has rolled: a real user must be able to approve again");

    // And the approval is real: the device's poll now yields a token.
    let token = srv
        .token(TokenRequest::DeviceCode {
            client_id: ClientId::new("device-only"),
            client_secret: Some(DEVICE_SECRET.to_string()),
            device_code: auth.device_code,
        })
        .await
        .expect("an approved grant issues");
    assert!(!token.access_token.is_empty());
}

/// A hit on approve is the whole loss, so the guessing budget must be spent by FAILURES rather
/// than by traffic: a busy verification page full of people typing CORRECT codes must not throttle
/// itself into an outage at the same point an attacker gets stopped.
///
/// With the shipped weights a success costs 1 and a failure costs 10, so the same 200-unit budget
/// buys 200 correct entries or 20 wrong ones.
#[tokio::test]
async fn successful_entries_cost_far_less_budget_than_wrong_ones() {
    let limiter = Arc::new(FixedWindowRateLimiter::new());
    let srv = server_with(limiter.clone()).await;

    // Fifty legitimate activations, each approved with the code its own grant minted. Under a
    // traffic-counting limiter with a 20-attempt ceiling this would have been refused at 21.
    for _ in 0..50 {
        let auth = srv
            .device_authorization(&ClientId::new("device-only"), Some(DEVICE_SECRET), None)
            .await
            .unwrap();
        srv.approve_device(&auth.user_code, "real-user")
            .await
            .expect("a correct code must not be throttled by other correct codes");
    }

    // 200 - 50 = 150 units left, which is 15 more wrong codes and no more.
    assert_eq!(
        wrong_codes_accepted(&srv, "BBBB", 200).await,
        15,
        "failures must be charged ten times what successes are"
    );
}

/// RFC 9700 section 4.13, credential stuffing at the token endpoint. The client-authentication
/// budget is keyed PER `client_id` (RFC 6749 section 2.2 makes the identifier explicitly not a
/// secret, so a limiter may key on it), so one client being stuffed must not lock every other
/// client out of the token endpoint.
#[tokio::test]
async fn client_authentication_is_budgeted_per_client() {
    let cfg = RateLimitConfig::default().with_client_authentication_budget(20, 4);
    let limiter = Arc::new(FixedWindowRateLimiter::with_config(cfg));
    let srv = server_with(limiter.clone()).await;

    // 20 units, 1 + 4 per failure: four wrong secrets for `other-app` exhaust it.
    for _ in 0..4 {
        let err = srv
            .token(TokenRequest::ClientCredentials {
                client_id: ClientId::new("other-app"),
                client_secret: Some("wrong".to_string()),
                scope: None,
            })
            .await
            .expect_err("a wrong secret is refused");
        assert_eq!(err.error, ErrorCode::InvalidClient);
    }

    // Exhausted: the throttle now refuses BEFORE the store is touched, and it says the same
    // `invalid_client` a wrong secret says, so it is not an oracle telling the attacker they had
    // found a live registration.
    let err = srv
        .token(TokenRequest::ClientCredentials {
            client_id: ClientId::new("other-app"),
            client_secret: Some(OTHER_SECRET.to_string()),
            scope: None,
        })
        .await
        .expect_err("the throttled client is refused even with the RIGHT secret");
    assert_eq!(err.error, ErrorCode::InvalidClient);

    // A DIFFERENT client is untouched: its budget is its own.
    srv.device_authorization(&ClientId::new("device-only"), Some(DEVICE_SECRET), None)
        .await
        .expect("another client's stuffing must not lock this one out");
}

/// The tracked-client map is the one thing here an attacker can grow, since `client_id` is
/// whatever they send. It is CAPPED: past the cap, unrecognised identifiers share one overflow
/// counter rather than each getting a fresh entry, so a spray of a million distinct identifiers
/// costs bounded memory and is throttled harder, not less.
#[tokio::test]
async fn a_spray_of_unknown_client_ids_cannot_grow_the_limiter_without_bound() {
    let cfg = RateLimitConfig::default()
        .with_max_tracked_clients(8)
        // A budget wide enough that the spray is not stopped by the throttle before it can test
        // the bound: this gate is about MEMORY, not about refusal.
        .with_client_authentication_budget(u64::MAX, 0);
    let limiter = Arc::new(FixedWindowRateLimiter::with_config(cfg));
    let srv = server_with(limiter.clone()).await;

    for i in 0..5_000 {
        let _ = srv
            .token(TokenRequest::ClientCredentials {
                client_id: ClientId::new(format!("sprayed-{i}")),
                client_secret: Some("x".to_string()),
                scope: None,
            })
            .await;
    }

    assert!(
        limiter.tracked_clients() <= 8,
        "the limiter must not grow a map keyed on attacker-supplied identifiers: {}",
        limiter.tracked_clients()
    );
}

/// A counter that never resets is a permanent outage after the first busy minute, and one that
/// resets on every call is not a limiter at all. This pins the window's shape end to end: the
/// budget is per window, and a fresh window is a fresh budget, repeatedly.
#[tokio::test]
async fn the_budget_is_per_window_and_not_cumulative() {
    let limiter = Arc::new(FixedWindowRateLimiter::with_config(
        RateLimitConfig::default()
            .with_window(Duration::from_millis(150))
            .with_device_user_code_budget(10, 4),
    ));
    let srv = server_with(limiter.clone()).await;

    // 10 units, 1 + 4 per failure: two wrong codes per window, in every window.
    assert_eq!(wrong_codes_accepted(&srv, "CCCC", 64).await, 2, "window 1");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(wrong_codes_accepted(&srv, "DDDD", 64).await, 2, "window 2");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(wrong_codes_accepted(&srv, "FFFF", 64).await, 2, "window 3");
}
