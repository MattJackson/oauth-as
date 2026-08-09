// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! THE test this crate exists to make possible: `take_*` and `claim_replay_id` raced from TWO
//! SEPARATE DATABASE CONNECTIONS, with exactly one winner.
//!
//! # Why this is not the same as the harness in `conformance.rs`
//!
//! The core crate's in-process harness says so itself, in its own module docs:
//!
//! > It cannot prove a store is atomic across PROCESSES or NODES, which is the deployment where
//! > the bug bites. Two racers inside one test process share whatever in-process lock the store
//! > holds; a mutex around a read-then-delete pair will pass this harness and still double-spend
//! > from two nodes.
//!
//! A real database gives back the thing that was missing: a second connection. Each racer here
//! holds its own `PostgresStorage` over its own pool of exactly ONE connection, so the two takes
//! provably travel over two different sessions and are resolved by the database, not by anything
//! in this process. That is as close to two nodes as a single test process can get, and it is the
//! configuration in which a read-then-delete actually double-spends.
//!
//! # Red before green, permanently
//!
//! A conformance test nobody has seen fail is a test nobody should trust, so every one of the
//! checks below is run TWICE: once against this crate's real implementation, which must never
//! double-spend, and once against the deliberately non-atomic `oauth_as_postgres::naive`, which
//! MUST. The red proof is not a commit that was reverted; it runs on every invocation, and if the
//! naive store ever stops double-spending, this file fails and says the detector has gone blind.

#![cfg(feature = "pg-integration")]

use std::sync::Arc;

use oauth_as::client::ClientId;
use oauth_as::scope::ScopeSet;
use oauth_as::store::Storage;
use oauth_as::token::{RefreshTokenRecord, RefreshTokenState};
use oauth_as_postgres::{naive, PostgresStorage};
use tokio::sync::Barrier;

mod support;

/// How many times each race is run. A race that loses is still a race: one clean round proves
/// nothing, and the naive store needs enough rounds that its double spend is a certainty rather
/// than a likelihood.
const ROUNDS: usize = 100;

/// Two stores that CANNOT share a connection: two pools, one connection each, eagerly opened.
///
/// Each test passes its OWN schema name, because these run on parallel threads in one binary and
/// they all count winners; sharing tables would make one test's rows another test's result.
async fn two_connections(schema: &str) -> (PostgresStorage, PostgresStorage) {
    support::fresh_schema(schema).await;
    let a = support::store(schema, 1).await;
    let b = support::store(schema, 1).await;
    (a, b)
}

fn refresh_record(token: &str) -> RefreshTokenRecord {
    RefreshTokenRecord {
        refresh_token: token.to_string(),
        client_id: ClientId::new("client-two-connection"),
        subject: Some("subject-two-connection".to_string()),
        scope: ScopeSet::parse("read write").expect("a valid RFC 6749 s3.3 scope"),
        resource: vec!["https://rs.example/".to_string()],
        #[cfg(feature = "rar")]
        authorization_details: Default::default(),
        expires_at: Some(
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2_000_000_000),
        ),
        #[cfg(feature = "dpop")]
        jkt: None,
        #[cfg(feature = "mtls")]
        x5t_s256: None,
        family_id: "family-two-connection".to_string(),
        state: RefreshTokenState::Active,
        #[cfg(feature = "consent")]
        authentication: None,
    }
}

/// One race over `take_refresh_token`, returning the number of callers handed the record.
async fn race_take(a: &PostgresStorage, b: &PostgresStorage, token: &str, atomic: bool) -> usize {
    let gate = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for store in [a.clone(), b.clone()] {
        let gate = Arc::clone(&gate);
        let token = token.to_string();
        handles.push(tokio::spawn(async move {
            gate.wait().await;
            if atomic {
                store
                    .take_refresh_token(&token)
                    .await
                    .expect("take_refresh_token")
                    .is_some()
            } else {
                naive::take_refresh_token_read_then_delete(store.pool(), &token)
                    .await
                    .expect("naive take")
                    .is_some()
            }
        }));
    }
    let mut winners = 0;
    for handle in handles {
        if handle.await.expect("racer did not panic") {
            winners += 1;
        }
    }
    winners
}

/// One race over `claim_replay_id`, returning the number of callers told they were FIRST.
async fn race_claim(a: &PostgresStorage, b: &PostgresStorage, id: &str, atomic: bool) -> usize {
    let deadline =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2_000_000_000);
    let gate = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for store in [a.clone(), b.clone()] {
        let gate = Arc::clone(&gate);
        let id = id.to_string();
        handles.push(tokio::spawn(async move {
            gate.wait().await;
            if atomic {
                store.claim_replay_id(&id, deadline).await.expect("claim")
            } else {
                naive::claim_replay_id_read_then_write(store.pool(), &id, deadline)
                    .await
                    .expect("naive claim")
            }
        }));
    }
    let mut winners = 0;
    for handle in handles {
        if handle.await.expect("racer did not panic") {
            winners += 1;
        }
    }
    winners
}

/// THE ONE. `take_refresh_token` from two separate connections: exactly one winner, every round.
///
/// Two winners is the RFC 9700 section 4.14.2 failure in full: the thief and the honest client
/// each rotate the same token and each end up holding a live chain, and because the honest client
/// is never locked out, the reuse signal that exists to catch the theft never fires. Zero winners
/// is a different bug with the same root, a non-atomic pair of steps, and it loses a credential
/// the client was entitled to.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn take_refresh_token_has_exactly_one_winner_across_two_connections() {
    let (a, b) = two_connections("oauth_as_two_conn_take").await;
    for round in 0..ROUNDS {
        let token = format!("rt-atomic-{round}");
        a.put_refresh_token(refresh_record(&token))
            .await
            .expect("plant the refresh record");
        let winners = race_take(&a, &b, &token, true).await;
        assert_eq!(
            winners, 1,
            "round {round}: DELETE ... RETURNING handed the same refresh token to {winners} \
             callers over two separate connections"
        );
    }
}

/// THE RED PROOF for the test above. The same race, against the read-then-delete implementation,
/// MUST double-spend. If it does not, the test above is not a detector and its green means
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_naive_take_is_caught_by_the_same_race() {
    let (a, b) = two_connections("oauth_as_two_conn_take_naive").await;
    let mut double_spends = 0;
    for round in 0..ROUNDS {
        let token = format!("rt-naive-{round}");
        a.put_refresh_token(refresh_record(&token))
            .await
            .expect("plant the refresh record");
        if race_take(&a, &b, &token, false).await > 1 {
            double_spends += 1;
        }
    }
    assert!(
        double_spends > 0,
        "the read-then-delete take double-spent in 0 of {ROUNDS} rounds, so \
         take_refresh_token_has_exactly_one_winner_across_two_connections is not detecting \
         anything and its green cannot be quoted as evidence"
    );
    eprintln!("red proof: read-then-delete double-spent in {double_spends}/{ROUNDS} rounds");
}

/// `claim_replay_id` from two separate connections: exactly one caller is told it was first.
///
/// RFC 7523 section 3 and RFC 9449 section 4.3 both make a `jti` single use. The trait notes this
/// failure is WORSE than a double-spent token, because a replayed assertion produces exactly the
/// request the client meant to send, twice, and nothing anywhere records that it happened.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_replay_id_has_exactly_one_winner_across_two_connections() {
    let (a, b) = two_connections("oauth_as_two_conn_claim").await;
    for round in 0..ROUNDS {
        let id = format!("jti-atomic-{round}");
        let winners = race_claim(&a, &b, &id, true).await;
        assert_eq!(
            winners, 1,
            "round {round}: INSERT ... ON CONFLICT DO NOTHING RETURNING told {winners} callers \
             they were the first to claim the same jti"
        );
    }
}

/// THE RED PROOF for the claim. Look-then-insert must tell both callers they were first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_naive_claim_is_caught_by_the_same_race() {
    let (a, b) = two_connections("oauth_as_two_conn_claim_naive").await;
    let mut double_claims = 0;
    for round in 0..ROUNDS {
        let id = format!("jti-naive-{round}");
        if race_claim(&a, &b, &id, false).await > 1 {
            double_claims += 1;
        }
    }
    assert!(
        double_claims > 0,
        "the look-then-insert claim told both callers they were first in 0 of {ROUNDS} rounds, so \
         claim_replay_id_has_exactly_one_winner_across_two_connections is not detecting anything"
    );
    eprintln!("red proof: look-then-insert double-claimed in {double_claims}/{ROUNDS} rounds");
}

/// A `Pending` device grant, the state both the polling device and the verification UI swap
/// against.
fn pending_grant(device_code: &str, user_code: &str) -> oauth_as::DeviceGrant {
    oauth_as::DeviceGrant {
        device_code: device_code.to_string(),
        user_code: user_code.to_string(),
        client_id: ClientId::new("client-two-connection"),
        scope: ScopeSet::parse("read").expect("a valid RFC 6749 s3.3 scope"),
        state: oauth_as::DeviceGrantState::Pending,
        created_at: std::time::SystemTime::UNIX_EPOCH,
        expires_at: std::time::SystemTime::UNIX_EPOCH
            + std::time::Duration::from_secs(2_000_000_000),
        interval: std::time::Duration::from_secs(5),
        last_poll_at: None,
    }
}

/// One race over `compare_and_swap_device_grant`, returning how many callers were told their swap
/// APPLIED. Both racers claim to have read `Pending`; one wants `Approved`, the other `Denied`.
async fn race_swap(
    a: &PostgresStorage,
    b: &PostgresStorage,
    device_code: &str,
    user_code: &str,
    atomic: bool,
) -> usize {
    let gate = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    let outcomes = [
        oauth_as::DeviceGrantState::Approved {
            subject: "subject-two-connection".to_string(),
        },
        oauth_as::DeviceGrantState::Denied,
    ];
    for (store, state) in [a.clone(), b.clone()].into_iter().zip(outcomes) {
        let gate = Arc::clone(&gate);
        let updated = oauth_as::DeviceGrant {
            state,
            ..pending_grant(device_code, user_code)
        };
        handles.push(tokio::spawn(async move {
            gate.wait().await;
            let expected = oauth_as::DeviceGrantState::Pending;
            if atomic {
                store
                    .compare_and_swap_device_grant(&expected, updated)
                    .await
                    .expect("compare_and_swap_device_grant")
            } else {
                naive::compare_and_swap_device_grant_read_then_write(
                    store.pool(),
                    &expected,
                    &updated,
                )
                .await
                .expect("naive swap")
            }
        }));
    }
    let mut winners = 0;
    for handle in handles {
        if handle.await.expect("racer did not panic") {
            winners += 1;
        }
    }
    winners
}

/// RFC 8628 section 3.3 is FIRST-DECISION-WINS, and across two connections only the database can
/// decide who was first. `UPDATE ... WHERE payload -> 'state' = $expected` does; a read followed
/// by a write does not.
///
/// Two winners means both the approval and the denial were applied, so the record holds whichever
/// arrived last and a user's answer was thrown away after the UI told them it was recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compare_and_swap_has_exactly_one_winner_across_two_connections() {
    let (a, b) = two_connections("oauth_as_two_conn_swap").await;
    for round in 0..ROUNDS {
        let device_code = format!("dc-atomic-{round}");
        let user_code = format!("SWAP-{round:04}");
        a.put_device_grant(pending_grant(&device_code, &user_code))
            .await
            .expect("plant the device grant");
        let winners = race_swap(&a, &b, &device_code, &user_code, true).await;
        assert_eq!(
            winners, 1,
            "round {round}: the conditional UPDATE told {winners} callers their swap applied over \
             two separate connections, so RFC 8628 s3.3 first-decision-wins does not hold"
        );
    }
}

/// THE RED PROOF for the test above.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_naive_swap_is_caught_by_the_same_race() {
    let (a, b) = two_connections("oauth_as_two_conn_swap_naive").await;
    let mut lost_updates = 0;
    for round in 0..ROUNDS {
        let device_code = format!("dc-naive-{round}");
        let user_code = format!("NAIV-{round:04}");
        a.put_device_grant(pending_grant(&device_code, &user_code))
            .await
            .expect("plant the device grant");
        if race_swap(&a, &b, &device_code, &user_code, false).await > 1 {
            lost_updates += 1;
        }
    }
    assert!(
        lost_updates > 0,
        "the read-compare-write swap lost an update in 0 of {ROUNDS} rounds, so \
         compare_and_swap_has_exactly_one_winner_across_two_connections is not detecting anything"
    );
    eprintln!("red proof: read-compare-write lost an update in {lost_updates}/{ROUNDS} rounds");
}

/// THE SECOND FAILURE MODE, and the one no race is needed to show: a swap that lands after the
/// grant was REDEEMED must not put it back. `take_device_grant` is RFC 8628 single-use redemption,
/// so a resurrected grant is a device code that can be exchanged for a token twice.
///
/// `UPDATE` cannot create a row, which is why the real implementation passes this by construction.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_swap_after_redemption_does_not_resurrect_the_grant() {
    let (a, _b) = two_connections("oauth_as_two_conn_swap_gone").await;
    let grant = pending_grant("dc-redeemed", "GONE-0001");
    a.put_device_grant(grant.clone())
        .await
        .expect("plant the device grant");
    a.take_device_grant(&grant.device_code)
        .await
        .expect("take_device_grant")
        .expect("the planted grant is there to redeem");

    let applied = a
        .compare_and_swap_device_grant(
            &oauth_as::DeviceGrantState::Pending,
            oauth_as::DeviceGrant {
                state: oauth_as::DeviceGrantState::Denied,
                ..grant.clone()
            },
        )
        .await
        .expect("compare_and_swap_device_grant");
    assert!(
        !applied,
        "a swap against a redeemed device_code reported that it applied"
    );
    assert!(
        a.get_device_grant(&grant.device_code)
            .await
            .expect("get_device_grant")
            .is_none(),
        "the swap resurrected a device grant that had already been exchanged for a token"
    );
}

/// THE RED PROOF for the test above: the read-compare-write shim, whose write is an upsert, brings
/// the redeemed grant back every time. This is the defect the core trait's removed default body
/// had, which is why it was removed rather than merely documented.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_naive_swap_resurrects_the_redeemed_grant() {
    let (a, _b) = two_connections("oauth_as_two_conn_swap_gone_naive").await;
    let grant = pending_grant("dc-redeemed-naive", "GONV-0001");
    a.put_device_grant(grant.clone())
        .await
        .expect("plant the device grant");
    a.take_device_grant(&grant.device_code)
        .await
        .expect("take_device_grant")
        .expect("the planted grant is there to redeem");

    let applied = naive::compare_and_swap_device_grant_read_then_write(
        a.pool(),
        &oauth_as::DeviceGrantState::Pending,
        &oauth_as::DeviceGrant {
            state: oauth_as::DeviceGrantState::Denied,
            ..grant.clone()
        },
    )
    .await
    .expect("naive swap");
    assert!(
        applied,
        "the shim reports success against a row that is gone"
    );
    assert!(
        a.get_device_grant(&grant.device_code)
            .await
            .expect("get_device_grant")
            .is_some(),
        "the read-compare-write shim did not resurrect the redeemed grant, so \
         a_swap_after_redemption_does_not_resurrect_the_grant is not detecting anything"
    );
}
