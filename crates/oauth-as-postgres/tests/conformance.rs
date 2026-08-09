// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The CORE crate's own `Storage` conformance harness, run against a real PostgreSQL.
//!
//! This is the harness a host is told to run against its own store (`oauth-as` feature
//! `test-util`). Running it here does two jobs at once: it checks this implementation, and it
//! checks that the harness is runnable by somebody who is not the crate that ships it, over a
//! store whose every operation is a network round trip.
//!
//! WHAT THIS PROVES AND WHAT IT DOES NOT. The harness's own module docs are explicit: it proves a
//! store is atomic across await points and CANNOT prove it is atomic across processes or nodes.
//! Two things narrow that gap here, and neither closes it:
//!
//! - `with_spawn` hands the racers to a multi-threaded runtime, and the store's pool is sized so
//!   that the racers hold DIFFERENT connections. So these races already reach the database on
//!   separate sessions rather than through one in-process lock.
//! - `tests/two_connection.rs` does the part this file still cannot, with two pools that
//!   physically cannot share a connection, and proves the same test catches a store that gets it
//!   wrong.

#![cfg(feature = "pg-integration")]

use oauth_as::storage_conformance::StorageConformance;

mod support;

/// One schema of this file's own, so the truncation between checks cannot reach another test.
const SCHEMA: &str = "oauth_as_conformance";

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn storage_conformance_against_real_postgres() {
    support::fresh_schema(SCHEMA).await;
    // Sixteen connections against eight racers, so a racer never waits on the pool for a
    // connection another racer is holding. A pool of one would serialize the races and this file
    // would prove nothing at all.
    let store = support::store(SCHEMA, 16).await;

    let violations = StorageConformance::new(|| async {
        // The harness requires the factory to hand back an EMPTY store: several checks count
        // records, and a row left over from an earlier check is indistinguishable from one the
        // store failed to remove. `PostgresStorage` is a handle on a pool, so this is the same
        // database each time, truncated.
        store.truncate_all().await.expect("truncate between checks");
        store.clone()
    })
    .with_spawn(|task| {
        tokio::spawn(task);
    })
    .run()
    .await;

    assert!(
        violations.is_empty(),
        "PostgresStorage failed the oauth-as Storage contract:\n{}",
        violations
            .iter()
            .map(|v| format!("  - {v}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Passing once is not passing always, which the harness says in as many words. A race that loses
/// is still a race, so the atomicity checks are run again with more racers than the default.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn storage_conformance_with_more_racers() {
    const REPEAT_SCHEMA: &str = "oauth_as_conformance_racers";
    support::fresh_schema(REPEAT_SCHEMA).await;
    let store = support::store(REPEAT_SCHEMA, 32).await;

    let violations = StorageConformance::new(|| async {
        store.truncate_all().await.expect("truncate between checks");
        store.clone()
    })
    .with_spawn(|task| {
        tokio::spawn(task);
    })
    .racers(24)
    .run()
    .await;

    assert!(
        violations.is_empty(),
        "PostgresStorage failed the oauth-as Storage contract under 24 racers:\n{}",
        violations
            .iter()
            .map(|v| format!("  - {v}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
