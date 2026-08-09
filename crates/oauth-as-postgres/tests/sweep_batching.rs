// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! `sweep_expired` over a backlog LARGER THAN ONE BATCH.
//!
//! The sweep deletes in batches of [`SWEEP_BATCH_ROWS`] and commits each one, so that reclaiming a
//! backlog is a sequence of short row locks rather than one long lock over every dead row in the
//! store. That is the point of the batching, and it is also what can silently go wrong: a sweep
//! that runs ONE batch per table per call still returns a plausible number and still empties a
//! small store, so nothing catches it until a deployment with millions of dead rows finds the
//! sweep never keeping up.
//!
//! So this file plants more than one batch of dead rows in every swept table and holds the sweep
//! to the trait's own words: "Remove every record that is dead at `now`, and return how many were
//! removed."
//!
//! ROWS ARE PLANTED WITH SQL rather than through the `Storage` API, because the point is a
//! BACKLOG: seeding tens of thousands of records one round trip at a time would make this test
//! minutes long to prove something about a `DELETE`. The inserts write the same columns the
//! `put_*` methods write, and the sweep reads only `expires_at_ns`, which is one of them.

#![cfg(feature = "pg-integration")]

use std::time::{Duration, SystemTime};

use oauth_as::store::Storage;
use oauth_as_postgres::{PostgresStorage, SWEEP_BATCH_ROWS};

mod support;

const SCHEMA: &str = "oauth_as_sweep_batching";

/// Comfortably more than one batch, and deliberately NOT a multiple of it: a loop that stops when
/// a batch comes back short needs a final short batch to stop on, and a loop that is off by one at
/// the boundary needs a boundary to be off by.
fn backlog() -> i64 {
    SWEEP_BATCH_ROWS as i64 * 2 + 7
}

/// One `INSERT ... SELECT FROM generate_series` per swept table, each writing that table's NOT
/// NULL columns and nothing else. `$1` is the expiry in nanoseconds, `$2` the row count.
const PLANTS: &[(&str, &str)] = &[
    (
        "oauth_as_device_grants",
        "INSERT INTO oauth_as_device_grants \
             (device_code, user_code_normalized, client_id, expires_at_ns, payload) \
         SELECT 'dead-' || g, 'CODE' || g, 'a-client', $1, '{}'::jsonb \
         FROM generate_series(1, $2) AS g",
    ),
    (
        "oauth_as_authorization_codes",
        "INSERT INTO oauth_as_authorization_codes \
             (code, client_id, subject, expires_at_ns, payload) \
         SELECT 'dead-' || g, 'a-client', 'a-subject', $1, '{}'::jsonb \
         FROM generate_series(1, $2) AS g",
    ),
    (
        "oauth_as_access_tokens",
        "INSERT INTO oauth_as_access_tokens (access_token, client_id, expires_at_ns, payload) \
         SELECT 'dead-' || g, 'a-client', $1, '{}'::jsonb FROM generate_series(1, $2) AS g",
    ),
    (
        "oauth_as_refresh_tokens",
        "INSERT INTO oauth_as_refresh_tokens \
             (refresh_token, client_id, family_id, expires_at_ns, payload) \
         SELECT 'dead-' || g, 'a-client', 'a-family', $1, '{}'::jsonb \
         FROM generate_series(1, $2) AS g",
    ),
    (
        "oauth_as_pushed_requests",
        "INSERT INTO oauth_as_pushed_requests (request_uri, client_id, expires_at_ns, payload) \
         SELECT 'dead-' || g, 'a-client', $1, '{}'::jsonb FROM generate_series(1, $2) AS g",
    ),
    (
        // No payload column: the claim IS the row.
        "oauth_as_replay_ids",
        "INSERT INTO oauth_as_replay_ids (id, expires_at_ns) \
         SELECT 'dead-' || g, $1 FROM generate_series(1, $2) AS g",
    ),
];

/// Nanoseconds since the Unix epoch, the units every `expires_at_ns` column is in.
fn nanos(at: SystemTime) -> i64 {
    at.duration_since(SystemTime::UNIX_EPOCH)
        .expect("after the epoch")
        .as_nanos() as i64
}

async fn count(store: &PostgresStorage, table: &str) -> i64 {
    // Every table name here is this file's own literal, never caller data.
    sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
        .fetch_one(store.pool())
        .await
        .unwrap_or_else(|e| panic!("count {table}: {e}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_backlog_of_several_batches_is_swept_whole_and_counted_truthfully() {
    support::fresh_schema(SCHEMA).await;
    let store = support::store(SCHEMA, 4).await;

    let now = SystemTime::now();
    // Dead a minute ago, so every planted row is past the cutoff whatever the seeding cost.
    let dead_ns = nanos(now - Duration::from_secs(60));
    let rows = backlog();

    for (table, sql) in PLANTS {
        sqlx::query(sql)
            .bind(dead_ns)
            .bind(rows)
            .execute(store.pool())
            .await
            .unwrap_or_else(|e| panic!("plant {rows} rows in {table}: {e}"));
    }

    let planted = rows as u64 * PLANTS.len() as u64;
    let removed = store
        .sweep_expired(now)
        .await
        .expect("the sweep must succeed");

    assert_eq!(
        removed, planted,
        "the sweep must remove every record dead at `now` and return how many, over a backlog of \
         more than two batches per table"
    );
    for (table, _) in PLANTS {
        assert_eq!(
            count(&store, table).await,
            0,
            "{table} still holds rows that were dead at the sweep's cutoff"
        );
    }
    // Nothing to do is not an error, and not a nonzero count either.
    assert_eq!(
        store.sweep_expired(now).await.expect("a second sweep"),
        0,
        "a sweep with nothing to reclaim answers 0"
    );
}

/// The other half of the contract, which batching must not break: a record that is NOT dead
/// survives however many batches run around it. A `LIMIT` in the wrong place (bounding the
/// predicate rather than the selected rows) is exactly the mistake that would take live rows with
/// it, and it would show up as clients being logged out rather than as a failed sweep.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_live_record_survives_a_multi_batch_sweep() {
    const LIVE_SCHEMA: &str = "oauth_as_sweep_batching_live";
    support::fresh_schema(LIVE_SCHEMA).await;
    let store = support::store(LIVE_SCHEMA, 4).await;

    let now = SystemTime::now();
    let dead_ns = nanos(now - Duration::from_secs(60));
    let live_ns = nanos(now + Duration::from_secs(3600));

    plant_tokens(&store, "dead", backlog(), dead_ns).await;
    plant_tokens(&store, "live", 3, live_ns).await;
    // A refresh record with NO absolute lifetime: the trait says such a chain is not dead however
    // old it is, and a batched delete must not be the thing that finally reaps it.
    sqlx::query(
        "INSERT INTO oauth_as_refresh_tokens \
             (refresh_token, client_id, family_id, expires_at_ns, payload) \
         VALUES ('eternal', 'a-client', 'a-family', NULL, '{}'::jsonb)",
    )
    .execute(store.pool())
    .await
    .expect("plant a refresh record with no absolute lifetime");

    let removed = store
        .sweep_expired(now)
        .await
        .expect("the sweep must succeed");
    assert_eq!(removed, backlog() as u64);
    assert_eq!(
        count(&store, "oauth_as_access_tokens").await,
        3,
        "a token that is still live must survive a sweep of the batches around it"
    );
    assert_eq!(
        count(&store, "oauth_as_refresh_tokens").await,
        1,
        "a refresh record with expires_at_ns NULL is a chain with no absolute lifetime"
    );
}

/// `rows` access tokens whose keys are prefixed with `prefix`.
async fn plant_tokens(store: &PostgresStorage, prefix: &str, rows: i64, expires_at_ns: i64) {
    sqlx::query(
        "INSERT INTO oauth_as_access_tokens (access_token, client_id, expires_at_ns, payload) \
         SELECT $1 || '-' || g, 'a-client', $2, '{}'::jsonb FROM generate_series(1, $3) AS g",
    )
    .bind(prefix)
    .bind(expires_at_ns)
    .bind(rows)
    .execute(store.pool())
    .await
    .expect("plant access tokens");
}
