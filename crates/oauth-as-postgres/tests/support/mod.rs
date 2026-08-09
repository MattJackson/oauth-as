// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Shared setup for the integration tests: a real PostgreSQL, one SCHEMA per test.
//!
//! WHY A SCHEMA PER TEST. Cargo runs test binaries in parallel and tests within a binary on
//! parallel threads, and every one of these tests either truncates the store or counts rows in
//! it. Sharing one set of tables would make them clobber each other, and the failure would look
//! like a storage bug rather than like a test-harness bug, which is the worst way for this
//! particular suite to be wrong. `search_path` is set on the connection, so the schema is
//! invisible to the crate under test: it runs exactly the SQL it would run in production.
//!
//! WHY THE MISSING DATABASE IS A PANIC AND NOT A SKIP. A test that quietly passes when it did not
//! run is how a suite comes to be quoted as evidence for something nobody checked. These tests
//! only compile with `--features pg-integration`, which is off by default so that
//! `cargo test --workspace` on a machine with no database is honest rather than red; with the
//! feature on, the caller has SAID they want the database, so a missing one is a failure.

#![allow(dead_code)]

use std::str::FromStr;

use oauth_as_postgres::PostgresStorage;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Executor, Pool, Postgres};

/// The environment variable a caller points at their test database.
pub const URL_VAR: &str = "OAUTH_AS_POSTGRES_TEST_URL";

/// The connection URL, or a panic that says exactly what to do about it.
pub fn database_url() -> String {
    match std::env::var(URL_VAR) {
        Ok(url) if !url.trim().is_empty() => url,
        _ => panic!(
            "\n\n\
             ================================================================================\n\
             oauth-as-postgres integration tests need a REAL PostgreSQL and {URL_VAR} is not\n\
             set. These tests are the only evidence this crate has that its take_* operations\n\
             are atomic ACROSS CONNECTIONS, which is the one thing the core crate's in-process\n\
             conformance harness says it cannot prove. Skipping them silently would leave that\n\
             claim unchecked.\n\
             \n\
             Run scripts/postgres-conformance.sh, which starts a throwaway container and sets\n\
             the variable, or set it yourself, for example:\n\
             \n\
               export {URL_VAR}=postgres://postgres:postgres@localhost:5432/postgres\n\
             ================================================================================\n\n"
        ),
    }
}

/// Drop and recreate `schema`, so a test starts on tables that do not exist yet.
pub async fn fresh_schema(schema: &str) {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url())
        .await
        .expect("connect to the test database");
    // The schema names are this file's own literals, never caller data; `CREATE SCHEMA` takes no
    // bind parameters, so there is no alternative to formatting them in.
    pool.execute(format!("DROP SCHEMA IF EXISTS {schema} CASCADE").as_str())
        .await
        .expect("drop the test schema");
    pool.execute(format!("CREATE SCHEMA {schema}").as_str())
        .await
        .expect("create the test schema");
    pool.close().await;
}

/// A pool pinned to `schema` with at most `max_connections` connections.
///
/// `max_connections(1)` is what the two-connection test uses to make "two separate connections"
/// a fact rather than a hope: two such pools cannot share one.
pub async fn pool(schema: &str, max_connections: u32) -> Pool<Postgres> {
    let options = PgConnectOptions::from_str(&database_url())
        .expect("parse the test database URL")
        .options([("search_path", schema)]);
    PgPoolOptions::new()
        .max_connections(max_connections)
        // Established eagerly, so that by the time a racer reaches the rendezvous gate its
        // connection already exists and the race is over the take rather than over the connect.
        .min_connections(max_connections)
        .connect_with(options)
        .await
        .expect("connect to the test schema")
}

/// A migrated store on its own pool in `schema`.
pub async fn store(schema: &str, max_connections: u32) -> PostgresStorage {
    let store = PostgresStorage::from_pool(pool(schema, max_connections).await);
    store.migrate().await.expect("apply the migrations");
    store
}
