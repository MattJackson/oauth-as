// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson
//! PostgreSQL-only SQLx vocabulary, without the multi-database umbrella dependency.
pub use sqlx_core::{
    error::Error, executor::Executor, pool::Pool, query::query, query_scalar::query_scalar,
    raw_sql::raw_sql, row::Row, transaction::Transaction,
};
pub use sqlx_postgres::{PgConnection, PgPool, Postgres};
/// PostgreSQL driver types used by callers and integration fixtures.
pub mod postgres {
    pub use sqlx_postgres::*;
}
