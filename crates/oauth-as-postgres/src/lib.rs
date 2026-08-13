// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A PostgreSQL implementation of [`oauth_as::store::Storage`].
//!
//! # Why this is a separate crate and not a feature of `oauth-as`
//!
//! The core crate's premise is a tiny dependency set that a host can read in one sitting. A
//! Postgres driver is a large tree, and an OPTIONAL dependency is still a line in the core's
//! manifest, still a thing a security team has to reason about, and still something that appears
//! in `cargo tree` the moment anything in a workspace turns it on. Keeping it out here means the
//! core's manifest never mentions a database at all.
//!
//! It also proves something a feature could not: that [`oauth_as::store::Storage`] is
//! implementable from OUTSIDE the crate, using only its public API. Nothing in this crate reaches
//! for a private item, because it cannot.
//!
//! # The property this crate exists for
//!
//! [`oauth_as::store::Storage`] requires every `take_*` to be an ATOMIC remove-and-return, and
//! [`oauth_as::store::Storage::claim_replay_id`] to be an atomic claim-if-absent. In one process
//! that is free: `MemoryStorage` gets it from one mutex. Across two nodes it is not free, and the
//! obvious implementation is wrong in a way that looks right:
//!
//! ```text
//! SELECT ... FROM refresh_tokens WHERE token = $1;   -- both nodes see the record
//! DELETE   FROM refresh_tokens WHERE token = $1;     -- both nodes delete it
//! ```
//!
//! Both callers then mint. The thief and the honest client each hold a live chain, and because
//! the honest client is never locked out, RFC 9700 section 4.14.2 reuse detection, the one signal
//! that would have revealed the theft, never fires. Every `take_*` here is therefore a single
//! statement of the form
//!
//! ```text
//! DELETE FROM <table> WHERE <key> = $1 RETURNING payload
//! ```
//!
//! so the DATABASE decides the winner, and `claim_replay_id` is a single
//! `INSERT ... ON CONFLICT DO NOTHING ... RETURNING`, so the unique index decides who was first.
//! `tests/two_connection.rs` proves it over two genuinely separate connections, which is the one
//! thing the core's in-process harness says it cannot do.
//!
//! # Using it
//!
//! ```no_run
//! # async fn doc() -> Result<(), Box<dyn std::error::Error>> {
//! use oauth_as_postgres::PostgresStorage;
//!
//! let store = PostgresStorage::connect("postgres://user:pw@localhost/as").await?;
//! store.migrate().await?;
//! # Ok(())
//! # }
//! ```
//!
//! [`PostgresStorage::migrate`] applies the checked-in `migrations/*.sql` that match the compiled
//! features. A deployment that would rather own its schema can skip it and apply those files with
//! whatever migration tool it already runs; they are plain SQL and idempotent.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use sqlx::postgres::{PgPoolOptions, Postgres};
use sqlx::Executor;
use sqlx::{Pool, Transaction};

mod error;
#[cfg(feature = "pg-integration")]
pub mod naive;
mod store;
mod time;

pub use time::{from_nanos, to_nanos};

/// How many rows one batch of [`oauth_as::store::Storage::sweep_expired`] removes per statement.
///
/// The sweep deletes in batches and commits each one, per table, until the table has nothing left
/// that is dead. This constant is the size of the LOCK WINDOW, not a limit on what a call
/// reclaims: a single call still drains the whole backlog, and the count it returns is still the
/// rows it actually removed. Through 0.9.0 each table was one unbounded `DELETE` inside one
/// transaction, which on a table with millions of dead rows holds a lock on every one of them
/// until the whole statement finishes, blocking the live redemptions that touch them.
///
/// FIVE THOUSAND, which is a compromise between two costs that pull opposite ways. Too small and
/// the sweep is dominated by round trips: a backlog of a million rows is 200 statements at this
/// size and 1000 at 1000, each one a network round trip that a sweep on a timer has no reason to
/// pay. Too large and the batch stops being a short lock, which is the entire point: at 5000 rows
/// a delete over the expiry index is single-digit milliseconds on ordinary hardware, comfortably
/// shorter than the round trip that carried it. It is not configurable because a host that needs
/// it to be has a different problem (a sweep interval too long for its issuance rate), and a knob
/// would let that problem be tuned around rather than found.
pub const SWEEP_BATCH_ROWS: usize = 5_000;

/// The advisory-lock key [`PostgresStorage::migrate`] serialises on.
///
/// Advisory locks live in ONE cluster-wide space that every application sharing the database draws
/// from, so the value matters: it is the ASCII bytes of `oauth_as`, read as a big-endian integer,
/// which is as close to a namespace as that space offers and is stable for as long as this crate
/// is called what it is. It is deliberately not derived from a schema name, because two nodes
/// migrating the SAME database is exactly the case it exists for.
const MIGRATION_LOCK_KEY: i64 = 0x6f61_7574_685f_6173;

/// Every checked-in migration this build needs, on one connection, in order.
///
/// The advisory lock is taken FIRST and the whole thing runs in one transaction, which is what
/// makes concurrent callers safe: see [`PostgresStorage::migrate`].
async fn apply_migrations(conn: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    // Transaction scoped, so a node that dies mid-migration releases it by disconnecting rather
    // than leaving every other node waiting for a lock nothing will ever free. DDL is transactional
    // in PostgreSQL, so the rollback that goes with it leaves no half-applied schema behind either.
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(MIGRATION_LOCK_KEY)
        .execute(&mut *conn)
        .await?;
    // A bare `&str` with no bound parameters runs over the SIMPLE query protocol, which is what
    // lets one call carry a whole multi-statement script — which is what a migration file is. It
    // binds nothing, so there is no parameter to inject into. (`sqlx::raw_sql` says the same thing
    // more explicitly and was what this used before the lock; on a `&mut PgConnection` its
    // higher-ranked bounds are what make the enclosing future stop being `Send`, and `migrate()`
    // being spawnable matters more than the extra word.)
    conn.execute(include_str!("../migrations/0001_core.sql"))
        .await?;
    #[cfg(feature = "par")]
    conn.execute(include_str!("../migrations/0002_par.sql"))
        .await?;
    #[cfg(feature = "consent")]
    conn.execute(include_str!("../migrations/0003_consent.sql"))
        .await?;
    #[cfg(any(feature = "client-assertion", feature = "dpop"))]
    conn.execute(include_str!("../migrations/0004_replay.sql"))
        .await?;
    // NOT feature gated, unlike the three above, and the asymmetry is deliberate: only the
    // `consent` build ever WRITES a consent-scoped barrier, but every build READS this table on
    // every issuance, because `put_token` consults it unconditionally. A feature gate here would
    // turn a default-features deployment's first token into a missing-table error.
    conn.execute(include_str!("../migrations/0005_revocation_barriers.sql"))
        .await?;
    Ok(())
}

/// A [`oauth_as::store::Storage`] backed by a PostgreSQL connection pool.
///
/// Cheap to clone in the sense that matters: it holds a [`sqlx::PgPool`], which is itself an
/// `Arc` internally, so a host may keep one and share it.
#[derive(Clone, Debug)]
pub struct PostgresStorage {
    pool: Pool<Postgres>,
}

/// The failure of a setup operation ([`PostgresStorage::connect`],
/// [`PostgresStorage::migrate`]).
///
/// Separate from [`oauth_as::store::StorageError`] on purpose: those two run at STARTUP, where a
/// host wants the driver's own diagnosis, and they are not on any request path so nothing maps
/// them to `server_error`. The redaction rule in this crate's error module applies to the
/// per-request path, which is where the text becomes a log line the host did not write.
#[derive(Debug)]
pub struct SetupError(sqlx::Error);

impl std::fmt::Display for SetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "oauth-as-postgres setup failed: {}", self.0)
    }
}

impl std::error::Error for SetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl From<sqlx::Error> for SetupError {
    fn from(e: sqlx::Error) -> Self {
        SetupError(e)
    }
}

impl PostgresStorage {
    /// Connect with the default pool settings.
    ///
    /// Use [`PostgresStorage::from_pool`] when the host already owns a pool, which it usually
    /// does: an authorization server is embedded in an application that has its own database
    /// connections, and a second pool doubles the connection count the server has to size for.
    pub async fn connect(url: &str) -> Result<Self, SetupError> {
        let pool = PgPoolOptions::new().connect(url).await?;
        Ok(Self { pool })
    }

    /// Adopt a pool the host already has.
    pub fn from_pool(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    /// The underlying pool, so a host can run its own statements against the same connections.
    pub fn pool(&self) -> &Pool<Postgres> {
        &self.pool
    }

    /// Apply the checked-in schema for the features this crate was compiled with.
    ///
    /// Every statement is `CREATE ... IF NOT EXISTS`, so this is safe to run on every boot. It is
    /// also safe to run concurrently from several nodes starting at once, and THAT part is not
    /// something `IF NOT EXISTS` provides: in PostgreSQL the existence check and the catalogue
    /// insert are not one atomic step, so two sessions running the same `CREATE TABLE IF NOT
    /// EXISTS` can both pass the check and the loser gets `23505 duplicate key value violates
    /// unique constraint "pg_type_typname_nsp_index"`. A replica set rolling out against a fresh
    /// database would crash-loop on that until one node's DDL committed. What makes the claim true
    /// is [`MIGRATION_LOCK_KEY`] below: the whole migration runs in ONE transaction holding one
    /// advisory lock, so the second node waits and then finds everything already there.
    ///
    /// FEATURE-SHAPED, deliberately: a build without `par` never creates the pushed-request
    /// table, because nothing in that build could write to it. Turning a feature on later and
    /// re-running this adds the table it needs.
    ///
    /// SCHEMA ONLY. Nothing here rewrites a stored `payload`, and 0.9.1 briefly shipped a
    /// migration that did: it backfilled the four grant instants this release added to records a
    /// 0.9.0 node had already written. That is no longer needed, because the core gives all four
    /// fields a `#[serde(default)]` of `UNIX_EPOCH`, which covers strictly more — including the
    /// 0.9.0 node still WRITING during a rolling upgrade, which no migration can reach. It was
    /// also the wrong shape for this crate: an unbounded single-statement rewrite of every live
    /// credential row, holding a lock on each one, which is exactly what [`SWEEP_BATCH_ROWS`]
    /// exists to avoid on the sweep — and here it would have run inside the transaction holding
    /// the lock every other node is waiting on to boot.
    pub async fn migrate(&self) -> Result<(), SetupError> {
        let mut tx = self.pool.begin().await?;
        // The body is a free function taking `&mut PgConnection` rather than statements written
        // inline here, and that is not a style choice: running the scripts on a CONNECTION rather
        // than on the pool is what the advisory lock requires, and doing it inline made the future
        // this returns depend on a higher-ranked `Executor` bound that rustc cannot prove is
        // `Send`, so `migrate()` stopped being something a host could `tokio::spawn` — which is
        // exactly what a host does at startup. `tests/revocation_races.rs` spawns it, so that
        // cannot regress unnoticed.
        apply_migrations(&mut tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Remove every row this crate owns, for a test suite that needs a store the core's
    /// conformance harness will accept as EMPTY.
    ///
    /// Not `#[cfg(test)]`: the harness lives in the CORE crate and a host runs it from its OWN
    /// test suite, so the factory it needs has to be callable from outside this crate. It is not
    /// something a deployment has any reason to call, and the doc says so rather than the name.
    ///
    /// One `TRUNCATE` over every table, so a caller cannot observe a half-emptied store.
    pub async fn truncate_all(&self) -> Result<(), SetupError> {
        // `mut` only when a feature below pushes onto it; a default build has six tables.
        #[allow(unused_mut)]
        let mut tables: Vec<&str> = vec![
            "oauth_as_clients",
            "oauth_as_device_grants",
            "oauth_as_authorization_codes",
            "oauth_as_access_tokens",
            "oauth_as_refresh_tokens",
            // NOT feature gated, for the same reason its migration is not: every build records
            // client and family barriers. Leaving it out made this method's own promise false, and
            // the harness caught it: barriers survived a truncate, so a check that revoked one
            // family saw a LATER check's unrelated token refused, which reads as "the barrier
            // matches too widely" when the real fault is a store that was never emptied.
            "oauth_as_revocation_barriers",
        ];
        #[cfg(feature = "par")]
        tables.push("oauth_as_pushed_requests");
        #[cfg(feature = "consent")]
        tables.push("oauth_as_consents");
        #[cfg(any(feature = "client-assertion", feature = "dpop"))]
        tables.push("oauth_as_replay_ids");
        // The table names are this crate's own literals, not caller data, so the join cannot be
        // an injection point; `TRUNCATE` takes no bind parameters, so there is no alternative.
        let stmt = format!("TRUNCATE {}", tables.join(", "));
        sqlx::raw_sql(&stmt).execute(&self.pool).await?;
        Ok(())
    }

    /// Begin a transaction, for the operations the trait requires to be all-or-nothing.
    pub(crate) async fn begin(
        &self,
        op: &'static str,
    ) -> Result<Transaction<'_, Postgres>, oauth_as::store::StorageError> {
        self.pool.begin().await.map_err(|e| error::db(op, e))
    }
}
