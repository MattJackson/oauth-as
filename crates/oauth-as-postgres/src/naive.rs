// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! DELIBERATELY WRONG implementations, kept so the atomicity test can be watched going RED.
//!
//! # Why this is in the tree and not in a commit that was reverted
//!
//! A conformance test nobody has seen fail is a test nobody should trust. The repository's own
//! house rule is red before green, and `scripts/oauth-conformance.sh --selftest` exists for
//! exactly this reason: to prove the gate can go red on its own axes before its green means
//! anything.
//!
//! `tests/two_connection.rs` claims to detect a non-atomic `take_*` across two separate database
//! connections. That claim is only worth something if the same test, pointed at a store that IS
//! non-atomic, reports the double spend. So the non-atomic store lives here, permanently, and the
//! test asserts BOTH directions on every run: the real implementation never double-spends, and
//! this one does.
//!
//! # What makes it wrong
//!
//! Nothing that looks wrong. It is the implementation a competent person writes first:
//!
//! ```text
//! SELECT payload FROM oauth_as_refresh_tokens WHERE refresh_token = $1;
//! DELETE            FROM oauth_as_refresh_tokens WHERE refresh_token = $1;
//! ```
//!
//! On one node it is indistinguishable from the correct version, because nothing interleaves
//! between the two round trips. On two, both nodes complete the SELECT before either reaches the
//! DELETE, both are handed the record, and both rotate. The thief and the honest client each end
//! up holding a live chain, and because the honest client is never locked out, the RFC 9700
//! section 4.14.2 reuse signal that exists to catch exactly this theft never fires.
//!
//! Behind the `pg-integration` feature, so it is not in any build a host could reach by accident.

use oauth_as::store::StorageError;
use oauth_as::token::RefreshTokenRecord;
use sqlx::{Pool, Postgres, Row};

use crate::error;

/// The read-then-delete refresh token take: THE BUG, in the shape it is usually written.
///
/// Returns the record when this caller's `SELECT` saw it, which under concurrency is more than
/// one caller. Never call this from anything but the red-proof in `tests/two_connection.rs`.
pub async fn take_refresh_token_read_then_delete(
    pool: &Pool<Postgres>,
    refresh_token: &str,
) -> Result<Option<RefreshTokenRecord>, StorageError> {
    const OP: &str = "naive take_refresh_token";
    // Round trip one. Every concurrent caller that gets here before anybody reaches the DELETE
    // below is told the record is theirs.
    let row = sqlx::query("SELECT payload FROM oauth_as_refresh_tokens WHERE refresh_token = $1")
        .bind(refresh_token)
        .fetch_optional(pool)
        .await
        .map_err(|e| error::db(OP, e))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let raw: serde_json::Value = row.try_get("payload").map_err(|e| error::db(OP, e))?;
    // Round trip two. The DELETE reports how many rows it removed, and a careful author might
    // reach for that as a tie break, but by then this caller has ALREADY been handed the record
    // and the honest client has already been handed it too.
    sqlx::query("DELETE FROM oauth_as_refresh_tokens WHERE refresh_token = $1")
        .bind(refresh_token)
        .execute(pool)
        .await
        .map_err(|e| error::db(OP, e))?;
    serde_json::from_value(raw)
        .map(Some)
        .map_err(|_| error::payload(OP))
}

/// The look-then-insert replay claim: the same defect at
/// [`oauth_as::store::Storage::claim_replay_id`], where the trait says the damage is SILENT.
///
/// A `take_*` that hands a record out twice at least produces two token responses somebody might
/// notice. A claim that answers "you were first" to two concurrent presentations of the same
/// RFC 7523 assertion or RFC 9449 proof produces exactly the request the client meant to send,
/// twice, and nothing anywhere records that it happened.
pub async fn claim_replay_id_read_then_write(
    pool: &Pool<Postgres>,
    id: &str,
    expires_at: std::time::SystemTime,
) -> Result<bool, StorageError> {
    const OP: &str = "naive claim_replay_id";
    let seen = sqlx::query("SELECT 1 AS present FROM oauth_as_replay_ids WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| error::db(OP, e))?
        .is_some();
    if seen {
        return Ok(false);
    }
    // `ON CONFLICT DO NOTHING` here does not save it: the decision that this caller was FIRST was
    // already taken above, on stale information, and it is the decision that matters.
    sqlx::query(
        "INSERT INTO oauth_as_replay_ids (id, expires_at_ns) VALUES ($1, $2) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(crate::to_nanos(expires_at))
    .execute(pool)
    .await
    .map_err(|e| error::db(OP, e))?;
    Ok(true)
}
