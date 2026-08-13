// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The [`Storage`] implementation.
//!
//! READ THE `take_*` METHODS FIRST. They are the reason this crate exists and each one is a
//! SINGLE statement, `DELETE ... RETURNING payload`, so the database picks the winner. There is
//! no read-then-delete anywhere in this file, and no `SELECT` on any single-use artifact's
//! redemption path.
//!
//! NO FOREIGN KEYS, and that is deliberate rather than an omission. `oauth_as_access_tokens`
//! could reference `oauth_as_clients (client_id)` with `ON DELETE CASCADE` and get
//! [`Storage::delete_client`]'s cascade for free. It is not done, for two reasons that both come
//! from the trait rather than from taste:
//!
//! - The trait does not say a credential's client must be present in the store. The core's own
//!   conformance harness plants tokens and refresh records for client ids it never registered,
//!   which is legitimate: a host may authenticate clients from somewhere else entirely and use
//!   this store only for what the server issues. A foreign key would fail those writes.
//! - It would turn an ordinary race into an error on a request path. A `put_token` that lands a
//!   microsecond after a concurrent `delete_client` would come back as a constraint violation,
//!   which the server maps to `server_error`, rather than as a write that the delete simply
//!   raced.
//!
//! The cascade is therefore explicit, inside ONE transaction, which is what the trait asks for.
//!
//! # THE DELETE IS A KILL SWITCH AS OF 0.9.1, and this section used to say the opposite
//!
//! [`Storage::delete_client`] removes the registration and everything the store holds for it, and
//! it now also STOPS what is issued a millisecond later. That second half is new, and the reason
//! this section is rewritten rather than deleted is that the old text was load bearing: it told
//! hosts to build a workaround that is no longer needed, and a host that still believes it will
//! carry that machinery forever.
//!
//! WHAT IT USED TO SAY, and why it was true at the time. A token request already in flight read
//! the registration BEFORE the delete committed, so its `put_token` landed after, and the row it
//! wrote was a live credential for a client that no longer existed, spendable until its own
//! expiry. The text called this "a property of the SEQUENCE, not of this implementation" and
//! argued that nothing inside a store could close it: a foreign key turns the losing write into a
//! `server_error` on a request that did nothing wrong, a higher isolation level does not see the
//! conflict because `put_token` is a single autocommit statement, and reordering statements inside
//! one transaction changes nothing visible from outside. All three of those observations are still
//! correct.
//!
//! WHAT WAS WRONG WAS THE CONCLUSION. The premise smuggled in was that the only tools available
//! are the ones the DATABASE offers. `delete_client` now records a
//! [`oauth_as::store::RevocationBarrier`] in the same transaction as its removals, and every write
//! on a revocable record consults it, so the in-flight `put_token` is REFUSED rather than raced.
//! The barrier is an ordinary row, so it commits atomically with the cascade. See `delete_client`
//! below, and the resurrection rule in the `oauth_as::store` module docs.
//!
//! THAT IS NOT ENOUGH ON ITS OWN, and an earlier version of this paragraph said it was: it claimed
//! the barrier was "visible to every later reader without any isolation-level change at all". A
//! barrier is indeed visible to every reader that STARTS after it commits, and that is precisely
//! the gap. At the pool's default READ COMMITTED a `put_token` takes one snapshot for its refusal
//! check and another for its insert, so a revocation can commit whole in between: the check sees
//! no barrier, the cascade sees no token (`put_token`'s row is still uncommitted, and an
//! uncommitted row is invisible to a `DELETE` rather than something it waits for), and the token
//! lands with nothing left to refuse it. Collapsing the check and the insert into one
//! `INSERT ... SELECT ... WHERE NOT EXISTS` narrows that window to the duration of the commit but
//! does not close it, for the same snapshot reason. What closes it is [`lock_barrier_scopes`]:
//! every guarded write takes a SHARED advisory lock over each identity a revocation could name it
//! by, and every revocation takes the matching EXCLUSIVE one before it records its barrier, so the
//! two can no longer interleave in either direction. Shared rather than exclusive on the write
//! side is what keeps issuance concurrent with itself: two token writes for one client never wait
//! on each other, and only a revocation of that client makes anything wait at all.
//!
//! WHAT A HOST NO LONGER HAS TO DO: the old advice was to stop admitting requests for the client,
//! then call [`Storage::delete_client`] a SECOND time once every request that could have read the
//! registration had drained. That second call is now unnecessary. It remains harmless (it answers
//! `Ok(false)` and re-runs the cascade), so a host that already does it is not broken, but nothing
//! requires it.
//!
//! WHAT IS STILL TRUE: a deletion does not reach tokens ALREADY ISSUED and already handed to the
//! client. Those live out their expiry unless something revokes them, which is what
//! [`Storage::revoke_token_family`] and the cascade are for. A deployment that needs "revoked NOW"
//! at the resource server still needs introspection or short token lifetimes; that was never a
//! statement about this race and it has not changed. The resource-server introspection channel is
//! 0.9.2 work, so short lifetimes are the 0.9.1 answer.

use oauth_as::authorization::AuthorizationCodeRecord;
use oauth_as::client::{Client, ClientId};
use oauth_as::device::{DeviceGrant, DeviceGrantState};
use oauth_as::store::{Storage, StorageError, WriteOutcome};
use oauth_as::token::{IssuedToken, RefreshTokenRecord};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sqlx::Row;

use crate::error;
use crate::time::to_nanos;
use crate::{PostgresStorage, SWEEP_BATCH_ROWS};

/// The `payload` column, serialized. See `migrations/0001_core.sql` for why the whole record goes
/// in one jsonb column instead of a column per field.
fn encode<T: Serialize>(op: &'static str, value: &T) -> Result<serde_json::Value, StorageError> {
    serde_json::to_value(value).map_err(|_| error::encode(op))
}

/// The `payload` column, deserialized back into the core's own type.
fn decode<T: DeserializeOwned>(
    op: &'static str,
    value: serde_json::Value,
) -> Result<T, StorageError> {
    serde_json::from_value(value).map_err(|_| error::payload(op))
}

/// Pull the `payload` column out of an optional row and decode it. Every read in this file ends
/// here, including the `take_*` ones, which is what keeps "what the store returns" identical
/// whether the row was read or removed.
fn payload_of<T: DeserializeOwned>(
    op: &'static str,
    row: Option<sqlx::postgres::PgRow>,
) -> Result<Option<T>, StorageError> {
    match row {
        Some(row) => {
            let raw: serde_json::Value = row.try_get("payload").map_err(|e| error::db(op, e))?;
            decode(op, raw).map(Some)
        }
        None => Ok(None),
    }
}

/// The same, for the PURE READS, which the trait has hand back `Arc<T>`.
///
/// The trait's own note is honest about what this costs a SQL-backed store: the record is built
/// per query anyway, so the `Arc` is ONE extra allocation on a path that has already done a
/// network round trip. It is the `take_*` half of the split that carries meaning here, and it is
/// unchanged: a taken record is owned, because there is nothing left in the store for a second
/// pointer to point at, which is what makes "exactly one caller got it" expressible in the type.
fn payload_arc_of<T: DeserializeOwned>(
    op: &'static str,
    row: Option<sqlx::postgres::PgRow>,
) -> Result<Option<std::sync::Arc<T>>, StorageError> {
    Ok(payload_of::<T>(op, row)?.map(std::sync::Arc::new))
}

/// The resource owner who APPROVED a device grant, if any.
///
/// `Pending` and `Denied` deliberately map to `NULL`: the trait's `revoke_consent` must reach a
/// grant the user approved but the device has not polled for, and must LEAVE A PENDING ONE
/// ALONE, because nobody has consented to it yet and killing it would end a login the user may be
/// in the middle of.
fn approved_subject(state: &DeviceGrantState) -> Option<&str> {
    match state {
        DeviceGrantState::Approved { subject } => Some(subject.as_str()),
        DeviceGrantState::Pending | DeviceGrantState::Denied => None,
    }
}

/// The advisory-lock key naming one revocable identity.
///
/// Three things make this unambiguous, and all three are load bearing, because two identities
/// that collapsed onto one key would over-serialise (harmless) while one identity that split into
/// two keys would let the revocation and the write miss each other entirely (the defect these
/// exist to close):
///
/// - The SCOPE PREFIX, so a client id and a family id that happen to be the same string are
///   different keys. A `family` barrier refuses unconditionally and a `client` barrier does not,
///   so they are not interchangeable.
/// - The LENGTH PREFIX on every variable part, so ("ab", "c") and ("a", "bc") cannot produce one
///   key. A separator character would need a character that cannot occur in a client id or a
///   subject, and this crate does not get to promise that about strings a host supplies.
/// - Hashing to a `bigint` happens in the DATABASE, with `hashtextextended`, so every node agrees
///   on the key without this crate having to pin a hash function of its own across Rust versions.
///   A collision between two UNRELATED identities costs one of them a brief wait and nothing else,
///   which is the right direction to fail.
fn scope_key(scope: &str, parts: [&str; 2]) -> String {
    let [first, second] = parts;
    format!("{scope}:{}:{first}:{}:{second}", first.len(), second.len())
}

/// Take the SHARED half of the barrier lock, for a write a revocation could refuse.
///
/// Called first thing inside the transaction that checks the barrier and then writes, and held
/// until that transaction ends. It names every identity a barrier could cover this record by: the
/// client always, the family when the record has one, and the (client, subject) pair when it names
/// a resource owner. That mirrors, key for key, the three-way `OR` in [`barrier_covers`].
///
/// SHARED, not exclusive, and that is the difference between a correct store and an unusable one.
/// Correctness needs mutual exclusion between a write and a REVOCATION, not between two writes:
/// two `put_token`s racing each other cannot resurrect anything, because neither of them records a
/// barrier. An exclusive lock here would put every token this deployment issues for one client
/// through one queue, at one transaction each. A shared lock lets them all through together and
/// makes only a revocation of that exact identity wait.
///
/// ONE STATEMENT over an array, rather than one statement per key. Lock ORDER does not matter
/// here and cannot deadlock: a shared lock waits only on an exclusive holder, the exclusive side
/// below takes exactly ONE of these locks per revocation, and nothing that holds one ever waits on
/// a lock a writer holds — a writer holds no row locks at the point it takes these, because it has
/// not written anything yet. So there is no cycle to form in either direction.
async fn lock_barrier_scopes(
    op: &'static str,
    tx: &mut sqlx::PgConnection,
    client_id: &str,
    family_id: Option<&str>,
    subject: Option<&str>,
) -> Result<(), StorageError> {
    let mut keys = vec![scope_key("client", [client_id, ""])];
    if let Some(family_id) = family_id {
        keys.push(scope_key("family", [family_id, ""]));
    }
    if let Some(subject) = subject {
        keys.push(scope_key("consent", [client_id, subject]));
    }
    sqlx::query(
        "SELECT pg_advisory_xact_lock_shared(hashtextextended(k, 0)) \
         FROM unnest($1::text[]) AS t(k)",
    )
    .bind(&keys)
    .execute(&mut *tx)
    .await
    .map_err(|e| error::db(op, e))?;
    Ok(())
}

/// Take the EXCLUSIVE half, for a revocation, BEFORE it records its barrier.
///
/// Whichever side wins is then a whole revocation or a whole write, never half of each: a write
/// that got here first has already committed its row by the time the cascade runs, so the cascade
/// removes it; a revocation that got here first has already committed its barrier by the time the
/// write's refusal check takes its snapshot, so the check refuses. Transaction scoped, so it is
/// released by the same commit or rollback that ends the removals.
async fn lock_barrier_scope_exclusive(
    op: &'static str,
    tx: &mut sqlx::PgConnection,
    key: &str,
) -> Result<(), StorageError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(key)
        .execute(&mut *tx)
        .await
        .map_err(|e| error::db(op, e))?;
    Ok(())
}

/// Record a revocation barrier, on the CALLER'S transaction.
///
/// Taking `&mut PgConnection` rather than the pool is the whole point: every caller is already
/// inside the transaction that does the removals, and the barrier has to commit or roll back with
/// them. A barrier written on its own connection would leave a window in which the records are
/// gone and nothing refuses the writes that put them back, which is the defect this exists to
/// close, reintroduced one level down.
///
/// The upsert EXTENDS an existing deadline and never shortens it: a second revocation of the same
/// scope is a second reason to refuse, so the later deadline wins.
async fn record_barrier(
    op: &'static str,
    tx: &mut sqlx::PgConnection,
    scope: &str,
    client_id: Option<&str>,
    family_id: Option<&str>,
    subject: Option<&str>,
    window: oauth_as::store::RevocationWindow,
) -> Result<(), StorageError> {
    sqlx::query(
        "INSERT INTO oauth_as_revocation_barriers \
             (scope, client_id, family_id, subject, expires_at_ns, recorded_at_ns) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (scope, client_id, family_id, subject) \
         DO UPDATE SET expires_at_ns = GREATEST( \
             oauth_as_revocation_barriers.expires_at_ns, EXCLUDED.expires_at_ns), \
             recorded_at_ns = GREATEST( \
             oauth_as_revocation_barriers.recorded_at_ns, EXCLUDED.recorded_at_ns)",
    )
    .bind(scope)
    // `''` for "not applicable", matching the schema: see `0005_revocation_barriers.sql` on why
    // the columns are NOT NULL rather than nullable.
    .bind(client_id.unwrap_or(""))
    .bind(family_id.unwrap_or(""))
    .bind(subject.unwrap_or(""))
    .bind(to_nanos(window.until))
    // Both GREATEST, and for different reasons: the deadline must never shorten, and
    // `recorded_at` must name the MOST RECENT revocation, because a grant established between two
    // revocations is one the second was entitled to kill.
    .bind(to_nanos(window.recorded_at))
    .execute(&mut *tx)
    .await
    .map_err(|e| error::db(op, e))?;
    Ok(())
}

/// THE RESURRECTION PREDICATE, in SQL. One query, three scopes, one round trip.
///
/// Written once and called from all three writes a barrier can cover — `put_token`,
/// `put_refresh_token` and `put_pushed_authorization_request` — rather than inlined into each: the
/// core crate's `MemoryStorage` has exactly one copy of this too, and the reason is the
/// defect that shipped in 0.9.0, where the same operation existed at three seams and the
/// hand-rolled copy was the one that failed open.
///
/// `EXISTS` with the three-way `OR` rather than three statements, because it must be ONE step with
/// the insert that follows it, and both live in the caller's transaction.
///
/// Note that an EXPIRED barrier still refuses here: the filter is on scope, not on
/// `expires_at_ns`. That matches `MemoryStorage` and it is the safe direction, since the deadline
/// is when the barrier may be RECLAIMED by the sweep, not when it stops meaning anything.
async fn barrier_covers(
    op: &'static str,
    tx: &mut sqlx::PgConnection,
    client_id: &str,
    family_id: Option<&str>,
    subject: Option<&str>,
    grant_established_at: std::time::SystemTime,
) -> Result<bool, StorageError> {
    // A record with no family or no subject binds `''`, which cannot match a stored barrier: the
    // schema forbids an empty `family_id` on a 'family' row and an empty `subject` on a 'consent'
    // row, because this crate never mints an empty one. So the `''` sentinel does the work an
    // `IS NOT NULL` guard would have, without a nullable bind.
    let row = sqlx::query(
        "SELECT EXISTS ( \
             SELECT 1 FROM oauth_as_revocation_barriers WHERE \
                 (scope = 'client'  AND client_id = $1 AND recorded_at_ns >= $4) \
              OR (scope = 'family'  AND family_id = $2) \
              OR (scope = 'consent' AND client_id = $1 AND subject = $3 \
                                    AND recorded_at_ns >= $4) \
         ) AS covered",
    )
    .bind(client_id)
    .bind(family_id.unwrap_or(""))
    .bind(subject.unwrap_or(""))
    .bind(to_nanos(grant_established_at))
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| error::db(op, e))?;
    row.try_get("covered").map_err(|e| error::db(op, e))
}

impl Storage for PostgresStorage {
    async fn get_client(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<std::sync::Arc<Client>>, StorageError> {
        const OP: &str = "get_client";
        let row = sqlx::query("SELECT payload FROM oauth_as_clients WHERE client_id = $1")
            .bind(client_id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| error::db(OP, e))?;
        payload_arc_of(OP, row)
    }

    async fn put_client(&self, client: Client) -> Result<(), StorageError> {
        const OP: &str = "put_client";
        let payload = encode(OP, &client)?;
        sqlx::query(
            "INSERT INTO oauth_as_clients (client_id, payload) VALUES ($1, $2) \
             ON CONFLICT (client_id) DO UPDATE SET payload = EXCLUDED.payload",
        )
        .bind(client.client_id.as_str())
        .bind(payload)
        .execute(&self.pool)
        .await
        .map_err(|e| error::db(OP, e))?;
        Ok(())
    }

    /// `UPDATE ... WHERE`, which cannot create a row. That is the entire contract: absence is what
    /// `delete_client` leaves, and an upsert here would put a deleted registration back with its
    /// old credential and its old registration access token hash.
    ///
    /// The comparison is made in SQL, against the stored `payload`, so the read and the write are
    /// ONE statement and no window exists between them. Comparing the serialized document rather
    /// than a revision column is what the trait asks for and it needs no schema of its own; it
    /// relies on this crate's `encode` being deterministic for a given record, which it is,
    /// because `serde_json` writes struct fields in declaration order.
    async fn compare_and_swap_client(
        &self,
        expected: &Client,
        updated: Client,
    ) -> Result<bool, StorageError> {
        const OP: &str = "compare_and_swap_client";
        let expected_payload = encode(OP, expected)?;
        let updated_payload = encode(OP, &updated)?;
        let affected = sqlx::query(
            "UPDATE oauth_as_clients SET payload = $3 \
             WHERE client_id = $1 AND payload = $2",
        )
        .bind(updated.client_id.as_str())
        .bind(expected_payload)
        .bind(updated_payload)
        .execute(&self.pool)
        .await
        .map_err(|e| error::db(OP, e))?
        .rows_affected();
        Ok(affected == 1)
    }

    /// ONE TRANSACTION, because the trait says so and says why: RFC 7592 section 2.3 deletes a
    /// registration and invalidates what that registration holds, and a delete that half
    /// succeeded is either an orphaned credential set that can still call resource servers or a
    /// registration nobody can reach.
    ///
    /// IT IS NOW A KILL SWITCH, and this doc used to say the opposite. It said a grant that read
    /// the registration before this committed still writes its token after, and that no store
    /// could close that window. The barrier recorded below closes it: the token that grant is
    /// about to write is refused by `put_token`, because the barrier commits in the SAME
    /// transaction as the deletions and every later write consults it.
    async fn delete_client(
        &self,
        client_id: &ClientId,
        window: oauth_as::store::RevocationWindow,
    ) -> Result<bool, StorageError> {
        const OP: &str = "delete_client";
        let id = client_id.as_str();
        let mut tx = self.begin(OP).await?;
        // BEFORE the barrier and the cascade, so an in-flight write for this client is either
        // wholly before this transaction (and the cascade below removes what it wrote) or wholly
        // after it (and its own refusal check sees the barrier). See `lock_barrier_scopes`.
        lock_barrier_scope_exclusive(OP, &mut tx, &scope_key("client", [id, ""])).await?;
        record_barrier(OP, &mut tx, "client", Some(id), None, None, window).await?;

        // A consent names a client that no longer exists; leaving it would show a user an
        // application they cannot revoke, on a registration nothing can reach.
        //
        // FIRST, AND THAT ORDER IS LOAD-BEARING. `revoke_consent` claims its consent row before
        // it cascades into the token tables, and its advisory key (`consent`) is deliberately a
        // different one from this method's (`client`), so nothing serialises the two. Cascading
        // into tokens before reaching consents would have this transaction hold a token row while
        // waiting for a consent row a concurrent withdrawal holds, and that withdrawal waiting for
        // the token row this one holds: PostgreSQL breaks the cycle with `40P01`, and the loser's
        // REVOCATION fails, reaching the caller as `server_error`. Both methods now touch
        // `oauth_as_consents` before `oauth_as_access_tokens`, so the second one queues behind the
        // first instead of closing a cycle with it. `tests/revocation_races.rs`'s
        // `a_client_deletion_and_a_consent_withdrawal_do_not_deadlock` forces the interleaving.
        #[cfg(feature = "consent")]
        sqlx::query("DELETE FROM oauth_as_consents WHERE client_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| error::db(OP, e))?;

        // "Everything it was issued", per the trait: access tokens, refresh records, device
        // grants (the user-code index goes with the row, it is a column of it) and authorization
        // codes. The order among THESE does not matter, because no other revocation reaches them
        // in a different one; the transaction is what makes it one event.
        for stmt in [
            "DELETE FROM oauth_as_access_tokens WHERE client_id = $1",
            "DELETE FROM oauth_as_refresh_tokens WHERE client_id = $1",
            "DELETE FROM oauth_as_authorization_codes WHERE client_id = $1",
            "DELETE FROM oauth_as_device_grants WHERE client_id = $1",
        ] {
            sqlx::query(stmt)
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(|e| error::db(OP, e))?;
        }
        // RFC 9126 s2.2 binds a request_uri to the client that pushed it, so a deleted client's
        // outstanding handles are handles nobody may ever redeem.
        #[cfg(feature = "par")]
        sqlx::query("DELETE FROM oauth_as_pushed_requests WHERE client_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| error::db(OP, e))?;
        let existed = sqlx::query("DELETE FROM oauth_as_clients WHERE client_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| error::db(OP, e))?
            .rows_affected()
            > 0;
        tx.commit().await.map_err(|e| error::db(OP, e))?;
        // Removing a client that is already gone is Ok(false), not an error: the credentials of a
        // client that does not exist are still worth removing, so the cascade above runs either
        // way.
        Ok(existed)
    }

    /// The upsert, and both of the trait's extra requirements, in ONE statement.
    ///
    /// Requirement 2 (a put that CHANGES the user code retires the old index entry) is satisfied
    /// by the shape of the schema rather than by code: the index entry IS the
    /// `user_code_normalized` column of this row, so `DO UPDATE SET user_code_normalized = ...`
    /// retires the old value by overwriting it.
    ///
    /// Requirement 1 (a user code already indexed for a DIFFERENT `device_code` must be REFUSED,
    /// writing nothing) is satisfied by the UNIQUE index, which means the DATABASE decides. That
    /// matters for the same reason the `take_*` methods do: the server's user-code collision
    /// retry loop asks the store whether a code is taken, and only the store can answer that
    /// without a race. A `SELECT` first would let two nodes generating the same code both be told
    /// it was free. The refusal writes nothing because a failed statement is rolled back whole.
    async fn put_device_grant(&self, grant: DeviceGrant) -> Result<(), StorageError> {
        const OP: &str = "put_device_grant";
        // The trait: lookups are by NORMALIZED code and the store indexes what it is GIVEN. The
        // server normalizes before it calls in; this is the same function it uses, applied to
        // what is being written, never to what is being looked up.
        let normalized = oauth_as::device::normalize_user_code(&grant.user_code);
        let payload = encode(OP, &grant)?;
        let result = sqlx::query(
            "INSERT INTO oauth_as_device_grants \
                 (device_code, user_code_normalized, client_id, approved_subject, \
                  expires_at_ns, payload) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (device_code) DO UPDATE SET \
                 user_code_normalized = EXCLUDED.user_code_normalized, \
                 client_id            = EXCLUDED.client_id, \
                 approved_subject     = EXCLUDED.approved_subject, \
                 expires_at_ns        = EXCLUDED.expires_at_ns, \
                 payload              = EXCLUDED.payload",
        )
        .bind(&grant.device_code)
        .bind(&normalized)
        .bind(grant.client_id.as_str())
        .bind(approved_subject(&grant.state))
        .bind(to_nanos(grant.expires_at))
        .bind(payload)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            // RFC 8628 s6.1: the user code is the credential a human types, so two live grants
            // answering to one code is two devices sharing an identity. Reported as a refusal
            // rather than as an outage, because the trait requires this specific failure and the
            // server acts on it.
            Err(e) if error::is_unique_violation(&e, "oauth_as_device_grants_user_code_key") => {
                Err(StorageError::new(
                    "oauth-as-postgres: user code is already indexed for a different device_code",
                ))
            }
            Err(e) => Err(error::db(OP, e)),
        }
    }

    async fn get_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        const OP: &str = "get_device_grant";
        let row = sqlx::query("SELECT payload FROM oauth_as_device_grants WHERE device_code = $1")
            .bind(device_code)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| error::db(OP, e))?;
        payload_of(OP, row)
    }

    async fn find_device_grant_by_user_code(
        &self,
        normalized_user_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        const OP: &str = "find_device_grant_by_user_code";
        // Matched EXACTLY, with no `lower()` and no hyphen stripping. The trait: the store
        // indexes what it is given and does not normalize. A store that normalized here would
        // silently accept the display form, which is precisely the input an attacker controls.
        let row = sqlx::query(
            "SELECT payload FROM oauth_as_device_grants WHERE user_code_normalized = $1",
        )
        .bind(normalized_user_code)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| error::db(OP, e))?;
        payload_of(OP, row)
    }

    /// ONE conditional statement, in the same spirit as the `DELETE ... RETURNING` above: the
    /// database performs the comparison and the write together and decides the winner, so RFC 8628
    /// section 3.3's first-decision-wins guarantee holds across as many AS processes as a
    /// deployment runs. That is the whole reason this override exists: this store is BY DEFINITION
    /// the shared, multi-process case, so it is exactly the deployment a read-compare-write cannot
    /// serve.
    ///
    /// `UPDATE`, NOT `INSERT ... ON CONFLICT`, and that is load bearing rather than incidental. An
    /// `UPDATE` cannot create a row. A grant redeemed by `take_device_grant` while this statement
    /// was on its way therefore leaves nothing to update, `rows_affected` is 0, and the answer is
    /// `Ok(false)`, which is what the trait requires: a swap must never bring a redeemed grant
    /// back, because an RFC 8628 device code that has been exchanged for a token must not become
    /// exchangeable a second time. DO NOT "helpfully" turn this into an upsert to share the shape
    /// of `put_device_grant`; that would reinstate exactly that defect, silently, and no test that
    /// runs on one node would notice.
    ///
    /// The comparison is against `payload -> 'state'` rather than a dedicated column. The state is
    /// already in the payload, JSONB equality is structural, and adding a column would put the same
    /// fact in two places with nothing keeping them equal.
    async fn compare_and_swap_device_grant(
        &self,
        expected: &oauth_as::DeviceGrantState,
        updated: DeviceGrant,
    ) -> Result<bool, StorageError> {
        const OP: &str = "compare_and_swap_device_grant";
        let normalized = oauth_as::device::normalize_user_code(&updated.user_code);
        let expected_json = encode(OP, expected)?;
        let payload = encode(OP, &updated)?;
        let result = sqlx::query(
            "UPDATE oauth_as_device_grants SET \
                 user_code_normalized = $2, \
                 client_id            = $3, \
                 approved_subject     = $4, \
                 expires_at_ns        = $5, \
                 payload              = $6 \
             WHERE device_code = $1 AND payload -> 'state' = $7",
        )
        .bind(&updated.device_code)
        .bind(&normalized)
        .bind(updated.client_id.as_str())
        .bind(approved_subject(&updated.state))
        .bind(to_nanos(updated.expires_at))
        .bind(payload)
        .bind(expected_json)
        .execute(&self.pool)
        .await;

        match result {
            Ok(done) => Ok(done.rows_affected() > 0),
            // The same refusal `put_device_grant` gives, for the same RFC 8628 s6.1 reason: this
            // statement can move a grant onto a user code another live grant already holds, and
            // the unique index is what stops two devices sharing one human-typed credential.
            Err(e) if error::is_unique_violation(&e, "oauth_as_device_grants_user_code_key") => {
                Err(StorageError::new(
                    "oauth-as-postgres: user code is already indexed for a different device_code",
                ))
            }
            Err(e) => Err(error::db(OP, e)),
        }
    }

    /// ATOMIC remove-and-return, RFC 8628 single-use redemption. One statement: the database
    /// decides which of N concurrent polls receives the grant, and the user-code index goes with
    /// it because the index is a column of the row being deleted.
    async fn take_device_grant(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceGrant>, StorageError> {
        const OP: &str = "take_device_grant";
        let row = sqlx::query(
            "DELETE FROM oauth_as_device_grants WHERE device_code = $1 RETURNING payload",
        )
        .bind(device_code)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| error::db(OP, e))?;
        payload_of(OP, row)
    }

    async fn put_authorization_code(
        &self,
        record: AuthorizationCodeRecord,
    ) -> Result<(), StorageError> {
        const OP: &str = "put_authorization_code";
        let payload = encode(OP, &record)?;
        sqlx::query(
            "INSERT INTO oauth_as_authorization_codes \
                 (code, client_id, subject, expires_at_ns, payload) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (code) DO UPDATE SET \
                 client_id     = EXCLUDED.client_id, \
                 subject       = EXCLUDED.subject, \
                 expires_at_ns = EXCLUDED.expires_at_ns, \
                 payload       = EXCLUDED.payload",
        )
        .bind(&record.code)
        .bind(record.client_id.as_str())
        .bind(&record.subject)
        .bind(to_nanos(record.expires_at))
        .bind(payload)
        .execute(&self.pool)
        .await
        .map_err(|e| error::db(OP, e))?;
        Ok(())
    }

    /// ATOMIC remove-and-return. If two nodes could both take the same `Issued` record, both
    /// would mint and both would write back `Consumed`, last write wins, and the server would
    /// believe the code was spent once: RFC 6749 s4.1.2 replay detection silently disabled.
    async fn take_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCodeRecord>, StorageError> {
        const OP: &str = "take_authorization_code";
        let row = sqlx::query(
            "DELETE FROM oauth_as_authorization_codes WHERE code = $1 RETURNING payload",
        )
        .bind(code)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| error::db(OP, e))?;
        payload_of(OP, row)
    }

    #[cfg(feature = "par")]
    async fn put_pushed_authorization_request(
        &self,
        record: oauth_as::par::PushedAuthorizationRequest,
    ) -> Result<WriteOutcome, StorageError> {
        const OP: &str = "put_pushed_authorization_request";
        let payload = encode(OP, &record)?;
        // The check and the write are ONE TRANSACTION and under the barrier lock, exactly as for
        // the two token writes: a look on one connection followed by an insert on another leaves
        // the window this exists to close, and one transaction alone does not close it either at
        // READ COMMITTED. A pushed request carries no family and no subject, so only the client
        // scope can cover it, and only that key is locked.
        let mut tx = self.begin(OP).await?;
        lock_barrier_scopes(OP, &mut tx, record.client_id.as_str(), None, None).await?;
        if barrier_covers(
            OP,
            &mut tx,
            record.client_id.as_str(),
            None,
            None,
            record.pushed_at,
        )
        .await?
        {
            tx.rollback().await.map_err(|e| error::db(OP, e))?;
            return Ok(WriteOutcome::RefusedRevoked);
        }
        sqlx::query(
            "INSERT INTO oauth_as_pushed_requests \
                 (request_uri, client_id, expires_at_ns, payload) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (request_uri) DO UPDATE SET \
                 client_id     = EXCLUDED.client_id, \
                 expires_at_ns = EXCLUDED.expires_at_ns, \
                 payload       = EXCLUDED.payload",
        )
        .bind(&record.request_uri)
        .bind(record.client_id.as_str())
        .bind(to_nanos(record.expires_at))
        .bind(payload)
        .execute(&mut *tx)
        .await
        .map_err(|e| error::db(OP, e))?;
        tx.commit().await.map_err(|e| error::db(OP, e))?;
        Ok(WriteOutcome::Applied)
    }

    /// ATOMIC remove-and-return. RFC 9126 s4 says a client MUST use a `request_uri` once and s7.3
    /// asks the server to ENFORCE it rather than trust it, which it can only do if the store
    /// hands the handle to exactly one caller.
    #[cfg(feature = "par")]
    async fn take_pushed_authorization_request(
        &self,
        request_uri: &str,
    ) -> Result<Option<oauth_as::par::PushedAuthorizationRequest>, StorageError> {
        const OP: &str = "take_pushed_authorization_request";
        let row = sqlx::query(
            "DELETE FROM oauth_as_pushed_requests WHERE request_uri = $1 RETURNING payload",
        )
        .bind(request_uri)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| error::db(OP, e))?;
        payload_of(OP, row)
    }

    /// `UPDATE ... WHERE`, which cannot create a row, comparing the SERIALIZED state so the read
    /// and the write are one statement. Absence refuses, which is what keeps a code that
    /// `delete_client` or `revoke_consent` cascaded away from being reinstated by a redemption
    /// that started before the cascade.
    ///
    /// THE WHOLE PROJECTION IS WRITTEN, not just the payload, exactly as
    /// `compare_and_swap_device_grant` above writes its whole projection. Through 0.9.1 this
    /// statement set `payload` alone and left `client_id`, `subject` and `expires_at_ns` holding
    /// the REPLACED record's values, which made them a second source of truth rather than the
    /// projection `0001_core.sql` says they are, and two readers key on the columns: the
    /// `revoke_consent` cascade (`WHERE client_id = $1 AND subject = $2`), so a code whose payload
    /// named a subject the swap moved it to survived that subject's withdrawal, and `sweep_expired`
    /// (`WHERE expires_at_ns <= $1`), so a code was reclaimed on a deadline its payload no longer
    /// carried. `AuthorizationServer` never reached it because the only field it ever swaps is
    /// `state`; a host driving `Storage` directly, which is what this crate exists for, did.
    /// `tests/persisted_shape.rs` holds both halves.
    async fn compare_and_swap_authorization_code(
        &self,
        expected: &oauth_as::authorization::AuthorizationCodeState,
        updated: AuthorizationCodeRecord,
    ) -> Result<bool, StorageError> {
        const OP: &str = "compare_and_swap_authorization_code";
        let expected_state = encode(OP, expected)?;
        let payload = encode(OP, &updated)?;
        let affected = sqlx::query(
            "UPDATE oauth_as_authorization_codes SET \
                 client_id     = $3, \
                 subject       = $4, \
                 expires_at_ns = $5, \
                 payload       = $6 \
             WHERE code = $1 AND payload -> 'state' = $2",
        )
        .bind(&updated.code)
        .bind(expected_state)
        .bind(updated.client_id.as_str())
        .bind(&updated.subject)
        .bind(to_nanos(updated.expires_at))
        .bind(payload)
        .execute(&self.pool)
        .await
        .map_err(|e| error::db(OP, e))?
        .rows_affected();
        Ok(affected == 1)
    }

    /// The check and the write are ONE TRANSACTION, which is what the trait requires of them: a
    /// look on one connection followed by an insert on another leaves exactly the window this
    /// method exists to close, and a revocation committing inside it would be undone by the
    /// insert.
    async fn put_token(&self, token: IssuedToken) -> Result<WriteOutcome, StorageError> {
        const OP: &str = "put_token";
        let payload = encode(OP, &token)?;
        let mut tx = self.begin(OP).await?;
        // BEFORE the check, so that no revocation of this token's client, family or consent can
        // commit between the check and the insert below. See `lock_barrier_scopes`.
        lock_barrier_scopes(
            OP,
            &mut tx,
            token.client_id.as_str(),
            token.family_id.as_deref(),
            token.subject.as_deref(),
        )
        .await?;
        if barrier_covers(
            OP,
            &mut tx,
            token.client_id.as_str(),
            token.family_id.as_deref(),
            token.subject.as_deref(),
            token.grant_established_at,
        )
        .await?
        {
            // Rolled back rather than committed: nothing was written, and saying so explicitly
            // costs one round trip on a path that is already refusing a request.
            tx.rollback().await.map_err(|e| error::db(OP, e))?;
            return Ok(WriteOutcome::RefusedRevoked);
        }
        sqlx::query(
            "INSERT INTO oauth_as_access_tokens \
                 (access_token, client_id, subject, family_id, expires_at_ns, payload) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (access_token) DO UPDATE SET \
                 client_id     = EXCLUDED.client_id, \
                 subject       = EXCLUDED.subject, \
                 family_id     = EXCLUDED.family_id, \
                 expires_at_ns = EXCLUDED.expires_at_ns, \
                 payload       = EXCLUDED.payload",
        )
        .bind(&token.access_token)
        .bind(token.client_id.as_str())
        .bind(token.subject.as_deref())
        .bind(token.family_id.as_deref())
        .bind(to_nanos(token.expires_at))
        .bind(payload)
        .execute(&mut *tx)
        .await
        .map_err(|e| error::db(OP, e))?;
        tx.commit().await.map_err(|e| error::db(OP, e))?;
        Ok(WriteOutcome::Applied)
    }

    async fn get_token(
        &self,
        access_token: &str,
    ) -> Result<Option<std::sync::Arc<IssuedToken>>, StorageError> {
        const OP: &str = "get_token";
        let row = sqlx::query("SELECT payload FROM oauth_as_access_tokens WHERE access_token = $1")
            .bind(access_token)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| error::db(OP, e))?;
        payload_arc_of(OP, row)
    }

    /// Idempotent: RFC 7009 s2.2 says an invalid token does not cause an error response, so a
    /// repeated revocation (which a client is entitled to send) must not fail. A `DELETE` that
    /// matches nothing is `Ok` in SQL too, so there is nothing to special-case.
    async fn delete_token(&self, access_token: &str) -> Result<(), StorageError> {
        const OP: &str = "delete_token";
        sqlx::query("DELETE FROM oauth_as_access_tokens WHERE access_token = $1")
            .bind(access_token)
            .execute(&self.pool)
            .await
            .map_err(|e| error::db(OP, e))?;
        Ok(())
    }

    /// Same one transaction as `put_token`, and it carries more here: this is the write every
    /// refusal path of a rotation makes, on a record `take_refresh_token` has already removed.
    async fn put_refresh_token(
        &self,
        record: RefreshTokenRecord,
    ) -> Result<WriteOutcome, StorageError> {
        const OP: &str = "put_refresh_token";
        let payload = encode(OP, &record)?;
        let mut tx = self.begin(OP).await?;
        lock_barrier_scopes(
            OP,
            &mut tx,
            record.client_id.as_str(),
            Some(&record.family_id),
            record.subject.as_deref(),
        )
        .await?;
        if barrier_covers(
            OP,
            &mut tx,
            record.client_id.as_str(),
            Some(&record.family_id),
            record.subject.as_deref(),
            record.grant_established_at,
        )
        .await?
        {
            tx.rollback().await.map_err(|e| error::db(OP, e))?;
            return Ok(WriteOutcome::RefusedRevoked);
        }
        sqlx::query(
            "INSERT INTO oauth_as_refresh_tokens \
                 (refresh_token, client_id, subject, family_id, expires_at_ns, payload) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (refresh_token) DO UPDATE SET \
                 client_id     = EXCLUDED.client_id, \
                 subject       = EXCLUDED.subject, \
                 family_id     = EXCLUDED.family_id, \
                 expires_at_ns = EXCLUDED.expires_at_ns, \
                 payload       = EXCLUDED.payload",
        )
        .bind(&record.refresh_token)
        .bind(record.client_id.as_str())
        .bind(record.subject.as_deref())
        .bind(&record.family_id)
        // `None` is a chain with no ABSOLUTE lifetime and stays NULL. The sweep must not treat
        // that as "expired at the epoch": doing so logs every such client out.
        .bind(record.expires_at.map(to_nanos))
        .bind(payload)
        .execute(&mut *tx)
        .await
        .map_err(|e| error::db(OP, e))?;
        tx.commit().await.map_err(|e| error::db(OP, e))?;
        Ok(WriteOutcome::Applied)
    }

    /// A read that does NOT remove, and the trait explains why it has to exist: RFC 7009 s2.1
    /// requires revocation to verify the token was issued to the requesting client, and doing
    /// that by taking the record and putting it back on a mismatch is a destructive operation on
    /// a credential the caller was never entitled to touch.
    async fn get_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<std::sync::Arc<RefreshTokenRecord>>, StorageError> {
        const OP: &str = "get_refresh_token";
        let row =
            sqlx::query("SELECT payload FROM oauth_as_refresh_tokens WHERE refresh_token = $1")
                .bind(refresh_token)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| error::db(OP, e))?;
        payload_arc_of(OP, row)
    }

    /// ATOMIC remove-and-return, and THE one that matters most. This is what makes rotation
    /// single use. A read-then-delete here lets a thief and the honest client both rotate the
    /// same token: two live chains from one credential, and because the honest client is never
    /// locked out, the RFC 9700 s4.14.2 reuse signal that exists to catch exactly this theft
    /// never fires.
    async fn take_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshTokenRecord>, StorageError> {
        const OP: &str = "take_refresh_token";
        let row = sqlx::query(
            "DELETE FROM oauth_as_refresh_tokens WHERE refresh_token = $1 RETURNING payload",
        )
        .bind(refresh_token)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| error::db(OP, e))?;
        payload_of(OP, row)
    }

    /// ONE TRANSACTION over both tables. RFC 9700 s4.14.2: on detected reuse the AS invalidates
    /// the presented token AND revokes the tokens issued for that authorization grant, so a
    /// half-done revocation leaves the thief holding either the rotated chain or the access
    /// tokens minted along it.
    ///
    /// `family_id IS NOT NULL` on the access token side is load bearing: an RFC 6749 s4.4 client
    /// credentials token has no refresh chain and therefore no family, and SQL's `NULL = $1` is
    /// already false, but the predicate is written out so a reader does not have to remember that
    /// to be sure a bystander is not swept up.
    async fn revoke_token_family(
        &self,
        family_id: &str,
        window: oauth_as::store::RevocationWindow,
    ) -> Result<u64, StorageError> {
        const OP: &str = "revoke_token_family";
        let mut tx = self.begin(OP).await?;
        // BEFORE the barrier and the removals, for the reason `lock_barrier_scopes` gives: a
        // rotation whose refusal check has already run would otherwise write its fresh chain after
        // this transaction committed, and nothing would be left to refuse it.
        lock_barrier_scope_exclusive(OP, &mut tx, &scope_key("family", [family_id, ""])).await?;
        // In the SAME transaction as the removals. The rotation this is racing has already taken
        // its refresh record, so the two DELETEs below cannot see it; the barrier is what refuses
        // the spent record and the fresh chain that rotation is about to write.
        record_barrier(OP, &mut tx, "family", None, Some(family_id), None, window).await?;
        let mut removed = 0u64;
        for stmt in [
            "DELETE FROM oauth_as_access_tokens WHERE family_id IS NOT NULL AND family_id = $1",
            "DELETE FROM oauth_as_refresh_tokens WHERE family_id = $1",
        ] {
            removed += sqlx::query(stmt)
                .bind(family_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| error::db(OP, e))?
                .rows_affected();
        }
        tx.commit().await.map_err(|e| error::db(OP, e))?;
        // Removing records that are already gone is success: this runs on evidence of compromise
        // and must not be turned into an error by a concurrent revocation.
        Ok(removed)
    }

    #[cfg(feature = "consent")]
    async fn put_consent(
        &self,
        record: oauth_as::consent::ConsentRecord,
    ) -> Result<(), StorageError> {
        const OP: &str = "put_consent";
        let payload = encode(OP, &record)?;
        sqlx::query(
            "INSERT INTO oauth_as_consents \
                 (consent_id, client_id, subject, granted_at_ns, payload) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (consent_id) DO UPDATE SET \
                 client_id     = EXCLUDED.client_id, \
                 subject       = EXCLUDED.subject, \
                 granted_at_ns = EXCLUDED.granted_at_ns, \
                 payload       = EXCLUDED.payload",
        )
        .bind(record.consent_id.as_ref())
        .bind(record.client_id.as_str())
        .bind(record.subject.as_ref())
        .bind(to_nanos(record.granted_at))
        .bind(payload)
        .execute(&self.pool)
        .await
        .map_err(|e| error::db(OP, e))?;
        Ok(())
    }

    /// ONE TRANSACTION, and the comparison is against what `find_consent` would answer for the
    /// PAIR rather than against a `consent_id`, exactly as the trait requires: a withdrawal
    /// removes the record the caller read, so a comparison keyed on its id would find nothing to
    /// compare and could not tell "withdrawn" from "never existed".
    ///
    /// TWO locks, because the two halves of this method race differently and a row lock only
    /// covers one of them.
    ///
    /// `SELECT ... FOR UPDATE` locks the row a WIDEN is derived from, which is what stops a
    /// withdrawal landing between the read and the write.
    ///
    /// It does NOT serialise two concurrent CREATES, and an earlier version of this doc claimed
    /// it did. A row lock on a query returning ZERO rows locks nothing, so at the pool's default
    /// READ COMMITTED both transactions see an empty pair, both take the `(None, None)` arm, and
    /// both insert — the pair index is deliberately not `UNIQUE` (see `0003_consent.sql`), so
    /// nothing downstream catches it. The consequence is not untidiness: `revoke_consent`
    /// withdraws ONE `consent_id`, so the surviving duplicate keeps answering `find_consent` and
    /// the user's withdrawal is undone.
    ///
    /// `pg_advisory_xact_lock` over the PAIR closes it. It is keyed on a value rather than a row,
    /// so it serialises when the pair is empty, and it is transaction scoped, so it is released by
    /// the same commit or rollback that ends everything else here. This is what makes the Postgres
    /// store agree with `MemoryStorage`, which serialises both halves under its one mutex.
    #[cfg(feature = "consent")]
    async fn compare_and_swap_consent(
        &self,
        expected: Option<&oauth_as::consent::ConsentRecord>,
        updated: oauth_as::consent::ConsentRecord,
    ) -> Result<bool, StorageError> {
        const OP: &str = "compare_and_swap_consent";
        let mut tx = self.begin(OP).await?;
        // BEFORE the read, so the whole compare-and-swap is inside it.
        //
        // KEYED THROUGH [`scope_key`], the same length-prefixed encoding every barrier lock uses.
        // This built its own key until the 0.9.1 audit, concatenating the pair around a separator
        // its comment called a NUL "which cannot appear in either field" — and neither half was
        // true. The Rust literal `"\\x00"` puts the four CHARACTERS `\`, `x`, `0`, `0` into the
        // SQL, and PostgreSQL `text` cannot hold a NUL byte at all, so the separator the argument
        // rested on was never available and the collision it ruled out was reachable:
        // ("a", "\x00b") and ("a\x00", "b") concatenated to the same string. `scope_key`'s length
        // prefixes are injective without needing a character no host may use, which is the reason
        // its own doc gives for choosing them.
        //
        // A DISTINCT SCOPE PREFIX from the `consent` barrier lock, because these two serialise
        // different things: this one orders two writers of one pair, `lock_barrier_scope_exclusive`
        // orders a revocation against them. Sharing a key would make every CAS wait on every
        // withdrawal for no correctness gain. A hash collision between two UNRELATED pairs costs
        // one of them a brief wait and nothing else, which is the right direction to fail.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(scope_key(
                "consent_cas",
                [updated.client_id.as_str(), &updated.subject],
            ))
            .execute(&mut *tx)
            .await
            .map_err(|e| error::db(OP, e))?;
        let live = sqlx::query(
            "SELECT consent_id, payload FROM oauth_as_consents \
             WHERE client_id = $1 AND subject = $2 \
             ORDER BY granted_at_ns DESC, consent_id DESC LIMIT 1 FOR UPDATE",
        )
        .bind(updated.client_id.as_str())
        .bind(updated.subject.as_ref())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| error::db(OP, e))?;

        let live_record: Option<oauth_as::consent::ConsentRecord> = match &live {
            Some(row) => {
                let raw: serde_json::Value =
                    row.try_get("payload").map_err(|e| error::db(OP, e))?;
                Some(decode(OP, raw)?)
            }
            None => None,
        };
        match (live_record.as_ref(), expected) {
            // Widening what was read, and it is still there unchanged.
            (Some(current), Some(expected)) if current == expected => {}
            // Creating, and the pair still holds nothing.
            (None, None) => {}
            // Withdrawn, replaced, or created underneath the caller.
            _ => {
                tx.rollback().await.map_err(|e| error::db(OP, e))?;
                return Ok(false);
            }
        }

        let payload = encode(OP, &updated)?;
        sqlx::query(
            "INSERT INTO oauth_as_consents \
                 (consent_id, client_id, subject, granted_at_ns, payload) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (consent_id) DO UPDATE SET \
                 client_id     = EXCLUDED.client_id, \
                 subject       = EXCLUDED.subject, \
                 granted_at_ns = EXCLUDED.granted_at_ns, \
                 payload       = EXCLUDED.payload",
        )
        .bind(updated.consent_id.as_ref())
        .bind(updated.client_id.as_str())
        .bind(updated.subject.as_ref())
        .bind(to_nanos(updated.granted_at))
        .bind(payload)
        .execute(&mut *tx)
        .await
        .map_err(|e| error::db(OP, e))?;
        tx.commit().await.map_err(|e| error::db(OP, e))?;
        Ok(true)
    }

    #[cfg(feature = "consent")]
    async fn get_consent(
        &self,
        consent_id: &str,
    ) -> Result<Option<std::sync::Arc<oauth_as::consent::ConsentRecord>>, StorageError> {
        const OP: &str = "get_consent";
        let row = sqlx::query("SELECT payload FROM oauth_as_consents WHERE consent_id = $1")
            .bind(consent_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| error::db(OP, e))?;
        payload_arc_of(OP, row)
    }

    /// The (client, subject) lookup, which the trait notes runs on the AUTHORIZATION ENDPOINT'S
    /// path. Indexed, not scanned.
    ///
    /// `ORDER BY granted_at_ns DESC` because the server keeps at most one live consent per pair,
    /// but the STORE does not enforce that (see the index note in `0003_consent.sql`): if a
    /// deployment ever holds two, the answer must be deterministic and must be the one the user
    /// most recently granted, not whichever row the planner reached first. `consent_id` breaks a
    /// tie so the answer is stable even at equal timestamps.
    #[cfg(feature = "consent")]
    async fn find_consent(
        &self,
        client_id: &ClientId,
        subject: &str,
    ) -> Result<Option<std::sync::Arc<oauth_as::consent::ConsentRecord>>, StorageError> {
        const OP: &str = "find_consent";
        let row = sqlx::query(
            "SELECT payload FROM oauth_as_consents WHERE client_id = $1 AND subject = $2 \
             ORDER BY granted_at_ns DESC, consent_id DESC LIMIT 1",
        )
        .bind(client_id.as_str())
        .bind(subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| error::db(OP, e))?;
        payload_arc_of(OP, row)
    }

    #[cfg(feature = "consent")]
    async fn consents_for_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<std::sync::Arc<oauth_as::consent::ConsentRecord>>, StorageError> {
        const OP: &str = "consents_for_subject";
        let rows = sqlx::query("SELECT payload FROM oauth_as_consents WHERE subject = $1")
            .bind(subject)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| error::db(OP, e))?;
        // Order is not specified by the trait; a host that wants one sorts what it gets back.
        rows.into_iter()
            .map(|row| {
                let raw: serde_json::Value =
                    row.try_get("payload").map_err(|e| error::db(OP, e))?;
                decode(OP, raw).map(std::sync::Arc::new)
            })
            .collect()
    }

    /// ONE TRANSACTION, because the trait is explicit that a withdrawal which half succeeded
    /// leaves a user believing they revoked something they did not, "which is the failure this
    /// whole feature exists to prevent".
    ///
    /// The consent row is removed FIRST, with `RETURNING`, so the (client, subject) pair the rest
    /// of the cascade keys on comes from the same statement that claimed the withdrawal. Two
    /// concurrent withdrawals of one consent therefore have exactly one winner, and the loser
    /// answers `Ok(0)`: a user who clicks twice has not made a mistake.
    #[cfg(feature = "consent")]
    async fn revoke_consent(
        &self,
        consent_id: &str,
        window: oauth_as::store::RevocationWindow,
    ) -> Result<u64, StorageError> {
        const OP: &str = "revoke_consent";
        let mut tx = self.begin(OP).await?;
        let row = sqlx::query(
            "DELETE FROM oauth_as_consents WHERE consent_id = $1 RETURNING client_id, subject",
        )
        .bind(consent_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| error::db(OP, e))?;
        let Some(row) = row else {
            // Already withdrawn, or never existed. Both are success; the trait says so.
            tx.commit().await.map_err(|e| error::db(OP, e))?;
            return Ok(0);
        };
        let client_id: String = row.try_get("client_id").map_err(|e| error::db(OP, e))?;
        let subject: String = row.try_get("subject").map_err(|e| error::db(OP, e))?;
        // AFTER the claim rather than before it, because the pair this is keyed on is what the
        // claim returns, and BEFORE the barrier and the cascade, which is where it has to be: see
        // `lock_barrier_scopes`. Taking it here rather than first is safe against deadlock because
        // it is the LAST lock this method takes — a transaction holding it never goes on to wait
        // for the consent row lock taken above, so there is no cycle for two withdrawals of one
        // pair to form.
        //
        // THAT ARGUMENT COVERS THE ADVISORY LOCKS AND TWO WITHDRAWALS, AND NOTHING ELSE. It says
        // nothing about the ROW locks the cascade below goes on to take, or about a concurrent
        // `delete_client`, whose advisory key is a different one — and the 0.9.1 audit found a
        // real `40P01` there. What keeps that closed is the TABLE ORDER: this method reaches
        // `oauth_as_consents` (the claim above) before `oauth_as_access_tokens` (the cascade
        // below), and `delete_client` was reordered to do the same. Anything added to either
        // cascade has to keep that order.
        lock_barrier_scope_exclusive(OP, &mut tx, &scope_key("consent", [&client_id, &subject]))
            .await?;
        // Recorded from the pair the DELETE ... RETURNING just claimed, so the barrier names
        // exactly the relationship that was withdrawn, in the same transaction as the cascade. The
        // loser of two concurrent withdrawals returns above without recording one, which is right:
        // the winner already did.
        record_barrier(
            OP,
            &mut tx,
            "consent",
            Some(&client_id),
            None,
            Some(&subject),
            window,
        )
        .await?;

        let mut removed = 0u64;
        for stmt in [
            "DELETE FROM oauth_as_access_tokens WHERE client_id = $1 AND subject = $2",
            "DELETE FROM oauth_as_refresh_tokens WHERE client_id = $1 AND subject = $2",
            // An unredeemed code is a grant IN FLIGHT: leaving it would let the client mint a
            // token seconds after the user withdrew.
            "DELETE FROM oauth_as_authorization_codes WHERE client_id = $1 AND subject = $2",
            // Approved but not yet polled, for the same reason. `approved_subject` is NULL for a
            // Pending grant, so this predicate cannot reach one: nobody has consented to a
            // pending grant, and killing it would end a login the user may be in the middle of.
            "DELETE FROM oauth_as_device_grants WHERE client_id = $1 AND approved_subject = $2",
        ] {
            removed += sqlx::query(stmt)
                .bind(&client_id)
                .bind(&subject)
                .execute(&mut *tx)
                .await
                .map_err(|e| error::db(OP, e))?
                .rows_affected();
        }
        tx.commit().await.map_err(|e| error::db(OP, e))?;
        // The consent record itself is NOT counted; the trait says so.
        Ok(removed)
    }

    /// ATOMIC claim-if-absent, in ONE statement, decided by the PRIMARY KEY.
    ///
    /// RFC 7523 s3 makes a client assertion's `jti` single use and RFC 9449 s4.3 makes a DPoP
    /// proof's `jti` single use. `ON CONFLICT DO NOTHING` with `RETURNING` gives back a row only
    /// when THIS statement inserted it, so "was I first?" is answered by the index rather than by
    /// a read this crate performed a round trip earlier. A read-then-write would tell two
    /// concurrent presentations of the SAME assertion that each was first, and nothing anywhere
    /// would record that it happened.
    ///
    /// An id that is present but EXPIRED counts as claimed, which the trait leaves to the store's
    /// discretion and calls the conservative reading. `MemoryStorage` does the same, and letting
    /// the sweep do the reclaiming keeps the two implementations answering alike.
    #[cfg(any(feature = "client-assertion", feature = "dpop"))]
    async fn claim_replay_id(
        &self,
        id: &str,
        expires_at: std::time::SystemTime,
    ) -> Result<bool, StorageError> {
        const OP: &str = "claim_replay_id";
        let row = sqlx::query(
            "INSERT INTO oauth_as_replay_ids (id, expires_at_ns) VALUES ($1, $2) \
             ON CONFLICT (id) DO NOTHING RETURNING id",
        )
        .bind(id)
        .bind(to_nanos(expires_at))
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| error::db(OP, e))?;
        Ok(row.is_some())
    }

    /// IN BATCHES, each one its own committed statement, looping per table until the table has
    /// nothing left that is dead at `now`.
    ///
    /// WHY NOT ONE UNBOUNDED `DELETE` PER TABLE, which is what this was through 0.9.0. That form
    /// takes a row lock on every dead row and holds all of them until the statement finishes, so a
    /// table with millions of dead rows blocks the redemptions that touch them for as long as the
    /// scan runs, and it is a single write transaction whose WAL record and dead-tuple bloat both
    /// arrive in one lump. The work is the same either way; what batching changes is the size of
    /// the window during which the store is holding it. [`SWEEP_BATCH_ROWS`] is the size of that
    /// window.
    ///
    /// WHY THE TRANSACTION IS GONE, and why that is not a weakening. It never bought atomicity
    /// anybody could observe: every row this removes is one the server ALREADY refuses on time
    /// alone (expiry is enforced on read, which is why an unswept store is unbounded rather than
    /// insecure), so a reader cannot tell a half-finished sweep from a finished one except by
    /// counting rows nothing is allowed to hand out. Keeping one transaction around a batched
    /// sweep would also defeat the batching exactly: locks are released at COMMIT, so batches
    /// inside one transaction hold every lock to the end just as the single statement did.
    ///
    /// THE COUNT STAYS TRUTHFUL, which the trait requires: it is the sum of the rows this call
    /// actually removed, and the loop leaves a table only when a batch comes back short, so a
    /// single call still reclaims the whole backlog. Two exceptions, both of which UNDERSTATE and
    /// neither of which loses a row: a concurrent sweeper's locked rows are skipped (see
    /// `SKIP LOCKED` below) and left for whichever sweeper holds them, and a record that expires
    /// while the pass is running may not be seen by it. Both are reclaimed by the next tick, which
    /// is why the trait asks for a sweep on a TIMER rather than a sweep that must be complete.
    ///
    /// "Dead at `now`" is `expires_at <= now`, NOT `<`: the core's harness plants a record
    /// exactly on the boundary, because a store using `<` keeps a record the server already
    /// treats as expired.
    async fn sweep_expired(&self, now: std::time::SystemTime) -> Result<u64, StorageError> {
        const OP: &str = "sweep_expired";
        let cutoff = to_nanos(now);
        let mut removed = 0u64;

        // `ctid` rather than the primary key, so the batch is bounded without a second index
        // lookup: the subquery walks the expiry index and hands the delete the physical row
        // addresses it already found. `FOR UPDATE SKIP LOCKED` is what makes N nodes sweeping at
        // once harmless rather than N nodes queueing behind each other, which the trait's "it
        // must be safe to call concurrently" invites a host to do.
        //
        // CAN A CONCURRENT UPSERT MOVE A ROW SO THAT A CAPTURED `ctid` NAMES A DIFFERENT ONE? No,
        // and the question is asked here because it is the right question and the answer is not
        // obvious: an `INSERT ... ON CONFLICT DO UPDATE` genuinely DOES move a row, since an update
        // writes a new tuple version at a new (block, offset), and every `put_*` in this file is
        // such a statement. What rules it out is `FOR UPDATE`, not the surrounding statement being
        // one statement. The subquery takes a ROW LOCK on everything it returns, and holds it for
        // the rest of the transaction, so by the time the outer `DELETE` looks up a `ctid` the
        // tuple at that address is one no other backend may update, delete, or vacuum away and
        // reuse the slot of. The two orders are the only two there are, and both are safe: the
        // upsert that arrives after the lock BLOCKS on it, and the upsert that got there first
        // holds the lock itself, so `SKIP LOCKED` leaves that row for the next tick. Measured
        // against the live server rather than reasoned about: with a sweeper holding the lock the
        // upsert never returned, and with an uncommitted upsert holding the row the sweeper's
        // subquery returned only the other row.
        //
        // The user-code index is not swept separately and is not counted separately: it is a
        // column of the grant, so it dies with the row it points at.
        // `mut` only when a feature below pushes onto it; a default build sweeps four tables.
        #[allow(unused_mut)]
        let mut statements: Vec<&str> = vec![
            "DELETE FROM oauth_as_device_grants WHERE ctid IN ( \
                 SELECT ctid FROM oauth_as_device_grants WHERE expires_at_ns <= $1 \
                 LIMIT $2 FOR UPDATE SKIP LOCKED)",
            "DELETE FROM oauth_as_authorization_codes WHERE ctid IN ( \
                 SELECT ctid FROM oauth_as_authorization_codes WHERE expires_at_ns <= $1 \
                 LIMIT $2 FOR UPDATE SKIP LOCKED)",
            "DELETE FROM oauth_as_access_tokens WHERE ctid IN ( \
                 SELECT ctid FROM oauth_as_access_tokens WHERE expires_at_ns <= $1 \
                 LIMIT $2 FOR UPDATE SKIP LOCKED)",
            // `IS NOT NULL` is the whole of the `Option<SystemTime>` contract: a chain with no
            // absolute lifetime is not dead however old it is. SQL would already answer false to
            // `NULL <= $1`, but this is the one place where being wrong logs every long-lived
            // client out, so the predicate is written where a reader can see it.
            "DELETE FROM oauth_as_refresh_tokens WHERE ctid IN ( \
                 SELECT ctid FROM oauth_as_refresh_tokens \
                 WHERE expires_at_ns IS NOT NULL AND expires_at_ns <= $1 \
                 LIMIT $2 FOR UPDATE SKIP LOCKED)",
        ];
        // RFC 9126 s4: an expired request_uri MUST be rejected, and once expired there is nothing
        // left to recognise it for.
        #[cfg(feature = "par")]
        statements.push(
            "DELETE FROM oauth_as_pushed_requests WHERE ctid IN ( \
                 SELECT ctid FROM oauth_as_pushed_requests WHERE expires_at_ns <= $1 \
                 LIMIT $2 FOR UPDATE SKIP LOCKED)",
        );
        // The replay set is the one table an unauthenticated caller can grow: every
        // refused-but-well-formed assertion or proof adds a row.
        #[cfg(any(feature = "client-assertion", feature = "dpop"))]
        statements.push(
            "DELETE FROM oauth_as_replay_ids WHERE ctid IN ( \
                 SELECT ctid FROM oauth_as_replay_ids WHERE expires_at_ns <= $1 \
                 LIMIT $2 FOR UPDATE SKIP LOCKED)",
        );
        // Barriers. NOT feature gated, for the same reason the migration is not: every build
        // records client and family barriers, and a table nothing sweeps is a table that grows by
        // one row per revocation forever. Reaping one EARLY reopens the window it closed, which is
        // why its deadline comes from the caller that recorded it rather than from a retention
        // policy here.
        statements.push(
            "DELETE FROM oauth_as_revocation_barriers WHERE ctid IN ( \
                 SELECT ctid FROM oauth_as_revocation_barriers WHERE expires_at_ns <= $1 \
                 LIMIT $2 FOR UPDATE SKIP LOCKED)",
        );

        for stmt in statements {
            loop {
                let batch = sqlx::query(stmt)
                    .bind(cutoff)
                    .bind(SWEEP_BATCH_ROWS as i64)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| error::db(OP, e))?
                    .rows_affected();
                removed += batch;
                // A short batch means the table had nothing more to give: either it is drained, or
                // what is left is locked by another sweeper, which is that sweeper's to count.
                if batch < SWEEP_BATCH_ROWS as u64 {
                    break;
                }
            }
        }
        Ok(removed)
    }
}
