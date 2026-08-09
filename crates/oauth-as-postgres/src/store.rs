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

use oauth_as::authorization::AuthorizationCodeRecord;
use oauth_as::client::{Client, ClientId};
use oauth_as::device::{DeviceGrant, DeviceGrantState};
use oauth_as::store::{Storage, StorageError};
use oauth_as::token::{IssuedToken, RefreshTokenRecord};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sqlx::Row;

use crate::error;
use crate::time::to_nanos;
use crate::PostgresStorage;

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

    /// ONE TRANSACTION, because the trait says so and says why: RFC 7592 section 2.3 deletes a
    /// registration and invalidates what that registration holds, and a delete that half
    /// succeeded is either an orphaned credential set that can still call resource servers or a
    /// registration nobody can reach.
    async fn delete_client(&self, client_id: &ClientId) -> Result<bool, StorageError> {
        const OP: &str = "delete_client";
        let id = client_id.as_str();
        let mut tx = self.begin(OP).await?;

        // "Everything it was issued", per the trait: access tokens, refresh records, device
        // grants (the user-code index goes with the row, it is a column of it) and authorization
        // codes. The order does not matter; the transaction is what makes it one event.
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
        // A consent names a client that no longer exists; leaving it would show a user an
        // application they cannot revoke, on a registration nothing can reach.
        #[cfg(feature = "consent")]
        sqlx::query("DELETE FROM oauth_as_consents WHERE client_id = $1")
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
    ) -> Result<(), StorageError> {
        const OP: &str = "put_pushed_authorization_request";
        let payload = encode(OP, &record)?;
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
        .execute(&self.pool)
        .await
        .map_err(|e| error::db(OP, e))?;
        Ok(())
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

    async fn put_token(&self, token: IssuedToken) -> Result<(), StorageError> {
        const OP: &str = "put_token";
        let payload = encode(OP, &token)?;
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
        .execute(&self.pool)
        .await
        .map_err(|e| error::db(OP, e))?;
        Ok(())
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

    async fn put_refresh_token(&self, record: RefreshTokenRecord) -> Result<(), StorageError> {
        const OP: &str = "put_refresh_token";
        let payload = encode(OP, &record)?;
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
        .execute(&self.pool)
        .await
        .map_err(|e| error::db(OP, e))?;
        Ok(())
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
    async fn revoke_token_family(&self, family_id: &str) -> Result<u64, StorageError> {
        const OP: &str = "revoke_token_family";
        let mut tx = self.begin(OP).await?;
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
    async fn revoke_consent(&self, consent_id: &str) -> Result<u64, StorageError> {
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
    #[cfg(any(feature = "client_assertion", feature = "dpop"))]
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

    /// One statement per table, all inside one transaction so the returned count describes a
    /// single consistent state of the store rather than a state that moved underneath it.
    ///
    /// "Dead at `now`" is `expires_at <= now`, NOT `<`: the core's harness plants a record
    /// exactly on the boundary, because a store using `<` keeps a record the server already
    /// treats as expired.
    async fn sweep_expired(&self, now: std::time::SystemTime) -> Result<u64, StorageError> {
        const OP: &str = "sweep_expired";
        let cutoff = to_nanos(now);
        let mut tx = self.begin(OP).await?;
        let mut removed = 0u64;

        // The user-code index is not swept separately and is not counted separately: it is a
        // column of the grant, so it dies with the row it points at.
        // `mut` only when a feature below pushes onto it; a default build sweeps four tables.
        #[allow(unused_mut)]
        let mut statements: Vec<&str> = vec![
            "DELETE FROM oauth_as_device_grants WHERE expires_at_ns <= $1",
            "DELETE FROM oauth_as_authorization_codes WHERE expires_at_ns <= $1",
            "DELETE FROM oauth_as_access_tokens WHERE expires_at_ns <= $1",
            // `IS NOT NULL` is the whole of the `Option<SystemTime>` contract: a chain with no
            // absolute lifetime is not dead however old it is. SQL would already answer false to
            // `NULL <= $1`, but this is the one place where being wrong logs every long-lived
            // client out, so the predicate is written where a reader can see it.
            "DELETE FROM oauth_as_refresh_tokens WHERE expires_at_ns IS NOT NULL \
             AND expires_at_ns <= $1",
        ];
        // RFC 9126 s4: an expired request_uri MUST be rejected, and once expired there is nothing
        // left to recognise it for.
        #[cfg(feature = "par")]
        statements.push("DELETE FROM oauth_as_pushed_requests WHERE expires_at_ns <= $1");
        // The replay set is the one table an unauthenticated caller can grow: every
        // refused-but-well-formed assertion or proof adds a row.
        #[cfg(any(feature = "client_assertion", feature = "dpop"))]
        statements.push("DELETE FROM oauth_as_replay_ids WHERE expires_at_ns <= $1");

        for stmt in statements {
            removed += sqlx::query(stmt)
                .bind(cutoff)
                .execute(&mut *tx)
                .await
                .map_err(|e| error::db(OP, e))?
                .rows_affected();
        }
        tx.commit().await.map_err(|e| error::db(OP, e))?;
        Ok(removed)
    }
}
