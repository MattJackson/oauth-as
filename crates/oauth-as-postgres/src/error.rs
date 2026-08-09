// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Driver error to [`StorageError`], and the rule about what may appear in the text.
//!
//! WHAT REACHES A HOST'S LOG. `StorageError`'s own doc says the text is for the host's logs and
//! never for the wire, and the server maps it to `server_error`. That makes the text a log line,
//! and a log line is the wrong place for two things a driver error carries by default:
//!
//! - THE CONNECTION STRING. `sqlx::Error::Configuration`, `Io` and `PoolTimedOut` are all
//!   routinely rendered by surrounding code alongside the URL that produced them, and that URL
//!   holds the database password.
//! - THE SQL AND ITS PARAMETERS. A `DatabaseError` from Postgres can carry the statement text and,
//!   with `log_statements` on, the bound values. Every `take_*` in this crate binds a BEARER
//!   CREDENTIAL: a refresh token, an authorization code, a device code, a `request_uri`. Echoing
//!   a driver message into a log is how a live credential ends up in a log aggregator.
//!
//! So nothing from the driver's `Display` is forwarded. What IS forwarded is the OPERATION that
//! failed and the SQLSTATE, which are the two facts an operator actually needs to route the
//! problem (a `40001` is a serialization failure to retry; a `53300` is a connection limit; a
//! `42P01` is an unrun migration) and neither of which can contain a secret: SQLSTATE is a
//! five-character code from a fixed alphabet defined by the SQL standard.

use oauth_as::store::StorageError;

/// Map a driver failure to a [`StorageError`] that names the operation and the SQLSTATE, and
/// nothing else. `op` is a literal from this crate, never caller-supplied data.
pub(crate) fn db(op: &'static str, e: sqlx::Error) -> StorageError {
    StorageError::new(format!("oauth-as-postgres: {op} failed ({})", kind(&e)))
}

/// A short, secret-free classification. Deliberately coarse: it is a routing hint, not a
/// diagnosis, and anything finer would mean quoting the driver.
fn kind(e: &sqlx::Error) -> String {
    if let Some(dbe) = e.as_database_error() {
        return match dbe.code() {
            // SQLSTATE is five characters from `[0-9A-Z]` (SQL standard, and Postgres appendix
            // A), so it cannot smuggle a credential or a statement into the message.
            Some(code) => format!("database, sqlstate {code}"),
            None => "database".to_string(),
        };
    }
    match e {
        // Named, not rendered: `Configuration` wraps the parse failure of a URL that holds the
        // password.
        sqlx::Error::Configuration(_) => "configuration".to_string(),
        sqlx::Error::Io(_) => "io".to_string(),
        sqlx::Error::Tls(_) => "tls".to_string(),
        sqlx::Error::Protocol(_) => "protocol".to_string(),
        sqlx::Error::RowNotFound => "no row".to_string(),
        sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_) => "decode".to_string(),
        sqlx::Error::PoolTimedOut => "pool timed out".to_string(),
        sqlx::Error::PoolClosed => "pool closed".to_string(),
        sqlx::Error::WorkerCrashed => "worker crashed".to_string(),
        _ => "driver".to_string(),
    }
}

/// True when the failure is a unique-index violation on `constraint`.
///
/// Used for exactly one thing: telling the RFC 8628 s6.1 user-code clash apart from any other
/// write failure, because the trait requires that one to be reported as a refusal rather than as
/// an outage. Matching on the constraint NAME rather than on SQLSTATE alone matters, since a
/// bare `23505` would also cover a primary-key collision and would turn an unrelated bug into a
/// message claiming the user code was taken.
pub(crate) fn is_unique_violation(e: &sqlx::Error, constraint: &str) -> bool {
    e.as_database_error()
        .map(|d| d.code().as_deref() == Some("23505") && d.constraint() == Some(constraint))
        .unwrap_or(false)
}

/// A record that came back from the database but could not be deserialized into the core's type.
///
/// This is a SCHEMA-VERSION failure, not a data failure, and it is worth its own message: it
/// means a row was written by a build of `oauth-as` whose record type differs from this one's,
/// which is what a rolling upgrade looks like when a field was added without a plan. The serde
/// error itself is dropped, because it quotes the JSON, and the JSON is the record.
pub(crate) fn payload(op: &'static str) -> StorageError {
    StorageError::new(format!(
        "oauth-as-postgres: {op} read a stored record this build of oauth-as cannot decode \
         (schema or crate version mismatch)"
    ))
}

/// A record that could not be serialized on the way IN. Practically unreachable (the core's
/// record types are plain data), so it is reported rather than unwrapped: a panic inside a
/// storage call would take down a host's request thread for a condition it can log.
pub(crate) fn encode(op: &'static str) -> StorageError {
    StorageError::new(format!(
        "oauth-as-postgres: {op} could not serialize the record it was given"
    ))
}
