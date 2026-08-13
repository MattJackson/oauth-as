// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! `SystemTime` to the `BIGINT` nanoseconds-since-epoch the expiry columns hold, and back.
//!
//! WHY NANOSECONDS AND NOT `timestamptz`. The trait speaks `std::time::SystemTime` throughout and
//! `Storage::sweep_expired` compares with `<=` at a boundary the core's own conformance harness
//! plants a record exactly on. `timestamptz` is microsecond-resolution, so a deadline with
//! sub-microsecond nanos would round, and rounding DOWN would sweep a record one tick before the
//! server considers it dead. An i64 of nanoseconds is exact for every instant between 1677 and
//! 2262, and it costs this crate no date-library dependency.
//!
//! WHY THE COLUMN IS NOT THE SOURCE OF TRUTH. The authoritative instant is in the `payload`, and
//! every read returns the payload. The column exists so the sweep can range-scan and so an
//! operator can look, which is why saturating at the ends of the range below is safe: a clamped
//! value can at worst make the sweep reach a record early or late, never hand back a record whose
//! deadline differs from the one the server wrote.
//!
//! THE REVOCATION BARRIER TABLE IS THE EXCEPTION. `oauth_as_revocation_barriers` has no `payload`:
//! `recorded_at_ns` IS the value, compared directly by the `GREATEST(...)` upsert and by
//! `barrier_covers`. For that table a clamp would change a refusal decision rather than a sweep
//! boundary. It is safe anyway, for a reason this module does not otherwise depend on: no instant
//! this crate produces falls outside 1677..2262, because barriers are derived from the host clock
//! plus a configured window, and `to_nanos` saturates rather than wrapping. If either ever stops
//! holding, this table is where it bites first.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Nanoseconds since the Unix epoch, saturating at the ends of `i64`.
pub fn to_nanos(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_nanos()).unwrap_or(i64::MAX),
        // Before 1970. The core never produces one (every deadline here is `now` plus a
        // lifetime), but a host is free to hand in whatever it likes and a panic in a storage
        // call would take down the host's request thread.
        Err(e) => i64::try_from(e.duration().as_nanos())
            .map(|n| -n)
            .unwrap_or(i64::MIN),
    }
}

/// The inverse, for a host reading a column back. Not used on any path in this crate: records
/// come back from the payload.
pub fn from_nanos(ns: i64) -> SystemTime {
    if ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(ns as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos(ns.unsigned_abs())
    }
}
