-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Copyright (C) 2026 Matthew Jackson
--
-- Revocation barriers. A revocation removes the records that exist WHEN IT RUNS; a request that
-- was already holding one, mid read-modify-write, writes afterwards and puts it back. That is the
-- resurrection defect the `Storage` trait's module docs describe, and this table is what closes
-- it: every revocation records what it removed, and `put_token` and `put_refresh_token` refuse to
-- write anything a recorded barrier covers.
--
-- Applied unconditionally. The consent scope is only ever WRITTEN under the `consent` feature, but
-- the table is not feature gated, because `put_token` reads it on every issuance in every build
-- and a missing table is a runtime error rather than a compile one.

CREATE TABLE IF NOT EXISTS oauth_as_revocation_barriers (
    -- The scope, decomposed into columns rather than stored as one opaque key, so that the
    -- refusal predicate in `put_token` is a single indexed query against all three shapes at once
    -- rather than three round trips or a scan.
    --
    -- 'client'  -> client_id set,  family_id '', subject ''
    -- 'family'  -> family_id set,  client_id '', subject ''
    -- 'consent' -> client_id AND subject set, family_id ''
    --
    -- NOT NULL with '' for "not applicable", rather than NULL, and that is load bearing rather
    -- than a style choice: NULL is not equal to itself, so a UNIQUE constraint over nullable
    -- columns would not collapse two barriers for the same scope, and the upsert below would have
    -- nothing to conflict on. The empty string is not ambiguous here because neither a client id
    -- nor a family id nor a subject is ever empty in this crate: all three are minted or supplied
    -- as non-empty strings.
    scope         TEXT NOT NULL CHECK (scope IN ('client', 'family', 'consent')),
    client_id     TEXT NOT NULL DEFAULT '',
    family_id     TEXT NOT NULL DEFAULT '',
    subject       TEXT NOT NULL DEFAULT '',
    -- When this barrier may be reclaimed by `sweep_expired`. Reaping EARLY reopens the window the
    -- barrier was recorded to close, so the sweep compares against this and never against a
    -- retention policy of its own. The caller supplies it, derived from the longest-lived
    -- credential the revocation removed.
    expires_at_ns BIGINT NOT NULL,
    -- WHEN the revocation happened, which is a different question from when the barrier may be
    -- reaped, and the one a write is compared against. A `client` or `consent` barrier refuses a
    -- write only when the GRANT behind it was established at or before this instant: an identity
    -- that can legitimately be established again (a user re-approving an application, a host
    -- re-provisioning a deleted client_id) must not be locked out for the barrier's whole life.
    -- A `family` barrier ignores it and refuses unconditionally, because rotation legitimately
    -- mints fresh records inside an existing family and a new grant gets a new family_id.
    --
    -- NOT NULL with no DEFAULT, deliberately: a row without it could not be compared, and the
    -- only safe reading of "unknown" would be to refuse everything forever.
    recorded_at_ns BIGINT NOT NULL,

    -- One row per scope. A second revocation of the same family must EXTEND the deadline, never
    -- shorten it, which is what the `ON CONFLICT ... DO UPDATE SET ... GREATEST(...)` in
    -- `record_barrier` expresses; without this constraint that upsert has nothing to conflict on
    -- and the table accumulates a row per revocation instead.
    UNIQUE (scope, client_id, family_id, subject),

    -- The `''` sentinel only works as one if a REAL identifier can never be empty, and these are
    -- what make that true in the database rather than merely true in this crate's callers. Without
    -- them a barrier recorded for an empty family id would sit in the table matching every token
    -- that has no family at all, refusing issuance for every client-credentials grant in the
    -- deployment. The refusal predicate in `barrier_covers` relies on this.
    CHECK (scope <> 'client' OR client_id <> ''),
    CHECK (scope <> 'family' OR family_id <> ''),
    CHECK (scope <> 'consent' OR (client_id <> '' AND subject <> ''))
);

-- The lookup `put_token` and `put_refresh_token` make on EVERY issuance. Both write paths are on
-- the token plane, so these indexes are not optional: without them every token issued costs a
-- sequential scan of every revocation the deployment has ever recorded and not yet swept.
--
-- TWO indexes, not one, because the predicate in `barrier_covers` is a three-way OR: the planner
-- builds a bitmap OR from one index probe per arm, and an arm with no cheap probe available drags
-- the WHOLE `EXISTS` down to a sequential scan of the table.
CREATE INDEX IF NOT EXISTS oauth_as_revocation_barriers_lookup_idx
    ON oauth_as_revocation_barriers (client_id, family_id, subject);

-- The 'family' arm, and it needs its own index for a reason that is easy to miss: it is not that
-- nothing can serve it. The UNIQUE constraint above creates a btree on
-- (scope, client_id, family_id, subject), and the arm says `scope = 'family' AND family_id = $2`,
-- so that index CAN be probed for it. The trouble is `scope`, which has three values: the probe
-- has an equality only on the leading column and on the THIRD, so it reads every 'family' entry in
-- the index and filters, and the planner (correctly) prices that above just scanning the table.
-- Measured on PostgreSQL 16 with 20,000 family barriers standing, the refusal lookup touched 113
-- shared buffers without this index and 6 with it. That cost is paid by `put_token` and
-- `put_refresh_token` on EVERY issuance, and it grows with the number of revocations a deployment
-- has recorded and not yet swept — worst exactly after the mass revocation that follows an
-- incident. `tests/revocation_races.rs` asserts the bound so this cannot regress silently.
--
-- PARTIAL on the scope, in the style of `0001_core.sql`'s family index: a 'client' or 'consent'
-- barrier has `family_id = ''` and is never looked up by family, so keeping those out of the index
-- keeps it the size of the family revocations alone.
CREATE INDEX IF NOT EXISTS oauth_as_revocation_barriers_family_idx
    ON oauth_as_revocation_barriers (family_id) WHERE scope = 'family';

-- `recorded_at_ns` is in neither index and does not need to be: they narrow to the handful of
-- barriers standing for one identity, and the comparison is then evaluated over those rows rather
-- than over the table.

-- The sweep's own index, same shape as every other expiring kind in this schema.
CREATE INDEX IF NOT EXISTS oauth_as_revocation_barriers_expiry_idx
    ON oauth_as_revocation_barriers (expires_at_ns);
