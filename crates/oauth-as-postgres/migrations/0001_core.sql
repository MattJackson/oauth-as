-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Copyright (C) 2026 Matthew Jackson
--
-- The tables every build needs, whatever features the core was compiled with.
--
-- SHAPE, and why it is this shape. Each row is ONE record of the core's own type, serialized
-- whole into `payload` (jsonb), plus the few columns that a QUERY actually keys on. The columns
-- are a projection of the payload, never a second source of truth: every read returns the
-- payload, so a column that drifted could at worst mis-select a row, never hand back a record
-- with a field the server did not write.
--
-- Column-per-field was rejected deliberately. `oauth-as` gates fields on cargo features
-- (`dpop` adds `jkt`, `mtls` adds `x5t_s256`, `rar` adds `authorization_details`, `consent` adds
-- `authentication`), so a column-per-field schema would need a migration per feature combination
-- and would silently DROP a field whose column a deployment had not created. Dropping one of
-- those fields is not cosmetic: the harness's own fixtures say why, a lost `jkt` turns a
-- sender-constrained token back into a bearer token and nothing on the token plane notices.
--
-- TIME is stored as `expires_at_ns`, a BIGINT of nanoseconds since the Unix epoch, rather than
-- `timestamptz`. Two reasons. The trait speaks in `std::time::SystemTime` and compares with `<=`
-- (see `Storage::sweep_expired`), and an integer round trip is exact where a `timestamptz` is
-- microseconds and would round a deadline; and it costs this crate no date-library dependency.
-- The value is only ever used for range scans: the authoritative instant is in the payload.

CREATE TABLE IF NOT EXISTS oauth_as_clients (
    client_id TEXT PRIMARY KEY,
    payload   JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_as_device_grants (
    device_code          TEXT PRIMARY KEY,
    -- The user-code index is a COLUMN of the grant, not a second table, and that is the whole
    -- reason this store satisfies the two `Storage::put_device_grant` requirements for free:
    --   * a put that CHANGES the user code retires the old entry, because the old entry IS the
    --     old value of this column and the upsert overwrites it;
    --   * `take_device_grant` clears the index with the record, because `DELETE ... RETURNING`
    --     removes the row that holds both.
    -- Stored NORMALIZED (RFC 8628 s6.1): the server normalizes before it calls in, and the trait
    -- says the store indexes what it is given, so nothing here folds case or strips hyphens.
    user_code_normalized TEXT NOT NULL,
    client_id            TEXT NOT NULL,
    -- The approved resource owner, or NULL when the grant is Pending or Denied. This is exactly
    -- what a consent withdrawal keys on: the trait's `revoke_consent` must reach a grant the user
    -- APPROVED but the device has not polled for, and must leave a PENDING one alone.
    approved_subject     TEXT,
    expires_at_ns        BIGINT NOT NULL,
    payload              JSONB NOT NULL
);

-- RFC 8628 s6.1 makes the user code the credential a human types, so two live grants answering to
-- one code is two devices sharing an identity. A UNIQUE index is what makes the refusal the
-- DATABASE's decision rather than a read-then-check in this crate: under two concurrent puts of
-- the same code from two nodes, exactly one commits and the other gets 23505. It is also what
-- makes the server's user-code collision retry loop mean anything.
CREATE UNIQUE INDEX IF NOT EXISTS oauth_as_device_grants_user_code_key
    ON oauth_as_device_grants (user_code_normalized);
-- `delete_client` cascades by client_id; `revoke_consent` by the (client, approved subject) pair.
CREATE INDEX IF NOT EXISTS oauth_as_device_grants_client_idx
    ON oauth_as_device_grants (client_id);
CREATE INDEX IF NOT EXISTS oauth_as_device_grants_consent_idx
    ON oauth_as_device_grants (client_id, approved_subject);
-- The sweep scans this. RFC 8628 s3.1 lets any entitled client allocate a grant per request, so
-- without a sweep the growth here is attacker-paced; without the index the sweep is a full scan.
CREATE INDEX IF NOT EXISTS oauth_as_device_grants_expiry_idx
    ON oauth_as_device_grants (expires_at_ns);

CREATE TABLE IF NOT EXISTS oauth_as_authorization_codes (
    code          TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL,
    -- NOT NULL: an authorization code always names the resource owner it was issued for.
    subject       TEXT NOT NULL,
    expires_at_ns BIGINT NOT NULL,
    payload       JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS oauth_as_authorization_codes_client_idx
    ON oauth_as_authorization_codes (client_id);
CREATE INDEX IF NOT EXISTS oauth_as_authorization_codes_consent_idx
    ON oauth_as_authorization_codes (client_id, subject);
CREATE INDEX IF NOT EXISTS oauth_as_authorization_codes_expiry_idx
    ON oauth_as_authorization_codes (expires_at_ns);

CREATE TABLE IF NOT EXISTS oauth_as_access_tokens (
    access_token  TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL,
    -- NULL for RFC 6749 s4.4 client credentials: there is no resource owner.
    subject       TEXT,
    -- NULL for the same reason: a client-credentials token has no refresh chain, so it belongs to
    -- no family. `revoke_token_family` must not sweep those up by matching NULL against an id.
    family_id     TEXT,
    expires_at_ns BIGINT NOT NULL,
    payload       JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS oauth_as_access_tokens_client_idx
    ON oauth_as_access_tokens (client_id);
-- The trait asks for this one by name: RFC 9700 s4.14.2 family revocation "must actually
-- complete", and it walks access tokens as well as refresh records. Partial, because the NULL
-- family_ids are the majority in a client-credentials-heavy deployment and are never matched.
CREATE INDEX IF NOT EXISTS oauth_as_access_tokens_family_idx
    ON oauth_as_access_tokens (family_id) WHERE family_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS oauth_as_access_tokens_consent_idx
    ON oauth_as_access_tokens (client_id, subject);
CREATE INDEX IF NOT EXISTS oauth_as_access_tokens_expiry_idx
    ON oauth_as_access_tokens (expires_at_ns);

CREATE TABLE IF NOT EXISTS oauth_as_refresh_tokens (
    refresh_token TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL,
    subject       TEXT,
    -- NOT NULL here, unlike the access token table: every refresh record belongs to a chain.
    family_id     TEXT NOT NULL,
    -- NULLABLE, and the null is load bearing. `RefreshTokenRecord::expires_at` is an Option, and
    -- `None` means a chain with no ABSOLUTE lifetime. The trait is explicit that such a record is
    -- NOT dead however old it is; treating the null as "expired at the epoch" would silently log
    -- every such client out on the first sweep.
    expires_at_ns BIGINT,
    payload       JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS oauth_as_refresh_tokens_client_idx
    ON oauth_as_refresh_tokens (client_id);
CREATE INDEX IF NOT EXISTS oauth_as_refresh_tokens_family_idx
    ON oauth_as_refresh_tokens (family_id);
CREATE INDEX IF NOT EXISTS oauth_as_refresh_tokens_consent_idx
    ON oauth_as_refresh_tokens (client_id, subject);
CREATE INDEX IF NOT EXISTS oauth_as_refresh_tokens_expiry_idx
    ON oauth_as_refresh_tokens (expires_at_ns) WHERE expires_at_ns IS NOT NULL;
