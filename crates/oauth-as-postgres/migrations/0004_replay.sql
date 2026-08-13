-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Copyright (C) 2026 Matthew Jackson
--
-- Claimed single-use identifiers: RFC 7523 s3 assertion `jti`s and RFC 9449 s4.3 DPoP proof
-- `jti`s. Applied only when `client-assertion` or `dpop` is on.

CREATE TABLE IF NOT EXISTS oauth_as_replay_ids (
    -- The PRIMARY KEY is the whole mechanism. `claim_replay_id` is an
    -- `INSERT ... ON CONFLICT DO NOTHING RETURNING`, so "was I first?" is answered by whether
    -- this unique index accepted the row, inside one statement, by the database. A read followed
    -- by a write would tell two concurrent presentations of the SAME assertion that each was
    -- first, and unlike a double-spent token nothing anywhere would record that it happened.
    id            TEXT PRIMARY KEY,
    expires_at_ns BIGINT NOT NULL
);

-- This is the one table an UNAUTHENTICATED caller can grow: every refused-but-well-formed
-- assertion or proof adds a row, and only the host's sweep reclaims them.
CREATE INDEX IF NOT EXISTS oauth_as_replay_ids_expiry_idx
    ON oauth_as_replay_ids (expires_at_ns);
