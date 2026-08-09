-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Copyright (C) 2026 Matthew Jackson
--
-- RFC 9126 pushed authorization requests. Applied only when the `par` feature is on, because a
-- deployment whose core has no PAR endpoint has nothing that could ever write here.

CREATE TABLE IF NOT EXISTS oauth_as_pushed_requests (
    -- RFC 9126 s2.2: the handle IS the key, and s4 makes it single use, which is why the only
    -- read path is a `DELETE ... RETURNING`.
    request_uri   TEXT PRIMARY KEY,
    -- RFC 9126 s2.2 binds a request_uri to the client that pushed it, so `delete_client` must
    -- reach these: a deleted client's outstanding handles are handles nobody may redeem.
    client_id     TEXT NOT NULL,
    expires_at_ns BIGINT NOT NULL,
    payload       JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS oauth_as_pushed_requests_client_idx
    ON oauth_as_pushed_requests (client_id);
CREATE INDEX IF NOT EXISTS oauth_as_pushed_requests_expiry_idx
    ON oauth_as_pushed_requests (expires_at_ns);
