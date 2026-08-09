-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Copyright (C) 2026 Matthew Jackson
--
-- Remembered consent. Applied only when the `consent` feature is on.

CREATE TABLE IF NOT EXISTS oauth_as_consents (
    consent_id    TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL,
    subject       TEXT NOT NULL,
    -- Only so `find_consent` can pick DETERMINISTICALLY; see the index note below.
    granted_at_ns BIGINT NOT NULL,
    payload       JSONB NOT NULL
);

-- NOT UNIQUE, and that is a decision rather than an oversight. The trait says the SERVER keeps at
-- most one live consent per (client, subject) and widens it in place; it does not make that the
-- STORE's invariant to enforce. A unique constraint here would turn a caller's choice into a
-- `put_consent` error on a path a person is waiting on, and this crate has no standing to refuse
-- a write the trait permits. `find_consent` therefore orders newest-first and takes one, so that
-- if a deployment ever does hold two, the answer is the one the user most recently granted rather
-- than whichever row the planner happened to reach.
--
-- `find_consent` runs on the AUTHORIZATION ENDPOINT'S path, which the trait doc calls out
-- specifically, so the pair is indexed rather than scanned.
CREATE INDEX IF NOT EXISTS oauth_as_consents_pair_idx
    ON oauth_as_consents (client_id, subject, granted_at_ns DESC);
-- `consents_for_subject`: what a host shows a user on their "applications you have approved"
-- page. Not a hot path, but it must not be a full scan of every consent in the deployment.
CREATE INDEX IF NOT EXISTS oauth_as_consents_subject_idx
    ON oauth_as_consents (subject);
-- A consent names a client; when the registration goes, so does the consent.
CREATE INDEX IF NOT EXISTS oauth_as_consents_client_idx
    ON oauth_as_consents (client_id);
