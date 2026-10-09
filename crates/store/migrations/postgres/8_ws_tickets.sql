-- WebSocket connection tickets (ADR-0017): hash-only, short-lived, single-use.
--
-- The ticket is the value a browser exchanges a valid access token for, so it
-- can open a WebSocket without putting the token in the URL. `used_at` makes
-- the claim atomic (one `UPDATE ... WHERE used_at IS NULL` wins); `expires_at`
-- bounds the ticket itself; `access_expires_at` is the hard ceiling for the
-- connection, copied from the access token that obtained the ticket.
--
-- Timestamps are `BIGINT`, like the rest of the schema, and that is not a
-- stylistic choice: the store decodes them as `i64`. Postgres `INTEGER` is
-- 32-bit and sqlx refuses to decode `INT4` into `i64`, which is what the first
-- run against real Postgres found: the inserts succeeded and every read failed.
-- SQLite is dynamically typed, so it hid the mistake completely. Fixed in place
-- because this migration is unreleased; a shipped one would need an ALTER.
--
-- The hash is the primary key, like refresh tokens, because nobody should ever
-- hold the plaintext here. Auditing and pruning happen in the API layer; this
-- table stays the source of truth.
CREATE TABLE ws_tickets (
    code_hash           TEXT PRIMARY KEY NOT NULL,
    session_id          TEXT NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    tenant_id           TEXT NOT NULL,
    subject_id          TEXT NOT NULL,
    access_expires_at   BIGINT NOT NULL,
    created_at          BIGINT NOT NULL,
    expires_at          BIGINT NOT NULL,
    used_at             BIGINT
);

-- The redeem path that matters: session revocation must refresh promptly, and
-- expired tickets are worthless, so the common lookups are the hash (exact)
-- and the sweep by creation time.
CREATE INDEX ws_tickets_created_at_idx ON ws_tickets (created_at);