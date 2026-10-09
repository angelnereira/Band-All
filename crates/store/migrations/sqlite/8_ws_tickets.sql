-- WebSocket connection tickets (ADR-0017): hash-only, short-lived, single-use.
--
-- Same shape as the Postgres migration. Foreign keys are enforced by the
-- store's connect options (`foreign_keys(true)`), and the atomic claim is a
-- single UPDATE inside the transaction, so exactly one redemption wins.
CREATE TABLE ws_tickets (
    code_hash           TEXT PRIMARY KEY NOT NULL,
    session_id          TEXT NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    tenant_id           TEXT NOT NULL,
    subject_id          TEXT NOT NULL,
    access_expires_at   INTEGER NOT NULL,
    created_at          INTEGER NOT NULL,
    expires_at          INTEGER NOT NULL,
    used_at             INTEGER
);

CREATE INDEX ws_tickets_created_at_idx ON ws_tickets (created_at);