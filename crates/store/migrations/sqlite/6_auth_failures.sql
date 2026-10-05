-- Shared rate-limit state (ADR-0008, remediation T2).
--
-- Append-only attempt rows: the window decision counts rows newer than
-- `since`. A surrogate id is required because one key can fail several times
-- within the same second and every attempt must count (a (policy_key,
-- failed_at) PK would collapse a concurrent burst into a single row and
-- defeat the limit).

CREATE TABLE auth_failures (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_key  TEXT NOT NULL,
    failed_at   INTEGER NOT NULL
);

CREATE INDEX idx_auth_failures_key ON auth_failures (policy_key, failed_at);
