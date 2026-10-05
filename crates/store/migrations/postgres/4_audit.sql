-- Append-only hash-chained audit log (H5). Tampering breaks the chain.

CREATE TABLE audit_log (
    seq         BIGSERIAL PRIMARY KEY,
    ts          BIGINT NOT NULL,
    tenant_id   TEXT NOT NULL,
    subject_id  TEXT NOT NULL,
    event       TEXT NOT NULL,
    prev_hash   BYTEA NOT NULL,
    hash        BYTEA NOT NULL
);
