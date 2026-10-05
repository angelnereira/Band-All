-- Append-only hash-chained audit log (H5). Tampering breaks the chain.

CREATE TABLE audit_log (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    tenant_id   TEXT NOT NULL,
    subject_id  TEXT NOT NULL,
    event       TEXT NOT NULL,
    prev_hash   BLOB NOT NULL,
    hash        BLOB NOT NULL
);
