-- BandAll core schema (SQLite). Times are Unix seconds (INTEGER is 64-bit).

CREATE TABLE tenants (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE subjects (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants (id),
    external_id TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    UNIQUE (tenant_id, external_id)
);

CREATE TABLE factors (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants (id),
    subject_id      TEXT NOT NULL REFERENCES subjects (id),
    status          TEXT NOT NULL DEFAULT 'pending',
    secret_version  INTEGER NOT NULL,
    kek_id          TEXT NOT NULL,
    wrapped_dek     BLOB NOT NULL,
    wrapped_nonce   BLOB NOT NULL,
    nonce           BLOB NOT NULL,
    ciphertext      BLOB NOT NULL,
    algorithm       TEXT NOT NULL,
    digits          INTEGER NOT NULL,
    period          INTEGER NOT NULL,
    last_step       INTEGER,
    created_at      INTEGER NOT NULL,
    confirmed_at    INTEGER
);

CREATE INDEX idx_factors_subject ON factors (subject_id);

CREATE TABLE recovery_codes (
    factor_id   TEXT NOT NULL REFERENCES factors (id) ON DELETE CASCADE,
    code_hash   TEXT NOT NULL,
    used_at     INTEGER,
    PRIMARY KEY (factor_id, code_hash)
);
