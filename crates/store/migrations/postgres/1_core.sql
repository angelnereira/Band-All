-- BandAll core schema (Postgres). Times are Unix seconds (BIGINT).

CREATE TABLE tenants (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  BIGINT NOT NULL
);

CREATE TABLE subjects (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants (id),
    external_id TEXT NOT NULL,
    created_at  BIGINT NOT NULL,
    UNIQUE (tenant_id, external_id)
);

CREATE TABLE factors (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants (id),
    subject_id      TEXT NOT NULL REFERENCES subjects (id),
    status          TEXT NOT NULL DEFAULT 'pending',
    secret_version  SMALLINT NOT NULL,
    kek_id          TEXT NOT NULL,
    wrapped_dek     BYTEA NOT NULL,
    wrapped_nonce   BYTEA NOT NULL,
    nonce           BYTEA NOT NULL,
    ciphertext      BYTEA NOT NULL,
    algorithm       TEXT NOT NULL,
    digits          SMALLINT NOT NULL,
    period          BIGINT NOT NULL,
    last_step       BIGINT,
    created_at      BIGINT NOT NULL,
    confirmed_at    BIGINT
);

CREATE INDEX idx_factors_subject ON factors (subject_id);

CREATE TABLE recovery_codes (
    factor_id   TEXT NOT NULL REFERENCES factors (id) ON DELETE CASCADE,
    code_hash   TEXT NOT NULL,
    used_at     BIGINT,
    PRIMARY KEY (factor_id, code_hash)
);
