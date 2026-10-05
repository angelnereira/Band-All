-- API clients for HMAC request signatures (H6). Secrets sealed with the vault.

CREATE TABLE api_clients (
    key_id          TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants (id),
    sealed_version  SMALLINT NOT NULL,
    kek_id          TEXT NOT NULL,
    wrapped_dek     BYTEA NOT NULL,
    wrapped_nonce   BYTEA NOT NULL,
    nonce           BYTEA NOT NULL,
    ciphertext      BYTEA NOT NULL,
    scopes          TEXT NOT NULL,
    created_at      BIGINT NOT NULL,
    revoked_at      BIGINT
);
