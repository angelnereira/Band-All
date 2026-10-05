-- API clients for HMAC request signatures (H6). Secrets sealed with the vault.

CREATE TABLE api_clients (
    key_id          TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants (id),
    sealed_version  INTEGER NOT NULL,
    kek_id          TEXT NOT NULL,
    wrapped_dek     BLOB NOT NULL,
    wrapped_nonce   BLOB NOT NULL,
    nonce           BLOB NOT NULL,
    ciphertext      BLOB NOT NULL,
    scopes          TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    revoked_at      INTEGER
);
