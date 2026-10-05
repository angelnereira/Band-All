-- Sessions and refresh-token families (H4).

CREATE TABLE sessions (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants (id),
    subject_id  TEXT NOT NULL REFERENCES subjects (id),
    created_at  INTEGER NOT NULL,
    revoked_at  INTEGER
);

CREATE TABLE refresh_tokens (
    code_hash   TEXT PRIMARY KEY,
    family_id   TEXT NOT NULL,
    session_id  TEXT NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER,
    revoked_at  INTEGER
);

CREATE INDEX idx_refresh_family ON refresh_tokens (family_id);
