-- Keyed audit chain v2 (remediation T4).
--
-- `chain_version` tells a verifier how `hash` was derived: 1 = legacy
-- unkeyed SHA-256 over (prev, event, ts), 2 = HMAC-SHA-256 over the
-- length-prefixed record with a key held outside the database. Existing rows
-- keep verifying as v1; only new appends write v2.
ALTER TABLE audit_log ADD COLUMN chain_version SMALLINT NOT NULL DEFAULT 1;

-- Append-only: the application role may insert and read, never rewrite
-- history. Revoked from PUBLIC so an unprivileged role inherits nothing.
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_log FROM PUBLIC;

-- The `bandall_app` role only exists on managed deployments; the guard keeps
-- the migration runnable on a fresh database (CI, local dev) where the
-- migration user is the owner and no such role is needed yet.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bandall_app') THEN
        EXECUTE 'GRANT INSERT, SELECT ON TABLE audit_log TO bandall_app';
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_log FROM bandall_app';
    END IF;
END
$$;