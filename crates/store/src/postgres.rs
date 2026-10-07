//! Postgres backend.

use sqlx::PgPool;
use sqlx::migrate::MigrateDatabase;
use uuid::Uuid;

use bandall_policy::{Decision, Limits};

use crate::error::Error;
use crate::store::{BoxFuture, Store};
use crate::types::{
    ApiClient, AuditEntry, AuditHasher, Factor, NewApiClient, NewAudit, NewFactor, NewRefresh,
    RecoveryHash, RefreshEntry, Session, Subject, Tenant,
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

/// Previous hash of the first entry in the chain (32 zero bytes).
const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// Postgres-backed store.
#[derive(Debug)]
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    /// Connects without running migrations.
    ///
    /// Fail closed on transport security: a remote Postgres must use TLS.
    /// Only loopback hosts may connect in clear (local dev / sidecar).
    pub async fn connect(url: &str) -> Result<Self, Error> {
        Self::require_tls_for_remote(url)?;
        if !sqlx::Postgres::database_exists(url).await.unwrap_or(false) {
            sqlx::Postgres::create_database(url).await?;
        }
        Ok(Self {
            pool: PgPool::connect(url).await?,
        })
    }

    /// Rejects clear-text connections to non-loopback hosts. Parsing a URL is
    /// best-effort: anything unparseable is refused too (fail closed), because
    /// we cannot tell whether it would have been encrypted.
    fn require_tls_for_remote(url: &str) -> Result<(), Error> {
        let parsed = url::Url::parse(url).map_err(|_| Error::InsecureConnection)?;
        if parsed.scheme() != "postgres" && parsed.scheme() != "postgresql" {
            return Err(Error::InsecureConnection);
        }
        let host = parsed.host_str().unwrap_or_default();
        let loopback = matches!(host, "localhost" | "::1")
            || host
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);
        let wants_tls = parsed.query_pairs().any(|(k, v)| {
            k == "sslmode" && (v == "require" || v == "verify-ca" || v == "verify-full")
        });
        if loopback || wants_tls {
            Ok(())
        } else {
            Err(Error::InsecureConnection)
        }
    }

    /// Runs pending migrations.
    pub async fn migrate(&self) -> Result<(), Error> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }
}

const FACTOR_COLS: &str = "id, tenant_id, subject_id, status, secret_version, kek_id, wrapped_dek, wrapped_nonce, nonce, ciphertext, algorithm, digits, period, last_step, drift_steps, created_at, confirmed_at";

impl Store for PgStore {
    fn create_tenant(&self, name: &str, now_secs: i64) -> BoxFuture<'_, Result<Tenant, Error>> {
        let tenant = Tenant {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            created_at: now_secs,
        };
        Box::pin(async move {
            sqlx::query("INSERT INTO tenants (id, name, created_at) VALUES ($1, $2, $3)")
                .bind(&tenant.id)
                .bind(&tenant.name)
                .bind(tenant.created_at)
                .execute(&self.pool)
                .await?;
            Ok(tenant)
        })
    }

    fn create_subject(
        &self,
        tenant_id: &str,
        external_id: &str,
        now_secs: i64,
    ) -> BoxFuture<'_, Result<Subject, Error>> {
        let subject = Subject {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            external_id: external_id.to_string(),
            created_at: now_secs,
        };
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO subjects (id, tenant_id, external_id, created_at) VALUES ($1, $2, $3, $4)",
            )
            .bind(&subject.id)
            .bind(&subject.tenant_id)
            .bind(&subject.external_id)
            .bind(subject.created_at)
            .execute(&self.pool)
            .await?;
            Ok(subject)
        })
    }

    fn create_factor(&self, input: NewFactor) -> BoxFuture<'_, Result<Factor, Error>> {
        let factor = Factor {
            id: input.id,
            tenant_id: input.tenant_id,
            subject_id: input.subject_id,
            status: input.status,
            secret_version: input.secret_version,
            kek_id: input.kek_id,
            wrapped_dek: input.wrapped_dek,
            wrapped_nonce: input.wrapped_nonce,
            nonce: input.nonce,
            ciphertext: input.ciphertext,
            algorithm: input.algorithm,
            digits: input.digits,
            period: input.period,
            last_step: None,
            drift_steps: 0,
            created_at: input.created_at,
            confirmed_at: None,
        };
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO factors (id, tenant_id, subject_id, status, secret_version, kek_id, wrapped_dek, wrapped_nonce, nonce, ciphertext, algorithm, digits, period, last_step, drift_steps, created_at, confirmed_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
            )
            .bind(&factor.id)
            .bind(&factor.tenant_id)
            .bind(&factor.subject_id)
            .bind(&factor.status)
            .bind(factor.secret_version)
            .bind(&factor.kek_id)
            .bind(&factor.wrapped_dek)
            .bind(&factor.wrapped_nonce)
            .bind(&factor.nonce)
            .bind(&factor.ciphertext)
            .bind(&factor.algorithm)
            .bind(factor.digits)
            .bind(factor.period)
            .bind(factor.last_step)
            .bind(factor.drift_steps)
            .bind(factor.created_at)
            .bind(factor.confirmed_at)
            .execute(&self.pool)
            .await?;
            Ok(factor)
        })
    }

    fn find_subject<'a>(
        &'a self,
        tenant_id: &'a str,
        external_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<Subject>, Error>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, Subject>(
                "SELECT id, tenant_id, external_id, created_at FROM subjects WHERE tenant_id = $1 AND external_id = $2",
            )
            .bind(tenant_id)
            .bind(external_id)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row)
        })
    }

    fn get_factor<'a>(
        &'a self,
        tenant_id: &'a str,
        subject_id: &'a str,
        factor_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<Factor>, Error>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, Factor>(&format!(
                "SELECT {FACTOR_COLS} FROM factors WHERE id = $1 AND tenant_id = $2 AND subject_id = $3"
            ))
            .bind(factor_id)
            .bind(tenant_id)
            .bind(subject_id)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row)
        })
    }

    fn cas_last_step<'a>(
        &'a self,
        factor_id: &'a str,
        step: u64,
    ) -> BoxFuture<'a, Result<bool, Error>> {
        Box::pin(async move {
            let step = i64::try_from(step).map_err(|_| Error::OutOfRange)?;
            let result = sqlx::query(
                "UPDATE factors SET last_step = $1 WHERE id = $2 AND (last_step IS NULL OR last_step < $1)",
            )
            .bind(step)
            .bind(factor_id)
            .execute(&self.pool)
            .await?;
            Ok(result.rows_affected() == 1)
        })
    }

    fn confirm_factor<'a>(
        &'a self,
        factor_id: &'a str,
        now_secs: i64,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            sqlx::query("UPDATE factors SET status = 'active', confirmed_at = $1 WHERE id = $2")
                .bind(now_secs)
                .bind(factor_id)
                .execute(&self.pool)
                .await?;
            Ok(())
        })
    }

    fn add_recovery_codes<'a>(
        &'a self,
        factor_id: &'a str,
        hashes: &'a [String],
    ) -> BoxFuture<'a, Result<(), Error>> {
        let hashes = hashes.to_vec();
        Box::pin(async move {
            for hash in &hashes {
                sqlx::query(
                    "INSERT INTO recovery_codes (factor_id, code_hash, used_at) VALUES ($1, $2, NULL)",
                )
                .bind(factor_id)
                .bind(hash)
                .execute(&self.pool)
                .await?;
            }
            Ok(())
        })
    }

    fn use_recovery_code<'a>(
        &'a self,
        factor_id: &'a str,
        hash: &'a str,
        now_secs: i64,
    ) -> BoxFuture<'a, Result<bool, Error>> {
        Box::pin(async move {
            let result = sqlx::query(
                "UPDATE recovery_codes SET used_at = $1 WHERE factor_id = $2 AND code_hash = $3 AND used_at IS NULL",
            )
            .bind(now_secs)
            .bind(factor_id)
            .bind(hash)
            .execute(&self.pool)
            .await?;
            Ok(result.rows_affected() == 1)
        })
    }

    fn health(&self) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            sqlx::query("SELECT 1").execute(&self.pool).await?;
            Ok(())
        })
    }

    fn record_drift<'a>(
        &'a self,
        factor_id: &'a str,
        drift_steps: i64,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            sqlx::query("UPDATE factors SET drift_steps = $1 WHERE id = $2")
                .bind(drift_steps)
                .bind(factor_id)
                .execute(&self.pool)
                .await?;
            Ok(())
        })
    }

    fn list_recovery_hashes<'a>(
        &'a self,
        factor_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<RecoveryHash>, Error>> {
        Box::pin(async move {
            let rows = sqlx::query_as::<_, RecoveryHash>(
                "SELECT code_hash, used_at FROM recovery_codes WHERE factor_id = $1",
            )
            .bind(factor_id)
            .fetch_all(&self.pool)
            .await?;
            Ok(rows)
        })
    }

    fn delete_factor<'a>(&'a self, factor_id: &'a str) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            sqlx::query("DELETE FROM factors WHERE id = $1")
                .bind(factor_id)
                .execute(&self.pool)
                .await?;
            Ok(())
        })
    }

    fn create_session(
        &self,
        tenant_id: &str,
        subject_id: &str,
        now_secs: i64,
    ) -> BoxFuture<'_, Result<Session, Error>> {
        let session = Session {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            subject_id: subject_id.to_string(),
            created_at: now_secs,
            revoked_at: None,
        };
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO sessions (id, tenant_id, subject_id, created_at, revoked_at) VALUES ($1, $2, $3, $4, NULL)",
            )
            .bind(&session.id)
            .bind(&session.tenant_id)
            .bind(&session.subject_id)
            .bind(session.created_at)
            .execute(&self.pool)
            .await?;
            Ok(session)
        })
    }

    fn get_session<'a>(
        &'a self,
        session_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<Session>, Error>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, Session>(
                "SELECT id, tenant_id, subject_id, created_at, revoked_at FROM sessions WHERE id = $1",
            )
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row)
        })
    }

    fn revoke_session<'a>(
        &'a self,
        session_id: &'a str,
        now_secs: i64,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            sqlx::query("UPDATE sessions SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL")
                .bind(now_secs)
                .bind(session_id)
                .execute(&self.pool)
                .await?;
            Ok(())
        })
    }

    fn store_refresh(&self, entry: NewRefresh) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO refresh_tokens (code_hash, family_id, session_id, created_at, expires_at, used_at, revoked_at) VALUES ($1, $2, $3, $4, $5, NULL, NULL)",
            )
            .bind(&entry.code_hash)
            .bind(&entry.family_id)
            .bind(&entry.session_id)
            .bind(entry.created_at)
            .bind(entry.expires_at)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    fn find_refresh<'a>(
        &'a self,
        hash: &'a str,
    ) -> BoxFuture<'a, Result<Option<RefreshEntry>, Error>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, RefreshEntry>(
                "SELECT code_hash, family_id, session_id, created_at, expires_at, used_at, revoked_at FROM refresh_tokens WHERE code_hash = $1",
            )
            .bind(hash)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row)
        })
    }

    fn use_refresh<'a>(
        &'a self,
        hash: &'a str,
        now_secs: i64,
    ) -> BoxFuture<'a, Result<bool, Error>> {
        Box::pin(async move {
            let result = sqlx::query(
                "UPDATE refresh_tokens SET used_at = $1 WHERE code_hash = $2 AND used_at IS NULL AND revoked_at IS NULL",
            )
            .bind(now_secs)
            .bind(hash)
            .execute(&self.pool)
            .await?;
            Ok(result.rows_affected() == 1)
        })
    }

    fn revoke_family<'a>(
        &'a self,
        family_id: &'a str,
        now_secs: i64,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            sqlx::query(
                "UPDATE refresh_tokens SET revoked_at = $1 WHERE family_id = $2 AND revoked_at IS NULL",
            )
            .bind(now_secs)
            .bind(family_id)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    fn append_audit_chained<'a>(
        &'a self,
        entry: NewAudit,
        hasher: &'a dyn AuditHasher,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            // One global advisory lock (not per tenant): the audit chain is a
            // single sequence, so two appends must never read the same tip.
            sqlx::query(
                "SELECT pg_advisory_xact_lock(hashtextextended('bandall.audit.chain', 0::bigint))",
            )
            .execute(&mut *tx)
            .await?;
            let prev: Option<(Vec<u8>,)> =
                sqlx::query_as("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1")
                    .fetch_optional(&mut *tx)
                    .await?;
            let prev_hash = prev
                .map(|row| row.0)
                .unwrap_or_else(|| GENESIS_HASH.to_vec());
            // Computed inside the transaction: the lock is still held, so the
            // link cannot be chained from a tip another writer just replaced.
            let hash = hasher.link(&entry, &prev_hash)?;
            sqlx::query(
                "INSERT INTO audit_log (ts, tenant_id, subject_id, event, prev_hash, hash, chain_version) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(entry.ts)
            .bind(&entry.tenant_id)
            .bind(&entry.subject_id)
            .bind(&entry.event)
            .bind(&prev_hash)
            .bind(&hash)
            .bind(entry.chain_version)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(())
        })
    }

    fn list_audit(&self, limit: i64) -> BoxFuture<'_, Result<Vec<AuditEntry>, Error>> {
        Box::pin(async move {
            let rows = sqlx::query_as::<_, AuditEntry>(
                "SELECT seq, ts, tenant_id, subject_id, event, prev_hash, hash, chain_version FROM audit_log ORDER BY seq ASC LIMIT $1",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
            Ok(rows)
        })
    }

    fn count_auth_failures<'a>(
        &'a self,
        key: &'a str,
        since: i64,
    ) -> BoxFuture<'a, Result<i64, Error>> {
        Box::pin(async move {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM auth_failures WHERE policy_key = $1 AND failed_at > $2",
            )
            .bind(key)
            .bind(since)
            .fetch_one(&self.pool)
            .await?;
            Ok(count)
        })
    }

    fn record_auth_failure<'a>(
        &'a self,
        key: &'a str,
        now_secs: i64,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            sqlx::query("INSERT INTO auth_failures (policy_key, failed_at) VALUES ($1, $2)")
                .bind(key)
                .bind(now_secs)
                .execute(&self.pool)
                .await?;
            Ok(())
        })
    }

    fn clear_auth_failures<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            sqlx::query("DELETE FROM auth_failures WHERE policy_key = $1")
                .bind(key)
                .execute(&self.pool)
                .await?;
            Ok(())
        })
    }

    fn reserve_auth_attempt<'a>(
        &'a self,
        key: &'a str,
        now_secs: i64,
        limits: Limits,
    ) -> BoxFuture<'a, Result<Decision, Error>> {
        Box::pin(async move {
            let since = window_start(now_secs, limits);
            let mut tx = self.pool.begin().await?;
            // Per-key advisory lock: the count inside this transaction sees
            // every earlier reservation, so concurrent callers stop exactly
            // at the limit (the lock is released on commit/rollback).
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0::bigint))")
                .bind(key)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM auth_failures WHERE policy_key = $1 AND failed_at <= $2")
                .bind(key)
                .bind(since)
                .execute(&mut *tx)
                .await?;
            let (count, last): (i64, Option<i64>) = sqlx::query_as(
                "SELECT COUNT(*), MAX(failed_at) FROM auth_failures WHERE policy_key = $1 AND failed_at > $2",
            )
            .bind(key)
            .bind(since)
            .fetch_one(&mut *tx)
            .await?;
            let count = u64::try_from(count).map_err(|_| Error::CorruptRow)?;
            let last = last
                .map(|value| u64::try_from(value).map_err(|_| Error::CorruptRow))
                .transpose()?;
            let now = u64::try_from(now_secs).map_err(|_| Error::CorruptRow)?;
            let decision = bandall_policy::evaluate(limits, count, last, now);
            if decision == Decision::Allow {
                sqlx::query("INSERT INTO auth_failures (policy_key, failed_at) VALUES ($1, $2)")
                    .bind(key)
                    .bind(now_secs)
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
            Ok(decision)
        })
    }

    fn create_api_client(&self, input: NewApiClient) -> BoxFuture<'_, Result<ApiClient, Error>> {
        let client = ApiClient {
            key_id: input.key_id,
            tenant_id: input.tenant_id,
            sealed_version: input.sealed_version,
            kek_id: input.kek_id,
            wrapped_dek: input.wrapped_dek,
            wrapped_nonce: input.wrapped_nonce,
            nonce: input.nonce,
            ciphertext: input.ciphertext,
            scopes: input.scopes,
            created_at: input.created_at,
            revoked_at: None,
        };
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO api_clients (key_id, tenant_id, sealed_version, kek_id, wrapped_dek, wrapped_nonce, nonce, ciphertext, scopes, created_at, revoked_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL)",
            )
            .bind(&client.key_id)
            .bind(&client.tenant_id)
            .bind(client.sealed_version)
            .bind(&client.kek_id)
            .bind(&client.wrapped_dek)
            .bind(&client.wrapped_nonce)
            .bind(&client.nonce)
            .bind(&client.ciphertext)
            .bind(&client.scopes)
            .bind(client.created_at)
            .execute(&self.pool)
            .await?;
            Ok(client)
        })
    }

    fn find_api_client<'a>(
        &'a self,
        key_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<ApiClient>, Error>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, ApiClient>(
                "SELECT key_id, tenant_id, sealed_version, kek_id, wrapped_dek, wrapped_nonce, nonce, ciphertext, scopes, created_at, revoked_at FROM api_clients WHERE key_id = $1",
            )
            .bind(key_id)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row)
        })
    }

    fn revoke_api_client<'a>(
        &'a self,
        key_id: &'a str,
        now_secs: i64,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            sqlx::query(
                "UPDATE api_clients SET revoked_at = $1 WHERE key_id = $2 AND revoked_at IS NULL",
            )
            .bind(now_secs)
            .bind(key_id)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }
}

/// Lower bound of the sliding window, saturating on absurd inputs.
fn window_start(now_secs: i64, limits: Limits) -> i64 {
    let window = i64::try_from(limits.window_secs).unwrap_or(i64::MAX);
    now_secs.saturating_sub(window)
}

#[cfg(test)]
mod tests {
    use super::PgStore;
    use crate::error::Error;
    use crate::tests_battery;
    use std::sync::Arc;

    #[tokio::test]
    async fn rejects_clear_text_remote() {
        // Remote host without TLS: must be refused before any I/O.
        let result = PgStore::connect("postgres://bandall:pw@db.internal:5432/bandall").await;
        assert!(matches!(result, Err(Error::InsecureConnection)));
        // Unparseable URL: also refused (fail closed).
        assert!(matches!(
            PgStore::connect("not-a-url").await,
            Err(Error::InsecureConnection)
        ));
    }

    #[tokio::test]
    async fn accepts_tls_or_loopback_urls_without_touching_network() {
        // These return before any connection attempt: the TLS/loopback gate
        // passes and the failure (if any) comes from name resolution, not the
        // security check.
        let with_tls =
            PgStore::connect("postgres://bandall:pw@db.internal:5432/bandall?sslmode=require")
                .await;
        assert!(!matches!(with_tls, Err(Error::InsecureConnection)));
        let loopback = PgStore::connect("postgres://bandall:pw@127.0.0.1:1/bandall").await;
        assert!(!matches!(loopback, Err(Error::InsecureConnection)));
    }

    /// Runs against Postgres when `BANDALL_TEST_PG` is set (CI service).
    /// Skips silently otherwise so local runs stay SQLite-only.
    ///
    /// The battery asserts absolute state (`last_audit_hash` at genesis, a
    /// single-use recovery hash), so it needs a database it owns. CI gets a
    /// fresh service container per run, but a developer's local database
    /// persists: without this the second run fails with a `duplicate key`
    /// error on `refresh_tokens` that says nothing about the code under test.
    #[tokio::test]
    async fn postgres_battery() {
        let Some(url) = std::env::var("BANDALL_TEST_PG").ok() else {
            return;
        };
        let store = PgStore::connect(&url).await.unwrap();
        drop_schema(&store).await.unwrap();
        store.migrate().await.unwrap();
        tests_battery::full_cycle(&store).await.unwrap();
        tests_battery::auth_failures(&store).await.unwrap();
        tests_battery::audit_chain_concurrency(&Arc::new(store))
            .await
            .unwrap();
    }

    /// Drops and recreates `public` so the battery starts from an empty schema.
    ///
    /// `public` specifically, never the whole database: `BANDALL_TEST_PG` may
    /// point at a database that also holds other schemas. Owner credentials are
    /// assumed, which is what CI's service container and the documented local
    /// cluster both provide.
    async fn drop_schema(store: &PgStore) -> Result<(), Error> {
        sqlx::query("DROP SCHEMA IF EXISTS public CASCADE")
            .execute(&store.pool)
            .await?;
        sqlx::query("CREATE SCHEMA public")
            .execute(&store.pool)
            .await?;
        Ok(())
    }
}
