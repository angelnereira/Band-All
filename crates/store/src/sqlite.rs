//! SQLite backend (embedded mode and local development).

use std::str::FromStr;

use bandall_policy::{Decision, Limits};
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use uuid::Uuid;

use crate::error::Error;
use crate::store::{BoxFuture, Store};
use crate::types::{
    ApiClient, AuditEntry, AuditHasher, Factor, NewApiClient, NewAudit, NewFactor, NewRefresh,
    NewWsTicket, RecoveryHash, RefreshEntry, Session, Subject, Tenant, WsTicketEntry,
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");

/// Previous hash of the first entry in the chain (32 zero bytes).
const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// SQLite-backed store.
#[derive(Debug)]
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    /// Connects to `url` without running migrations.
    ///
    /// Creates the database file when it does not exist. Without this, a first
    /// deployment on an empty volume fails to start: the documented config
    /// (`sqlite:bandall.db`) and the H6 demo (`sqlite:/data/bandall.db`) both
    /// point at a file that is not there yet. A missing *directory* still
    /// fails, which is the case worth failing on: it means the mount or the
    /// path is wrong.
    pub async fn connect(url: &str) -> Result<Self, Error> {
        let options = SqliteConnectOptions::from_str(url)?
            .create_if_missing(true)
            .foreign_keys(true);
        Ok(Self {
            pool: SqlitePool::connect_with(options).await?,
        })
    }

    /// Shared in-memory database for tests.
    pub async fn in_memory() -> Result<Self, Error> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")?
            .create_if_missing(true)
            .shared_cache(true)
            .foreign_keys(true);
        Ok(Self {
            pool: SqlitePool::connect_with(options).await?,
        })
    }

    /// The underlying pool, for tests and maintenance that must inspect or
    /// alter the schema directly.
    #[must_use]
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Runs pending migrations.
    pub async fn migrate(&self) -> Result<(), Error> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }
}

const FACTOR_COLS: &str = "id, tenant_id, subject_id, status, secret_version, kek_id, wrapped_dek, wrapped_nonce, nonce, ciphertext, algorithm, digits, period, last_step, drift_steps, created_at, confirmed_at";

impl Store for SqliteStore {
    fn create_tenant(&self, name: &str, now_secs: i64) -> BoxFuture<'_, Result<Tenant, Error>> {
        let tenant = Tenant {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            created_at: now_secs,
        };
        Box::pin(async move {
            sqlx::query("INSERT INTO tenants (id, name, created_at) VALUES (?, ?, ?)")
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
                "INSERT INTO subjects (id, tenant_id, external_id, created_at) VALUES (?, ?, ?, ?)",
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
                "INSERT INTO factors (id, tenant_id, subject_id, status, secret_version, kek_id, wrapped_dek, wrapped_nonce, nonce, ciphertext, algorithm, digits, period, last_step, drift_steps, created_at, confirmed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                "SELECT id, tenant_id, external_id, created_at FROM subjects WHERE tenant_id = ? AND external_id = ?",
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
                "SELECT {FACTOR_COLS} FROM factors WHERE id = ? AND tenant_id = ? AND subject_id = ?"
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
                "UPDATE factors SET last_step = ? WHERE id = ? AND (last_step IS NULL OR last_step < ?)",
            )
            .bind(step)
            .bind(factor_id)
            .bind(step)
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
            sqlx::query("UPDATE factors SET status = 'active', confirmed_at = ? WHERE id = ?")
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
                    "INSERT INTO recovery_codes (factor_id, code_hash, used_at) VALUES (?, ?, NULL)",
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
                "UPDATE recovery_codes SET used_at = ? WHERE factor_id = ? AND code_hash = ? AND used_at IS NULL",
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
            // A table the service cannot work without, not `SELECT 1`: the
            // database answers a constant query with success even when every
            // table has been dropped, which is exactly the state readiness
            // must refuse to advertise (the H8 restore rehearsal found this).
            sqlx::query("SELECT 1 FROM factors LIMIT 1")
                .fetch_optional(&self.pool)
                .await?;
            Ok(())
        })
    }

    fn record_drift<'a>(
        &'a self,
        factor_id: &'a str,
        drift_steps: i64,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            sqlx::query("UPDATE factors SET drift_steps = ? WHERE id = ?")
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
                "SELECT code_hash, used_at FROM recovery_codes WHERE factor_id = ?",
            )
            .bind(factor_id)
            .fetch_all(&self.pool)
            .await?;
            Ok(rows)
        })
    }

    fn delete_factor<'a>(&'a self, factor_id: &'a str) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            sqlx::query("DELETE FROM factors WHERE id = ?")
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
                "INSERT INTO sessions (id, tenant_id, subject_id, created_at, revoked_at) VALUES (?, ?, ?, ?, NULL)",
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
                "SELECT id, tenant_id, subject_id, created_at, revoked_at FROM sessions WHERE id = ?",
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
            sqlx::query("UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
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
                "INSERT INTO refresh_tokens (code_hash, family_id, session_id, created_at, expires_at, used_at, revoked_at) VALUES (?, ?, ?, ?, ?, NULL, NULL)",
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
                "SELECT code_hash, family_id, session_id, created_at, expires_at, used_at, revoked_at FROM refresh_tokens WHERE code_hash = ?",
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
                "UPDATE refresh_tokens SET used_at = ? WHERE code_hash = ? AND used_at IS NULL AND revoked_at IS NULL",
            )
            .bind(now_secs)
            .bind(hash)
            .execute(&self.pool)
            .await?;
            Ok(result.rows_affected() == 1)
        })
    }

    fn store_ws_ticket(&self, entry: NewWsTicket) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO ws_tickets (code_hash, session_id, tenant_id, subject_id, access_expires_at, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(entry.code_hash)
            .bind(entry.session_id)
            .bind(entry.tenant_id)
            .bind(entry.subject_id)
            .bind(entry.access_expires_at)
            .bind(entry.created_at)
            .bind(entry.expires_at)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    fn claim_ws_ticket<'a>(
        &'a self,
        hash: &'a str,
        now_secs: i64,
    ) -> BoxFuture<'a, Result<Option<WsTicketEntry>, Error>> {
        Box::pin(async move {
            // One atomic statement: whoever marks `used_at` first wins, and the
            // winner comes back with everything the redeemer needs. A spent or
            // unknown ticket is simply absent.
            let entry = sqlx::query_as::<_, WsTicketEntry>(
                "UPDATE ws_tickets SET used_at = ? WHERE code_hash = ? AND used_at IS NULL RETURNING code_hash, session_id, tenant_id, subject_id, access_expires_at, created_at, expires_at, used_at",
            )
            .bind(now_secs)
            .bind(hash)
            .fetch_optional(&self.pool)
            .await?;
            Ok(entry)
        })
    }

    fn revoke_family<'a>(
        &'a self,
        family_id: &'a str,
        now_secs: i64,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            sqlx::query(
                "UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL",
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
            // `BEGIN IMMEDIATE` takes the write lock before reading the tip, so
            // a concurrent burst cannot read the same predecessor twice.
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            let prev: Option<(Vec<u8>,)> =
                sqlx::query_as("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1")
                    .fetch_optional(&mut *tx)
                    .await?;
            let prev_hash = prev
                .map(|row| row.0)
                .unwrap_or_else(|| GENESIS_HASH.to_vec());
            // Computed inside the transaction: the write lock is still held, so
            // the link cannot be chained from a tip another writer replaced.
            let hash = hasher.link(&entry, &prev_hash)?;
            sqlx::query(
                "INSERT INTO audit_log (ts, tenant_id, subject_id, event, prev_hash, hash, chain_version) VALUES (?, ?, ?, ?, ?, ?, ?)",
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
                "SELECT seq, ts, tenant_id, subject_id, event, prev_hash, hash, chain_version FROM audit_log ORDER BY seq ASC LIMIT ?",
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
                "SELECT COUNT(*) FROM auth_failures WHERE policy_key = ? AND failed_at > ?",
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
            sqlx::query("INSERT INTO auth_failures (policy_key, failed_at) VALUES (?, ?)")
                .bind(key)
                .bind(now_secs)
                .execute(&self.pool)
                .await?;
            Ok(())
        })
    }

    fn clear_auth_failures<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            sqlx::query("DELETE FROM auth_failures WHERE policy_key = ?")
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
            // `BEGIN IMMEDIATE` takes the write lock before reading, so the
            // count sees every committed reservation: a concurrent burst is
            // serialized and stops exactly at the limit.
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            let decision = reserve(&mut tx, key, now_secs, since, limits).await?;
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
                "INSERT INTO api_clients (key_id, tenant_id, sealed_version, kek_id, wrapped_dek, wrapped_nonce, nonce, ciphertext, scopes, created_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
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
                "SELECT key_id, tenant_id, sealed_version, kek_id, wrapped_dek, wrapped_nonce, nonce, ciphertext, scopes, created_at, revoked_at FROM api_clients WHERE key_id = ?",
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
                "UPDATE api_clients SET revoked_at = ? WHERE key_id = ? AND revoked_at IS NULL",
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

/// Prune, count and (on `Allow`) reserve, inside the caller's transaction.
async fn reserve(
    conn: &mut sqlx::SqliteConnection,
    key: &str,
    now_secs: i64,
    since: i64,
    limits: Limits,
) -> Result<Decision, Error> {
    sqlx::query("DELETE FROM auth_failures WHERE policy_key = ? AND failed_at <= ?")
        .bind(key)
        .bind(since)
        .execute(&mut *conn)
        .await?;
    let (count, last): (i64, Option<i64>) = sqlx::query_as(
        "SELECT COUNT(*), MAX(failed_at) FROM auth_failures WHERE policy_key = ? AND failed_at > ?",
    )
    .bind(key)
    .bind(since)
    .fetch_one(&mut *conn)
    .await?;
    let count = u64::try_from(count).map_err(|_| Error::CorruptRow)?;
    let last = last
        .map(|value| u64::try_from(value).map_err(|_| Error::CorruptRow))
        .transpose()?;
    let now = u64::try_from(now_secs).map_err(|_| Error::CorruptRow)?;
    let decision = bandall_policy::evaluate(limits, count, last, now);
    if decision == Decision::Allow {
        sqlx::query("INSERT INTO auth_failures (policy_key, failed_at) VALUES (?, ?)")
            .bind(key)
            .bind(now_secs)
            .execute(&mut *conn)
            .await?;
    }
    Ok(decision)
}

#[cfg(test)]
mod tests {
    use super::SqliteStore;
    use crate::store::Store;
    use crate::tests_battery;
    use std::sync::Arc;

    /// A first deployment points at a file that does not exist yet; refusing
    /// to start there made the default config and the H6 demo fail on a fresh
    /// volume.
    #[tokio::test]
    async fn connect_creates_a_missing_database_file() {
        let path = std::env::temp_dir().join(format!(
            "bandall-sqlite-create-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_file(&path);
        let url = format!("sqlite:{}", path.display());

        let store = SqliteStore::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        assert!(path.exists(), "connect must create the database file");
        tests_battery::full_cycle(&store).await.unwrap();

        let _ = std::fs::remove_file(&path);
    }

    /// A missing parent directory still fails: that is a wrong path or a wrong
    /// mount, not a first run.
    #[tokio::test]
    async fn connect_refuses_a_missing_directory() {
        let path = std::env::temp_dir()
            .join(format!("bandall-no-such-dir-{}", std::process::id()))
            .join("bandall.db");
        let url = format!("sqlite:{}", path.display());
        assert!(SqliteStore::connect(&url).await.is_err());
    }

    #[tokio::test]
    async fn sqlite_battery() {
        let store = SqliteStore::in_memory().await.unwrap();
        store.migrate().await.unwrap();
        tests_battery::full_cycle(&store).await.unwrap();
        tests_battery::auth_failures(&store).await.unwrap();
        tests_battery::audit_chain_concurrency(&Arc::new(store))
            .await
            .unwrap();
    }

    /// The ticket battery, against SQLite (ADR-0017).
    #[tokio::test]
    async fn sqlite_ws_tickets_battery() {
        let store = Arc::new(SqliteStore::in_memory().await.unwrap());
        store.migrate().await.unwrap();
        crate::tests_battery_ws::ws_tickets(&store).await.unwrap();
    }

    /// Readiness must refuse a database whose schema is gone.
    ///
    /// `SELECT 1` answers happily in an empty database, so a readiness probe
    /// built on it advertises a service that cannot answer anything. Found by
    /// the H8 restore rehearsal, which dropped the schema under a running
    /// service and watched `/readyz` keep returning 200.
    #[tokio::test]
    async fn health_fails_once_the_schema_is_gone() {
        let store = SqliteStore::in_memory().await.unwrap();
        store.migrate().await.unwrap();
        Store::health(&store)
            .await
            .expect("a migrated store is healthy");

        // Deliberately NOT the same statement as the Postgres version: SQLite
        // has no `CASCADE` keyword on `DROP TABLE` and rejects it as a syntax
        // error. Both tests express the same intent — the schema must be gone,
        // not merely empty — but the two SQL dialects spell it differently. The
        // previous version used the identical statement in both and passed in
        // SQLite while erroring in Postgres, because SQLite only refuses to drop
        // a parent table when foreign keys are enforced, and this connection does
        // not enforce them.
        sqlx::query("DROP TABLE factors")
            .execute(store.pool())
            .await
            .unwrap();

        assert!(
            Store::health(&store).await.is_err(),
            "readiness must fail when the tables it needs are missing"
        );
    }
}
