//! Postgres backend.

use sqlx::PgPool;
use sqlx::migrate::MigrateDatabase;
use uuid::Uuid;

use crate::error::Error;
use crate::store::{BoxFuture, Store};
use crate::types::{
    Factor, NewFactor, NewRefresh, RecoveryHash, RefreshEntry, Session, Subject, Tenant,
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

/// Postgres-backed store.
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    /// Connects without running migrations.
    pub async fn connect(url: &str) -> Result<Self, Error> {
        if !sqlx::Postgres::database_exists(url).await.unwrap_or(false) {
            sqlx::Postgres::create_database(url).await?;
        }
        Ok(Self {
            pool: PgPool::connect(url).await?,
        })
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
}

#[cfg(test)]
mod tests {
    use super::PgStore;
    use crate::tests_battery;

    /// Runs against Postgres when `BANDALL_TEST_PG` is set (CI service).
    /// Skips silently otherwise so local runs stay SQLite-only.
    #[tokio::test]
    async fn postgres_battery() {
        let Some(url) = std::env::var("BANDALL_TEST_PG").ok() else {
            return;
        };
        let store = PgStore::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        tests_battery::full_cycle(&store).await.unwrap();
    }
}
