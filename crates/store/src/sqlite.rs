//! SQLite backend (embedded mode and local development).

use std::str::FromStr;

use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use uuid::Uuid;

use crate::error::Error;
use crate::store::{BoxFuture, Store};
use crate::types::{Factor, NewFactor, Subject, Tenant};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");

/// SQLite-backed store.
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    /// Connects to `url` without running migrations.
    pub async fn connect(url: &str) -> Result<Self, Error> {
        Ok(Self {
            pool: SqlitePool::connect(url).await?,
        })
    }

    /// Shared in-memory database for tests.
    pub async fn in_memory() -> Result<Self, Error> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")?
            .create_if_missing(true)
            .shared_cache(true);
        Ok(Self {
            pool: SqlitePool::connect_with(options).await?,
        })
    }

    /// Runs pending migrations.
    pub async fn migrate(&self) -> Result<(), Error> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }
}

const FACTOR_COLS: &str = "id, tenant_id, subject_id, status, secret_version, kek_id, wrapped_dek, wrapped_nonce, nonce, ciphertext, algorithm, digits, period, last_step, created_at, confirmed_at";

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
            id: Uuid::new_v4().to_string(),
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
            created_at: input.created_at,
            confirmed_at: None,
        };
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO factors (id, tenant_id, subject_id, status, secret_version, kek_id, wrapped_dek, wrapped_nonce, nonce, ciphertext, algorithm, digits, period, last_step, created_at, confirmed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            .bind(factor.created_at)
            .bind(factor.confirmed_at)
            .execute(&self.pool)
            .await?;
            Ok(factor)
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
            sqlx::query("SELECT 1").execute(&self.pool).await?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::SqliteStore;
    use crate::tests_battery;

    #[tokio::test]
    async fn sqlite_battery() {
        let store = SqliteStore::in_memory().await.unwrap();
        store.migrate().await.unwrap();
        tests_battery::full_cycle(&store).await.unwrap();
    }
}
