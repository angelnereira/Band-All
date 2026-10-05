//! Postgres backend.

use sqlx::PgPool;
use sqlx::migrate::MigrateDatabase;
use uuid::Uuid;

use crate::error::Error;
use crate::store::Store;
use crate::types::{Factor, NewFactor, Subject, Tenant};

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

const FACTOR_COLS: &str = "id, tenant_id, subject_id, status, secret_version, kek_id, wrapped_dek, wrapped_nonce, nonce, ciphertext, algorithm, digits, period, last_step, created_at, confirmed_at";

impl Store for PgStore {
    async fn create_tenant(&self, name: &str, now_secs: i64) -> Result<Tenant, Error> {
        let tenant = Tenant {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            created_at: now_secs,
        };
        sqlx::query("INSERT INTO tenants (id, name, created_at) VALUES ($1, $2, $3)")
            .bind(&tenant.id)
            .bind(&tenant.name)
            .bind(tenant.created_at)
            .execute(&self.pool)
            .await?;
        Ok(tenant)
    }

    async fn create_subject(
        &self,
        tenant_id: &str,
        external_id: &str,
        now_secs: i64,
    ) -> Result<Subject, Error> {
        let subject = Subject {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            external_id: external_id.to_string(),
            created_at: now_secs,
        };
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
    }

    async fn create_factor(&self, input: NewFactor) -> Result<Factor, Error> {
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
        sqlx::query(
            "INSERT INTO factors (id, tenant_id, subject_id, status, secret_version, kek_id, wrapped_dek, wrapped_nonce, nonce, ciphertext, algorithm, digits, period, last_step, created_at, confirmed_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
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
    }

    async fn get_factor(
        &self,
        tenant_id: &str,
        subject_id: &str,
        factor_id: &str,
    ) -> Result<Option<Factor>, Error> {
        let row = sqlx::query_as::<_, Factor>(&format!(
            "SELECT {FACTOR_COLS} FROM factors WHERE id = $1 AND tenant_id = $2 AND subject_id = $3"
        ))
        .bind(factor_id)
        .bind(tenant_id)
        .bind(subject_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn cas_last_step(&self, factor_id: &str, step: u64) -> Result<bool, Error> {
        let step = i64::try_from(step).map_err(|_| Error::OutOfRange)?;
        let result = sqlx::query(
            "UPDATE factors SET last_step = $1 WHERE id = $2 AND (last_step IS NULL OR last_step < $1)",
        )
        .bind(step)
        .bind(factor_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn confirm_factor(&self, factor_id: &str, now_secs: i64) -> Result<(), Error> {
        sqlx::query("UPDATE factors SET status = 'active', confirmed_at = $1 WHERE id = $2")
            .bind(now_secs)
            .bind(factor_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn add_recovery_codes(&self, factor_id: &str, hashes: &[String]) -> Result<(), Error> {
        for hash in hashes {
            sqlx::query(
                "INSERT INTO recovery_codes (factor_id, code_hash, used_at) VALUES ($1, $2, NULL)",
            )
            .bind(factor_id)
            .bind(hash)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    async fn use_recovery_code(
        &self,
        factor_id: &str,
        hash: &str,
        now_secs: i64,
    ) -> Result<bool, Error> {
        let result = sqlx::query(
            "UPDATE recovery_codes SET used_at = $1 WHERE factor_id = $2 AND code_hash = $3 AND used_at IS NULL",
        )
        .bind(now_secs)
        .bind(factor_id)
        .bind(hash)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn health(&self) -> Result<(), Error> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
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
