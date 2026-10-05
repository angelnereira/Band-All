//! The `Store` trait: the only persistence contract the API depends on.
//!
//! Backends (Postgres, SQLite) must pass the same battery of tests, run by
//! CI. Concurrency-critical transitions (`cas_last_step`,
//! `use_recovery_code`) are single atomic statements: exactly one winner.
//!
//! Methods return boxed futures so the trait stays object-safe
//! (`Arc<dyn Store>` in `AppState`) without extra dependencies.

use std::future::Future;
use std::pin::Pin;

use crate::error::Error;
use crate::types::{Factor, NewFactor, RecoveryHash, Subject, Tenant};

/// Boxed future shorthand for trait methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Persistence contract. All methods fail closed on database errors.
pub trait Store: Send + Sync {
    /// Creates a tenant with a fresh random id.
    fn create_tenant(&self, name: &str, now_secs: i64) -> BoxFuture<'_, Result<Tenant, Error>>;

    /// Creates a subject with a fresh random id.
    fn create_subject(
        &self,
        tenant_id: &str,
        external_id: &str,
        now_secs: i64,
    ) -> BoxFuture<'_, Result<Subject, Error>>;

    /// Finds a subject by its caller-provided external id.
    fn find_subject<'a>(
        &'a self,
        tenant_id: &'a str,
        external_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<Subject>, Error>>;

    /// Inserts a factor with a fresh random id.
    fn create_factor(&self, factor: NewFactor) -> BoxFuture<'_, Result<Factor, Error>>;

    /// Fetches one factor scoped to its tenant and subject.
    fn get_factor<'a>(
        &'a self,
        tenant_id: &'a str,
        subject_id: &'a str,
        factor_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<Factor>, Error>>;

    /// Atomically records `step` as consumed iff it is newer than the stored
    /// one. Returns `true` for exactly one concurrent winner.
    fn cas_last_step<'a>(
        &'a self,
        factor_id: &'a str,
        step: u64,
    ) -> BoxFuture<'a, Result<bool, Error>>;

    /// Marks a factor `active` with its confirmation time.
    fn confirm_factor<'a>(
        &'a self,
        factor_id: &'a str,
        now_secs: i64,
    ) -> BoxFuture<'a, Result<(), Error>>;

    /// Stores recovery-code hashes (PHC strings) for a factor.
    fn add_recovery_codes<'a>(
        &'a self,
        factor_id: &'a str,
        hashes: &'a [String],
    ) -> BoxFuture<'a, Result<(), Error>>;

    /// Atomically consumes one recovery code by hash. Returns `true` iff the
    /// code existed and was unused: single-use even under concurrency.
    fn use_recovery_code<'a>(
        &'a self,
        factor_id: &'a str,
        hash: &'a str,
        now_secs: i64,
    ) -> BoxFuture<'a, Result<bool, Error>>;

    /// Liveness probe (`SELECT 1`).
    fn health(&self) -> BoxFuture<'_, Result<(), Error>>;

    /// Persists the learned clock drift (bounded to ±5 by callers).
    fn record_drift<'a>(
        &'a self,
        factor_id: &'a str,
        drift_steps: i64,
    ) -> BoxFuture<'a, Result<(), Error>>;

    /// Lists recovery-code hashes for a factor (used and unused).
    fn list_recovery_hashes<'a>(
        &'a self,
        factor_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<RecoveryHash>, Error>>;

    /// Deletes a factor and its recovery codes (post-recovery re-enrolment).
    fn delete_factor<'a>(&'a self, factor_id: &'a str) -> BoxFuture<'a, Result<(), Error>>;
}
