//! The `Store` trait: the only persistence contract the API depends on.
//!
//! Backends (Postgres, SQLite) must pass the same battery of tests, run by
//! CI. Concurrency-critical transitions (`cas_last_step`,
//! `use_recovery_code`) are single atomic statements: exactly one winner.

use crate::error::Error;
use crate::types::{Factor, NewFactor, Subject, Tenant};

/// Persistence contract. All methods fail closed on database errors.
pub trait Store: Send + Sync {
    /// Creates a tenant with a fresh random id.
    fn create_tenant(
        &self,
        name: &str,
        now_secs: i64,
    ) -> impl Future<Output = Result<Tenant, Error>> + Send;

    /// Creates a subject with a fresh random id.
    fn create_subject(
        &self,
        tenant_id: &str,
        external_id: &str,
        now_secs: i64,
    ) -> impl Future<Output = Result<Subject, Error>> + Send;

    /// Inserts a factor with a fresh random id.
    fn create_factor(
        &self,
        factor: NewFactor,
    ) -> impl Future<Output = Result<Factor, Error>> + Send;

    /// Fetches one factor scoped to its tenant and subject.
    fn get_factor(
        &self,
        tenant_id: &str,
        subject_id: &str,
        factor_id: &str,
    ) -> impl Future<Output = Result<Option<Factor>, Error>> + Send;

    /// Atomically records `step` as consumed iff it is newer than the stored
    /// one. Returns `true` for exactly one concurrent winner.
    fn cas_last_step(
        &self,
        factor_id: &str,
        step: u64,
    ) -> impl Future<Output = Result<bool, Error>> + Send;

    /// Marks a factor `active` with its confirmation time.
    fn confirm_factor(
        &self,
        factor_id: &str,
        now_secs: i64,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Stores recovery-code hashes (PHC strings) for a factor.
    fn add_recovery_codes(
        &self,
        factor_id: &str,
        hashes: &[String],
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Atomically consumes one recovery code by hash. Returns `true` iff the
    /// code existed and was unused: single-use even under concurrency.
    fn use_recovery_code(
        &self,
        factor_id: &str,
        hash: &str,
        now_secs: i64,
    ) -> impl Future<Output = Result<bool, Error>> + Send;

    /// Liveness probe (`SELECT 1`).
    fn health(&self) -> impl Future<Output = Result<(), Error>> + Send;
}
