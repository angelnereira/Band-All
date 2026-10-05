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
use crate::types::{
    ApiClient, AuditEntry, Factor, NewApiClient, NewFactor, NewRefresh, RecoveryHash, RefreshEntry,
    Session, Subject, Tenant,
};

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

    /// Creates a session with a fresh random id.
    fn create_session(
        &self,
        tenant_id: &str,
        subject_id: &str,
        now_secs: i64,
    ) -> BoxFuture<'_, Result<Session, Error>>;

    /// Fetches a session by id.
    fn get_session<'a>(
        &'a self,
        session_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<Session>, Error>>;

    /// Revokes a session (idempotent).
    fn revoke_session<'a>(
        &'a self,
        session_id: &'a str,
        now_secs: i64,
    ) -> BoxFuture<'a, Result<(), Error>>;

    /// Persists a refresh-token hash.
    fn store_refresh(&self, entry: NewRefresh) -> BoxFuture<'_, Result<(), Error>>;

    /// Fetches a refresh entry by hash.
    fn find_refresh<'a>(
        &'a self,
        hash: &'a str,
    ) -> BoxFuture<'a, Result<Option<RefreshEntry>, Error>>;

    /// Atomically consumes a refresh token. Returns `false` when already
    /// used (reuse signal for theft detection).
    fn use_refresh<'a>(
        &'a self,
        hash: &'a str,
        now_secs: i64,
    ) -> BoxFuture<'a, Result<bool, Error>>;

    /// Revokes a whole refresh family (reuse detected).
    fn revoke_family<'a>(
        &'a self,
        family_id: &'a str,
        now_secs: i64,
    ) -> BoxFuture<'a, Result<(), Error>>;

    /// Appends an audit entry with its chain hashes.
    fn append_audit<'a>(
        &'a self,
        ts: i64,
        tenant_id: &'a str,
        subject_id: &'a str,
        event: &'a str,
        prev_hash: &'a [u8],
        hash: &'a [u8],
    ) -> BoxFuture<'a, Result<(), Error>>;

    /// Latest audit hash (`None` at genesis).
    fn last_audit_hash(&self) -> BoxFuture<'_, Result<Option<Vec<u8>>, Error>>;

    /// Lists audit entries in sequence order (bounded, newest last).
    fn list_audit(&self, limit: i64) -> BoxFuture<'_, Result<Vec<AuditEntry>, Error>>;

    /// Creates an API client with a caller-assigned key id.
    fn create_api_client(&self, client: NewApiClient) -> BoxFuture<'_, Result<ApiClient, Error>>;

    /// Fetches an API client by key id (revoked included; callers check).
    fn find_api_client<'a>(
        &'a self,
        key_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<ApiClient>, Error>>;

    /// Revokes an API client (idempotent).
    fn revoke_api_client<'a>(
        &'a self,
        key_id: &'a str,
        now_secs: i64,
    ) -> BoxFuture<'a, Result<(), Error>>;
}
