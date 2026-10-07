//! Typed errors for `bandall-store`.

use thiserror::Error;

/// All errors produced by this crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Database failure (fail closed upstream).
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Migration failure at startup (fail closed).
    #[error("migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    /// Clear-text connection to a remote Postgres (fail closed).
    #[error("remote postgres requires TLS (add sslmode=require/verify-full)")]
    InsecureConnection,

    /// Stored value violates an invariant (e.g. negative step).
    #[error("corrupt row")]
    CorruptRow,

    /// Integer out of range for the domain type.
    #[error("integer out of range")]
    OutOfRange,

    /// A chain-link hash could not be computed (fail closed: the entry is not
    /// appended, so the log never gains an unverifiable row).
    #[error("audit chain hash failure")]
    ChainHash,
}
