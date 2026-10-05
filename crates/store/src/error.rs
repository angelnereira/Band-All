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

    /// Stored value violates an invariant (e.g. negative step).
    #[error("corrupt row")]
    CorruptRow,

    /// Integer out of range for the domain type.
    #[error("integer out of range")]
    OutOfRange,
}
