//! Typed errors for `bandall-tokens`. Failures are uniform: callers cannot
//! distinguish an unknown key from a forged signature.

use thiserror::Error;

/// All errors produced by this crate.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Error {
    /// Malformed token, unknown key, bad signature or invalid claims.
    #[error("invalid token")]
    Invalid,

    /// Key material has the wrong length.
    #[error("invalid key length")]
    InvalidKeyLength,

    /// Filesystem error for key files (message only).
    #[error("key file error: {0}")]
    KeyFile(String),

    /// Randomness failure (fail closed).
    #[error("randomness failure")]
    Random,
}
