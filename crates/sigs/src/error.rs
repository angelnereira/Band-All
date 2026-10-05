//! Typed errors for `bandall-sigs`. Verification failures are uniform.

use thiserror::Error;

/// All errors produced by this crate.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Error {
    /// Bad signature, unknown key, stale timestamp or reused nonce.
    #[error("invalid signature")]
    Invalid,

    /// Malformed signature header.
    #[error("malformed signature")]
    Malformed,

    /// Timestamp outside the tolerance window.
    #[error("stale timestamp")]
    Stale,

    /// Nonce already seen (replay).
    #[error("reused nonce")]
    Reused,

    /// Randomness failure (fail closed).
    #[error("randomness failure")]
    Random,
}
