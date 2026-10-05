//! Typed errors for `bandall-authenticator-core`.

use thiserror::Error;

/// All errors produced by this crate. Never carries secrets.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Error {
    /// Malformed account data or backup envelope.
    #[error("invalid account data")]
    Invalid,

    /// Backup decryption failed (wrong passphrase or tampered file).
    #[error("cannot open backup")]
    Sealed,

    /// Randomness failure (fail closed).
    #[error("randomness failure")]
    Random,
}
