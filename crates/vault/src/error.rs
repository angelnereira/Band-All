//! Typed errors for `bandall-vault`.
//!
//! Decryption failures are uniform: a wrong key, wrong AAD or tampered
//! ciphertext all surface as `DecryptionFailed` (no oracle for callers).

use thiserror::Error;

/// All errors produced by this crate. Never carries secret material.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// KMS key material has the wrong length (exactly 32 bytes required).
    #[error("invalid KMS key length")]
    InvalidKeyLength,

    /// Filesystem error loading a local KMS key (message only, no secret).
    #[error("kms key file error: {0}")]
    KeyFile(String),

    /// Local KMS key file has unsafe permissions (must be 0600 or stricter).
    #[error("unsafe kms key file permissions")]
    UnsafeKeyPermissions,

    /// Encryption failed (fail closed).
    #[error("encryption failed")]
    EncryptionFailed,

    /// Decryption failed: wrong key, wrong AAD or tampered data.
    #[error("decryption failed")]
    DecryptionFailed,

    /// The OS CSPRNG failed (fail closed).
    #[error("randomness failure")]
    Random,

    /// Malformed password hash (recovery codes).
    #[error("invalid recovery hash")]
    InvalidRecoveryHash,

    /// Recovery code parameter out of range.
    #[error("invalid recovery parameter")]
    InvalidRecoveryParam,
}
