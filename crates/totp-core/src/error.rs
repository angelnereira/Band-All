//! Typed errors for `bandall-totp-core`.
//!
//! Verification failures distinguish `CodeMismatch` from `CodeReplayed` so
//! callers can audit them differently. API layers must still answer both with
//! a uniform response (anti-enumeration, see the blueprint).

use thiserror::Error;

/// All errors produced by this crate. Never carries secret material.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Error {
    /// Secret is not strict RFC 4648 Base32 (uppercase, no padding).
    #[error("invalid base32 secret")]
    InvalidBase32,

    /// Malformed `otpauth://` URI or unsupported parameter value.
    #[error("invalid otpauth URI")]
    InvalidUri,

    /// Digit count is not 6, 7 or 8.
    #[error("invalid digit count: {0}")]
    InvalidDigits(u8),

    /// Period is zero.
    #[error("invalid period")]
    InvalidPeriod,

    /// Tolerance window exceeds the allowed maximum.
    #[error("invalid window")]
    InvalidWindow,

    /// Step counter overflowed (practically unreachable).
    #[error("counter overflow")]
    CounterOverflow,

    /// The code is well-formed but matches no step in the window.
    #[error("code mismatch")]
    CodeMismatch,

    /// The code is valid but its step was already consumed (replay).
    #[error("code replayed")]
    CodeReplayed,

    /// The submitted code is not numeric or has the wrong length.
    #[error("invalid code")]
    InvalidCode,

    /// Secret length outside 16..=128 bytes.
    #[error("invalid secret length: {0}")]
    InvalidSecretLength(usize),

    /// HMAC failure (treated as invalid secret; fail closed).
    #[error("crypto failure")]
    Crypto,

    /// The OS CSPRNG failed (fail closed).
    #[error("randomness failure")]
    Random,
}
