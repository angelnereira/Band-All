//! Typed errors for the embedded facade. Uniform and without secret detail.

use thiserror::Error;

/// Errors produced by the facade.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The store or vault failed under the hood. The detail stays internal.
    #[error("embedded store/vault failure")]
    Internal,

    /// Tenant, subject or factor does not exist, or the code is wrong,
    /// expired, out of window or replayed: uniform, anti-enumeration.
    #[error("not verified")]
    Unverified,

    /// The factor exists but is not in a usable state.
    #[error("factor not usable")]
    FactorState,

    /// The KEK provided cannot be used.
    #[error("invalid key material")]
    InvalidKey,

    /// The subject external id is empty.
    #[error("subject required")]
    MissingSubject,

    /// The account label is empty.
    #[error("account required")]
    MissingAccount,
}

impl From<bandall_vault::Error> for Error {
    fn from(_: bandall_vault::Error) -> Self {
        // A wrong KEK, tampered ciphertext or bad AAD all map to the same
        // denial: no oracle for whoever holds a copy of the database.
        Self::Internal
    }
}

impl From<bandall_store::Error> for Error {
    fn from(_: bandall_store::Error) -> Self {
        Self::Internal
    }
}

impl From<bandall_totp_core::Error> for Error {
    fn from(_: bandall_totp_core::Error) -> Self {
        Self::Unverified
    }
}
