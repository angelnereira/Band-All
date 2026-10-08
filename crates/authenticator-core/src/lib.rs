//! `bandall-authenticator-core`: offline account logic for the mobile app.
//!
//! Pure Rust: provisioning, codes, countdowns, skew warnings and optional
//! encrypted backup. Secure storage, biometrics and the UI live in the
//! native shells (binding strategy in ADR-0006).
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod accounts;
pub mod backup;
pub mod error;

pub use accounts::{Account, AccountSnapshot, AccountStore, SKEW_WARN_SECS, clock_skew};
pub use backup::{export_encrypted, import_encrypted};
pub use error::Error;
// `Account::manual` takes an `Algorithm` and the backup format carries it as a
// name, so a caller cannot build an account without those types. Re-exported
// rather than reached around, so the core stays the only path to the math.
pub use bandall_totp_core::{Algorithm, Secret, TotpParams};
