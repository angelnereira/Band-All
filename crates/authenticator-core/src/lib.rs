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
