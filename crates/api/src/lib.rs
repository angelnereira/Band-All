//! `bandall-api`: axum HTTP service (enrolment, verification, probes).
//!
//! Async lives here by design; the crypto core stays synchronous.
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

pub mod config;
pub mod enroll;
pub mod error;
pub mod health;
pub mod openapi;
pub mod server;
pub mod state;
pub mod token;
pub mod verify;

pub use config::{Config, DatabaseKind};
pub use error::Error;
pub use state::AppState;
