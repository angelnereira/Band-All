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

pub mod audit;
pub mod authz;
pub mod config;
pub mod enroll;
pub mod error;
pub mod gates;
pub mod health;
pub mod metrics;
pub mod openapi;
pub mod server;
pub mod sigs;
pub mod state;
pub mod token;
pub mod verify;
pub mod wsticket;

pub use audit::AuditChain;
pub use bandall_store::AuditEntry;
pub use bandall_store::NewApiClient;
pub use config::{Config, DatabaseKind};
pub use error::Error;
pub use state::AppState;
