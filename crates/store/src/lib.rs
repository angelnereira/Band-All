//! `bandall-store`: persistence trait with Postgres and SQLite backends.
//!
//! Both backends pass the same conformance battery (`tests_battery`, run by
//! CI). Time is Unix seconds; steps map to `u64` with corruption checks.
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

pub mod error;
pub mod postgres;
pub mod sqlite;
pub mod store;
pub mod types;

#[cfg(test)]
pub(crate) mod tests_battery;
#[cfg(test)]
pub(crate) mod tests_battery_ws;

pub use error::Error;
pub use postgres::PgStore;
pub use sqlite::SqliteStore;
pub use store::Store;
pub use types::{
    ApiClient, AuditEntry, AuditHasher, Factor, NewApiClient, NewAudit, NewFactor, NewRefresh,
    NewWsTicket, RecoveryHash, RefreshEntry, Session, Subject, Tenant, WsTicketEntry,
    new_factor_id, new_session_id,
};
