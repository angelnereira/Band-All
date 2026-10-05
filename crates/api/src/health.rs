//! Operational probes. `healthz` is liveness (always 200 when the process
//! runs); `readyz` fails closed when the database is unreachable.

use axum::{Json, extract::State};
use serde::Serialize;

use crate::error::Error;
use crate::state::AppState;

/// Liveness body.
#[derive(Debug, Serialize)]
pub struct Health {
    /// Service name.
    pub service: &'static str,
    /// Crate version.
    pub version: &'static str,
}

/// `GET /healthz`: process is alive.
pub async fn healthz() -> Json<Health> {
    Json(Health {
        service: "bandall",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Readiness body.
#[derive(Debug, Serialize)]
pub struct Ready {
    /// Whether the store answered.
    pub store: bool,
}

/// `GET /readyz`: 200 only when the store answers, else 503 (fail closed).
pub async fn readyz(State(state): State<AppState>) -> Result<Json<Ready>, Error> {
    match state.store.health().await {
        Ok(()) => Ok(Json(Ready { store: true })),
        Err(_) => Err(Error::Unavailable),
    }
}

/// Fallback for unknown routes: RFC 7807, not the default HTML page.
pub async fn not_found() -> Error {
    Error::NotFound
}
