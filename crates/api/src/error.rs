//! RFC 7807 problem responses. Every client-facing error maps to a stable
//! `type` URI with `title`, `status` and `detail` — never internal details.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// Machine-readable problem type URIs (stable contract).
pub const PROBLEM_BAD_REQUEST: &str = "https://bandall.dev/problems/bad-request";
/// Authentication or verification failure (uniform, anti-enumeration).
pub const PROBLEM_UNAUTHORIZED: &str = "https://bandall.dev/problems/unauthorized";
/// Unknown or unscoped route.
pub const PROBLEM_NOT_FOUND: &str = "https://bandall.dev/problems/not-found";
/// Dependency (database) unreachable: fail closed with 503.
pub const PROBLEM_UNAVAILABLE: &str = "https://bandall.dev/problems/unavailable";
/// Deprecation-free rate limiting (H5 fills the policy behind it).
pub const PROBLEM_RATE_LIMITED: &str = "https://bandall.dev/problems/rate-limited";
/// Anything else: fail closed without leaking internals.
pub const PROBLEM_INTERNAL: &str = "https://bandall.dev/problems/internal";

/// RFC 7807 problem body.
#[derive(Debug, Serialize)]
pub struct Problem {
    /// Stable problem type URI.
    #[serde(rename = "type")]
    pub problem_type: &'static str,
    /// Short human-readable summary.
    pub title: &'static str,
    /// HTTP status code.
    pub status: u16,
    /// Request-specific detail (no internals, no secrets).
    pub detail: String,
}

/// API error: maps to a problem response.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Malformed request or failed validation.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Verification or authentication failure. Always uniform.
    #[error("unauthorized")]
    Unauthorized,

    /// Unknown resource.
    #[error("not found")]
    NotFound,

    /// A dependency is unreachable. Detail is intentionally generic.
    #[error("service unavailable")]
    Unavailable,

    /// Internal failure. Detail is intentionally generic.
    #[error("internal error")]
    Internal(#[from] anyhow::Error),

    /// Startup configuration failure. Only surfaces in server logs, never
    /// over HTTP (the server never starts).
    #[error("configuration error: {0}")]
    Config(String),
}

impl Error {
    /// Generic internal failure without leaking `source`.
    pub fn internal(message: &str) -> Self {
        Self::Internal(anyhow::anyhow!("{message}"))
    }

    /// Uniform denial for verification paths (wrong code, unknown factor,
    /// replayed code, locked account: all identical).
    pub fn denied() -> Self {
        Self::Unauthorized
    }
}

impl From<bandall_store::Error> for Error {
    fn from(_: bandall_store::Error) -> Self {
        Self::internal("store failure")
    }
}

impl From<bandall_vault::Error> for Error {
    fn from(_: bandall_vault::Error) -> Self {
        Self::internal("vault failure")
    }
}

impl From<bandall_totp_core::Error> for Error {
    fn from(_: bandall_totp_core::Error) -> Self {
        // TOTP math errors (bad digits, bad URI) are server-side bugs once
        // inputs are validated; verification mismatches become `denied()`.
        Self::internal("totp failure")
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, problem_type, title, detail) = match &self {
            Self::BadRequest(detail) => (
                StatusCode::BAD_REQUEST,
                PROBLEM_BAD_REQUEST,
                "Bad request",
                detail.clone(),
            ),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                PROBLEM_UNAUTHORIZED,
                "Unauthorized",
                "Invalid credentials.".to_string(),
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                PROBLEM_NOT_FOUND,
                "Not found",
                "Unknown resource.".to_string(),
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                PROBLEM_UNAVAILABLE,
                "Service unavailable",
                "A dependency is unreachable.".to_string(),
            ),
            Self::Internal(_) | Self::Config(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                PROBLEM_INTERNAL,
                "Internal error",
                "Something went wrong.".to_string(),
            ),
        };
        tracing::warn!(status = %status, error = %self, "request failed");
        (
            status,
            Json(Problem {
                problem_type,
                title,
                status: status.as_u16(),
                detail,
            }),
        )
            .into_response()
    }
}
