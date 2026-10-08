//! `bandall-embedded`: fachada de integración para el **modo embebido**
//! (ADR-0014).
//!
//! Un sistema puede embeber BandAll como biblioteca con la misma garantía que
//! el servicio HTTP: secretos cifrados en reposo (la KEK la aporta el
//! integrador), antirreplay atómico (`cas_last_step`), deriva acotada y
//! recovery codes — pero **sin red, sin HTTP y sin arrancar nada**.
//!
//! Uso mínimo:
//!
//! ```no_run
//! use bandall_embedded::Embedded;
//! use std::sync::Arc;
//!
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let embedded = Arc::new(Embedded::sqlite_path("/tmp/demo.db", [7u8; 32]).await?);
//! let enrolled = embedded.enroll("acme", "alice", "BandAll", "alice@example.com").await?;
//! # let factor_id = enrolled.factor_id.clone();
//! // En una app real el reloj viene del dispositivo; aquí se inyecta (el
//! // núcleo nunca pide `SystemTime` por sí mismo).
//! let codes = embedded.confirm("acme", "alice", &factor_id, "123456", 1_700_000_030).await?;
//! # let _ = (enrolled, codes);
//! # Ok(())
//! # }
//! ```
//!
//! Lo que la fachada **no** hace: emitir JWTs, hablar con un servidor o validar
//! sesiones. Para eso está el servicio (`bandall-api`) o `bandall-sdk-axum`.

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

mod error;
mod fachada;

pub use error::Error;
pub use fachada::{Embedded, EnrollOutcome};
