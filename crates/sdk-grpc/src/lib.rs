//! `bandall-sdk-grpc`: authentication for gRPC services (ADR-0017).
//!
//! A `tonic` `Interceptor` that does what `bandall-sdk-axum`'s `RequireToken`
//! does over HTTP, but for gRPC metadata: it validates the `authorization:
//! Bearer <access token>` metadata on every request, verifies it against a
//! JWKS document, and rejects with `UNAUTHENTICATED` when anything is wrong.
//!
//! gRPC's model is the same as the WebSocket case the ticket solves: a stream
//! outlives the token that opened it. So the interceptor enforces **the
//! connection ceiling**: the token's `exp` is stamped into each accepted
//! request's extensions, and the service is responsible for re-checking the
//! session (via `recheck`/`authz/check`) before the ceiling — that is the
//! "TTL de conexión atado a `exp`" from ADR-0017.
#![forbid(unsafe_code)]

mod intercept;
mod verify;

pub use intercept::RequireTokenInterceptor;
pub use verify::{CachedJwks, StaticJwks, Verifier, VerifyError};
