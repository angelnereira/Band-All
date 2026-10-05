//! `bandall-policy`: rate limiting, exponential backoff and lockout.
//!
//! Pure, synchronous and time-injected. The API composes keys per factor, IP
//! and tenant and maps `Decision` to 429 responses.
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

pub mod policy;

pub use policy::{Decision, Limits, Policy};
