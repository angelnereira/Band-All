//! `bandall-sigs`: HMAC request/webhook signatures (blueprint §10).
//!
//! Pure and time-injected. Nonce replay storage is the caller's
//! responsibility via `NonceCache`.
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
pub mod sign;

pub use error::Error;
pub use sign::{
    CLOCK_TOLERANCE_SECS, NonceCache, SignedRequest, canonical, fresh_nonce, sign, verify,
};
