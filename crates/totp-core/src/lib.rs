//! `bandall-totp-core`: pure HOTP/TOTP maths (RFC 4226 / RFC 6238).
//!
//! No network, no database, no clock: time enters as a parameter so every
//! path is deterministic and fuzzable. Secrets are handled with `secrecy`
//! and codes are compared with `subtle`.
//!
//! ```
//! use bandall_totp_core::{Secret, TotpParams, totp};
//!
//! let secret = Secret::from_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")?;
//! let params = TotpParams::default_params();
//! let code = totp::generate(&secret, params, 1_700_000_000)?;
//! let step = totp::verify(&secret, params, &code, 1_700_000_000, 1, None)?;
//! assert_eq!(step, totp::counter_for(params, 1_700_000_000));
//! # Ok::<(), bandall_totp_core::Error>(())
//! ```
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

pub mod algorithm;
pub mod base32;
pub mod error;
pub mod hotp;
pub mod otpauth;
pub mod secret;
pub mod totp;

pub use algorithm::Algorithm;
pub use error::Error;
pub use otpauth::Otpauth;
pub use secret::Secret;
pub use totp::{Period, Step, TotpParams};
