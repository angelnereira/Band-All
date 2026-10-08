//! `bandall-tokens`: Ed25519 access tokens (JWT), opaque refresh tokens and
//! JWKS. No network, no database: persistence of hashes and sessions lives
//! in `bandall-store`.
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

pub mod access;
pub mod error;
pub mod jwks;
pub mod keys;
pub mod refresh;

pub use access::{ACCESS_TTL_SECS, Claims, issue, verify, verify_with_jwks};
pub use error::Error;
pub use jwks::{Jwk, Jwks, document};
pub use keys::{KeyManager, KeyPair};
pub use refresh::{REFRESH_TTL_SECS, RefreshToken, hash_plaintext};
