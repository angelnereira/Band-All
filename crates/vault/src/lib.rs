//! `bandall-vault`: envelope encryption for TOTP secrets.
//!
//! Secrets are encrypted under fresh per-factor DEKs; DEKs are wrapped by a
//! KMS key (KEK). Row identity rides as AAD, so ciphertext cannot move
//! between rows. Also hosts Argon2id recovery-code hashing.
//!
//! ```
//! use bandall_vault::{LocalKms, Vault};
//! use std::sync::Arc;
//!
//! let kms = LocalKms::from_bytes("kek-1".to_string(), vec![1u8; 32])?;
//! let vault = Vault::new(Arc::new(kms));
//! let sealed = vault.seal("tenant", "subject", "factor", b"secret")?;
//! let back = vault.open(&sealed, "tenant", "subject", "factor")?;
//! use secrecy::ExposeSecret;
//! assert_eq!(back.expose_secret(), b"secret");
//! # Ok::<(), bandall_vault::Error>(())
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

pub mod error;
pub mod kms;
pub mod recovery;
pub mod vault;

pub use error::Error;
pub use kms::{KmsProvider, LocalKms, WrappedDek};
pub use vault::{SealedSecret, Vault};
