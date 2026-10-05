//! Stored rows. Times are Unix seconds (`i64`); steps map to `u64` with a
//! corruption check, so a tampered `last_step` fails closed instead of
//! wrapping.

use sqlx::FromRow;

use crate::error::Error;

/// Tenant row.
#[derive(Debug, Clone, FromRow)]
pub struct Tenant {
    /// Tenant id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Creation time (Unix seconds).
    pub created_at: i64,
}

/// Subject (user/device) row.
#[derive(Debug, Clone, FromRow)]
pub struct Subject {
    /// Subject id.
    pub id: String,
    /// Owning tenant.
    pub tenant_id: String,
    /// Caller-provided stable identifier (unique per tenant).
    pub external_id: String,
    /// Creation time (Unix seconds).
    pub created_at: i64,
}

/// TOTP factor row, mirroring the sealed secret plus policy state.
#[derive(Debug, Clone, FromRow)]
pub struct Factor {
    /// Factor id.
    pub id: String,
    /// Owning tenant.
    pub tenant_id: String,
    /// Owning subject.
    pub subject_id: String,
    /// `pending` or `active`.
    pub status: String,
    /// Seal format version.
    pub secret_version: i16,
    /// KEK id that wrapped the DEK.
    pub kek_id: String,
    /// Wrapped DEK bytes.
    pub wrapped_dek: Vec<u8>,
    /// DEK-wrapping nonce.
    pub wrapped_nonce: Vec<u8>,
    /// Data nonce.
    pub nonce: Vec<u8>,
    /// Encrypted secret bytes.
    pub ciphertext: Vec<u8>,
    /// Algorithm name (`SHA1`/`SHA256`/`SHA512`).
    pub algorithm: String,
    /// Digit count.
    pub digits: i16,
    /// Period in seconds.
    pub period: i64,
    /// Last accepted TOTP step (`None` = never verified).
    pub last_step: Option<i64>,
    /// Creation time (Unix seconds).
    pub created_at: i64,
    /// Confirmation time (Unix seconds, `None` while pending).
    pub confirmed_at: Option<i64>,
}

impl Factor {
    /// `last_step` as a step counter, rejecting tampered negatives.
    pub fn last_step_u64(&self) -> Result<Option<u64>, Error> {
        self.last_step
            .map(|s| u64::try_from(s).map_err(|_| Error::CorruptRow))
            .transpose()
    }
}

/// New factor to insert.
#[derive(Debug, Clone)]
pub struct NewFactor {
    /// Owning tenant.
    pub tenant_id: String,
    /// Owning subject.
    pub subject_id: String,
    /// Initial status (`pending` for enrolment).
    pub status: String,
    /// Seal format version.
    pub secret_version: i16,
    /// KEK id that wrapped the DEK.
    pub kek_id: String,
    /// Wrapped DEK bytes.
    pub wrapped_dek: Vec<u8>,
    /// DEK-wrapping nonce.
    pub wrapped_nonce: Vec<u8>,
    /// Data nonce.
    pub nonce: Vec<u8>,
    /// Encrypted secret bytes.
    pub ciphertext: Vec<u8>,
    /// Algorithm name.
    pub algorithm: String,
    /// Digit count.
    pub digits: i16,
    /// Period in seconds.
    pub period: i64,
    /// Creation time (Unix seconds).
    pub created_at: i64,
}
