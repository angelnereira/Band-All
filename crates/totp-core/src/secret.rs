//! TOTP secret handling.
//!
//! Secrets live in `secrecy::Secret` (zeroed on drop) and never appear in
//! `Debug` output, logs or errors. Generation uses the OS CSPRNG only.

use secrecy::{ExposeSecret, SecretBox};
use std::fmt;

use crate::algorithm::Algorithm;
use crate::base32;
use crate::error::Error;

/// Minimum secret length: 128 bits.
const MIN_LEN: usize = 16;
/// Maximum accepted secret length.
const MAX_LEN: usize = 128;

/// A TOTP/HOTP shared secret. Redacted in `Debug`. Not `Clone`: duplicating
/// secrets is a deliberate, fallible operation via `Secret::new`.
pub struct Secret(SecretBox<Vec<u8>>);

impl Secret {
    /// Wraps raw bytes, enforcing the 16..=128 byte range.
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        if !(MIN_LEN..=MAX_LEN).contains(&bytes.len()) {
            return Err(Error::InvalidSecretLength(bytes.len()));
        }
        Ok(Self(SecretBox::new(Box::new(bytes))))
    }

    /// Generates `len` random bytes from the OS CSPRNG.
    pub fn generate(len: usize) -> Result<Self, Error> {
        if !(MIN_LEN..=MAX_LEN).contains(&len) {
            return Err(Error::InvalidSecretLength(len));
        }
        let mut bytes = vec![0u8; len];
        getrandom::getrandom(&mut bytes).map_err(|_| Error::Random)?;
        Ok(Self(SecretBox::new(Box::new(bytes))))
    }

    /// Generates a secret sized for `algorithm` (20/32/64 bytes).
    pub fn generate_for(algorithm: Algorithm) -> Result<Self, Error> {
        Self::generate(algorithm.secret_len())
    }

    /// Decodes a strict Base32 secret (uppercase, no padding, no whitespace).
    pub fn from_base32(encoded: &str) -> Result<Self, Error> {
        Self::new(base32::decode(encoded)?)
    }

    /// Encodes the secret as strict Base32 for `otpauth://` URIs (QR enrolment).
    #[must_use]
    pub fn to_base32(&self) -> String {
        base32::encode(self.bytes())
    }

    /// Raw secret bytes. Visible inside this crate only; callers use
    /// `hotp`/`totp` functions that expose the secret solely to HMAC.
    pub(crate) fn bytes(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Secret length in bytes (not secret-dependent control flow).
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes().len()
    }

    /// Whether the secret is empty (always false after `new`/`generate`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes().is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;
    use crate::algorithm::Algorithm;

    #[test]
    fn debug_is_redacted() {
        let secret = Secret::new(vec![1u8; 20]).unwrap();
        assert_eq!(format!("{secret:?}"), "Secret([redacted])");
    }

    #[test]
    fn base32_round_trip() {
        let secret = Secret::generate_for(Algorithm::Sha256).unwrap();
        let encoded = secret.to_base32();
        let back = Secret::from_base32(&encoded).unwrap();
        assert_eq!(back.len(), 32);
        assert_eq!(back.to_base32(), encoded);
    }

    #[test]
    fn rejects_short_secret() {
        assert!(Secret::new(vec![0u8; 8]).is_err());
        assert!(Secret::generate(8).is_err());
    }

    #[test]
    fn generates_expected_lengths() {
        assert_eq!(Secret::generate_for(Algorithm::Sha1).unwrap().len(), 20);
        assert_eq!(Secret::generate_for(Algorithm::Sha256).unwrap().len(), 32);
        assert_eq!(Secret::generate_for(Algorithm::Sha512).unwrap().len(), 64);
    }
}
