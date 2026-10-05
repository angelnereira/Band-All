//! Hash algorithm selection.
//!
//! SHA-1 exists only for compatibility with third-party authenticator apps,
//! which ignore the `algorithm` parameter. New factors default to SHA-256
//! (see ADR-0003).

use crate::error::Error;

/// HMAC hash function used for HOTP/TOTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// HMAC-SHA-1. Compatibility only.
    Sha1,
    /// HMAC-SHA-256. Default for new factors.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl Algorithm {
    /// The `otpauth://` algorithm name (`SHA1`, `SHA256`, `SHA512`).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    /// Parses an `otpauth://` algorithm name (case-insensitive).
    pub fn from_name(name: &str) -> Result<Self, Error> {
        match name.to_ascii_uppercase().as_str() {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            _ => Err(Error::InvalidUri),
        }
    }

    /// Recommended secret length in bytes for this algorithm.
    #[must_use]
    pub fn secret_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Algorithm;

    #[test]
    fn names_round_trip() {
        for algo in [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512] {
            assert_eq!(Algorithm::from_name(algo.name()), Ok(algo));
        }
    }

    #[test]
    fn rejects_unknown_algorithm() {
        assert!(Algorithm::from_name("MD5").is_err());
    }
}
