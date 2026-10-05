//! Refresh tokens: opaque 256-bit values, stored as SHA-256 hashes.
//!
//! Rotation happens on every use and reuse of a spent token revokes the
//! whole family (theft detection). The plaintext leaves this process only
//! once, inside the refresh response.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

use crate::error::Error;

/// Refresh token entropy in bytes.
const TOKEN_BYTES: usize = 32;
/// Refresh token lifetime in seconds (7 days).
pub const REFRESH_TTL_SECS: u64 = 7 * 24 * 3600;

/// A fresh refresh token: plaintext for the response, hash for storage.
#[derive(Debug)]
pub struct RefreshToken {
    /// Plaintext token (shown once).
    pub plaintext: String,
    /// SHA-256 hash in hex (persisted).
    pub hash: String,
}

impl RefreshToken {
    /// Generates a fresh token from the OS CSPRNG.
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = vec![0u8; TOKEN_BYTES];
        getrandom::getrandom(&mut bytes).map_err(|_| Error::Random)?;
        let plaintext = URL_SAFE_NO_PAD.encode(&bytes);
        let hash = hash_plaintext(&plaintext);
        Ok(Self { plaintext, hash })
    }
}

/// Hashes a presented token for database lookup (hex SHA-256).
#[must_use]
pub fn hash_plaintext(plaintext: &str) -> String {
    let digest = Sha256::digest(plaintext.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::{RefreshToken, hash_plaintext};

    #[test]
    fn hash_is_stable_and_hiding() {
        let token = RefreshToken::generate().unwrap();
        assert_eq!(hash_plaintext(&token.plaintext), token.hash);
        assert!(!token.hash.contains(&token.plaintext));
        assert_eq!(RefreshToken::generate().unwrap().hash.len(), 64);
    }
}
