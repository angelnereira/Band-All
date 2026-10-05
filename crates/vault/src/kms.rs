//! Key management: the `KmsProvider` trait and a local file-backed KMS.
//!
//! The KEK never leaves the provider. Cloud HSMs (AWS KMS, Azure Key Vault,
//! PKCS#11) implement the same trait later; `LocalKms` is for development and
//! air-gapped deployments only.

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use secrecy::{ExposeSecret, SecretBox};

use crate::error::Error;

/// Master key length in bytes (XChaCha20-Poly1305 key).
const KEK_LEN: usize = 32;
/// Wrapping nonce length in bytes (XChaCha).
const WRAP_NONCE_LEN: usize = 24;

/// A wrapped (encrypted) data-encryption key.
#[derive(Debug, Clone)]
pub struct WrappedDek {
    nonce: [u8; WRAP_NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl WrappedDek {
    /// Reassembles a wrapped DEK from persisted columns.
    #[must_use]
    pub fn new(nonce: [u8; WRAP_NONCE_LEN], ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    /// Wrapping nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8; WRAP_NONCE_LEN] {
        &self.nonce
    }

    /// Encrypted DEK bytes.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// Key-encryption-key provider. Object-safe so deployments can share one
/// instance behind `Arc`.
pub trait KmsProvider: Send + Sync {
    /// Stable identifier recorded next to each sealed secret (`kek_id`).
    fn key_id(&self) -> &str;

    /// Wraps a data-encryption key under this KEK.
    fn wrap_dek(&self, dek: &[u8]) -> Result<WrappedDek, Error>;

    /// Unwraps a data-encryption key. Failures are uniform.
    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<SecretBox<Vec<u8>>, Error>;
}

/// File-backed KMS for development and offline deployments.
///
/// The key file holds exactly 32 raw bytes and must be readable only by its
/// owner (mode `0600` or stricter on Unix).
pub struct LocalKms {
    id: String,
    key: SecretBox<Vec<u8>>,
}

impl LocalKms {
    /// Loads a KEK from raw bytes (exactly 32).
    pub fn from_bytes(id: String, key: Vec<u8>) -> Result<Self, Error> {
        if key.len() != KEK_LEN {
            return Err(Error::InvalidKeyLength);
        }
        Ok(Self {
            id,
            key: SecretBox::new(Box::new(key)),
        })
    }

    /// Loads a KEK from a file with exactly 32 raw bytes.
    pub fn from_file(id: String, path: &std::path::Path) -> Result<Self, Error> {
        check_permissions(path)?;
        let key = std::fs::read(path).map_err(|e| Error::KeyFile(e.to_string()))?;
        Self::from_bytes(id, key)
    }

    /// Provider identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, Error> {
        // The key is validated to exactly 32 bytes at construction, so this
        // cannot fail; the error path fails closed rather than panicking.
        XChaCha20Poly1305::new_from_slice(self.key.expose_secret())
            .map_err(|_| Error::EncryptionFailed)
    }
}

impl KmsProvider for LocalKms {
    fn key_id(&self) -> &str {
        &self.id
    }

    fn wrap_dek(&self, dek: &[u8]) -> Result<WrappedDek, Error> {
        let cipher = self.cipher()?;
        let nonce_bytes = random_bytes(WRAP_NONCE_LEN)?;
        let nonce_array: [u8; WRAP_NONCE_LEN] = nonce_bytes
            .try_into()
            .map_err(|_| Error::EncryptionFailed)?;
        let ciphertext = cipher
            .encrypt(
                chacha20poly1305::XNonce::from_slice(&nonce_array),
                Payload {
                    msg: dek,
                    aad: self.id.as_bytes(),
                },
            )
            .map_err(|_| Error::EncryptionFailed)?;
        Ok(WrappedDek {
            nonce: nonce_array,
            ciphertext,
        })
    }

    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<SecretBox<Vec<u8>>, Error> {
        let cipher = self.cipher()?;
        let dek = cipher
            .decrypt(
                chacha20poly1305::XNonce::from_slice(&wrapped.nonce),
                Payload {
                    msg: &wrapped.ciphertext,
                    aad: self.id.as_bytes(),
                },
            )
            .map_err(|_| Error::DecryptionFailed)?;
        Ok(SecretBox::new(Box::new(dek)))
    }
}

/// Random bytes from the OS CSPRNG.
fn random_bytes(len: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Random)?;
    Ok(bytes)
}

/// Rejects key files readable by group or others (Unix). Non-Unix platforms
/// rely on the deployment to restrict access.
fn check_permissions(path: &std::path::Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|e| Error::KeyFile(e.to_string()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(Error::UnsafeKeyPermissions);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{KmsProvider, LocalKms};

    fn test_kms() -> LocalKms {
        LocalKms::from_bytes("test-kek".to_string(), vec![7u8; 32]).unwrap()
    }

    #[test]
    fn wrap_round_trip() {
        use secrecy::ExposeSecret;
        let kms = test_kms();
        let wrapped = kms.wrap_dek(b"data-encryption-key").unwrap();
        let back = kms.unwrap_dek(&wrapped).unwrap();
        assert_eq!(back.expose_secret(), b"data-encryption-key");
    }

    #[test]
    fn rejects_bad_key_length() {
        assert!(LocalKms::from_bytes("x".to_string(), vec![0u8; 16]).is_err());
    }

    #[test]
    fn wrong_kek_fails_closed() {
        let kms = test_kms();
        let wrapped = kms.wrap_dek(b"dek").unwrap();
        let other = LocalKms::from_bytes("other".to_string(), vec![9u8; 32]).unwrap();
        assert!(other.unwrap_dek(&wrapped).is_err());
    }
}
