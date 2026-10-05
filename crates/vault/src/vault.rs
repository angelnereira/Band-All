//! Envelope encryption for TOTP secrets.
//!
//! Each factor gets a fresh random DEK. The DEK is wrapped by the KMS (KEK)
//! and the secret is encrypted under the DEK with the row identity as AAD,
//! so a stolen ciphertext cannot be transplanted to another row.

use std::sync::Arc;

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use secrecy::{ExposeSecret, SecretBox};

use crate::error::Error;
use crate::kms::{KmsProvider, WrappedDek};

/// Sealed format version.
const SEAL_VERSION: u8 = 1;
/// Fresh DEK length in bytes.
const DEK_LEN: usize = 32;
/// Data nonce length in bytes (XChaCha).
const DATA_NONCE_LEN: usize = 24;

/// A sealed TOTP secret, ready to persist column by column.
#[derive(Debug, Clone)]
pub struct SealedSecret {
    version: u8,
    kek_id: String,
    wrapped_dek: WrappedDek,
    nonce: [u8; DATA_NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl SealedSecret {
    /// Format version (always 1 for now).
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// KEK identifier that wrapped the DEK.
    #[must_use]
    pub fn kek_id(&self) -> &str {
        &self.kek_id
    }

    /// Wrapped DEK.
    #[must_use]
    pub fn wrapped_dek(&self) -> &WrappedDek {
        &self.wrapped_dek
    }

    /// Data nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8; DATA_NONCE_LEN] {
        &self.nonce
    }

    /// Encrypted secret bytes.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// Envelope vault bound to one KMS provider.
#[derive(Clone)]
pub struct Vault {
    kms: Arc<dyn KmsProvider>,
}

impl Vault {
    /// Builds a vault around a shared KMS provider.
    #[must_use]
    pub fn new(kms: Arc<dyn KmsProvider>) -> Self {
        Self { kms }
    }

    /// KEK identifier of the backing provider.
    #[must_use]
    pub fn kek_id(&self) -> &str {
        self.kms.key_id()
    }

    /// Seals `plaintext` for the `(tenant, subject, factor)` row.
    pub fn seal(
        &self,
        tenant: &str,
        subject: &str,
        factor: &str,
        plaintext: &[u8],
    ) -> Result<SealedSecret, Error> {
        let dek = random_bytes(DEK_LEN)?;
        let wrapped_dek = self.kms.wrap_dek(&dek)?;
        let nonce_bytes = random_bytes(DATA_NONCE_LEN)?;
        let nonce: [u8; DATA_NONCE_LEN] = nonce_bytes
            .try_into()
            .map_err(|_| Error::EncryptionFailed)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&dek).map_err(|_| Error::EncryptionFailed)?;
        let aad = aad_bytes(tenant, subject, factor)?;
        let ciphertext = cipher
            .encrypt(
                chacha20poly1305::XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::EncryptionFailed)?;
        Ok(SealedSecret {
            version: SEAL_VERSION,
            kek_id: self.kms.key_id().to_string(),
            wrapped_dek,
            nonce,
            ciphertext,
        })
    }

    /// Opens a sealed secret, checking row identity via AAD.
    pub fn open(
        &self,
        sealed: &SealedSecret,
        tenant: &str,
        subject: &str,
        factor: &str,
    ) -> Result<SecretBox<Vec<u8>>, Error> {
        if sealed.version != SEAL_VERSION {
            return Err(Error::DecryptionFailed);
        }
        let dek = self.kms.unwrap_dek(sealed.wrapped_dek())?;
        let cipher = XChaCha20Poly1305::new_from_slice(dek.expose_secret())
            .map_err(|_| Error::DecryptionFailed)?;
        let aad = aad_bytes(tenant, subject, factor)?;
        let plaintext = cipher
            .decrypt(
                chacha20poly1305::XNonce::from_slice(sealed.nonce()),
                Payload {
                    msg: sealed.ciphertext(),
                    aad: &aad,
                },
            )
            .map_err(|_| Error::DecryptionFailed)?;
        Ok(SecretBox::new(Box::new(plaintext)))
    }

    /// Re-wraps `sealed` under this vault's KEK (`self` is the NEW vault,
    /// `old` opened the secret). Used for KEK rotation without downtime.
    pub fn rewrap_with(
        &self,
        old: &Vault,
        sealed: &SealedSecret,
        tenant: &str,
        subject: &str,
        factor: &str,
    ) -> Result<SealedSecret, Error> {
        let plaintext = old.open(sealed, tenant, subject, factor)?;
        self.seal(tenant, subject, factor, plaintext.expose_secret())
    }
}

/// Row-identity AAD: domain separator plus length-prefixed fields, so
/// `"ab" | "c"` and `"a" | "bc"` never collide.
fn aad_bytes(tenant: &str, subject: &str, factor: &str) -> Result<Vec<u8>, Error> {
    let mut aad = Vec::with_capacity(32 + tenant.len() + subject.len() + factor.len());
    aad.extend_from_slice(b"bandall-seal-v1");
    for part in [tenant, subject, factor] {
        let len = u64::try_from(part.len()).map_err(|_| Error::EncryptionFailed)?;
        aad.extend_from_slice(&len.to_be_bytes());
        aad.extend_from_slice(part.as_bytes());
    }
    Ok(aad)
}

fn random_bytes(len: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Random)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::Vault;
    use crate::kms::LocalKms;
    use secrecy::ExposeSecret;
    use std::sync::Arc;

    fn vault(id: &str) -> Vault {
        Vault::new(Arc::new(
            LocalKms::from_bytes(id.to_string(), vec![1u8; 32]).unwrap(),
        ))
    }

    #[test]
    fn seal_open_round_trip() {
        let vault = vault("kek-1");
        let sealed = vault.seal("t", "s", "f", b"totp-secret").unwrap();
        assert_eq!(sealed.kek_id(), "kek-1");
        let back = vault.open(&sealed, "t", "s", "f").unwrap();
        assert_eq!(back.expose_secret(), b"totp-secret");
    }

    #[test]
    fn transplanted_ciphertext_fails() {
        let vault = vault("kek-1");
        let sealed = vault.seal("t", "s", "f", b"totp-secret").unwrap();
        assert!(vault.open(&sealed, "t", "s", "other-factor").is_err());
        assert!(vault.open(&sealed, "other-tenant", "s", "f").is_err());
    }

    #[test]
    fn rewrap_rotates_kek() {
        let old = vault("kek-1");
        let new_vault = Vault::new(Arc::new(
            LocalKms::from_bytes("kek-2".to_string(), vec![2u8; 32]).unwrap(),
        ));
        let sealed = old.seal("t", "s", "f", b"totp-secret").unwrap();
        let rotated = new_vault.rewrap_with(&old, &sealed, "t", "s", "f").unwrap();
        assert_eq!(rotated.kek_id(), "kek-2");
        let back = new_vault.open(&rotated, "t", "s", "f").unwrap();
        assert_eq!(back.expose_secret(), b"totp-secret");
    }
}
