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
use secrecy::{ExposeSecret, SecretBox, zeroize::Zeroizing};

use crate::error::Error;
use crate::kms::{KmsProvider, WrappedDek};

/// Legacy format version (v1: no version or kek_id in AAD).
pub const SEAL_VERSION_V1: u8 = 1;
/// Current format version (v2: version and kek_id authenticated in AAD).
pub const SEAL_VERSION_V2: u8 = 2;
/// Format version written by `seal`.
pub const CURRENT_SEAL_VERSION: u8 = SEAL_VERSION_V2;

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
    /// Reassembles a sealed secret from persisted columns (the inverse of
    /// splitting it at seal time). Version and AAD checks still happen in
    /// `Vault::open`.
    #[must_use]
    pub fn reassemble(
        version: u8,
        kek_id: String,
        wrapped_dek: WrappedDek,
        nonce: [u8; DATA_NONCE_LEN],
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            version,
            kek_id,
            wrapped_dek,
            nonce,
            ciphertext,
        }
    }

    /// Format version.
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

impl std::fmt::Debug for Vault {
    /// Opaque on purpose: the provider holds key material, so nothing is
    /// printed here.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").finish_non_exhaustive()
    }
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

    /// Seals `plaintext` for the `(tenant, subject, factor)` row using format v2.
    pub async fn seal(
        &self,
        tenant: &str,
        subject: &str,
        factor: &str,
        plaintext: &[u8],
    ) -> Result<SealedSecret, Error> {
        let dek = random_bytes(DEK_LEN)?;
        let wrapped_dek = self.kms.wrap_dek(&dek).await?;
        let nonce_bytes = random_bytes(DATA_NONCE_LEN)?;
        let nonce: [u8; DATA_NONCE_LEN] = nonce_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::EncryptionFailed)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&dek).map_err(|_| Error::EncryptionFailed)?;
        let aad = aad_v2_bytes(
            CURRENT_SEAL_VERSION,
            self.kms.key_id(),
            tenant,
            subject,
            factor,
        )?;
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
            version: CURRENT_SEAL_VERSION,
            kek_id: self.kms.key_id().to_string(),
            wrapped_dek,
            nonce,
            ciphertext,
        })
    }

    /// Opens a sealed secret, checking row identity via AAD. Accepts v1 and v2.
    pub async fn open(
        &self,
        sealed: &SealedSecret,
        tenant: &str,
        subject: &str,
        factor: &str,
    ) -> Result<SecretBox<Vec<u8>>, Error> {
        let aad = match sealed.version {
            SEAL_VERSION_V1 => aad_v1_bytes(tenant, subject, factor)?,
            SEAL_VERSION_V2 => {
                aad_v2_bytes(sealed.version, &sealed.kek_id, tenant, subject, factor)?
            }
            _ => return Err(Error::DecryptionFailed),
        };
        let dek = self.kms.unwrap_dek(sealed.wrapped_dek()).await?;
        let cipher = XChaCha20Poly1305::new_from_slice(&dek)
            .map_err(|_| Error::DecryptionFailed)?;
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
    /// `old` opened the secret). Upgrades format to v2. Used for KEK rotation.
    pub async fn rewrap_with(
        &self,
        old: &Vault,
        sealed: &SealedSecret,
        tenant: &str,
        subject: &str,
        factor: &str,
    ) -> Result<SealedSecret, Error> {
        let plaintext = old.open(sealed, tenant, subject, factor).await?;
        self.seal(tenant, subject, factor, plaintext.expose_secret())
            .await
    }
}

/// Row-identity AAD for legacy format v1: domain separator plus length-prefixed fields.
pub(crate) fn aad_v1_bytes(tenant: &str, subject: &str, factor: &str) -> Result<Vec<u8>, Error> {
    let mut aad = Vec::with_capacity(32 + tenant.len() + subject.len() + factor.len());
    aad.extend_from_slice(b"bandall-seal-v1");
    for part in [tenant, subject, factor] {
        let len = u64::try_from(part.len()).map_err(|_| Error::EncryptionFailed)?;
        aad.extend_from_slice(&len.to_be_bytes());
        aad.extend_from_slice(part.as_bytes());
    }
    Ok(aad)
}

/// Row-identity AAD for format v2: includes format version and kek_id.
pub(crate) fn aad_v2_bytes(
    version: u8,
    kek_id: &str,
    tenant: &str,
    subject: &str,
    factor: &str,
) -> Result<Vec<u8>, Error> {
    let mut aad = Vec::with_capacity(
        32 + kek_id.len() + tenant.len() + subject.len() + factor.len(),
    );
    aad.extend_from_slice(b"bandall-seal-v2");
    aad.push(version);
    for part in [kek_id, tenant, subject, factor] {
        let len = u64::try_from(part.len()).map_err(|_| Error::EncryptionFailed)?;
        aad.extend_from_slice(&len.to_be_bytes());
        aad.extend_from_slice(part.as_bytes());
    }
    Ok(aad)
}

fn random_bytes(len: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut bytes = Zeroizing::new(vec![0u8; len]);
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Random)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{
        CURRENT_SEAL_VERSION, SEAL_VERSION_V1, SEAL_VERSION_V2, SealedSecret, Vault,
        aad_v1_bytes, aad_v2_bytes,
    };
    use crate::kms::{KmsProvider, LocalKms};
    use chacha20poly1305::{
        XChaCha20Poly1305,
        aead::{Aead, KeyInit, Payload},
    };
    use secrecy::ExposeSecret;
    use std::sync::Arc;

    fn vault(id: &str) -> Vault {
        Vault::new(Arc::new(
            LocalKms::from_bytes(id.to_string(), vec![1u8; 32]).unwrap(),
        ))
    }

    #[tokio::test]
    async fn seal_open_v2_round_trip() {
        let vault = vault("kek-1");
        let sealed = vault.seal("t", "s", "f", b"totp-secret").await.unwrap();
        assert_eq!(sealed.version(), CURRENT_SEAL_VERSION);
        assert_eq!(sealed.version(), SEAL_VERSION_V2);
        assert_eq!(sealed.kek_id(), "kek-1");
        let back = vault.open(&sealed, "t", "s", "f").await.unwrap();
        assert_eq!(back.expose_secret(), b"totp-secret");
    }

    #[tokio::test]
    async fn v1_ciphertext_opens_successfully() {
        let kms = Arc::new(LocalKms::from_bytes("kek-1".to_string(), vec![1u8; 32]).unwrap());
        let vault = Vault::new(kms.clone());

        // Construct a genuine v1 ciphertext using v1 AAD and wrap_dek.
        let dek = vec![3u8; 32];
        let wrapped_dek = kms.wrap_dek(&dek).await.unwrap();
        let nonce = [4u8; 24];
        let cipher = XChaCha20Poly1305::new_from_slice(&dek).unwrap();
        let aad = aad_v1_bytes("t", "s", "f").unwrap();
        let ciphertext = cipher
            .encrypt(
                chacha20poly1305::XNonce::from_slice(&nonce),
                Payload {
                    msg: b"legacy-v1-secret",
                    aad: &aad,
                },
            )
            .unwrap();

        let v1_sealed = SealedSecret::reassemble(
            SEAL_VERSION_V1,
            "kek-1".to_string(),
            wrapped_dek,
            nonce,
            ciphertext,
        );

        let back = vault.open(&v1_sealed, "t", "s", "f").await.unwrap();
        assert_eq!(back.expose_secret(), b"legacy-v1-secret");
    }

    #[tokio::test]
    async fn v2_with_tampered_kek_id_fails() {
        let vault = vault("kek-1");
        let sealed = vault.seal("t", "s", "f", b"totp-secret").await.unwrap();
        let tampered = SealedSecret::reassemble(
            sealed.version(),
            "kek-tampered".to_string(),
            sealed.wrapped_dek().clone(),
            *sealed.nonce(),
            sealed.ciphertext().to_vec(),
        );
        assert!(vault.open(&tampered, "t", "s", "f").await.is_err());
    }

    #[tokio::test]
    async fn v2_with_tampered_version_fails() {
        let vault = vault("kek-1");
        let sealed = vault.seal("t", "s", "f", b"totp-secret").await.unwrap();
        let tampered = SealedSecret::reassemble(
            SEAL_VERSION_V1, // tampered version: was encrypted with v2 AAD
            sealed.kek_id().to_string(),
            sealed.wrapped_dek().clone(),
            *sealed.nonce(),
            sealed.ciphertext().to_vec(),
        );
        assert!(vault.open(&tampered, "t", "s", "f").await.is_err());
    }

    #[tokio::test]
    async fn unknown_version_fails() {
        let vault = vault("kek-1");
        let sealed = vault.seal("t", "s", "f", b"totp-secret").await.unwrap();
        let tampered = SealedSecret::reassemble(
            99,
            sealed.kek_id().to_string(),
            sealed.wrapped_dek().clone(),
            *sealed.nonce(),
            sealed.ciphertext().to_vec(),
        );
        assert!(vault.open(&tampered, "t", "s", "f").await.is_err());
    }

    #[tokio::test]
    async fn transplanted_ciphertext_fails() {
        let vault = vault("kek-1");
        let sealed = vault.seal("t", "s", "f", b"totp-secret").await.unwrap();
        assert!(vault.open(&sealed, "t", "s", "other-factor").await.is_err());
        assert!(vault.open(&sealed, "other-tenant", "s", "f").await.is_err());
        assert!(vault.open(&sealed, "t", "other-subject", "f").await.is_err());
    }

    #[tokio::test]
    async fn rewrap_rotates_kek_and_upgrades_v1_to_v2() {
        let kms1 = Arc::new(LocalKms::from_bytes("kek-1".to_string(), vec![1u8; 32]).unwrap());
        let old = Vault::new(kms1.clone());

        // Create a v1 secret
        let dek = vec![5u8; 32];
        let wrapped_dek = kms1.wrap_dek(&dek).await.unwrap();
        let nonce = [6u8; 24];
        let cipher = XChaCha20Poly1305::new_from_slice(&dek).unwrap();
        let aad = aad_v1_bytes("t", "s", "f").unwrap();
        let ciphertext = cipher
            .encrypt(
                chacha20poly1305::XNonce::from_slice(&nonce),
                Payload {
                    msg: b"upgrade-me",
                    aad: &aad,
                },
            )
            .unwrap();
        let v1_sealed = SealedSecret::reassemble(
            SEAL_VERSION_V1,
            "kek-1".to_string(),
            wrapped_dek,
            nonce,
            ciphertext,
        );

        let new_vault = Vault::new(Arc::new(
            LocalKms::from_bytes("kek-2".to_string(), vec![2u8; 32]).unwrap(),
        ));
        let rotated = new_vault
            .rewrap_with(&old, &v1_sealed, "t", "s", "f")
            .await
            .unwrap();
        assert_eq!(rotated.version(), SEAL_VERSION_V2);
        assert_eq!(rotated.kek_id(), "kek-2");
        let back = new_vault.open(&rotated, "t", "s", "f").await.unwrap();
        assert_eq!(back.expose_secret(), b"upgrade-me");
    }

    #[test]
    fn aad_changes_when_version_changes() {
        let v1 = aad_v1_bytes("t", "s", "f").unwrap();
        let v2 = aad_v2_bytes(2, "kek-1", "t", "s", "f").unwrap();
        assert_ne!(v1, v2);
    }
}

