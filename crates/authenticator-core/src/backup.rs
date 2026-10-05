//! Optional encrypted backup: accounts sealed under a passphrase.
//!
//! Format (JSON, versioned): Argon2id derives a 32-byte key from the
//! passphrase and a random salt; XChaCha20-Poly1305 encrypts the account
//! list with the backup purpose as AAD. Cloud backup stays off by default;
//! this is strictly opt-in.

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, SaltString},
};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};

use crate::error::Error;

/// Backup envelope version.
const BACKUP_VERSION: u8 = 1;
/// Argon2id memory cost in KiB.
const M_COST: u32 = 19_456;
/// Argon2id time cost.
const T_COST: u32 = 2;
/// Argon2id parallelism.
const P_COST: u32 = 1;
/// Derived key length.
const KEY_LEN: usize = 32;
/// Salt and nonce lengths.
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

/// One backed-up account (secret as strict Base32).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupAccount {
    issuer: String,
    name: String,
    algorithm: String,
    digits: u8,
    period_secs: u64,
    secret_base32: String,
}

/// Versioned backup envelope.
#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    version: u8,
    salt_base32: String,
    nonce_base32: String,
    ciphertext_base32: String,
}

/// Exports accounts encrypted under `passphrase` (JSON envelope).
pub fn export_encrypted(
    accounts: &[crate::accounts::AccountSnapshot],
    passphrase: &str,
) -> Result<String, Error> {
    if passphrase.len() < 12 {
        return Err(Error::Invalid);
    }
    let plain = serde_json::to_vec(&to_backup(accounts)).map_err(|_| Error::Invalid)?;
    let mut salt = vec![0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|_| Error::Random)?;
    let mut nonce = vec![0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::Random)?;
    let key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| Error::Sealed)?;
    let nonce_array: [u8; NONCE_LEN] = nonce.clone().try_into().map_err(|_| Error::Sealed)?;
    let ciphertext = cipher
        .encrypt(
            chacha20poly1305::XNonce::from_slice(&nonce_array),
            Payload {
                msg: &plain,
                aad: b"bandall-backup-v1",
            },
        )
        .map_err(|_| Error::Sealed)?;
    let envelope = Envelope {
        version: BACKUP_VERSION,
        salt_base32: data_encoding::BASE32_NOPAD.encode(&salt),
        nonce_base32: data_encoding::BASE32_NOPAD.encode(&nonce),
        ciphertext_base32: data_encoding::BASE32_NOPAD.encode(&ciphertext),
    };
    serde_json::to_string(&envelope).map_err(|_| Error::Invalid)
}

/// Decrypts an envelope back into account snapshots.
pub fn import_encrypted(
    envelope_json: &str,
    passphrase: &str,
) -> Result<Vec<crate::accounts::AccountSnapshot>, Error> {
    let envelope: Envelope = serde_json::from_str(envelope_json).map_err(|_| Error::Invalid)?;
    if envelope.version != BACKUP_VERSION {
        return Err(Error::Invalid);
    }
    let salt = data_encoding::BASE32_NOPAD
        .decode(envelope.salt_base32.as_bytes())
        .map_err(|_| Error::Invalid)?;
    let nonce_bytes = data_encoding::BASE32_NOPAD
        .decode(envelope.nonce_base32.as_bytes())
        .map_err(|_| Error::Invalid)?;
    let ciphertext = data_encoding::BASE32_NOPAD
        .decode(envelope.ciphertext_base32.as_bytes())
        .map_err(|_| Error::Invalid)?;
    let key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| Error::Sealed)?;
    let nonce: [u8; NONCE_LEN] = nonce_bytes.try_into().map_err(|_| Error::Invalid)?;
    let plain = cipher
        .decrypt(
            chacha20poly1305::XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: b"bandall-backup-v1",
            },
        )
        .map_err(|_| Error::Sealed)?;
    let backup: Vec<BackupAccount> = serde_json::from_slice(&plain).map_err(|_| Error::Sealed)?;
    from_backup(&backup)
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Vec<u8>, Error> {
    let params = Params::new(M_COST, T_COST, P_COST, Some(KEY_LEN)).map_err(|_| Error::Invalid)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt_string = SaltString::encode_b64(salt).map_err(|_| Error::Invalid)?;
    let hash = argon2
        .hash_password(passphrase.as_bytes(), &salt_string)
        .map_err(|_| Error::Invalid)?;
    hash.hash
        .map(|output| output.as_bytes().to_vec())
        .ok_or(Error::Invalid)
}

fn to_backup(accounts: &[crate::accounts::AccountSnapshot]) -> Vec<BackupAccount> {
    accounts
        .iter()
        .map(|account| BackupAccount {
            issuer: account.issuer.clone(),
            name: account.name.clone(),
            algorithm: account.algorithm.to_string(),
            digits: account.digits,
            period_secs: account.period_secs,
            secret_base32: account.secret_base32.clone(),
        })
        .collect()
}

fn from_backup(backup: &[BackupAccount]) -> Result<Vec<crate::accounts::AccountSnapshot>, Error> {
    backup
        .iter()
        .map(|entry| {
            Ok(crate::accounts::AccountSnapshot {
                issuer: entry.issuer.clone(),
                name: entry.name.clone(),
                algorithm: entry.algorithm.clone(),
                digits: entry.digits,
                period_secs: entry.period_secs,
                secret_base32: entry.secret_base32.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{export_encrypted, import_encrypted};
    use crate::accounts::AccountSnapshot;

    fn snapshot() -> AccountSnapshot {
        AccountSnapshot {
            issuer: "BandAll".to_string(),
            name: "alice@example.com".to_string(),
            algorithm: "SHA256".to_string(),
            digits: 6,
            period_secs: 30,
            secret_base32: "JBSWY3DPEHPK3PXP".to_string(),
        }
    }

    #[test]
    fn round_trip() {
        let envelope = export_encrypted(&[snapshot()], "correct horse battery staple").unwrap();
        let back = import_encrypted(&envelope, "correct horse battery staple").unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].name, "alice@example.com");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let envelope = export_encrypted(&[snapshot()], "correct horse battery staple").unwrap();
        assert!(import_encrypted(&envelope, "wrong passphrase!!").is_err());
    }

    #[test]
    fn weak_passphrase_rejected() {
        assert!(export_encrypted(&[snapshot()], "short").is_err());
    }
}
