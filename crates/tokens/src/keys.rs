//! Ed25519 signing keys with `kid` rotation overlap.
//!
//! Keys live as raw 32-byte files (mode `0600`) under a directory:
//! `<dir>/current.key`, plus `<dir>/previous.key` during rotation overlap.
//! The `kid` derives deterministically from the public key, so verifiers
//! need no extra registry.

use std::path::{Path, PathBuf};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::Error;

/// Current key file name.
const CURRENT_FILE: &str = "current.key";
/// Previous key file name (rotation overlap).
const PREVIOUS_FILE: &str = "previous.key";

/// A signing key with its derived `kid`.
#[derive(Debug, Clone)]
pub struct KeyPair {
    kid: String,
    signing: SigningKey,
}

impl KeyPair {
    /// Generates a fresh key from the OS CSPRNG.
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = vec![0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| Error::Random)?;
        let array: [u8; 32] = bytes.try_into().map_err(|_| Error::Random)?;
        Ok(Self::from_bytes(&array))
    }

    /// Builds from raw 32-byte secret material.
    #[must_use]
    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(secret);
        let kid = key_id(&signing.verifying_key());
        Self { kid, signing }
    }

    /// Key identifier (derived from the public key).
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Signing key.
    #[must_use]
    pub fn signing(&self) -> &SigningKey {
        &self.signing
    }

    /// Verifying key.
    #[must_use]
    pub fn verifying(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }
}

/// Deterministic `kid`: base64url of the first 12 SHA-256 bytes of the
/// public key.
fn key_id(verifying: &VerifyingKey) -> String {
    let digest = Sha256::digest(verifying.to_bytes());
    let mut short = [0u8; 12];
    let n = short.len();
    for (dst, src) in short.iter_mut().zip(digest.iter().take(n)) {
        *dst = *src;
    }
    URL_SAFE_NO_PAD.encode(short)
}

/// Signing key set: current plus the previous key during rotation overlap.
#[derive(Debug, Clone)]
pub struct KeyManager {
    current: KeyPair,
    previous: Option<KeyPair>,
}

impl KeyManager {
    /// Single fresh key, no overlap.
    pub fn generate() -> Result<Self, Error> {
        Ok(Self {
            current: KeyPair::generate()?,
            previous: None,
        })
    }

    /// Current signing key.
    #[must_use]
    pub fn current(&self) -> &KeyPair {
        &self.current
    }

    /// Verifier for `kid` (current or previous).
    #[must_use]
    pub fn verifier(&self, kid: &str) -> Option<VerifyingKey> {
        if self.current.kid() == kid {
            return Some(self.current.verifying());
        }
        if let Some(previous) = &self.previous {
            if previous.kid() == kid {
                return Some(previous.verifying());
            }
        }
        None
    }

    /// All public keys for JWKS (current first).
    #[must_use]
    pub fn all_verifying(&self) -> Vec<(String, VerifyingKey)> {
        let mut keys = vec![(self.current.kid().to_string(), self.current.verifying())];
        if let Some(previous) = &self.previous {
            keys.push((previous.kid().to_string(), previous.verifying()));
        }
        keys
    }

    /// Rotates: current becomes previous, a fresh key becomes current.
    pub fn rotate(&mut self) -> Result<(), Error> {
        let fresh = KeyPair::generate()?;
        self.previous = Some(std::mem::replace(&mut self.current, fresh));
        Ok(())
    }

    /// Loads `<dir>/{current,previous}.key`, generating and saving a fresh
    /// set when the directory holds no keys.
    pub fn load_or_generate(dir: &Path) -> Result<Self, Error> {
        let current_path = dir.join(CURRENT_FILE);
        if !current_path.exists() {
            let manager = Self::generate()?;
            manager.save(dir)?;
            return Ok(manager);
        }
        let current = read_key(&current_path)?;
        let previous_path = dir.join(PREVIOUS_FILE);
        let previous = if previous_path.exists() {
            Some(read_key(&previous_path)?)
        } else {
            None
        };
        Ok(Self { current, previous })
    }

    /// Persists keys with `0600` permissions (Unix).
    pub fn save(&self, dir: &Path) -> Result<(), Error> {
        std::fs::create_dir_all(dir).map_err(|e| Error::KeyFile(e.to_string()))?;
        write_key(&dir.join(CURRENT_FILE), &self.current)?;
        match &self.previous {
            Some(previous) => write_key(&dir.join(PREVIOUS_FILE), previous)?,
            None => {
                let stale = dir.join(PREVIOUS_FILE);
                if stale.exists() {
                    std::fs::remove_file(&stale).map_err(|e| Error::KeyFile(e.to_string()))?;
                }
            }
        }
        Ok(())
    }

    /// Directory paths (for operators, not secrets).
    #[must_use]
    pub fn paths(dir: &Path) -> (PathBuf, PathBuf) {
        (dir.join(CURRENT_FILE), dir.join(PREVIOUS_FILE))
    }
}

fn read_key(path: &Path) -> Result<KeyPair, Error> {
    let bytes = std::fs::read(path).map_err(|e| Error::KeyFile(e.to_string()))?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidKeyLength)?;
    Ok(KeyPair::from_bytes(&array))
}

fn write_key(path: &Path, key: &KeyPair) -> Result<(), Error> {
    std::fs::write(path, key.signing().to_bytes()).map_err(|e| Error::KeyFile(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::KeyFile(e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::KeyManager;

    #[test]
    fn round_trip_through_files() {
        let dir = std::env::temp_dir().join(format!("bandall-keys-{}", std::process::id()));
        let manager = KeyManager::generate().unwrap();
        manager.save(&dir).unwrap();
        let back = KeyManager::load_or_generate(&dir).unwrap();
        assert_eq!(back.current().kid(), manager.current().kid());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotation_keeps_previous_verifier() {
        let mut manager = KeyManager::generate().unwrap();
        let old_kid = manager.current().kid().to_string();
        manager.rotate().unwrap();
        assert!(manager.verifier(&old_kid).is_some());
        assert!(manager.verifier("unknown").is_none());
    }
}
