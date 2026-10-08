//! JWKS document for offline verification (`GET /.well-known/jwks.json`).
//!
//! The server serializes it (ADRs 0004/0005); SDKs and the remote verifier
//! deserialize it with the same `Jwk`/`Jwks` shapes.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::keys::KeyManager;

/// One JWKS entry (Ed25519 octet key pair, public half).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Jwk {
    /// Key type (`OKP`).
    pub kty: String,
    /// Curve (`Ed25519`).
    pub crv: String,
    /// Key id.
    pub kid: String,
    /// Base64url public key.
    pub x: String,
    /// Intended use (`sig`).
    #[serde(rename = "use", default)]
    pub use_: String,
}

/// JWKS document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Jwks {
    /// Public keys (current first).
    pub keys: Vec<Jwk>,
}

/// Builds the document from the key manager.
#[must_use]
pub fn document(keys: &KeyManager) -> Jwks {
    Jwks {
        keys: keys
            .all_verifying()
            .into_iter()
            .map(|(kid, verifying)| Jwk {
                kty: "OKP".to_string(),
                crv: "Ed25519".to_string(),
                kid,
                x: URL_SAFE_NO_PAD.encode(verifying.to_bytes()),
                use_: "sig".to_string(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyManager, document};

    #[test]
    fn document_lists_current_key() {
        let keys = KeyManager::generate().unwrap();
        let jwks = document(&keys);
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid, keys.current().kid());
        assert_eq!(jwks.keys[0].kty, "OKP");
    }
}
