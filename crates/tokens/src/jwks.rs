//! JWKS document for offline verification (`GET /.well-known/jwks.json`).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;

use crate::keys::KeyManager;

/// One JWKS entry (Ed25519 octet key pair, public half).
#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    /// Key type (`OKP`).
    pub kty: &'static str,
    /// Curve (`Ed25519`).
    pub crv: &'static str,
    /// Key id.
    pub kid: String,
    /// Base64url public key.
    pub x: String,
    /// Intended use (`sig`).
    #[serde(rename = "use")]
    pub use_: &'static str,
}

/// JWKS document.
#[derive(Debug, Clone, Serialize)]
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
                kty: "OKP",
                crv: "Ed25519",
                kid,
                x: URL_SAFE_NO_PAD.encode(verifying.to_bytes()),
                use_: "sig",
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
