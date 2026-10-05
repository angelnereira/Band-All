//! HMAC request/webhook signatures (blueprint §10).
//!
//! Canonical string: `METHOD\nPATH\nQUERY\nSHA256(body)\ntimestamp\nnonce`.
//! The signature travels as `X-Signature: v1=<hex>` plus `X-Key-Id`,
//! `X-Timestamp` and `X-Nonce`. Verification enforces clock tolerance (±5
//! min), single-use nonces and constant-time comparison. Pure and
//! time-injected; nonce storage is the caller's `NonceCache`.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::Error;

/// Signature scheme version prefix.
const VERSION: &str = "v1";
/// Clock tolerance in seconds (±5 minutes).
pub const CLOCK_TOLERANCE_SECS: u64 = 300;
/// Nonce length in bytes (128 bits).
pub const NONCE_BYTES: usize = 16;

/// A signed request's components.
#[derive(Debug, Clone)]
pub struct SignedRequest {
    /// Uppercase HTTP method (`GET`, `POST`, ...).
    pub method: String,
    /// Request path (no query string).
    pub path: String,
    /// Raw query string (empty when none).
    pub query: String,
    /// Raw body bytes.
    pub body: Vec<u8>,
    /// Unix seconds claimed by the signer.
    pub timestamp: u64,
    /// Unique nonce (base64 or hex, caller-opaque).
    pub nonce: String,
}

/// Builds the canonical string (exactly one `\n` separator, no trailing one
/// except inside fields which are rejected when containing newlines).
pub fn canonical(req: &SignedRequest) -> Result<String, Error> {
    for field in [&req.method, &req.path, &req.query, &req.nonce] {
        if field.contains('\n') || field.contains('\r') {
            return Err(Error::Malformed);
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(&req.body);
    let body_hash = hex_encode(&hasher.finalize());
    Ok(format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method.to_ascii_uppercase(),
        req.path,
        req.query,
        body_hash,
        req.timestamp,
        req.nonce
    ))
}

/// Signs the canonical string with `key`, returning `v1=<hex>`.
pub fn sign(key: &[u8], req: &SignedRequest) -> Result<String, Error> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Invalid)?;
    mac.update(canonical(req)?.as_bytes());
    Ok(format!(
        "{VERSION}={}",
        hex_encode(&mac.finalize().into_bytes())
    ))
}

/// Verifies structure, timestamp, nonce freshness and signature. Every
/// failure maps to `Error` variants the caller must answer uniformly.
pub fn verify(
    key: &[u8],
    req: &SignedRequest,
    presented: &str,
    now_secs: u64,
    nonces: &mut NonceCache,
) -> Result<(), Error> {
    let (version, hex) = presented.split_once('=').ok_or(Error::Malformed)?;
    if version != VERSION || hex.is_empty() {
        return Err(Error::Malformed);
    }
    let skew = now_secs.abs_diff(req.timestamp);
    if skew > CLOCK_TOLERANCE_SECS {
        return Err(Error::Stale);
    }
    if req.nonce.is_empty() || req.nonce.len() > 128 {
        return Err(Error::Malformed);
    }
    nonces.check_and_insert(&req.nonce, now_secs)?;
    let expected = sign(key, req)?;
    if expected.len() != presented.len() {
        return Err(Error::Invalid);
    }
    if bool::from(expected.as_bytes().ct_eq(presented.as_bytes())) {
        Ok(())
    } else {
        Err(Error::Invalid)
    }
}

/// Lowercase hex encoding.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Generates a fresh random nonce (hex, 128 bits).
pub fn fresh_nonce() -> Result<String, Error> {
    let mut bytes = vec![0u8; NONCE_BYTES];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Random)?;
    Ok(hex_encode(&bytes))
}

/// Single-use nonce store with TTL. Time-injected; the API wires one per
/// process (a distributed deployment would back this with Redis in H8).
#[derive(Debug, Default)]
pub struct NonceCache {
    /// Nonce to expiry timestamp.
    seen: std::collections::HashMap<String, u64>,
}

impl NonceCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Rejects seen or expired-tracked nonces, then records this one until
    /// `now + CLOCK_TOLERANCE_SECS`.
    pub fn check_and_insert(&mut self, nonce: &str, now_secs: u64) -> Result<(), Error> {
        self.evict(now_secs);
        if self.seen.contains_key(nonce) {
            return Err(Error::Reused);
        }
        self.seen.insert(
            nonce.to_string(),
            now_secs.saturating_add(CLOCK_TOLERANCE_SECS),
        );
        Ok(())
    }

    fn evict(&mut self, now_secs: u64) {
        self.seen.retain(|_, expiry| *expiry > now_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::{NonceCache, SignedRequest, fresh_nonce, sign, verify};

    fn request() -> SignedRequest {
        SignedRequest {
            method: "POST".to_string(),
            path: "/v1/verify".to_string(),
            query: String::new(),
            body: b"{\"code\":\"123456\"}".to_vec(),
            timestamp: 1_700_000_000,
            nonce: "abc123".to_string(),
        }
    }

    #[test]
    fn round_trip() {
        let key = vec![9u8; 32];
        let req = request();
        let sig = sign(&key, &req).unwrap();
        assert!(sig.starts_with("v1="));
        verify(&key, &req, &sig, 1_700_000_000, &mut NonceCache::new()).unwrap();
    }

    #[test]
    fn rejects_replay_stale_and_tampered() {
        let key = vec![9u8; 32];
        let req = request();
        let sig = sign(&key, &req).unwrap();
        let mut nonces = NonceCache::new();
        verify(&key, &req, &sig, 1_700_000_000, &mut nonces).unwrap();
        assert!(verify(&key, &req, &sig, 1_700_000_001, &mut nonces).is_err());
        assert!(
            verify(
                &key,
                &req,
                &sig,
                1_700_000_000 + 10_000,
                &mut NonceCache::new()
            )
            .is_err()
        );
        let mut tampered = req;
        tampered.body = b"{}".to_vec();
        assert!(verify(&key, &tampered, &sig, 1_700_000_000, &mut NonceCache::new()).is_err());
        assert!(
            verify(
                &[1u8; 32],
                &request(),
                &sig,
                1_700_000_000,
                &mut NonceCache::new()
            )
            .is_err()
        );
    }

    #[test]
    fn nonces_are_fresh() {
        assert_ne!(fresh_nonce().unwrap(), fresh_nonce().unwrap());
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        let bytes = hex.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() / 2);
        let mut pair = bytes.chunks_exact(2);
        for chunk in &mut pair {
            let hi = hex_val(chunk[0]);
            let lo = hex_val(chunk[1]);
            out.push(hi << 4 | lo);
        }
        return out;

        fn hex_val(byte: u8) -> u8 {
            match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => 0,
            }
        }
    }

    /// Cross-implementation check: vectors generated with Python's hashlib
    /// must match this crate's canonical string and signature byte for byte.
    #[test]
    fn conformance_vectors() {
        let raw = include_str!("../../../sdks/conformance/vectors.json");
        let vectors: serde_json::Value = serde_json::from_str(raw).unwrap();
        let hmac = &vectors["hmac"];
        let get = |key: &str| hmac[key].as_str().unwrap().to_string();
        let key = hex_decode(hmac["key_hex"].as_str().unwrap());
        let req = SignedRequest {
            method: get("method"),
            path: get("path"),
            query: get("query"),
            body: get("body").into_bytes(),
            timestamp: hmac["timestamp"].as_u64().unwrap(),
            nonce: get("nonce"),
        };
        assert_eq!(crate::canonical(&req).unwrap(), get("canonical"));
        assert_eq!(crate::sign(&key, &req).unwrap(), get("signature"));
    }
}
