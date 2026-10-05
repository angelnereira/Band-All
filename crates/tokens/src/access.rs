//! Access tokens: hand-rolled JWT with EdDSA (Ed25519).
//!
//! Strict by design: the algorithm is fixed to `EdDSA` (anything else,
//! including `none`, is rejected), and `iss`/`aud`/`exp` are mandatory.
//! Services validate offline against the JWKS document.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::keys::KeyManager;

/// Fixed JWT algorithm.
const ALGORITHM: &str = "EdDSA";
/// Clock-skew leeway in seconds for `exp`.
const EXP_LEEWAY_SECS: u64 = 60;
/// Access token lifetime in seconds (10 minutes).
pub const ACCESS_TTL_SECS: u64 = 600;

/// Access token claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer (this service).
    pub iss: String,
    /// Audience (the relying service).
    pub aud: String,
    /// Subject id.
    pub sub: String,
    /// Tenant id.
    pub tenant: String,
    /// Session id (revocation handle).
    pub sid: String,
    /// Authentication methods actually verified (e.g. `["otp"]`).
    pub amr: Vec<String>,
    /// Assurance level actually achieved (1 until pwd+otp, see ADR-0005).
    pub aal: u8,
    /// Token id (uniqueness).
    pub jti: String,
    /// Issued at (Unix seconds).
    pub iat: u64,
    /// Expires at (Unix seconds).
    pub exp: u64,
}

impl Claims {
    /// Builds claims for a fresh OTP-verified session.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        iss: String,
        aud: String,
        sub: String,
        tenant: String,
        sid: String,
        now_secs: u64,
    ) -> Result<Self, Error> {
        Ok(Self {
            iss,
            aud,
            sub,
            tenant,
            sid,
            amr: vec!["otp".to_string()],
            aal: 1,
            jti: new_id()?,
            iat: now_secs,
            exp: now_secs.saturating_add(ACCESS_TTL_SECS),
        })
    }
}

/// Fresh random id (jti, sid, families). Fails closed on CSPRNG failure.
fn new_id() -> Result<String, Error> {
    let mut bytes = vec![0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Random)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[derive(Debug, Serialize, Deserialize)]
struct Header {
    alg: String,
    kid: String,
    #[serde(default = "default_typ")]
    typ: String,
}

fn default_typ() -> String {
    "JWT".to_string()
}

/// Issues a compact JWT for `claims`, signed with the current key.
pub fn issue(keys: &KeyManager, claims: &Claims) -> Result<String, Error> {
    let header = Header {
        alg: ALGORITHM.to_string(),
        kid: keys.current().kid().to_string(),
        typ: "JWT".to_string(),
    };
    let header_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|_| Error::Invalid)?);
    let claims_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|_| Error::Invalid)?);
    let signing_input = format!("{header_b64}.{claims_b64}");
    let signature = keys.current().signing().sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

/// Verifies a token strictly: structure, fixed `alg`, known `kid`,
/// signature, then `iss`/`aud`/`exp`.
pub fn verify(
    keys: &KeyManager,
    token: &str,
    expected_iss: &str,
    expected_aud: &str,
    now_secs: u64,
) -> Result<Claims, Error> {
    let (header_b64, rest) = token.split_once('.').ok_or(Error::Invalid)?;
    let (claims_b64, sig_b64) = rest.split_once('.').ok_or(Error::Invalid)?;
    if sig_b64.contains('.') {
        return Err(Error::Invalid);
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| Error::Invalid)?;
    let header: Header = serde_json::from_slice(&header_bytes).map_err(|_| Error::Invalid)?;
    if header.alg != ALGORITHM {
        return Err(Error::Invalid);
    }
    let verifier: VerifyingKey = keys.verifier(&header.kid).ok_or(Error::Invalid)?;
    let signing_input = format!("{header_b64}.{claims_b64}");
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| Error::Invalid)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| Error::Invalid)?;
    verifier
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| Error::Invalid)?;

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(claims_b64)
        .map_err(|_| Error::Invalid)?;
    let claims: Claims = serde_json::from_slice(&claims_bytes).map_err(|_| Error::Invalid)?;
    if claims.iss != expected_iss || claims.aud != expected_aud {
        return Err(Error::Invalid);
    }
    if claims.exp.saturating_add(EXP_LEEWAY_SECS) <= now_secs {
        return Err(Error::Invalid);
    }
    if claims.iat > now_secs.saturating_add(EXP_LEEWAY_SECS) {
        return Err(Error::Invalid);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::KeyManager;
    use super::{issue, verify};
    use crate::error::Error;

    fn manager() -> KeyManager {
        KeyManager::generate().unwrap()
    }

    fn claims(now: u64) -> super::Claims {
        super::Claims::new(
            "https://bandall.example".to_string(),
            "my-app".to_string(),
            "sub-1".to_string(),
            "tenant-1".to_string(),
            "sid-1".to_string(),
            now,
        )
        .unwrap()
    }

    #[test]
    fn round_trip() {
        let keys = manager();
        let token = issue(&keys, &claims(1_700_000_000)).unwrap();
        let back = verify(
            &keys,
            &token,
            "https://bandall.example",
            "my-app",
            1_700_000_100,
        )
        .unwrap();
        assert_eq!(back.sub, "sub-1");
        assert_eq!(back.aal, 1);
    }

    #[test]
    fn rejects_tampered_and_foreign_tokens() {
        let keys = manager();
        let other = manager();
        let now = 1_700_000_000;
        let token = issue(&keys, &claims(now)).unwrap();
        // Tampered payload.
        let mut bad = token.clone();
        bad.push('x');
        assert_eq!(
            verify(&keys, &bad, "https://bandall.example", "my-app", now),
            Err(Error::Invalid)
        );
        // Unknown key.
        assert_eq!(
            verify(&other, &token, "https://bandall.example", "my-app", now),
            Err(Error::Invalid)
        );
        // Wrong audience / issuer.
        assert_eq!(
            verify(&keys, &token, "https://bandall.example", "other-app", now),
            Err(Error::Invalid)
        );
        // Expired.
        assert_eq!(
            verify(
                &keys,
                &token,
                "https://bandall.example",
                "my-app",
                now + 10_000
            ),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn previous_key_still_verifies_after_rotation() {
        let mut keys = manager();
        let token = issue(&keys, &claims(1_700_000_000)).unwrap();
        keys.rotate().unwrap();
        assert!(
            verify(
                &keys,
                &token,
                "https://bandall.example",
                "my-app",
                1_700_000_100
            )
            .is_ok()
        );
        // New tokens carry the new kid.
        let fresh = issue(&keys, &claims(1_700_000_000)).unwrap();
        assert_ne!(fresh, token);
    }

    #[test]
    fn rejects_confused_algorithm() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let keys = manager();
        let token = issue(&keys, &claims(1_700_000_000)).unwrap();
        let mut parts = token.split('.');
        let claims_b64 = parts.nth(1).unwrap().to_string();
        let sig_b64 = parts.next().unwrap().to_string();
        // Attacker re-labels the header as HS256, keeping body and signature.
        let evil_header = URL_SAFE_NO_PAD.encode(
            format!(
                "{{\"alg\":\"HS256\",\"kid\":\"{}\",\"typ\":\"JWT\"}}",
                keys.current().kid()
            )
            .as_bytes(),
        );
        let evil = format!("{evil_header}.{claims_b64}.{sig_b64}");
        assert_eq!(
            verify(
                &keys,
                &evil,
                "https://bandall.example",
                "my-app",
                1_700_000_000
            ),
            Err(Error::Invalid)
        );
    }
}
