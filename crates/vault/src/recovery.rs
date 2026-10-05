//! Recovery codes: high-entropy single-use fallbacks.
//!
//! Plaintexts are generated here and shown to the user once; only Argon2id
//! hashes (PHC strings) are persisted. Verification distinguishes a wrong
//! code (`Ok(false)`) from a malformed hash (`Err`).

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use secrecy::{ExposeSecret, SecretBox};

use crate::error::Error;

/// Argon2id memory cost in KiB (19 MiB, RFC 9106 first recommendation).
const M_COST: u32 = 19_456;
/// Argon2id time cost (passes).
const T_COST: u32 = 2;
/// Argon2id parallelism (lanes).
const P_COST: u32 = 1;
/// Hash output length in bytes.
const OUT_LEN: usize = 32;
/// Salt length in bytes.
const SALT_LEN: usize = 16;
/// Recovery code entropy in bytes (80 bits, rendered as 16 Base32 chars).
const CODE_BYTES: usize = 10;
/// Recovery codes issued per factor.
pub const CODE_COUNT: usize = 10;

/// A plaintext recovery code. Shown once, then hashed and forgotten.
pub struct RecoveryCode(SecretBox<String>);

impl RecoveryCode {
    /// Renders the code for one-time display (`XXXX-XXXX-XXXX-XXXX`).
    #[must_use]
    pub fn display(&self) -> String {
        self.0.expose_secret().clone()
    }
}

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryCode([redacted])")
    }
}

/// Generates `CODE_COUNT` fresh recovery codes.
pub fn generate() -> Result<Vec<RecoveryCode>, Error> {
    let mut codes = Vec::with_capacity(CODE_COUNT);
    for _ in 0..CODE_COUNT {
        codes.push(new_code()?);
    }
    Ok(codes)
}

fn new_code() -> Result<RecoveryCode, Error> {
    let mut bytes = vec![0u8; CODE_BYTES];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Random)?;
    let encoded = data_encoding::BASE32_NOPAD.encode(&bytes);
    let grouped = group4(&encoded);
    Ok(RecoveryCode(SecretBox::new(Box::new(grouped))))
}

/// Groups a 16-char code as `XXXX-XXXX-XXXX-XXXX`.
fn group4(code: &str) -> String {
    let mut out = String::with_capacity(code.len() + 3);
    for (i, ch) in code.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(ch);
    }
    out
}

fn argon2() -> Result<Argon2<'static>, Error> {
    let params = Params::new(M_COST, T_COST, P_COST, Some(OUT_LEN))
        .map_err(|_| Error::InvalidRecoveryParam)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hashes a code for storage (PHC string).
pub fn hash(code: &RecoveryCode) -> Result<String, Error> {
    let mut salt_bytes = vec![0u8; SALT_LEN];
    getrandom::getrandom(&mut salt_bytes).map_err(|_| Error::Random)?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| Error::InvalidRecoveryParam)?;
    argon2()?
        .hash_password(code.0.expose_secret().as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| Error::InvalidRecoveryParam)
}

/// Verifies a candidate against a stored PHC hash. `Ok(false)` means "wrong
/// code"; `Err` means the stored hash itself is malformed.
pub fn verify(candidate: &str, phc: &str) -> Result<bool, Error> {
    let parsed = PasswordHash::new(phc).map_err(|_| Error::InvalidRecoveryHash)?;
    match argon2()?.verify_password(candidate.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(password_hash::Error::Password) => Ok(false),
        Err(_) => Err(Error::InvalidRecoveryHash),
    }
}

#[cfg(test)]
mod tests {
    use super::{generate, hash, verify};

    #[test]
    fn hash_verify_round_trip() {
        let codes = generate().unwrap();
        assert_eq!(codes.len(), 10);
        let phc = hash(&codes[0]).unwrap();
        assert!(phc.starts_with("$argon2id$"));
        assert!(verify(&codes[0].display(), &phc).unwrap());
        assert!(!verify("AAAA-BBBB-CCCC-DDDD", &phc).unwrap());
    }

    #[test]
    fn rejects_malformed_hash() {
        assert!(verify("whatever", "not-a-phc-hash").is_err());
    }
}
