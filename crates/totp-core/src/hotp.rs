//! HOTP (RFC 4226): HMAC + dynamic truncation.
//!
//! TOTP is HOTP with a time-derived counter; the truncation core lives here
//! and is shared.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::algorithm::Algorithm;
use crate::error::Error;
use crate::secret::Secret;

/// Allowed digit counts and their moduli (RFC 4226 permits 6-8).
fn modulus_for(digits: u8) -> Result<u32, Error> {
    match digits {
        6 => Ok(1_000_000),
        7 => Ok(10_000_000),
        8 => Ok(100_000_000),
        other => Err(Error::InvalidDigits(other)),
    }
}

/// HMAC with a statically known hash function.
fn mac_bytes<M>(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error>
where
    M: Mac + KeyInit,
{
    let mut mac = <M as KeyInit>::new_from_slice(key).map_err(|_| Error::Crypto)?;
    mac.update(msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Raw HOTP value for `counter` (not yet zero-padded).
pub(crate) fn hotp_value(
    secret: &Secret,
    algorithm: Algorithm,
    counter: u64,
    digits: u8,
) -> Result<u32, Error> {
    let modulus = modulus_for(digits)?;
    let msg = counter.to_be_bytes();
    let mac = match algorithm {
        Algorithm::Sha1 => mac_bytes::<Hmac<Sha1>>(secret.bytes(), &msg)?,
        Algorithm::Sha256 => mac_bytes::<Hmac<Sha256>>(secret.bytes(), &msg)?,
        Algorithm::Sha512 => mac_bytes::<Hmac<Sha512>>(secret.bytes(), &msg)?,
    };
    let offset = usize::from(mac.last().ok_or(Error::Crypto)? & 0x0F);
    let byte = |i: usize| mac.get(i).copied().ok_or(Error::Crypto);
    let code = (u32::from(byte(offset)? & 0x7F) << 24)
        | (u32::from(byte(offset + 1)?) << 16)
        | (u32::from(byte(offset + 2)?) << 8)
        | u32::from(byte(offset + 3)?);
    Ok(code % modulus)
}

/// HOTP code for `counter`, zero-padded to `digits` (6-8).
pub fn generate(
    secret: &Secret,
    algorithm: Algorithm,
    counter: u64,
    digits: u8,
) -> Result<String, Error> {
    let value = hotp_value(secret, algorithm, counter, digits)?;
    Ok(format!("{value:0>width$}", width = usize::from(digits)))
}

#[cfg(test)]
mod tests {
    use super::generate;
    use crate::algorithm::Algorithm;
    use crate::secret::Secret;

    /// RFC 4226 Appendix D, secret `12345678901234567890`.
    const RFC4226: [(u64, &str); 10] = [
        (0, "755224"),
        (1, "287082"),
        (2, "359152"),
        (3, "969429"),
        (4, "338314"),
        (5, "254676"),
        (6, "287922"),
        (7, "162583"),
        (8, "399871"),
        (9, "520489"),
    ];

    #[test]
    fn rfc4226_vectors() {
        let secret = Secret::new(b"12345678901234567890".to_vec()).unwrap();
        for (counter, expected) in RFC4226 {
            assert_eq!(
                generate(&secret, Algorithm::Sha1, counter, 6).unwrap(),
                expected,
                "counter {counter}"
            );
        }
    }

    #[test]
    fn rejects_bad_digits() {
        let secret = Secret::new(vec![0u8; 20]).unwrap();
        assert!(generate(&secret, Algorithm::Sha1, 0, 5).is_err());
        assert!(generate(&secret, Algorithm::Sha1, 0, 9).is_err());
    }
}
