//! Strict RFC 4648 Base32 without padding.
//!
//! Only uppercase `A-Z` and `2-7` are accepted: no lowercase, no padding,
//! no whitespace. The alphabet gate runs before decoding so behaviour does
//! not depend on decoder leniency quirks.

use crate::error::Error;

/// Encodes bytes as uppercase Base32 without padding.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(bytes)
}

/// Decodes strict Base32, rejecting anything outside `A-Z2-7`.
pub fn decode(encoded: &str) -> Result<Vec<u8>, Error> {
    if encoded.is_empty()
        || !encoded
            .bytes()
            .all(|b| b.is_ascii_uppercase() || matches!(b, b'2'..=b'7'))
    {
        return Err(Error::InvalidBase32);
    }
    data_encoding::BASE32_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|_| Error::InvalidBase32)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn round_trip() {
        let raw = b"12345678901234567890";
        let encoded = encode(raw);
        assert_eq!(encoded, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(decode(&encoded).unwrap(), raw);
    }

    #[test]
    fn rejects_non_strict_input() {
        assert!(decode("").is_err());
        assert!(decode("gezdgnbvgy3tqojq").is_err());
        assert!(decode("GEZDGNBVGY3TQOJQ==").is_err());
        assert!(decode("GEZD GNBV").is_err());
        assert!(decode("GEZDGNBV!").is_err());
    }
}
