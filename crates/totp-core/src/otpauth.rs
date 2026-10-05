//! `otpauth://` enrolment URIs (what the QR code carries).
//!
//! Only `totp` entries are supported. Parsing is strict about structure but
//! lenient about unknown query parameters (forward compatibility).

use crate::algorithm::Algorithm;
use crate::error::Error;
use crate::secret::Secret;
use crate::totp::{Period, TotpParams};

/// An enrolment URI: everything needed to provision a factor.
#[derive(Debug)]
pub struct Otpauth {
    params: TotpParams,
    secret: Secret,
    issuer: String,
    account: String,
}

impl Otpauth {
    /// Builds an enrolment entry, requiring a non-empty account name.
    pub fn new(
        params: TotpParams,
        secret: Secret,
        issuer: String,
        account: String,
    ) -> Result<Self, Error> {
        if account.is_empty() {
            return Err(Error::InvalidUri);
        }
        Ok(Self {
            params,
            secret,
            issuer,
            account,
        })
    }

    /// Parameters.
    #[must_use]
    pub fn params(&self) -> TotpParams {
        self.params
    }

    /// Issuer (may be empty for legacy entries).
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Account name.
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// Renders the `otpauth://totp/...` URI for the QR code.
    #[must_use]
    pub fn to_uri(&self) -> String {
        let label = if self.issuer.is_empty() {
            pct_encode(&self.account)
        } else {
            format!("{}:{}", pct_encode(&self.issuer), pct_encode(&self.account))
        };
        let mut uri = format!("otpauth://totp/{label}?secret={}", self.secret.to_base32());
        if !self.issuer.is_empty() {
            uri.push_str("&issuer=");
            uri.push_str(&pct_encode(&self.issuer));
        }
        uri.push_str("&algorithm=");
        uri.push_str(self.params.algorithm().name());
        uri.push_str("&digits=");
        uri.push_str(&self.params.digits().to_string());
        uri.push_str("&period=");
        uri.push_str(&self.params.period().as_u64().to_string());
        uri
    }

    /// Parses an `otpauth://totp/...` URI.
    pub fn parse(uri: &str) -> Result<Self, Error> {
        let rest = uri.strip_prefix("otpauth://").ok_or(Error::InvalidUri)?;
        let rest = rest.strip_prefix("totp/").ok_or(Error::InvalidUri)?;
        let (label, query) = rest.split_once('?').ok_or(Error::InvalidUri)?;
        if label.is_empty() || query.is_empty() {
            return Err(Error::InvalidUri);
        }
        let label = pct_decode(label)?;
        let (label_issuer, account) = match label.split_once(':') {
            Some((issuer, account)) => (issuer.to_string(), account.to_string()),
            None => (String::new(), label),
        };
        if account.is_empty() {
            return Err(Error::InvalidUri);
        }
        let mut secret: Option<Secret> = None;
        let mut query_issuer: Option<String> = None;
        let mut algorithm = Algorithm::Sha1;
        let mut digits = 6u8;
        let mut period = Period::STANDARD;
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').ok_or(Error::InvalidUri)?;
            match key {
                "secret" => secret = Some(Secret::from_base32(value)?),
                "issuer" => query_issuer = Some(pct_decode(value)?),
                "algorithm" => algorithm = Algorithm::from_name(value)?,
                "digits" => {
                    digits = value.parse::<u8>().map_err(|_| Error::InvalidUri)?;
                }
                "period" => {
                    let secs = value.parse::<u64>().map_err(|_| Error::InvalidUri)?;
                    period = Period::new(secs)?;
                }
                _ => {}
            }
        }
        if !(6..=8).contains(&digits) {
            return Err(Error::InvalidDigits(digits));
        }
        if let Some(query_issuer) = query_issuer.as_deref() {
            if !label_issuer.is_empty() && label_issuer != query_issuer {
                return Err(Error::InvalidUri);
            }
        }
        let issuer = query_issuer.unwrap_or(label_issuer);
        let params = TotpParams::new(algorithm, digits, period)?;
        Ok(Self {
            params,
            secret: secret.ok_or(Error::InvalidUri)?,
            issuer,
            account,
        })
    }
}

/// Percent-decodes `%XX` sequences.
fn pct_decode(s: &str) -> Result<String, Error> {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.as_bytes().iter();
    while let Some(&b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next().ok_or(Error::InvalidUri)?;
            let lo = bytes.next().ok_or(Error::InvalidUri)?;
            out.push(hex_val(*hi)? << 4 | hex_val(*lo)?);
        } else {
            out.push(b);
        }
    }
    String::from_utf8(out).map_err(|_| Error::InvalidUri)
}

/// Percent-encodes everything outside the RFC 3986 unreserved set.
fn pct_encode(s: &str) -> String {
    const UNRESERVED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if UNRESERVED.contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

fn hex_val(b: u8) -> Result<u8, Error> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(Error::InvalidUri),
    }
}

#[cfg(test)]
mod tests {
    use super::Otpauth;
    use crate::algorithm::Algorithm;
    use crate::secret::Secret;
    use crate::totp::{Period, TotpParams};

    #[test]
    fn parses_typical_uri() {
        let entry = Otpauth::parse(
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30",
        )
        .unwrap();
        assert_eq!(entry.issuer(), "Example");
        assert_eq!(entry.account(), "alice@example.com");
        assert_eq!(entry.params().algorithm(), Algorithm::Sha1);
        assert_eq!(entry.params().digits(), 6);
        assert_eq!(entry.params().period(), Period::STANDARD);
    }

    #[test]
    fn round_trip() {
        let params = TotpParams::new(Algorithm::Sha256, 6, Period::STANDARD).unwrap();
        let secret = Secret::generate_for(Algorithm::Sha256).unwrap();
        let entry = Otpauth::new(
            params,
            secret,
            "BandAll".to_string(),
            "bob@example.com".to_string(),
        )
        .unwrap();
        let back = Otpauth::parse(&entry.to_uri()).unwrap();
        assert_eq!(back.to_uri(), entry.to_uri());
    }

    #[test]
    fn rejects_bad_uris() {
        assert!(Otpauth::parse("https://example.com").is_err());
        assert!(Otpauth::parse("otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(Otpauth::parse("otpauth://totp/a?issuer=x").is_err());
        assert!(Otpauth::parse("otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP&issuer=B").is_err());
    }
}
