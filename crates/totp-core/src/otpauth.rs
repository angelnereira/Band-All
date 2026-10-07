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

    /// Enrolled secret as strict Base32. The app scanned this QR itself, so
    /// it owns the value; it must still move it straight into platform
    /// storage (Keystore/Enclave), never into logs.
    #[must_use]
    pub fn secret_base32(&self) -> String {
        self.secret.to_base32()
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
        // Split on the first *literal* colon, then percent-decode each side.
        // Decoding first would let an issuer that contains a colon (encoded as
        // `%3A`) consume the separator: `%3A:a` decodes to `::a`, whose first
        // colon yields an empty issuer and the account `:a`. Splitting first
        // keeps `ACME%3ACorp:alice` as ("ACME:Corp", "alice").
        let (label_issuer, account) = match label.split_once(':') {
            Some((issuer, account)) => (pct_decode(issuer)?, pct_decode(account)?),
            None => (String::new(), pct_decode(label)?),
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
///
/// Every escape is `%XX`. Omitting the `%` (which this function did until
/// 2026-10-06) does not merely produce a non-conforming URI: the decoder sees
/// plain hex digits, so `alice+bob@example.com` round-trips as
/// `alice2Bbob40example.com`. That corruption lands in the QR code, and the
/// user's authenticator then shows an account label that is not the one they
/// enrolled — with `+` and `@` being common in email addresses.
fn pct_encode(s: &str) -> String {
    const UNRESERVED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if UNRESERVED.contains(&b) {
            out.push(char::from(b));
        } else {
            out.push('%');
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
        // 160-bit secret (20 bytes), as Google/Microsoft Authenticator issue.
        let entry = Otpauth::parse(
            "otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA1&digits=6&period=30",
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
        // Compare the *fields*, not just the URI: comparing URI to URI is
        // tautological and let a broken percent-encoder pass for months (see
        // `percent_encoding_survives_special_characters`).
        assert_eq!(back.issuer(), entry.issuer());
        assert_eq!(back.account(), entry.account());
        assert_eq!(back.secret_base32(), entry.secret_base32());
        assert_eq!(back.params().algorithm(), entry.params().algorithm());
        assert_eq!(back.params().digits(), entry.params().digits());
        assert_eq!(back.params().period(), entry.params().period());
        assert_eq!(back.to_uri(), entry.to_uri());
    }

    #[test]
    fn percent_encoding_survives_special_characters() {
        // Regression: `pct_encode` emitted `XX` without the `%`, so these
        // labels arrived at the authenticator app corrupted (space -> "20",
        // `+` -> "2B", `@` -> "40"). Both characters are common in emails.
        let params = TotpParams::default_params();
        let secret = Secret::from_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        let entry = Otpauth::new(
            params,
            secret,
            "Band All".to_string(),
            "alice+bob@example.com".to_string(),
        )
        .unwrap();

        let uri = entry.to_uri();
        assert!(uri.contains("Band%20All"), "space must be %20, got {uri}");
        assert!(
            uri.contains("alice%2Bbob%40example.com"),
            "`+` and `@` must be escaped, got {uri}"
        );

        let back = Otpauth::parse(&uri).unwrap();
        assert_eq!(back.issuer(), "Band All");
        assert_eq!(back.account(), "alice+bob@example.com");
    }

    #[test]
    fn percent_encoded_utf8_survives() {
        // Non-ASCII labels must be percent-encoded byte by byte and decoded
        // back to the same characters.
        let params = TotpParams::default_params();
        let secret = Secret::from_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        let entry = Otpauth::new(
            params,
            secret,
            "Añejo".to_string(),
            "josé@example.com".to_string(),
        )
        .unwrap();
        let back = Otpauth::parse(&entry.to_uri()).unwrap();
        assert_eq!(back.issuer(), "Añejo");
        assert_eq!(back.account(), "josé@example.com");
    }

    #[test]
    fn issuer_containing_a_colon_does_not_eat_the_separator() {
        // Regression: the parser percent-decoded the whole label before
        // splitting on ':', so `%3A:a` became `::a` and the account came back
        // as `:a` instead of `a`. Real issuers like "ACME:Corp" hit this.
        let params = TotpParams::default_params();
        let secret = Secret::from_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        let entry =
            Otpauth::new(params, secret, "ACME:Corp".to_string(), "alice".to_string()).unwrap();
        let uri = entry.to_uri();
        assert!(uri.contains("ACME%3ACorp:alice"), "got {uri}");

        let back = Otpauth::parse(&uri).unwrap();
        assert_eq!(back.issuer(), "ACME:Corp");
        assert_eq!(back.account(), "alice");
    }

    #[test]
    fn account_containing_a_colon_survives() {
        // The separator is the first colon; a colon in the account is data and
        // must come back intact.
        let params = TotpParams::default_params();
        let secret = Secret::from_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        let entry = Otpauth::new(params, secret, "ACME".to_string(), "a:b".to_string()).unwrap();
        let back = Otpauth::parse(&entry.to_uri()).unwrap();
        assert_eq!(back.issuer(), "ACME");
        assert_eq!(back.account(), "a:b");
    }

    #[test]
    fn rejects_bad_uris() {
        assert!(Otpauth::parse("https://example.com").is_err());
        assert!(
            Otpauth::parse("otpauth://hotp/a?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").is_err()
        );
        assert!(Otpauth::parse("otpauth://totp/a?issuer=x").is_err());
        assert!(
            Otpauth::parse("otpauth://totp/A:a?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=B")
                .is_err()
        );
    }
}
