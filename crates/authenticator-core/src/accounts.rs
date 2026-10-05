//! Device-side accounts: provisioning from `otpauth://`, current codes with
//! countdowns and clock-skew warnings.
//!
//! Secrets stay inside `bandall_totp_core::Secret` (zeroed on drop). Storage
//! in the Secure Enclave / Keystore and the UI live in the native shells;
//! native bindings (UniFFI vs Flutter) are decided in ADR-0006.

use bandall_totp_core::{Algorithm, Otpauth, Period, Secret, TotpParams, totp};

use crate::error::Error;

/// Clock-skew warning threshold in seconds (three 30 s steps).
pub const SKEW_WARN_SECS: u64 = 90;

/// One authenticator entry.
pub struct Account {
    issuer: String,
    name: String,
    params: TotpParams,
    secret: Secret,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("issuer", &self.issuer)
            .field("name", &self.name)
            .field("params", &self.params)
            .field("secret", &"[redacted]")
            .finish()
    }
}

impl Account {
    /// Provisions from an `otpauth://` URI (QR scan result).
    pub fn import(uri: &str) -> Result<Self, Error> {
        let entry = Otpauth::parse(uri).map_err(|_| Error::Invalid)?;
        let secret = Secret::from_base32(&entry.secret_base32()).map_err(|_| Error::Invalid)?;
        Ok(Self {
            issuer: entry.issuer().to_string(),
            name: entry.account().to_string(),
            params: entry.params(),
            secret,
        })
    }

    /// Builds from explicit parts (manual entry).
    pub fn manual(
        issuer: String,
        name: String,
        algorithm: Algorithm,
        digits: u8,
        period_secs: u64,
        base32_secret: &str,
    ) -> Result<Self, Error> {
        if name.is_empty() || name.len() > 256 {
            return Err(Error::Invalid);
        }
        let period = Period::new(period_secs).map_err(|_| Error::Invalid)?;
        let params = TotpParams::new(algorithm, digits, period).map_err(|_| Error::Invalid)?;
        let secret = Secret::from_base32(base32_secret).map_err(|_| Error::Invalid)?;
        Ok(Self {
            issuer,
            name,
            params,
            secret,
        })
    }

    /// Issuer label.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Account label.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Current code plus seconds until it expires, for `now_secs`.
    pub fn code_at(&self, now_secs: u64) -> Result<(String, u64), Error> {
        let code =
            totp::generate(&self.secret, self.params, now_secs).map_err(|_| Error::Invalid)?;
        let period = self.params.period().as_u64();
        Ok((code, period.saturating_sub(now_secs % period)))
    }

    /// Portable snapshot for encrypted backup (never logged).
    #[must_use]
    pub fn snapshot(&self) -> AccountSnapshot {
        AccountSnapshot {
            issuer: self.issuer.clone(),
            name: self.name.clone(),
            algorithm: self.params.algorithm().name().to_string(),
            digits: self.params.digits(),
            period_secs: self.params.period().as_u64(),
            secret_base32: self.secret.to_base32(),
        }
    }

    /// Restores an account from a snapshot (validates everything).
    pub fn restore(snapshot: AccountSnapshot) -> Result<Self, Error> {
        let algorithm = Algorithm::from_name(&snapshot.algorithm).map_err(|_| Error::Invalid)?;
        Self::manual(
            snapshot.issuer,
            snapshot.name,
            algorithm,
            snapshot.digits,
            snapshot.period_secs,
            &snapshot.secret_base32,
        )
    }
}

/// Portable account snapshot: the unit of encrypted backup.
#[derive(Debug, Clone)]
pub struct AccountSnapshot {
    /// Issuer label.
    pub issuer: String,
    /// Account label.
    pub name: String,
    /// Algorithm name (`SHA256`, ...).
    pub algorithm: String,
    /// Digit count.
    pub digits: u8,
    /// Period in seconds.
    pub period_secs: u64,
    /// Secret as strict Base32.
    pub secret_base32: String,
}

/// In-memory account list (device storage lives in the native shell).
#[derive(Debug, Default)]
pub struct AccountStore {
    accounts: Vec<Account>,
}

impl AccountStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an account, rejecting duplicate names.
    pub fn add(&mut self, account: Account) -> Result<(), Error> {
        if self.accounts.iter().any(|a| a.name() == account.name()) {
            return Err(Error::Invalid);
        }
        self.accounts.push(account);
        Ok(())
    }

    /// Removes an account by name. Returns `false` when absent.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.accounts.len();
        self.accounts.retain(|a| a.name() != name);
        self.accounts.len() != before
    }

    /// Iterates accounts.
    pub fn accounts(&self) -> impl Iterator<Item = &Account> {
        self.accounts.iter()
    }

    /// Number of accounts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }
}

/// Compares the device clock against a reference (e.g. the server time from
/// the last successful verification). Returns the absolute skew and whether
/// it exceeds the warning threshold.
#[must_use]
pub fn clock_skew(device_secs: u64, reference_secs: u64) -> (u64, bool) {
    let skew = device_secs.abs_diff(reference_secs);
    (skew, skew > SKEW_WARN_SECS)
}

#[cfg(test)]
mod tests {
    use super::{Account, AccountStore, clock_skew};

    const URI: &str = "otpauth://totp/BandAll:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=BandAll&algorithm=SHA256&digits=6&period=30";

    #[test]
    fn import_and_code() {
        let account = Account::import(URI).unwrap();
        assert_eq!(account.name(), "alice@example.com");
        let (code, remaining) = account.code_at(1_700_000_000).unwrap();
        assert_eq!(code.len(), 6);
        assert!(remaining <= 30);
    }

    #[test]
    fn rejects_duplicates() {
        let mut store = AccountStore::new();
        store.add(Account::import(URI).unwrap()).unwrap();
        assert!(store.add(Account::import(URI).unwrap()).is_err());
        assert!(store.remove("alice@example.com"));
        assert!(!store.remove("alice@example.com"));
    }

    #[test]
    fn skew_warning() {
        assert_eq!(clock_skew(100, 120), (20, false));
        assert_eq!(clock_skew(100, 500), (400, true));
    }
}
