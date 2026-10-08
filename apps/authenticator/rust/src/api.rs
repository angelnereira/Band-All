//! The API the Flutter app calls.
//!
//! Plain data in, plain data out. The types are deliberately boring (strings,
//! integers, vectors of structs) because that is what crosses a language
//! boundary safely; the cryptography stays behind `bandall-authenticator-core`.
//!
//! No `unsafe` here, and the compiler holds it to that: the generated FFI glue
//! is the only place in the crate allowed to lift the ban (see the crate root).
#![forbid(unsafe_code)]

use bandall_authenticator_core::accounts::{Account, AccountSnapshot, clock_skew};
use bandall_authenticator_core::{Algorithm, backup};
use flutter_rust_bridge::frb;

/// One account as the UI sees it: everything needed to draw a row and generate
/// the current code, and nothing that requires holding Rust state.
///
/// `secret_base32` is here because the app has to persist it: the Dart side
/// hands this struct to platform secure storage (Keystore/Keychain) and reads
/// it back on launch. It must never be written to an unencrypted store, logged,
/// or put in a widget's state.
#[derive(Clone)]
pub struct AccountView {
    /// Issuer label, e.g. `BandAll`.
    pub issuer: String,
    /// Account label, e.g. `alice@example.com`.
    pub name: String,
    /// Secret as strict Base32 (persisted by the app, never logged).
    pub secret_base32: String,
    /// `SHA1`, `SHA256` or `SHA512`.
    pub algorithm: String,
    /// Digit count (6-8).
    pub digits: u8,
    /// Period in seconds.
    pub period_secs: u64,
}

/// Redacts the secret. `AccountView` crosses into Dart and appears in error
/// reports, so `derive(Debug)` would put raw secret material one `print` away
/// from a log — the same rule the service follows for its own secrets.
impl std::fmt::Debug for AccountView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AccountView")
            .field("issuer", &self.issuer)
            .field("name", &self.name)
            .field("secret_base32", &"[redacted]")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period_secs", &self.period_secs)
            .finish()
    }
}

/// A code and how long it lasts.
#[derive(Debug, Clone)]
pub struct CodeView {
    /// The current code, zero padded to `digits`.
    pub code: String,
    /// Seconds until it rotates (1..=period).
    pub seconds_remaining: u64,
}

/// Clock drift verdict, for the "your phone's clock looks off" banner.
#[derive(Debug, Clone)]
pub struct SkewView {
    /// Absolute difference in seconds.
    pub seconds: u64,
    /// Whether it exceeds the warning threshold (three steps).
    pub warns: bool,
}

impl AccountView {
    fn from_snapshot(snapshot: &AccountSnapshot) -> Self {
        Self {
            issuer: snapshot.issuer.clone(),
            name: snapshot.name.clone(),
            secret_base32: snapshot.secret_base32.clone(),
            algorithm: snapshot.algorithm.clone(),
            digits: snapshot.digits,
            period_secs: snapshot.period_secs,
        }
    }

    fn to_snapshot(&self) -> AccountSnapshot {
        AccountSnapshot {
            issuer: self.issuer.clone(),
            name: self.name.clone(),
            algorithm: self.algorithm.clone(),
            digits: self.digits,
            period_secs: self.period_secs,
            secret_base32: self.secret_base32.clone(),
        }
    }
}

/// Parses an `otpauth://` URI, which is what a QR scan produces.
///
/// Errors are deliberately opaque: a malformed QR must not tell the user (or a
/// malicious QR) which part parsed and which did not.
///
/// Synchronous: parsing is string work with no I/O, and making the UI await a
/// future for it would only add a frame of flicker.
#[frb(sync)]
pub fn parse_otpauth(uri: String) -> Result<AccountView, String> {
    let account = Account::import(&uri).map_err(|_| "not a valid otpauth URI".to_string())?;
    Ok(AccountView::from_snapshot(&account.snapshot()))
}

/// Builds an account from manual entry (no QR available).
///
/// Synchronous for the same reason as `parse_otpauth`: it validates strings and
/// a Base32 secret, nothing more.
#[frb(sync)]
pub fn manual_account(
    issuer: String,
    name: String,
    algorithm: String,
    digits: u8,
    period_secs: u64,
    secret_base32: String,
) -> Result<AccountView, String> {
    let algorithm =
        Algorithm::from_name(&algorithm).map_err(|_| "unknown algorithm".to_string())?;
    let account = Account::manual(issuer, name, algorithm, digits, period_secs, &secret_base32)
        .map_err(|_| "invalid account".to_string())?;
    Ok(AccountView::from_snapshot(&account.snapshot()))
}

/// Generates the code for `unix_secs`.
///
/// The time is a parameter, never `SystemTime::now()`: it is what makes the
/// whole path testable, and what lets the app show a code for a chosen instant
/// when the user is checking a clock problem.
///
/// Synchronous: it is one HMAC, and the UI redraws it every second.
#[frb(sync)]
pub fn code_at(view: AccountView, unix_secs: u64) -> Result<CodeView, String> {
    let account = Account::restore(view.to_snapshot()).map_err(|_| "invalid account".to_string())?;
    let (code, seconds_remaining) = account.code_at(unix_secs).map_err(|_| "invalid account".to_string())?;
    Ok(CodeView {
        code,
        seconds_remaining,
    })
}

/// Compares the device clock against a reference (the server's time from the
/// last successful verification).
#[frb(sync)]
#[must_use]
pub fn skew(device_secs: u64, reference_secs: u64) -> SkewView {
    let (seconds, warns) = clock_skew(device_secs, reference_secs);
    SkewView { seconds, warns }
}

/// Encrypts the accounts under `passphrase` (Argon2id + XChaCha20-Poly1305).
///
/// This is the *optional* backup: the app does not upload anything anywhere on
/// its own, and the string this returns is the user's to keep.
///
/// **Asynchronous on purpose.** Argon2id is tuned to be slow (19 MiB, two
/// passes): running it synchronously would freeze the UI for a noticeable
/// moment. It stays on the async runtime so the spinner actually spins.
pub fn export_backup(accounts: Vec<AccountView>, passphrase: String) -> Result<String, String> {
    let snapshots: Vec<AccountSnapshot> = accounts.iter().map(AccountView::to_snapshot).collect();
    backup::export_encrypted(&snapshots, &passphrase).map_err(|_| "cannot create the backup".to_string())
}

/// Restores accounts from an encrypted backup.
///
/// A wrong passphrase and a tampered file are the same error on purpose: the
/// envelope is authenticated, so there is nothing useful to tell apart.
///
/// Asynchronous for the same reason as `export_backup`: it derives a key with
/// Argon2id before it can say "no".
pub fn import_backup(payload: String, passphrase: String) -> Result<Vec<AccountView>, String> {
    let snapshots = backup::import_encrypted(&payload, &passphrase)
        .map_err(|_| "cannot open the backup".to_string())?;
    Ok(snapshots
        .iter()
        .map(AccountView::from_snapshot)
        .collect())
}

/// Whether a Base32 secret and its parameters are usable, for manual entry as
/// the user types.
///
/// Goes through the same constructor the account will use, so "valid here"
/// means "will work", not "looks like Base32".
///
/// Synchronous: it runs on every keystroke of the manual-entry field.
#[frb(sync)]
#[must_use]
pub fn is_valid_secret(secret_base32: String, algorithm: String, digits: u8, period_secs: u64) -> bool {
    manual_account(
        "check".to_string(),
        "check".to_string(),
        algorithm,
        digits,
        period_secs,
        secret_base32,
    )
    .is_ok()
}
