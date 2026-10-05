//! TOTP (RFC 6238): time-derived HOTP with windowed, replay-aware verification.
//!
//! Pure by design: wall-clock time enters as `unix_secs`, never via
//! `SystemTime`. Replay protection compares against the caller's
//! `last_accepted` step; durable enforcement (`UPDATE ... WHERE last_step <
//! $step`) belongs to the store layer (H2/H3).

use subtle::ConstantTimeEq;

use crate::algorithm::Algorithm;
use crate::error::Error;
use crate::hotp;
use crate::secret::Secret;

/// Maximum accepted tolerance window (steps each side). The design uses ±1;
/// the cap only guards against accidental huge windows.
const MAX_WINDOW: u32 = 10;

/// A TOTP time step (`floor(unix_secs / period)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Step(u64);

impl Step {
    /// Wraps a raw step counter.
    #[must_use]
    pub fn new(step: u64) -> Self {
        Self(step)
    }

    /// The raw step counter, to persist as `last_step`.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

/// TOTP period in seconds. Must be non-zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Period(u64);

impl Period {
    /// The standard 30-second period.
    pub const STANDARD: Self = Self(30);

    /// Builds a period, rejecting zero.
    pub fn new(secs: u64) -> Result<Self, Error> {
        if secs == 0 {
            return Err(Error::InvalidPeriod);
        }
        Ok(Self(secs))
    }

    /// Period length in seconds.
    #[must_use]
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// TOTP parameters for one factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpParams {
    algorithm: Algorithm,
    digits: u8,
    period: Period,
}

impl TotpParams {
    /// Default for new factors: SHA-256, 6 digits, 30 s (see ADR-0003).
    #[must_use]
    pub fn default_params() -> Self {
        Self {
            algorithm: Algorithm::Sha256,
            digits: 6,
            period: Period::STANDARD,
        }
    }

    /// Builds parameters, validating digits (6-8) — the period is already
    /// validated by construction.
    pub fn new(algorithm: Algorithm, digits: u8, period: Period) -> Result<Self, Error> {
        if !(6..=8).contains(&digits) {
            return Err(Error::InvalidDigits(digits));
        }
        Ok(Self {
            algorithm,
            digits,
            period,
        })
    }

    /// Hash algorithm.
    #[must_use]
    pub fn algorithm(self) -> Algorithm {
        self.algorithm
    }

    /// Digit count (6-8).
    #[must_use]
    pub fn digits(self) -> u8 {
        self.digits
    }

    /// Period.
    #[must_use]
    pub fn period(self) -> Period {
        self.period
    }
}

/// Step for a Unix timestamp.
#[must_use]
pub fn counter_for(params: TotpParams, unix_secs: u64) -> Step {
    Step(unix_secs / params.period.as_u64())
}

/// TOTP code for a Unix timestamp, zero-padded.
pub fn generate(secret: &Secret, params: TotpParams, unix_secs: u64) -> Result<String, Error> {
    hotp::generate(
        secret,
        params.algorithm,
        counter_for(params, unix_secs).get(),
        params.digits,
    )
}

/// Constant-time equality for same-length code bytes.
fn codes_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Verifies `code` against the window around `unix_secs`.
///
/// Accepts only steps strictly greater than `last_accepted` (anti-replay at
/// the math level). Returns the matched step so the caller can persist it.
/// Distinguishes `CodeMismatch` from `CodeReplayed` for auditing; API layers
/// must still answer both uniformly.
pub fn verify(
    secret: &Secret,
    params: TotpParams,
    code: &str,
    unix_secs: u64,
    window: u32,
    last_accepted: Option<Step>,
) -> Result<Step, Error> {
    if window > MAX_WINDOW {
        return Err(Error::InvalidWindow);
    }
    let digits = usize::from(params.digits);
    if code.len() != digits || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidCode);
    }
    let current = counter_for(params, unix_secs).get();
    let start = current.saturating_sub(u64::from(window));
    let end = current
        .checked_add(u64::from(window))
        .ok_or(Error::CounterOverflow)?;
    let mut step = start;
    let mut saw_replay = false;
    loop {
        let fresh = last_accepted.is_none_or(|last| step > last.get());
        let candidate = hotp::generate(secret, params.algorithm, step, params.digits)?;
        if codes_equal(candidate.as_bytes(), code.as_bytes()) {
            if fresh {
                return Ok(Step(step));
            }
            saw_replay = true;
        }
        if step == end {
            break;
        }
        step = step.checked_add(1).ok_or(Error::CounterOverflow)?;
    }
    if saw_replay {
        return Err(Error::CodeReplayed);
    }
    Err(Error::CodeMismatch)
}

#[cfg(test)]
mod tests {
    use super::{Period, Step, TotpParams, counter_for, generate, verify};
    use crate::algorithm::Algorithm;
    use crate::error::Error;
    use crate::secret::Secret;

    fn sha1_params() -> TotpParams {
        TotpParams::new(Algorithm::Sha1, 8, Period::STANDARD).unwrap()
    }

    #[test]
    fn rfc6238_sha1_vectors() {
        let secret = Secret::new(b"12345678901234567890".to_vec()).unwrap();
        let params = sha1_params();
        for (time, expected) in [
            (59u64, "94287082"),
            (1_111_111_109u64, "07081804"),
            (1_111_111_111u64, "14050471"),
            (1_234_567_890u64, "89005924"),
            (2_000_000_000u64, "69279037"),
            (20_000_000_000u64, "65353130"),
        ] {
            assert_eq!(generate(&secret, params, time).unwrap(), expected);
        }
    }

    #[test]
    fn rfc6238_sha256_vectors() {
        let secret = Secret::new(b"12345678901234567890123456789012".to_vec()).unwrap();
        let params = TotpParams::new(Algorithm::Sha256, 8, Period::STANDARD).unwrap();
        for (time, expected) in [
            (59u64, "46119246"),
            (1_111_111_109u64, "68084774"),
            (1_234_567_890u64, "91819424"),
            (2_000_000_000u64, "90698825"),
        ] {
            assert_eq!(generate(&secret, params, time).unwrap(), expected);
        }
    }

    #[test]
    fn rfc6238_sha512_vectors() {
        let secret = Secret::new(
            b"1234567890123456789012345678901234567890123456789012345678901234".to_vec(),
        )
        .unwrap();
        let params = TotpParams::new(Algorithm::Sha512, 8, Period::STANDARD).unwrap();
        for (time, expected) in [
            (59u64, "90693936"),
            (1_111_111_109u64, "25091201"),
            (1_234_567_890u64, "93441116"),
            (2_000_000_000u64, "38618901"),
        ] {
            assert_eq!(generate(&secret, params, time).unwrap(), expected);
        }
    }

    #[test]
    fn verify_round_trip_and_replay() {
        let secret = Secret::generate_for(Algorithm::Sha256).unwrap();
        let params = TotpParams::default_params();
        let now = 1_700_000_000u64;
        let code = generate(&secret, params, now).unwrap();
        let step = verify(&secret, params, &code, now, 1, None).unwrap();
        assert_eq!(step, counter_for(params, now));
        assert_eq!(
            verify(&secret, params, &code, now, 1, Some(step)),
            Err(Error::CodeReplayed)
        );
        assert_eq!(
            verify(&secret, params, "000000", now, 1, None),
            Err(Error::CodeMismatch)
        );
    }

    #[test]
    fn rejects_malformed_codes() {
        let secret = Secret::generate_for(Algorithm::Sha256).unwrap();
        let params = TotpParams::default_params();
        assert_eq!(
            verify(&secret, params, "12345", 100, 1, None),
            Err(Error::InvalidCode)
        );
        assert_eq!(
            verify(&secret, params, "abcdef", 100, 1, None),
            Err(Error::InvalidCode)
        );
    }

    #[test]
    fn step_accessors() {
        assert_eq!(Step::new(7).get(), 7);
        assert_eq!(Period::new(30).unwrap().as_u64(), 30);
        assert!(Period::new(0).is_err());
    }
}
