//! Property tests for the pure core (H1, roadmap item 8).
//!
//! The RFC vectors pin specific outputs; these search for the counterexamples
//! a fixed vector cannot reach. Two families:
//!
//! - **Round-trips**: `decode(encode(x)) == x` for Base32 and for `otpauth`.
//! - **Monotonicity and bounds**: steps never go backwards, codes always have
//!   the configured digit count, and the verification window contains exactly
//!   the steps it promises.
//!
//! When one of these fails, proptest shrinks to a minimal input, which is what
//! turns "verify sometimes misbehaves" into a bug report.

use bandall_totp_core::base32;
use bandall_totp_core::otpauth::Otpauth;
use bandall_totp_core::{Algorithm, Period, Secret, TotpParams, totp};
use proptest::prelude::*;

/// Non-empty byte strings: `base32::decode` deliberately rejects the empty
/// string (a secret is never empty), so `encode("")` has no valid inverse.
fn any_bytes() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 1..64)
}

/// Text drawn from the Base32 alphabet plus the characters that appear in real
/// `otpauth` secrets: padding, whitespace and lowercase.
fn any_base32_text() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        proptest::sample::select(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567abcdefghijklmnopqrstuvwxyz= \t\n-_%+@:/?&#"
                .chars()
                .collect::<Vec<char>>(),
        ),
        0..48,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

/// Label characters that matter for URI encoding: unreserved, reserved,
/// percent itself, and multi-byte UTF-8.
fn any_label() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        proptest::sample::select(
            "abcXYZ019 -._~!*'()+,;:@&=+$/%áéñ日本語"
                .chars()
                .collect::<Vec<char>>(),
        ),
        1..24,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

fn any_params() -> impl Strategy<Value = TotpParams> {
    (
        proptest::sample::select(vec![Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512]),
        6u8..=8,
    )
        .prop_map(|(algorithm, digits)| {
            // Both are in range by construction, so the unwrap-free path is
            // just `new`; anything else would be a bug in this strategy.
            TotpParams::new(algorithm, digits, Period::STANDARD)
                .unwrap_or_else(|_| TotpParams::default_params())
        })
}

proptest! {
    /// Base32 survives any byte string, including the padding boundaries.
    #[test]
    fn base32_round_trip(bytes in any_bytes()) {
        let encoded = base32::encode(&bytes);
        let decoded = base32::decode(&encoded)
            .map_err(|e| TestCaseError::fail(format!("encode output must decode: {e}")))?;
        prop_assert_eq!(decoded, bytes);
    }

    /// The decoder is total: arbitrary text is `Ok` or a typed error, never a
    /// panic or a silent truncation.
    #[test]
    fn base32_decode_is_total(text in any_base32_text()) {
        // The only assertion is that this returns at all. An `Ok` must also
        // be self-consistent.
        if let Ok(bytes) = base32::decode(&text) {
            let re = base32::decode(&base32::encode(&bytes))
                .map_err(|e| TestCaseError::fail(format!("re-decode failed: {e}")))?;
            prop_assert_eq!(re, bytes);
        }
    }

    /// Base32 output is canonical: uppercase, no lowercase letters leak.
    #[test]
    fn base32_encoding_is_uppercase(bytes in any_bytes()) {
        let encoded = base32::encode(&bytes);
        prop_assert!(
            encoded.chars().all(|c| !c.is_ascii_lowercase()),
            "encoder emitted lowercase in {encoded}"
        );
    }

    /// `otpauth` round-trips field by field. Comparing only the URI would be
    /// tautological and hid a broken percent-encoder for months, so this
    /// compares every field the QR code carries.
    #[test]
    fn otpauth_round_trip(
        issuer in any_label(),
        account in any_label(),
        params in any_params(),
        secret_bytes in proptest::collection::vec(any::<u8>(), 16..=128),
    ) {
        let secret = Secret::new(secret_bytes)
            .map_err(|e| TestCaseError::fail(format!("valid length must build: {e}")))?;
        let entry = Otpauth::new(params, secret, issuer.clone(), account.clone())
            .map_err(|e| TestCaseError::fail(format!("non-empty labels must build: {e}")))?;

        let parsed = Otpauth::parse(&entry.to_uri())
            .map_err(|e| TestCaseError::fail(format!("own URI must parse: {e}")))?;

        prop_assert_eq!(parsed.issuer(), issuer.as_str());
        prop_assert_eq!(parsed.account(), account.as_str());
        prop_assert_eq!(parsed.secret_base32(), entry.secret_base32());
        prop_assert_eq!(parsed.params().algorithm(), params.algorithm());
        prop_assert_eq!(parsed.params().digits(), params.digits());
        prop_assert_eq!(parsed.params().period(), params.period());
        prop_assert_eq!(parsed.to_uri(), entry.to_uri());
    }

    /// The parser is total over arbitrary text.
    #[test]
    fn otpauth_parse_is_total(text in "\\PC{0,128}") {
        let _ = Otpauth::parse(&text);
    }

    /// The step is exactly `floor(t / period)`: the definition the anti-replay
    /// counter and the drift maths both rest on.
    #[test]
    fn step_is_floor_of_time_over_period(
        unix_secs in 0u64..4_000_000_000,
        params in any_params(),
    ) {
        let expected = unix_secs / params.period().as_u64();
        prop_assert_eq!(totp::counter_for(params, unix_secs).get(), expected);
    }

    /// Time never moves the step backwards, and a difference smaller than the
    /// period keeps it equal. (`floor(a/p) + floor(b/p) != floor((a+b)/p)` in
    /// general, so the exact value is pinned by the test above instead.)
    #[test]
    fn step_is_monotonic_in_time(
        base in 0u64..u32::MAX as u64,
        delta in 0u64..1_000_000,
        params in any_params(),
    ) {
        let period = params.period().as_u64();
        let first = totp::counter_for(params, base).get();
        let second = totp::counter_for(params, base + delta).get();
        prop_assert!(second >= first, "step went backwards in time");
        if delta < period {
            prop_assert_eq!(first, second, "a sub-period jump must not change the step");
        }
    }

    /// Generated codes always carry exactly the configured digits.
    #[test]
    fn code_has_exactly_digits(
        params in any_params(),
        unix_secs in 0u64..4_000_000_000,
    ) {
        let secret = Secret::generate_for(params.algorithm())
            .map_err(|e| TestCaseError::fail(format!("generation failed: {e}")))?;
        let code = totp::generate(&secret, params, unix_secs)
            .map_err(|e| TestCaseError::fail(format!("generation failed: {e}")))?;
        prop_assert_eq!(code.len(), usize::from(params.digits()));
        prop_assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    /// Generation and verification agree at `window = 0`, and verification
    /// returns the step the code belongs to.
    #[test]
    fn verify_accepts_its_own_code(
        params in any_params(),
        unix_secs in 0u64..4_000_000_000,
    ) {
        let secret = Secret::generate_for(params.algorithm())
            .map_err(|e| TestCaseError::fail(format!("generation failed: {e}")))?;
        let code = totp::generate(&secret, params, unix_secs)
            .map_err(|e| TestCaseError::fail(format!("generation failed: {e}")))?;
        let step = totp::verify(&secret, params, &code, unix_secs, 0, None)
            .map_err(|e| TestCaseError::fail(format!("own code must verify: {e}")))?;
        prop_assert_eq!(step, totp::counter_for(params, unix_secs));
    }

    /// A step already consumed is rejected: the pure core never accepts two
    /// codes from the same step, which is what the store then enforces
    /// atomically.
    #[test]
    fn consumed_step_is_rejected(
        params in any_params(),
        unix_secs in 1u64..4_000_000_000,
    ) {
        let secret = Secret::generate_for(params.algorithm())
            .map_err(|e| TestCaseError::fail(format!("generation failed: {e}")))?;
        let step = totp::counter_for(params, unix_secs);
        let code = totp::generate(&secret, params, unix_secs)
            .map_err(|e| TestCaseError::fail(format!("generation failed: {e}")))?;
        let result = totp::verify(&secret, params, &code, unix_secs, 1, Some(step));
        prop_assert!(result.is_err(), "a consumed step must not verify again");
    }

    /// The window is a closed interval around the drift: every step within
    /// `window` of the candidate set verifies, and one step beyond does not.
    #[test]
    fn window_bounds_are_exact(
        params in any_params(),
        unix_secs in 1_000_000u64..4_000_000_000,
        window in 0u32..4,
    ) {
        let secret = Secret::generate_for(params.algorithm())
            .map_err(|e| TestCaseError::fail(format!("generation failed: {e}")))?;
        let period = params.period().as_u64();

        // Inside the window: accepts.
        let inside = unix_secs - u64::from(window) * period;
        let code = totp::generate(&secret, params, inside)
            .map_err(|e| TestCaseError::fail(format!("generation failed: {e}")))?;
        prop_assert!(totp::verify(&secret, params, &code, unix_secs, window, None).is_ok());

        // One step further out: rejects. Guard the underflow at the epoch.
        if unix_secs > (u64::from(window) + 1) * period {
            let outside = unix_secs - (u64::from(window) + 1) * period;
            let code = totp::generate(&secret, params, outside)
                .map_err(|e| TestCaseError::fail(format!("generation failed: {e}")))?;
            prop_assert!(
                totp::verify(&secret, params, &code, unix_secs, window, None).is_err(),
                "step one beyond the window must not verify"
            );
        }
    }

    /// Verification never depends on how the secret was built: Base32 round
    /// trips are enough to reproduce the same code.
    #[test]
    fn secret_base32_round_trip(bytes in proptest::collection::vec(any::<u8>(), 16..=128)) {
        let secret = Secret::new(bytes)
            .map_err(|e| TestCaseError::fail(format!("valid length must build: {e}")))?;
        let restored = Secret::from_base32(&secret.to_base32())
            .map_err(|e| TestCaseError::fail(format!("own encoding must parse: {e}")))?;
        prop_assert_eq!(restored.expose_secret_bytes(), secret.expose_secret_bytes());
    }
}
