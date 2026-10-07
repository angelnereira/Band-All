//! Fuzz target: `Secret::from_base32`, the path every enrolment takes.
//!
//! Beyond totality, this checks the property the enrolment flow depends on:
//! anything that becomes a `Secret` must survive a `to_base32` /
//! `from_base32` round trip unchanged, and its length must stay inside the
//! documented 16..=128 range. A secret that shrinks or grows on re-encoding
//! would silently change the codes a user's authenticator produces.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(secret) = bandall_totp_core::Secret::from_base32(text) else {
        return;
    };

    // Length invariant: `Secret::new` enforces 16..=128, so the constructor
    // must never hand back something outside it.
    assert!(
        (16..=128).contains(&secret.len()),
        "secret length {} escaped the documented range",
        secret.len()
    );
    assert!(!secret.is_empty());

    // Round-trip: the Base32 form is what the QR carries, so it must reproduce
    // the exact bytes.
    let encoded = secret.to_base32();
    let restored = bandall_totp_core::Secret::from_base32(&encoded)
        .expect("our own Base32 output must parse");
    assert_eq!(
        restored.expose_secret_bytes(),
        secret.expose_secret_bytes(),
        "secret bytes changed across a Base32 round trip"
    );

    // And a regenerated code must match, which is the user-visible guarantee.
    let params = bandall_totp_core::TotpParams::default_params();
    let now = 1_700_000_000u64;
    let from_original = bandall_totp_core::totp::generate(&secret, params, now)
        .expect("generation must not fail for a valid secret");
    let from_restored = bandall_totp_core::totp::generate(&restored, params, now)
        .expect("generation must not fail for a valid secret");
    assert_eq!(from_original, from_restored, "codes diverged after round trip");
});
