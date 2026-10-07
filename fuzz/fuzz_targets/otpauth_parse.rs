//! Fuzz target: `otpauth://` URI parsing.
//!
//! The URI is attacker-adjacent input: it arrives from a QR code, from a
//! third-party IdP, or from an operator's script. The invariants:
//!
//! 1. **Totality**: any input returns `Ok` or a typed `Err`, never a panic.
//! 2. **Round-trip**: a URI that parses must re-serialise and parse again to
//!    the same fields. A parse that silently drops or rewrites a field would
//!    provision the user a different factor than the QR claims.
//!
//! The round-trip is checked field by field, not URI against URI: comparing
//! URIs is tautological and hid a broken percent-encoder (see
//! `crates/totp-core/src/otpauth.rs`).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(uri) = std::str::from_utf8(data) else {
        return;
    };

    // Totality first: no panic for anything.
    let Ok(parsed) = bandall_totp_core::Otpauth::parse(uri) else {
        return;
    };

    // Re-serialising the parsed entry must produce a URI that parses back to
    // the same values, or the parser is lossy.
    let reserialised = parsed.to_uri();
    let Ok(again) = bandall_totp_core::Otpauth::parse(&reserialised) else {
        panic!("our own output must parse: {reserialised}");
    };

    assert_eq!(again.issuer(), parsed.issuer(), "issuer changed on re-parse");
    assert_eq!(again.account(), parsed.account(), "account changed on re-parse");
    assert_eq!(
        again.secret_base32(),
        parsed.secret_base32(),
        "secret changed on re-parse"
    );
    assert_eq!(
        again.params().algorithm(),
        parsed.params().algorithm(),
        "algorithm changed on re-parse"
    );
    assert_eq!(
        again.params().digits(),
        parsed.params().digits(),
        "digits changed on re-parse"
    );
    assert_eq!(
        again.params().period(),
        parsed.params().period(),
        "period changed on re-parse"
    );
});
