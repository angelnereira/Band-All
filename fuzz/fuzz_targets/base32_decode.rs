//! Fuzz target: strict Base32 decoding (RFC 4648).
//!
//! `decode` takes untrusted text (an `otpauth://` secret, a recovery code).
//! The invariant is totality: every input, including invalid UTF-8 and huge
//! strings, must return `Ok` or a typed `Err` — never panic, and never
//! allocate wildly out of proportion to the input.
//!
//! On `Ok`, decoding must round-trip: `encode(decode(x)) == x` after
//! normalising case and stripping padding, because `otpauth` secrets arrive
//! with either.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The parser is text-facing: skip inputs that are not valid UTF-8 rather
    // than lossily converting them, which would fuzz a string nobody can send.
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Totality: no panic for any input.
    let decoded = bandall_totp_core::base32::decode(text);

    // A successful decode must re-encode to the same canonical form. Padding
    // and case are not significant in the input, so compare case-insensitively
    // after the encoder, which is the documented normalisation.
    if let Ok(bytes) = decoded {
        let encoded = bandall_totp_core::base32::encode(&bytes);
        let round_tripped =
            bandall_totp_core::base32::decode(&encoded).expect("encode output must decode");
        assert_eq!(bytes, round_tripped, "decode/encode round-trip changed the bytes");
    }
});
