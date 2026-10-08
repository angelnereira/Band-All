//! Tests of the bridge API.
//!
//! These run the exact functions the Flutter app calls, with the real crypto
//! behind them. What they cannot cover is the FFI boundary itself, which needs
//! a device or an emulator; everything on this side of it is checked here.
#![forbid(unsafe_code)]

use crate::{
    AccountView, code_at, export_backup, import_backup, is_valid_secret, manual_account,
    parse_otpauth, skew,
};

/// RFC 6238 Appendix B, SHA-256 vector, expressed as an `otpauth://` URI the
/// way a QR code would carry it.
///
/// RFC 6238 uses a *different secret per algorithm length*: 20 bytes for SHA-1,
/// 32 for SHA-256, 64 for SHA-512 (the same ASCII run, truncated). Using the
/// 20-byte one with SHA-256 produces a code that is correct for that secret and
/// matches nothing in the RFC, which is how this test was wrong the first time.
///
/// The secret below is the RFC's 32-byte `12345678901234567890123456789012` in
/// Base32, so the expected code has an authority outside this repository.
const RFC_SHA256_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";

/// RFC 6238 Appendix B, SHA-1 vector (20-byte secret), for the compatibility
/// path: services that only speak SHA-1 are still common.
const RFC_SHA1_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn rfc_uri() -> String {
    format!(
        "otpauth://totp/BandAll:alice@example.com?secret={RFC_SHA256_SECRET}\
         &issuer=BandAll&algorithm=SHA256&digits=6&period=30"
    )
}

#[test]
fn imports_an_otpauth_uri() {
    let account = parse_otpauth(rfc_uri()).expect("a well-formed URI must import");
    assert_eq!(account.issuer, "BandAll");
    assert_eq!(account.name, "alice@example.com");
    assert_eq!(account.algorithm, "SHA256");
    assert_eq!(account.digits, 6);
    assert_eq!(account.period_secs, 30);
    assert_eq!(account.secret_base32, RFC_SHA256_SECRET);
}

#[test]
fn rejects_a_malformed_uri_without_saying_why() {
    for bad in [
        "",
        "not a uri",
        "otpauth://hotp/BandAll:alice?secret=AAAA",
        "otpauth://totp/BandAll:alice", // no secret
        "otpauth://totp/BandAll:alice?secret=not-base32!!",
    ] {
        let error = parse_otpauth(bad.to_string()).expect_err("must be refused");
        assert_eq!(
            error, "not a valid otpauth URI",
            "the error must not describe which part failed: {bad:?}"
        );
    }
}

/// The code the app shows must be the code the RFC says, for a known instant.
///
/// This is the property that matters most in the whole app: an authenticator
/// that computes its own flavour of TOTP is worse than none, because it looks
/// right until someone tries to log in.
#[test]
fn generates_the_rfc_code_offline() {
    let account = parse_otpauth(rfc_uri()).expect("import");
    // RFC 6238 Appendix B gives the value for SHA-256 as 46119246 in 8 digits;
    // truncating to 6 keeps the low digits, 119246.
    let generated = code_at(account, 59).expect("generate");
    assert_eq!(generated.code, "119246");
    assert_eq!(generated.seconds_remaining, 1);
}

/// The SHA-1 path against its own RFC vector (RFC 4226 Appendix D counter 1 is
/// the same instant: t = 59 s is step 1). Compatibility with services that only
/// offer SHA-1 depends on this, and it is a different secret than SHA-256 uses.
#[test]
fn generates_the_sha1_compatibility_code() {
    let uri = format!(
        "otpauth://totp/Legacy:alice?secret={RFC_SHA1_SECRET}&algorithm=SHA1&digits=6&period=30"
    );
    let account = parse_otpauth(uri).expect("import");
    assert_eq!(account.algorithm, "SHA1");
    assert_eq!(code_at(account, 59).expect("generate").code, "287082");
}

#[test]
fn countdown_decreases_within_a_step_and_resets_at_the_boundary() {
    let account = parse_otpauth(rfc_uri()).expect("import");
    let at_start = code_at(account.clone(), 30).expect("generate");
    let at_end = code_at(account.clone(), 59).expect("generate");
    assert_eq!(at_start.seconds_remaining, 30);
    assert_eq!(at_end.seconds_remaining, 1);
    // Same step, same code: a countdown that changes the code would be a bug.
    assert_eq!(at_start.code, at_end.code);

    let next = code_at(account, 60).expect("generate");
    assert_eq!(next.seconds_remaining, 30);
    assert_ne!(next.code, at_start.code, "the code must rotate at the boundary");
}

#[test]
fn manual_entry_validates_every_parameter() {
    let ok = manual_account(
        "BandAll".to_string(),
        "alice".to_string(),
        "SHA256".to_string(),
        6,
        30,
        RFC_SHA256_SECRET.to_string(),
    );
    assert!(ok.is_ok());

    let cases: Vec<(&str, String, u8, u64)> = vec![
        ("MD5", RFC_SHA256_SECRET.to_string(), 6, 30),      // unknown algorithm
        ("SHA256", RFC_SHA256_SECRET.to_string(), 5, 30),   // too few digits
        ("SHA256", RFC_SHA256_SECRET.to_string(), 9, 30),   // too many digits
        ("SHA256", RFC_SHA256_SECRET.to_string(), 6, 0),    // zero period
        ("SHA256", "not-base32!!".to_string(), 6, 30), // bad secret
        ("SHA256", String::new(), 6, 30),            // empty secret
    ];
    for (algorithm, secret, digits, period) in cases {
        assert!(
            manual_account(
                "BandAll".to_string(),
                "alice".to_string(),
                algorithm.to_string(),
                digits,
                period,
                secret.clone(),
            )
            .is_err(),
            "must refuse {algorithm}/{digits}/{period}/{secret:?}"
        );
    }
}

#[test]
fn secret_validity_uses_the_same_constructor_the_account_will_use() {
    assert!(is_valid_secret(RFC_SHA256_SECRET.to_string(), "SHA256".to_string(), 6, 30));
    assert!(!is_valid_secret("!!!".to_string(), "SHA256".to_string(), 6, 30));
    assert!(!is_valid_secret(RFC_SHA256_SECRET.to_string(), "MD5".to_string(), 6, 30));
}

#[test]
fn skew_warns_past_three_steps() {
    let fine = skew(1_700_000_000, 1_700_000_030);
    assert_eq!(fine.seconds, 30);
    assert!(!fine.warns, "30 s is inside the tolerance");

    let warning = skew(1_700_000_000, 1_700_000_091);
    assert_eq!(warning.seconds, 91);
    assert!(warning.warns);
}

#[test]
fn backup_round_trips_every_account() {
    let account = parse_otpauth(rfc_uri()).expect("import");
    let payload =
        export_backup(vec![account.clone()], "correct horse battery staple".to_string())
            .expect("export");

    let restored = import_backup(payload, "correct horse battery staple".to_string())
        .expect("import");
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].issuer, account.issuer);
    assert_eq!(restored[0].name, account.name);
    assert_eq!(restored[0].secret_base32, account.secret_base32);

    // And the restored account still generates the same code, which is the
    // only property the user cares about.
    let before = code_at(account, 1_700_000_000).expect("generate");
    let after = code_at(restored[0].clone(), 1_700_000_000).expect("generate");
    assert_eq!(before.code, after.code);
}

#[test]
fn backup_refuses_a_wrong_passphrase_and_a_tampered_payload() {
    let account = parse_otpauth(rfc_uri()).expect("import");
    let payload = export_backup(vec![account], "correct horse battery staple".to_string())
        .expect("export");

    assert!(
        import_backup(payload.clone(), "wrong passphrase entirely".to_string()).is_err(),
        "a wrong passphrase must not open the backup"
    );

    // Flip a character in the middle of the payload: the AEAD must notice.
    let mut tampered = payload.clone().into_bytes();
    let middle = tampered.len() / 2;
    tampered[middle] = if tampered[middle] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8_lossy(&tampered).to_string();
    assert!(
        import_backup(tampered, "correct horse battery staple".to_string()).is_err(),
        "a tampered payload must not open"
    );
}

#[test]
fn a_short_passphrase_is_refused_at_export() {
    let account = parse_otpauth(rfc_uri()).expect("import");
    assert!(
        export_backup(vec![account], "short".to_string()).is_err(),
        "the core refuses passphrases it considers too weak"
    );
}

/// The account view must not print the secret: it ends up in logs and crash
/// reports, and nothing in this repo may leak secret material.
#[test]
fn the_debug_representation_carries_no_secret() {
    let account: AccountView = parse_otpauth(rfc_uri()).expect("import");
    let rendered = format!("{account:?}");
    assert!(
        !rendered.contains(&account.secret_base32),
        "Debug leaked the secret: {rendered}"
    );
}
