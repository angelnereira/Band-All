//! Battery for the embedded facade (ADR-0014): the same guarantees as the
//! HTTP service, without network.
//!
//! The core has no clock; `unix_secs` is injected, which is what makes these
//! tests deterministic and the facade safe to use on devices with odd clocks.
//!
//! Test-only unwraps are allowed here by policy (see crate `AGENTS.md`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use bandall_embedded::{Embedded, Error};

async fn embedded() -> Embedded {
    Embedded::in_memory([0x11; 32]).await.unwrap()
}

fn generate(secret_b32: &str, unix_secs: u64) -> String {
    use bandall_totp_core::{Secret, TotpParams, totp};
    let secret = Secret::from_base32(secret_b32).unwrap();
    totp::generate(&secret, TotpParams::default_params(), unix_secs).unwrap()
}

fn secret_from_uri(uri: &str) -> String {
    uri.split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn full_cycle_enroll_confirm_verify() {
    let e = embedded().await;
    let tenant = e.create_tenant("acme").await.unwrap();

    let outcome = e
        .enroll(&tenant, "alice", "BandAll", "alice@example.com")
        .await
        .unwrap();
    assert!(outcome.otpauth_uri.starts_with("otpauth://totp/"));
    assert!(outcome.recovery_codes.is_empty(), "codes come from confirm");

    // First confirm consumes step T; a replay of the same code must fail.
    let secret = secret_from_uri(&outcome.otpauth_uri);
    let now = 1_700_000_000;
    let code = generate(&secret, now);
    let codes = e
        .confirm(&tenant, "alice", &outcome.factor_id, &code, now)
        .await
        .unwrap();
    assert_eq!(codes.len(), 10);

    // First confirm consumes step T; the factor is now active, so a second
    // confirm is a state error, not a replay (the replay check belongs to
    // `verify`, tested below).
    let replay = generate(&secret, now + 5);
    assert!(matches!(
        e.confirm(&tenant, "alice", &outcome.factor_id, &replay, now + 5)
            .await,
        Err(Error::FactorState)
    ));

    // Verify a fresh step; replay it again; delete and re-enroll.
    let fresh = generate(&secret, now + 120);
    e.verify(&tenant, "alice", &outcome.factor_id, &fresh, now + 120)
        .await
        .unwrap();
    let fresh_replay = generate(&secret, now + 121);
    assert!(matches!(
        e.verify(
            &tenant,
            "alice",
            &outcome.factor_id,
            &fresh_replay,
            now + 121
        )
        .await,
        Err(Error::Unverified)
    ));
}

#[tokio::test]
async fn wrong_code_and_wrong_factor_deny() {
    let e = embedded().await;
    let tenant = e.create_tenant("acme").await.unwrap();
    let outcome = e.enroll(&tenant, "alice", "B", "a@b.c").await.unwrap();
    let secret = secret_from_uri(&outcome.otpauth_uri);
    let now = 1_700_000_000;
    let code = generate(&secret, now);
    e.confirm(&tenant, "alice", &outcome.factor_id, &code, now)
        .await
        .unwrap();

    let wrong = "000000".to_string();
    assert!(matches!(
        e.verify(&tenant, "alice", &outcome.factor_id, &wrong, now)
            .await,
        Err(Error::Unverified)
    ));

    // Different subject external id for the same factor: uniform denial.
    assert!(matches!(
        e.verify("acme", "bob", &outcome.factor_id, &wrong, now)
            .await,
        Err(Error::Unverified)
    ));
}

#[tokio::test]
async fn out_of_window_code_is_denied() {
    let e = embedded().await;
    let tenant = e.create_tenant("acme").await.unwrap();
    let outcome = e.enroll(&tenant, "alice", "B", "a@b.c").await.unwrap();
    let secret = secret_from_uri(&outcome.otpauth_uri);
    let now = 1_700_000_000;
    let code = generate(&secret, now);
    e.confirm(&tenant, "alice", &outcome.factor_id, &code, now)
        .await
        .unwrap();

    // Code from 3 periods away (90 s) is outside the ±1 window (T3).
    let far = generate(&secret, now + 90);
    assert!(matches!(
        e.verify(&tenant, "alice", &outcome.factor_id, &far, now)
            .await,
        Err(Error::Unverified)
    ));
}

#[tokio::test]
async fn tampered_database_is_denied_without_oracle() {
    // Wrong KEK at open time: uniform internal failure, no secret detail.
    let e1 = Embedded::in_memory([0x11; 32]).await.unwrap();
    let tenant = e1.create_tenant("acme").await.unwrap();
    let outcome = e1.enroll(&tenant, "alice", "B", "a@b.c").await.unwrap();

    let e2 = Embedded::in_memory([0x22; 32]).await.unwrap();
    let secret = secret_from_uri(&outcome.otpauth_uri);
    let code = generate(&secret, 1_700_000_000);
    let result = e2
        .verify("acme", "alice", &outcome.factor_id, &code, 1_700_000_000)
        .await;
    assert!(result.is_err());
    // And the error never carries key material.
    let text = format!("{:?}", result.err().unwrap());
    assert!(!text.contains("0x11") && !text.contains("22"));
}

#[tokio::test]
async fn delete_factor_allows_reenrolment() {
    let e = embedded().await;
    let tenant = e.create_tenant("acme").await.unwrap();
    let first = e.enroll(&tenant, "alice", "B", "a@b.c").await.unwrap();
    e.delete_factor(&tenant, "alice", &first.factor_id)
        .await
        .unwrap();
    assert!(matches!(
        e.verify(&tenant, "alice", &first.factor_id, "000000", 1_700_000_000)
            .await,
        Err(Error::Unverified)
    ));
    let second = e.enroll(&tenant, "alice", "B", "a@b.c").await.unwrap();
    assert_ne!(first.factor_id, second.factor_id);
}

#[tokio::test]
async fn facade_is_clone_friendly() {
    // The facade is Arc-able and Send: an integrator can hold it in state.
    let e = Arc::new(Embedded::in_memory([0x11; 32]).await.unwrap());
    let tenant = e.create_tenant("t").await.unwrap();
    let handle = tokio::spawn({
        let e = Arc::clone(&e);
        async move {
            let tenant = tenant;
            let outcome = e.enroll(&tenant, "u", "B", "a@b.c").await.unwrap();
            outcome.factor_id
        }
    });
    let _ = handle.await.unwrap();
}
