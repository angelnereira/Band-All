//! End-to-end MFA flow through real store and vault (SQLite in-memory).
//! Runs in CI; Postgres parity comes from the shared store battery.
//!
//! Test-only unwraps are allowed here by policy (see crate `AGENTS.md`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use axum::{Json, extract::State, http::HeaderMap};
use bandall_api::{
    AppState,
    enroll::{EnrollConfirmRequest, EnrollStartRequest, confirm, start},
    token::{RefreshRequest, RevokeRequest, jwks, refresh, revoke},
    verify::{MfaVerifyRequest, RecoverRequest, S2sVerifyRequest, mfa_verify, recover, s2s_verify},
};
use bandall_policy::Policy;
use bandall_store::{SqliteStore, Store};
use bandall_tokens::{KeyManager, verify as verify_token};
use bandall_totp_core::{Secret, TotpParams, totp};
use bandall_vault::{LocalKms, Vault};

const SERVICE_KEY: &str = "e2e-service-key-0123456789abcdef";
const ISSUER: &str = "https://bandall.example";
const AUDIENCE: &str = "my-app";
const NOW_SKEW: u64 = 60;

async fn setup() -> (AppState, String) {
    let sqlite = SqliteStore::in_memory().await.unwrap();
    sqlite.migrate().await.unwrap();
    let store: Arc<dyn Store> = Arc::new(sqlite);
    let kms = LocalKms::from_bytes("kek-e2e".to_string(), vec![3u8; 32]).unwrap();
    let vault = Arc::new(Vault::new(Arc::new(kms)));
    let keys = Arc::new(KeyManager::generate().unwrap());
    let policy = Arc::new(Policy::default());
    let tenant = store.create_tenant("e2e", 1_700_000_000).await.unwrap();
    let state = AppState::new(
        store,
        vault,
        keys,
        policy,
        ISSUER.to_string(),
        AUDIENCE.to_string(),
        SERVICE_KEY.to_string(),
    );
    (state, tenant.id)
}

fn service_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-service-key", SERVICE_KEY.parse().unwrap());
    headers
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Extracts the `secret` query value from an `otpauth://` URI.
fn uri_secret(uri: &str) -> String {
    uri.split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string()
}

async fn enroll_active(state: &AppState, tenant_id: &str) -> (String, String, Secret) {
    let started = start(
        State(state.clone()),
        service_headers(),
        Json(EnrollStartRequest {
            tenant_id: tenant_id.to_string(),
            subject_external_id: "alice".to_string(),
            issuer: "BandAll".to_string(),
            account: "alice@example.com".to_string(),
            algorithm: None,
            digits: None,
            period: None,
        }),
    )
    .await
    .unwrap()
    .0;
    let subject = state
        .store
        .find_subject(tenant_id, "alice")
        .await
        .unwrap()
        .unwrap();
    let secret = Secret::from_base32(&uri_secret(&started.otpauth_uri)).unwrap();
    let params = TotpParams::default_params();
    let code = totp::generate(&secret, params, now_unix()).unwrap();
    let confirmed = confirm(
        State(state.clone()),
        Json(EnrollConfirmRequest {
            tenant_id: tenant_id.to_string(),
            subject_id: subject.id.clone(),
            factor_id: started.factor_id.clone(),
            code,
        }),
    )
    .await
    .unwrap()
    .0;
    assert_eq!(confirmed.recovery_codes.len(), 10);
    (started.factor_id, subject.id, secret)
}

#[tokio::test]
async fn full_mfa_cycle() {
    let (state, tenant) = setup().await;
    let (factor_id, subject_id, _) = enroll_active(&state, &tenant).await;

    // Fresh code verifies once, then replays are denied.
    let params = TotpParams::default_params();
    let secret = return_recover_secret(&state, &tenant, &subject_id, &factor_id).await;
    let code = totp::generate(&secret, params, now_unix() + NOW_SKEW).unwrap();
    let body = MfaVerifyRequest {
        tenant_id: tenant.clone(),
        subject_id: subject_id.clone(),
        factor_id: factor_id.clone(),
        code: code.clone(),
    };
    assert!(mfa_verify(State(state.clone()), Json(body)).await.is_ok());
    let replay = MfaVerifyRequest {
        tenant_id: tenant.clone(),
        subject_id: subject_id.clone(),
        factor_id: factor_id.clone(),
        code,
    };
    assert!(
        mfa_verify(State(state.clone()), Json(replay))
            .await
            .is_err()
    );

    // Unknown factor and wrong code are denied uniformly.
    let unknown = MfaVerifyRequest {
        tenant_id: tenant.clone(),
        subject_id: subject_id.clone(),
        factor_id: "missing".to_string(),
        code: "123456".to_string(),
    };
    assert!(
        mfa_verify(State(state.clone()), Json(unknown))
            .await
            .is_err()
    );

    // Codes outside the tolerance window are rejected.
    let far = totp::generate(&secret, params, now_unix() + 3600).unwrap();
    let outside = MfaVerifyRequest {
        tenant_id: tenant.clone(),
        subject_id: subject_id.clone(),
        factor_id: factor_id.clone(),
        code: far,
    };
    assert!(
        mfa_verify(State(state.clone()), Json(outside))
            .await
            .is_err()
    );
}

/// Re-opens the factor secret through the vault (test-only plumbing).
async fn return_recover_secret(
    state: &AppState,
    tenant_id: &str,
    subject_id: &str,
    factor_id: &str,
) -> Secret {
    use secrecy::ExposeSecret;
    let factor = state
        .store
        .get_factor(tenant_id, subject_id, factor_id)
        .await
        .unwrap()
        .unwrap();
    // Rebuild via the same path the handlers use: test reaches into columns.
    let sealed = bandall_vault::SealedSecret::reassemble(
        u8::try_from(factor.secret_version).unwrap(),
        factor.kek_id.clone(),
        bandall_vault::WrappedDek::new(
            factor.wrapped_nonce.clone().try_into().unwrap(),
            factor.wrapped_dek.clone(),
        ),
        factor.nonce.clone().try_into().unwrap(),
        factor.ciphertext.clone(),
    );
    let opened = state
        .vault
        .open(&sealed, tenant_id, subject_id, factor_id)
        .unwrap();
    Secret::new(opened.expose_secret().clone()).unwrap()
}

#[tokio::test]
async fn concurrent_replay_single_winner() {
    let (state, tenant) = setup().await;
    let (factor_id, subject_id, secret) = enroll_active(&state, &tenant).await;
    let params = TotpParams::default_params();
    let code = totp::generate(&secret, params, now_unix() + 2 * NOW_SKEW).unwrap();

    let mut handles = Vec::new();
    for _ in 0..100 {
        let (task_state, task_tenant, task_subject, task_factor, task_code) = (
            state.clone(),
            tenant.clone(),
            subject_id.clone(),
            factor_id.clone(),
            code.clone(),
        );
        handles.push(tokio::spawn(async move {
            mfa_verify(
                State(task_state),
                Json(MfaVerifyRequest {
                    tenant_id: task_tenant,
                    subject_id: task_subject,
                    factor_id: task_factor,
                    code: task_code,
                }),
            )
            .await
            .is_ok()
        }));
    }
    let mut wins = 0;
    for handle in handles {
        if handle.await.unwrap() {
            wins += 1;
        }
    }
    assert_eq!(wins, 1);
}

#[tokio::test]
async fn s2s_and_recovery() {
    let (state, tenant) = setup().await;
    let (factor_id, subject_id, secret) = enroll_active(&state, &tenant).await;
    let params = TotpParams::default_params();

    // S2S verifies with the service key and rejects without it.
    let code = totp::generate(&secret, params, now_unix() + NOW_SKEW).unwrap();
    let answer = s2s_verify(
        State(state.clone()),
        service_headers(),
        Json(S2sVerifyRequest {
            tenant_id: tenant.clone(),
            subject_id: subject_id.clone(),
            factor_id: factor_id.clone(),
            code,
        }),
    )
    .await
    .unwrap()
    .0;
    assert!(answer.valid);
    let denied = s2s_verify(
        State(state.clone()),
        HeaderMap::new(),
        Json(S2sVerifyRequest {
            tenant_id: tenant.clone(),
            subject_id: subject_id.clone(),
            factor_id: factor_id.clone(),
            code: "123456".to_string(),
        }),
    )
    .await;
    assert!(denied.is_err());

    // Recovery consumes a code and retires the factor.
    let codes = {
        // Fresh enrolment so recovery codes are known to this test.
        let started = start(
            State(state.clone()),
            service_headers(),
            Json(EnrollStartRequest {
                tenant_id: tenant.clone(),
                subject_external_id: "bob".to_string(),
                issuer: "BandAll".to_string(),
                account: "bob@example.com".to_string(),
                algorithm: None,
                digits: None,
                period: None,
            }),
        )
        .await
        .unwrap()
        .0;
        let subject = state
            .store
            .find_subject(&tenant, "bob")
            .await
            .unwrap()
            .unwrap();
        let bob_secret = Secret::from_base32(&uri_secret(&started.otpauth_uri)).unwrap();
        let first = totp::generate(&bob_secret, params, now_unix()).unwrap();
        let confirmed = confirm(
            State(state.clone()),
            Json(EnrollConfirmRequest {
                tenant_id: tenant.clone(),
                subject_id: subject.id.clone(),
                factor_id: started.factor_id.clone(),
                code: first,
            }),
        )
        .await
        .unwrap()
        .0;
        (started.factor_id, subject.id, confirmed.recovery_codes)
    };
    let answer = recover(
        State(state.clone()),
        Json(RecoverRequest {
            tenant_id: tenant.clone(),
            subject_id: codes.1.clone(),
            factor_id: codes.0.clone(),
            recovery_code: codes.2.first().cloned().unwrap_or_default(),
        }),
    )
    .await
    .unwrap()
    .0;
    assert!(answer.valid);
    assert!(answer.must_reenroll);
    // Factor is gone: further verification is denied.
    let gone = mfa_verify(
        State(state.clone()),
        Json(MfaVerifyRequest {
            tenant_id: tenant.clone(),
            subject_id: codes.1,
            factor_id: codes.0,
            code: "123456".to_string(),
        }),
    )
    .await;
    assert!(gone.is_err());
}

#[tokio::test]
async fn token_rotation_and_reuse_detection() {
    let (state, tenant) = setup().await;
    let (factor_id, subject_id, secret) = enroll_active(&state, &tenant).await;
    let params = TotpParams::default_params();

    // Login issues a usable access token plus a refresh token.
    let code = totp::generate(&secret, params, now_unix() + NOW_SKEW).unwrap();
    let pair = mfa_verify(
        State(state.clone()),
        Json(MfaVerifyRequest {
            tenant_id: tenant.clone(),
            subject_id: subject_id.clone(),
            factor_id: factor_id.clone(),
            code,
        }),
    )
    .await
    .unwrap()
    .0;
    assert!(pair.valid);
    let claims = verify_token(
        &state.keys,
        &pair.access_token,
        ISSUER,
        AUDIENCE,
        now_unix(),
    )
    .unwrap();
    assert_eq!(claims.sub, subject_id);
    assert_eq!(claims.tenant, tenant);

    // Rotation yields a fresh pair; the old refresh token is spent.
    let rotated = refresh(
        State(state.clone()),
        Json(RefreshRequest {
            refresh_token: pair.refresh_token.clone(),
        }),
    )
    .await
    .unwrap()
    .0;
    assert_ne!(rotated.refresh_token, pair.refresh_token);

    // Reusing the spent token burns the whole family.
    let reuse = refresh(
        State(state.clone()),
        Json(RefreshRequest {
            refresh_token: pair.refresh_token.clone(),
        }),
    )
    .await;
    assert!(reuse.is_err());
    let dead = refresh(
        State(state.clone()),
        Json(RefreshRequest {
            refresh_token: rotated.refresh_token.clone(),
        }),
    )
    .await;
    assert!(dead.is_err());

    // JWKS exposes the signing key.
    let jwks_doc = jwks(State(state.clone())).await.0;
    assert_eq!(jwks_doc.keys.len(), 1);
    assert_eq!(jwks_doc.keys[0].kid, state.keys.current().kid());
}

#[tokio::test]
async fn token_revoke() {
    let (state, tenant) = setup().await;
    let (factor_id, subject_id, secret) = enroll_active(&state, &tenant).await;
    let params = TotpParams::default_params();
    let code = totp::generate(&secret, params, now_unix() + NOW_SKEW).unwrap();
    let pair = mfa_verify(
        State(state.clone()),
        Json(MfaVerifyRequest {
            tenant_id: tenant.clone(),
            subject_id: subject_id.clone(),
            factor_id: factor_id.clone(),
            code,
        }),
    )
    .await
    .unwrap()
    .0;

    let answer = revoke(
        State(state.clone()),
        Json(RevokeRequest {
            refresh_token: pair.refresh_token.clone(),
        }),
    )
    .await
    .unwrap()
    .0;
    assert!(answer.revoked);
    // Revoked family no longer refreshes; unknown tokens answer identically.
    let gone = refresh(
        State(state.clone()),
        Json(RefreshRequest {
            refresh_token: pair.refresh_token,
        }),
    )
    .await;
    assert!(gone.is_err());
    let unknown = revoke(
        State(state.clone()),
        Json(RevokeRequest {
            refresh_token: "unknown-token".to_string(),
        }),
    )
    .await
    .unwrap()
    .0;
    assert!(unknown.revoked);
}
