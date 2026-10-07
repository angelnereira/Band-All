//! H5 item 4: "prueba automática que busca patrones [de secretos] en logs".
//!
//! The rule in `AGENTS.md` is that secrets never reach logs, errors or
//! metrics. Until now that rested on review. This test makes it mechanical: it
//! installs a tracing subscriber that captures everything the service emits,
//! drives every handler through both success and failure paths, then scans the
//! captured output for material that must never be there.
//!
//! Scanning the rendered text (not the event fields) is deliberate: a
//! `tracing::info!(?state)` with a leaked `Debug` impl would show up here, and
//! that is exactly the accident worth catching.
//!
//! Test-only unwraps are allowed here by policy (see crate `AGENTS.md`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Write as _;
use std::sync::{Arc, Mutex, OnceLock};

use axum::{Json, extract::State, http::HeaderMap};
use bandall_api::{
    AppState, AuditChain,
    config::TrustedProxies,
    enroll::{EnrollConfirmRequest, EnrollStartRequest, confirm, start},
    gates::PeerAddr,
    sigs::{SigsVerifyRequest, verify_signature},
    state::PolicyHandle,
    token::{RefreshRequest, RevokeRequest, refresh, revoke},
    verify::{MfaVerifyRequest, RecoverRequest, S2sVerifyRequest, mfa_verify, recover, s2s_verify},
};
use bandall_policy::Policy;
use bandall_store::{SqliteStore, Store};
use bandall_tokens::KeyManager;
use bandall_totp_core::{Secret, TotpParams, totp};
use bandall_vault::{LocalKms, Vault};

const SERVICE_KEY: &str = "logs-service-key-0123456789abcdef";
const KEK: [u8; 32] = [0x11; 32];
const AUDIT_KEY: [u8; 32] = [0x22; 32];

/// Everything written to the subscriber, as raw bytes.
type LogBuffer = Arc<Mutex<Vec<u8>>>;

static BUFFER: OnceLock<LogBuffer> = OnceLock::new();

/// `MakeWriter` that appends into a shared buffer instead of stderr.
#[derive(Clone)]
struct CaptureWriter(LogBuffer);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
    type Writer = CaptureGuard;
    fn make_writer(&'a self) -> Self::Writer {
        CaptureGuard(self.0.clone())
    }
}

struct CaptureGuard(LogBuffer);

impl std::io::Write for CaptureGuard {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Installs the capture subscriber exactly once per test binary, at the
/// most verbose level so nothing is filtered out before the scan.
fn install_capture() -> LogBuffer {
    BUFFER
        .get_or_init(|| {
            let buffer: LogBuffer = Arc::new(Mutex::new(Vec::new()));
            let subscriber = tracing_subscriber::fmt()
                .with_writer(CaptureWriter(buffer.clone()))
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .finish();
            // `try_init` rather than `init`: a second call is a no-op instead
            // of a panic, so the test stays robust if run in the same process
            // as something else.
            let _ = tracing::subscriber::set_global_default(subscriber);
            buffer
        })
        .clone()
}

fn captured_text(buffer: &LogBuffer) -> String {
    String::from_utf8_lossy(&buffer.lock().unwrap().clone()).into_owned()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn uri_secret(uri: &str) -> String {
    uri.split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string()
}

fn service_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-service-key", SERVICE_KEY.parse().unwrap());
    headers
}

async fn state() -> AppState {
    let sqlite = SqliteStore::in_memory().await.unwrap();
    sqlite.migrate().await.unwrap();
    let store: Arc<dyn Store> = Arc::new(sqlite);
    let kms = LocalKms::from_bytes("kek-logs".to_string(), KEK.to_vec()).unwrap();
    let vault = Arc::new(Vault::new(Arc::new(kms)));
    AppState::new(
        store,
        vault,
        Arc::new(KeyManager::generate().unwrap()),
        PolicyHandle::Memory(Arc::new(Policy::default())),
        Arc::new(AuditChain::from_bytes(AUDIT_KEY)),
        Arc::new(TrustedProxies::default()),
        "https://bandall.example".to_string(),
        "logs-app".to_string(),
        SERVICE_KEY.to_string(),
    )
}

/// Every handler, on the paths that emit logs, with the values that must not
/// leak recorded first.
#[tokio::test]
async fn no_secret_material_reaches_the_logs() {
    let buffer = install_capture();
    let state = state().await;
    let tenant = state
        .store
        .create_tenant("logs", 1_700_000_000)
        .await
        .unwrap();

    // --- Enrolment (success) ---
    let started = start(
        State(state.clone()),
        service_headers(),
        Json(EnrollStartRequest {
            tenant_id: tenant.id.clone(),
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
    let secret_base32 = uri_secret(&started.otpauth_uri);
    let secret = Secret::from_base32(&secret_base32).unwrap();
    let subject = state
        .store
        .find_subject(&tenant.id, "alice")
        .await
        .unwrap()
        .unwrap();
    let params = TotpParams::default_params();
    let code = totp::generate(&secret, params, now_unix()).unwrap();
    let _: bandall_api::enroll::EnrollConfirmResponse = confirm(
        State(state.clone()),
        HeaderMap::new(),
        PeerAddr(None),
        Json(EnrollConfirmRequest {
            tenant_id: tenant.id.clone(),
            subject_id: subject.id.clone(),
            factor_id: started.factor_id.clone(),
            code: code.clone(),
        }),
    )
    .await
    .unwrap()
    .0;

    // --- Verification (success, then a wrong code to hit the denial path) ---
    let verify_code = totp::generate(&secret, params, now_unix() + 30).unwrap();
    let verified = mfa_verify(
        State(state.clone()),
        HeaderMap::new(),
        PeerAddr(None),
        Json(MfaVerifyRequest {
            tenant_id: tenant.id.clone(),
            subject_id: subject.id.clone(),
            factor_id: started.factor_id.clone(),
            code: verify_code.clone(),
        }),
    )
    .await
    .unwrap()
    .0;
    let wrong_code = "000000".to_string();
    let _ = mfa_verify(
        State(state.clone()),
        HeaderMap::new(),
        PeerAddr(None),
        Json(MfaVerifyRequest {
            tenant_id: tenant.id.clone(),
            subject_id: subject.id.clone(),
            factor_id: started.factor_id.clone(),
            code: wrong_code.clone(),
        }),
    )
    .await;

    // --- Refresh and revoke ---
    let rotated = refresh(
        State(state.clone()),
        Json(RefreshRequest {
            refresh_token: verified.refresh_token.clone(),
        }),
    )
    .await
    .unwrap()
    .0;
    let _ = refresh(
        State(state.clone()),
        Json(RefreshRequest {
            // Reused token: theft path, which audits and revokes a family.
            refresh_token: verified.refresh_token.clone(),
        }),
    )
    .await;
    let _ = revoke(
        State(state.clone()),
        Json(RevokeRequest {
            refresh_token: rotated.refresh_token.clone(),
        }),
    )
    .await;

    // --- S2S and signature verification failure paths ---
    let s2s_code = "123456".to_string();
    let _ = s2s_verify(
        State(state.clone()),
        service_headers(),
        PeerAddr(None),
        Json(S2sVerifyRequest {
            tenant_id: tenant.id.clone(),
            subject_id: subject.id.clone(),
            factor_id: started.factor_id.clone(),
            code: s2s_code.clone(),
        }),
    )
    .await;
    let _ = verify_signature(
        State(state.clone()),
        Json(SigsVerifyRequest {
            key_id: "missing".to_string(),
            method: "POST".to_string(),
            path: "/x".to_string(),
            query: String::new(),
            body: String::new(),
            timestamp: 1_700_000_000,
            nonce: "n".to_string(),
            signature: "00".repeat(32),
            scope: String::new(),
        }),
    )
    .await;

    // --- Recovery: wrong code, then a real one so the success path logs too ---
    let _ = recover(
        State(state.clone()),
        HeaderMap::new(),
        PeerAddr(None),
        Json(RecoverRequest {
            tenant_id: tenant.id.clone(),
            subject_id: subject.id.clone(),
            factor_id: started.factor_id.clone(),
            recovery_code: "AAAA-BBBB-CCCC".to_string(),
        }),
    )
    .await;
    let (factor_id, subject_id, secret2) = enroll_again(&state, &tenant.id).await;
    let second_enrol_code = totp::generate(&secret2, params, now_unix()).unwrap();
    let recovery_codes = confirm_factor(
        &state,
        &tenant.id,
        &subject_id,
        &factor_id,
        &secret2,
        &second_enrol_code,
    )
    .await;
    let _ = recover(
        State(state.clone()),
        HeaderMap::new(),
        PeerAddr(None),
        Json(RecoverRequest {
            tenant_id: tenant.id.clone(),
            subject_id: subject_id.clone(),
            factor_id: factor_id.clone(),
            recovery_code: recovery_codes.first().cloned().unwrap(),
        }),
    )
    .await;

    // --- HTTP layer: the path that actually logs denials (RFC 7807 response).
    // Handlers called directly never build a response, so `Error::into_response`
    // and its `request failed` log only run through the router.
    {
        use axum::body::Body;
        use tower::ServiceExt as _;

        let router = bandall_api::server::router(state.clone(), 64 * 1024);
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/mfa/verify")
                    .header("content-type", "application/json")
                    // Missing fields: a 400 through the real error path.
                    .body(Body::from(r#"{"tenant_id":"x"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            response.status().is_client_error(),
            "malformed request must be a client error, got {}",
            response.status()
        );

        // And an authenticated-looking but invalid token on the protected
        // route, so the authorization denial path logs too.
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/v1/authz/check")
                    .header("authorization", format!("Bearer {}", verified.access_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            response.status().is_client_error(),
            "a revoked session must be denied, got {}",
            response.status()
        );
    }

    // Make sure something was actually captured, or the scan is vacuous.
    let logs = captured_text(&buffer);
    assert!(
        logs.len() > 200,
        "the capture looks empty ({} bytes); the subscriber is not wired",
        logs.len()
    );

    // Everything a leak would expose, in the forms it would take.
    let forbidden: Vec<(&str, String)> = vec![
        ("TOTP secret (Base32)", secret_base32.clone()),
        ("second TOTP secret (Base32)", secret2.to_base32()),
        // Codes are one-shot credentials: the user typed them, and a log that
        // carries one lets whoever reads the log replay it inside its window.
        ("enrolment code", code.clone()),
        ("verification code", verify_code.clone()),
        ("wrong verification code", wrong_code.clone()),
        ("S2S code", s2s_code.clone()),
        ("second factor enrolment code", second_enrol_code.clone()),
        ("service key", SERVICE_KEY.to_string()),
        ("KEK", format!("{KEK:02x?}")),
        ("audit key", format!("{AUDIT_KEY:02x?}")),
        ("access token", verified.access_token.clone()),
        ("refresh token", verified.refresh_token.clone()),
        ("rotated refresh token", rotated.refresh_token.clone()),
    ];
    for (label, needle) in &forbidden {
        assert!(
            !logs.contains(needle.as_str()),
            "{label} appeared in the logs: {needle}"
        );
    }
    for recovery in &recovery_codes {
        assert!(
            !logs.contains(recovery.as_str()),
            "recovery code appeared in the logs: {recovery}"
        );
    }

    // The scan must be able to find things that ARE logged, or the assertions
    // above would pass on a broken capture. The error path logs the outcome.
    assert!(
        logs.contains("request failed"),
        "the capture cannot find the request-failure log line: not capturing"
    );
}

/// Enrols a second factor and returns it active, for the recovery-code path.
async fn enroll_again(state: &AppState, tenant_id: &str) -> (String, String, Secret) {
    let started = start(
        State(state.clone()),
        service_headers(),
        Json(EnrollStartRequest {
            tenant_id: tenant_id.to_string(),
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
        .find_subject(tenant_id, "bob")
        .await
        .unwrap()
        .unwrap();
    let secret = Secret::from_base32(&uri_secret(&started.otpauth_uri)).unwrap();
    (started.factor_id, subject.id, secret)
}

async fn confirm_factor(
    state: &AppState,
    tenant_id: &str,
    subject_id: &str,
    factor_id: &str,
    secret: &Secret,
    code: &str,
) -> Vec<String> {
    let _ = secret;
    confirm(
        State(state.clone()),
        HeaderMap::new(),
        PeerAddr(None),
        Json(EnrollConfirmRequest {
            tenant_id: tenant_id.to_string(),
            subject_id: subject_id.to_string(),
            factor_id: factor_id.to_string(),
            code: code.to_string(),
        }),
    )
    .await
    .unwrap()
    .0
    .recovery_codes
}

/// The scan helper itself must be able to fail: a canary test so a broken
/// `contains` cannot make the assertions above meaningless.
#[test]
fn the_scan_would_notice_a_leak() {
    let buffer = install_capture();
    {
        let mut guard = buffer.lock().unwrap();
        let before = guard.len();
        // Write a fake leak straight to the buffer, then check detection.
        let _ = guard.write_all(b"canary-secret-value-12345");
        let _ = before;
    }
    let logs = captured_text(&buffer);
    assert!(
        logs.contains("canary-secret-value-12345"),
        "the capture dropped a direct write: the scan is not reading the buffer"
    );
    {
        let mut guard = buffer.lock().unwrap();
        guard.clear();
    }
}
