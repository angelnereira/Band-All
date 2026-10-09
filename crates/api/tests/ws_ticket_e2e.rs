//! WebSocket connection tickets (ADR-0017), end to end through real store and
//! vault: a client exchanges its access token for a ticket, the service
//! redeems it once, the session bound to it is re-checked, and a revoked
//! session fails the re-check.
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
    AppState, AuditChain,
    config::TrustedProxies,
    enroll::{EnrollConfirmRequest, EnrollStartRequest, confirm, start},
    gates::PeerAddr,
    state::PolicyHandle,
    token::revoke,
    verify::{MfaVerifyRequest, mfa_verify},
    wsticket::{RecheckRequest, RedeemRequest, recheck, redeem, ticket as ws_ticket},
};
use bandall_policy::Policy;
use bandall_store::{SqliteStore, Store};
use bandall_tokens::KeyManager;
use bandall_totp_core::{Secret, TotpParams, totp};
use bandall_vault::{LocalKms, Vault};

const SERVICE_KEY: &str = "ws-e2e-service-key-0123456789ab";
const ISSUER: &str = "https://bandall.example";
const AUDIENCE: &str = "my-app";

async fn setup() -> AppState {
    let sqlite = SqliteStore::in_memory().await.unwrap();
    sqlite.migrate().await.unwrap();
    let store: Arc<dyn Store> = Arc::new(sqlite);
    let kms = LocalKms::from_bytes("kek-ws".to_string(), vec![3u8; 32]).unwrap();
    let vault = Arc::new(Vault::new(Arc::new(kms)));
    let keys = Arc::new(KeyManager::generate().unwrap());
    let policy = PolicyHandle::Memory(Arc::new(Policy::default()));
    let audit = Arc::new(AuditChain::from_bytes([7u8; 32]));
    let trusted_proxies = Arc::new(TrustedProxies::default());
    // `store.create_tenant` returns the fresh id; the state needs it stored in
    // the same store, which `create_tenant` did.
    AppState::new(
        store.clone(),
        vault,
        keys,
        policy,
        audit,
        trusted_proxies,
        ISSUER.to_string(),
        AUDIENCE.to_string(),
        SERVICE_KEY.to_string(),
    )
}

fn service_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-service-key", SERVICE_KEY.parse().unwrap());
    headers
}

fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
    headers
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Enrols and logs in one user under a fresh tenant, returning
/// `(tenant_id, subject_id, access_token, sid)`.
async fn enrolled_session(state: &AppState) -> (String, String, String, String) {
    let tenant = state
        .store
        .create_tenant("ws-e2e", i64::try_from(now_unix()).unwrap())
        .await
        .unwrap();
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
    let subject = state
        .store
        .find_subject(&tenant.id, "alice")
        .await
        .unwrap()
        .unwrap();
    let secret = Secret::from_base32(
        started
            .otpauth_uri
            .split("secret=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap(),
    )
    .unwrap();
    let code = totp::generate(&secret, TotpParams::default_params(), now_unix()).unwrap();
    let _confirmed = confirm(
        State(state.clone()),
        HeaderMap::new(),
        PeerAddr(None),
        Json(EnrollConfirmRequest {
            tenant_id: tenant.id.clone(),
            subject_id: subject.id.clone(),
            factor_id: started.factor_id.clone(),
            code,
        }),
    )
    .await
    .unwrap();
    let _ = _confirmed;

    // One step later, so the confirm step is not replayed as the login step.
    let later = now_unix() + 30;
    let code = totp::generate(&secret, TotpParams::default_params(), later).unwrap();
    let pair = mfa_verify(
        State(state.clone()),
        HeaderMap::new(),
        PeerAddr(None),
        Json(MfaVerifyRequest {
            tenant_id: tenant.id.clone(),
            subject_id: subject.id.clone(),
            factor_id: started.factor_id.clone(),
            code,
        }),
    )
    .await
    .unwrap()
    .0;
    let claims = bandall_tokens::verify(
        &state.keys,
        &pair.access_token,
        ISSUER,
        AUDIENCE,
        now_unix(),
    )
    .unwrap();
    (tenant.id, subject.id, pair.access_token, claims.sid)
}

#[tokio::test]
async fn ticket_lifecycle_issue_redeem_recheck() {
    let state = setup().await;
    let (_tenant, _subject, token, sid) = enrolled_session(&state).await;

    // 1. The client exchanges its access token for a ticket.
    let issued = ws_ticket(State(state.clone()), bearer(&token))
        .await
        .unwrap()
        .0;
    assert_eq!(issued.expires_in, bandall_tokens::WS_TICKET_TTL_SECS);
    assert_eq!(issued.ticket.len(), 43, "32 bytes, base64url unpadded");

    // 2. The service redeems the ticket exactly once.
    let redeemed = redeem(
        State(state.clone()),
        service_headers(),
        Json(RedeemRequest {
            ticket: issued.ticket.clone(),
        }),
    )
    .await
    .unwrap()
    .0;
    assert!(redeemed.valid);
    assert_eq!(redeemed.session_id, sid);
    assert!(redeemed.expires_at > now_unix());

    // 3. A second redeem is denied: single-use.
    let replay = redeem(
        State(state.clone()),
        service_headers(),
        Json(RedeemRequest {
            ticket: issued.ticket,
        }),
    )
    .await;
    assert!(replay.is_err(), "a spent ticket must not redeem twice");

    // 4. An unknown ticket is denied.
    let unknown = redeem(
        State(state.clone()),
        service_headers(),
        Json(RedeemRequest {
            ticket: "no-such-ticket".to_string(),
        }),
    )
    .await;
    assert!(unknown.is_err(), "an unknown ticket must be denied");

    // 5. The session bound to the ticket is still live.
    let rechecked = recheck(
        State(state.clone()),
        service_headers(),
        Json(RecheckRequest {
            session_id: sid.clone(),
        }),
    )
    .await
    .unwrap()
    .0;
    assert!(rechecked.live);

    // 6. After revoking the session, the re-check must deny it: this is what
    //    lets an established WebSocket be cut without waiting for the token.
    state
        .store
        .revoke_session(&sid, i64::try_from(now_unix()).unwrap())
        .await
        .unwrap();

    let dead = recheck(
        State(state.clone()),
        service_headers(),
        Json(RecheckRequest { session_id: sid }),
    )
    .await;
    assert!(dead.is_err(), "a revoked session must fail the re-check");
}

#[tokio::test]
async fn ticket_requires_a_verifiable_token() {
    let state = setup().await;
    // No Bearer header, or a nonsense token: uniform denial.
    let missing = ws_ticket(State(state.clone()), HeaderMap::new()).await;
    assert!(missing.is_err(), "a ticket requires a Bearer token");
    let forged = ws_ticket(State(state.clone()), bearer("not-a-real-token")).await;
    assert!(forged.is_err(), "a forged token must not mint a ticket");
}

#[tokio::test]
async fn redeem_and_recheck_require_the_service_key() {
    let state = setup().await;
    let anonymous = redeem(
        State(state.clone()),
        HeaderMap::new(),
        Json(RedeemRequest {
            ticket: "anything".to_string(),
        }),
    )
    .await;
    assert!(
        anonymous.is_err(),
        "redeem is S2S: it needs the service key"
    );

    let anon_recheck = recheck(
        State(state.clone()),
        HeaderMap::new(),
        Json(RecheckRequest {
            session_id: "anything".to_string(),
        }),
    )
    .await;
    assert!(
        anon_recheck.is_err(),
        "recheck is S2S: it needs the service key"
    );

    let _ = revoke; // lint guard: token::revoke exercises the same session store
}
