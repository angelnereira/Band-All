//! Token endpoints: refresh rotation, revocation and JWKS.
//!
//! Refresh reuse revokes the whole family and its session (theft
//! detection). All failures are uniform.

use axum::{Json, extract::State};
use bandall_store::NewRefresh;
use bandall_tokens::{Claims, KeyManager, RefreshToken, hash_plaintext};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::Error;
use crate::state::AppState;

/// Issued pair returned after verification or refresh.
#[derive(Debug, Serialize, ToSchema)]
pub struct TokenPair {
    /// JWT access token (10-minute life).
    pub access_token: String,
    /// Opaque refresh token (shown once per rotation).
    pub refresh_token: String,
    /// Access token lifetime in seconds.
    pub expires_in: u64,
    /// Always `Bearer`.
    pub token_type: String,
}

/// Issues a session: creates the session row, stores the refresh hash and
/// signs the access token.
pub async fn issue_session(
    state: &AppState,
    keys: &KeyManager,
    tenant_id: &str,
    subject_id: &str,
    now_secs: u64,
) -> Result<TokenPair, Error> {
    let now_i64 = i64::try_from(now_secs).map_err(|_| Error::internal("clock range"))?;
    let session = state
        .store
        .create_session(tenant_id, subject_id, now_i64)
        .await?;
    let refresh = RefreshToken::generate().map_err(|_| Error::internal("token failure"))?;
    let family = bandall_store::new_session_id();
    let expires_at = now_i64.saturating_add(refresh_ttl_secs());
    state
        .store
        .store_refresh(NewRefresh {
            code_hash: refresh.hash.clone(),
            family_id: family,
            session_id: session.id.clone(),
            created_at: now_i64,
            expires_at,
        })
        .await?;
    let claims = Claims::new(
        state.issuer.clone(),
        state.audience.clone(),
        subject_id.to_string(),
        tenant_id.to_string(),
        session.id,
        now_secs,
    )
    .map_err(|_| Error::internal("token failure"))?;
    let access_token =
        bandall_tokens::issue(keys, &claims).map_err(|_| Error::internal("token failure"))?;
    Ok(TokenPair {
        access_token,
        refresh_token: refresh.plaintext,
        expires_in: bandall_tokens::ACCESS_TTL_SECS,
        token_type: "Bearer".to_string(),
    })
}

fn refresh_ttl_secs() -> i64 {
    i64::try_from(bandall_tokens::REFRESH_TTL_SECS).unwrap_or(7 * 24 * 3600)
}

/// `POST /v1/token/refresh` body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RefreshRequest {
    /// Current refresh token.
    pub refresh_token: String,
}

/// Rotates a refresh token, detecting reuse.
#[utoipa::path(
    post,
    path = "/v1/token/refresh",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "Rotated pair", body = TokenPair),
        (status = 401, description = "Uniform denial")
    )
)]
pub async fn refresh(
    State(state): State<AppState>,
    Json(body): Json<RefreshRequest>,
) -> Result<Json<TokenPair>, Error> {
    let now = crate::enroll::now_unix().map_err(|_| Error::denied())?;
    // Refresh tokens carry 256 bits of entropy: abuse accounting stays light
    // (tenant key only) since guessing is infeasible.
    let keys = [crate::gates::tenant_key("refresh")];
    crate::gates::check(&state, &keys, now)?;
    let outcome = refresh_inner(&state, &body).await;
    crate::gates::record(&state, &keys, now, outcome.is_ok());
    outcome
}

async fn refresh_inner(state: &AppState, body: &RefreshRequest) -> Result<Json<TokenPair>, Error> {
    let now = crate::enroll::now_unix().map_err(|_| Error::denied())?;
    let now_i64 = i64::try_from(now).map_err(|_| Error::denied())?;
    let hash = hash_plaintext(&body.refresh_token);
    let entry = state
        .store
        .find_refresh(&hash)
        .await?
        .ok_or_else(Error::denied)?;
    if entry.revoked_at.is_some() || entry.expires_at < now_i64 {
        return Err(Error::denied());
    }
    let session = state
        .store
        .get_session(&entry.session_id)
        .await?
        .ok_or_else(Error::denied)?;
    if session.revoked_at.is_some() {
        crate::audit::record(
            state,
            &session.tenant_id,
            &session.subject_id,
            crate::audit::event::TOKEN_REFRESH_DENIED,
        )
        .await?;
        return Err(Error::denied());
    }
    if !state
        .store
        .use_refresh(&hash, now_i64)
        .await
        .map_err(|_| Error::denied())?
    {
        // Spent token presented again: theft signal, burn the family.
        state.store.revoke_family(&entry.family_id, now_i64).await?;
        state
            .store
            .revoke_session(&entry.session_id, now_i64)
            .await?;
        crate::audit::record(
            state,
            &session.tenant_id,
            &session.subject_id,
            crate::audit::event::TOKEN_REFRESH_DENIED,
        )
        .await?;
        return Err(Error::denied());
    }
    let next = RefreshToken::generate().map_err(|_| Error::denied())?;
    state
        .store
        .store_refresh(NewRefresh {
            code_hash: next.hash.clone(),
            family_id: entry.family_id.clone(),
            session_id: entry.session_id.clone(),
            created_at: now_i64,
            expires_at: now_i64.saturating_add(refresh_ttl_secs()),
        })
        .await?;
    let claims = Claims::new(
        state.issuer.clone(),
        state.audience.clone(),
        session.subject_id.clone(),
        session.tenant_id.clone(),
        session.id.clone(),
        now,
    )
    .map_err(|_| Error::denied())?;
    let access_token = bandall_tokens::issue(&state.keys, &claims).map_err(|_| Error::denied())?;
    state.metrics.refreshed();
    crate::audit::record(
        state,
        &session.tenant_id,
        &session.subject_id,
        crate::audit::event::TOKEN_REFRESHED,
    )
    .await?;
    Ok(Json(TokenPair {
        access_token,
        refresh_token: next.plaintext,
        expires_in: bandall_tokens::ACCESS_TTL_SECS,
        token_type: "Bearer".to_string(),
    }))
}

/// `POST /v1/token/revoke` body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RevokeRequest {
    /// Refresh token to revoke (proof of possession).
    pub refresh_token: String,
}

/// `POST /v1/token/revoke` response. Always `true`: unknown tokens answer
/// identically (no oracle).
#[derive(Debug, Serialize, ToSchema)]
pub struct RevokeResponse {
    /// Always `true`.
    pub revoked: bool,
}

/// Revokes a refresh family and its session. Unknown tokens still answer
/// `true`.
#[utoipa::path(
    post,
    path = "/v1/token/revoke",
    request_body = RevokeRequest,
    responses((status = 200, description = "Revoked", body = RevokeResponse))
)]
pub async fn revoke(
    State(state): State<AppState>,
    Json(body): Json<RevokeRequest>,
) -> Result<Json<RevokeResponse>, Error> {
    let now = crate::enroll::now_unix()?;
    let now_i64 = i64::try_from(now).map_err(|_| Error::internal("clock range"))?;
    let hash = hash_plaintext(&body.refresh_token);
    if let Some(entry) = state.store.find_refresh(&hash).await? {
        state.store.revoke_family(&entry.family_id, now_i64).await?;
        state
            .store
            .revoke_session(&entry.session_id, now_i64)
            .await?;
        if let Some(session) = state.store.get_session(&entry.session_id).await? {
            crate::audit::record(
                &state,
                &session.tenant_id,
                &session.subject_id,
                crate::audit::event::TOKEN_REVOKED,
            )
            .await?;
        }
    }
    Ok(Json(RevokeResponse { revoked: true }))
}

/// `GET /.well-known/jwks.json`: public keys for offline verification.
#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    responses((status = 200, description = "JWKS document with Ed25519 public keys"))
)]
pub async fn jwks(State(state): State<AppState>) -> Json<bandall_tokens::Jwks> {
    Json(bandall_tokens::document(&state.keys))
}
