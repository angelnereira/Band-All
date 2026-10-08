//! WebSocket connection tickets (ADR-0017).
//!
//! `POST /v1/ws/ticket` turns a valid access token into a short-lived,
//! single-use ticket. The browser cannot put a header on a WebSocket
//! `Upgrade`, and the obvious fallback — the token in the query string — puts
//! it in proxy logs, `Referer` and history; the ticket is what goes on the
//! wire instead.
//!
//! `POST /v1/ws/ticket/redeem` (S2S) validates the ticket when the connection
//! opens, returning the identity and the *hard ceiling* for the connection
//! (the access token's expiry). `POST /v1/ws/ticket/recheck` (S2S) answers
//! "is this session still live?" for services that want revocation to cut
//! established connections faster than the ceiling; the re-check budget is the
//! caller's, and the uniform 401 keeps this endpoint from becoming an oracle.

use axum::{Json, extract::State, http::HeaderMap};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::enroll::now_unix;
use crate::error::Error;
use crate::gates;
use crate::state::AppState;

/// Access-token ceiling for a connection: the ticket may outlive the token by
/// seconds, but the connection must not. This is the "TTL de conexión atado a
/// `exp`" from ADR-0017.
const WS_CONNECT_EXPIRY_GRACE_SECS: u64 = 5;

/// `POST /v1/ws/ticket` (Bearer-authenticated client, no body).
#[derive(Debug, Deserialize, ToSchema)]
pub struct TicketRequest {}

/// `POST /v1/ws/ticket` response.
#[derive(Debug, Serialize, ToSchema)]
pub struct TicketResponse {
    /// Single-use ticket for the WebSocket handshake.
    pub ticket: String,
    /// Ticket lifetime in seconds (30).
    pub expires_in: u64,
}

/// `POST /v1/ws/ticket/redeem` body (S2S).
#[derive(Debug, Deserialize, ToSchema)]
pub struct RedeemRequest {
    /// The ticket from `POST /v1/ws/ticket`.
    pub ticket: String,
}

/// `POST /v1/ws/ticket/redeem` response.
#[derive(Debug, Serialize, ToSchema)]
pub struct RedeemResponse {
    /// Always `true` on success (uniform 401 otherwise).
    pub valid: bool,
    /// Subject id (same as the access token's `sub`).
    pub subject_id: String,
    /// Tenant id.
    pub tenant_id: String,
    /// Session id (for re-checks and revocation).
    pub session_id: String,
    /// Hard ceiling: the connection must be torn down by this Unix second,
    /// unless a re-check grants a fresh ticket.
    pub expires_at: u64,
}

/// `POST /v1/ws/ticket/recheck` body (S2S).
#[derive(Debug, Deserialize, ToSchema)]
pub struct RecheckRequest {
    /// Session id from `redeem`.
    pub session_id: String,
}

/// `POST /v1/ws/ticket/recheck` response.
#[derive(Debug, Serialize, ToSchema)]
pub struct RecheckResponse {
    /// Whether the session is still live (uniform 401 otherwise).
    pub live: bool,
}

/// Issues a ticket for a WebSocket connection (ADR-0017).
#[utoipa::path(
    post,
    path = "/v1/ws/ticket",
    responses(
        (status = 200, description = "Ticket issued", body = TicketResponse),
        (status = 401, description = "Uniform denial")
    )
)]
pub async fn ticket(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TicketResponse>, Error> {
    let now = now_unix().map_err(|_| Error::denied())?;
    let token = bearer(&headers).ok_or_else(Error::denied)?;
    let claims = bandall_tokens::verify(&state.keys, token, &state.issuer, &state.audience, now)
        .map_err(|_| Error::denied())?;

    // The session must be live *now*; the ticket must not outlive the token by
    // more than the grace period.
    let session = state
        .store
        .get_session(&claims.sid)
        .await?
        .filter(|s| s.revoked_at.is_none())
        .ok_or_else(Error::denied)?;
    let now_i64 = i64::try_from(now).map_err(|_| Error::internal("clock range"))?;
    let grace = i64::try_from(WS_CONNECT_EXPIRY_GRACE_SECS).unwrap_or(0);
    let expiry = session
        .created_at
        .saturating_add(grace)
        .min(i64::try_from(claims.exp).map_err(|_| Error::denied())?);

    let ticket =
        bandall_tokens::WsTicket::generate().map_err(|_| Error::internal("ticket failure"))?;
    state
        .store
        .store_ws_ticket(bandall_store::NewWsTicket {
            code_hash: ticket.hash.clone(),
            session_id: session.id.clone(),
            tenant_id: claims.tenant.clone(),
            subject_id: claims.sub.clone(),
            access_expires_at: expiry,
            created_at: now_i64,
            expires_at: now_i64.saturating_add(
                i64::try_from(bandall_tokens::WS_TICKET_TTL_SECS).map_err(|_| Error::denied())?,
            ),
        })
        .await?;
    crate::audit::record(
        &state,
        &claims.tenant,
        &claims.sub,
        crate::audit::event::WS_TICKET_ISSUED,
    )
    .await?;
    Ok(Json(TicketResponse {
        ticket: ticket.plaintext,
        expires_in: bandall_tokens::WS_TICKET_TTL_SECS,
    }))
}

/// Redeems a ticket when the WebSocket handshake arrives (S2S, ADR-0017).
#[utoipa::path(
    post,
    path = "/v1/ws/ticket/redeem",
    responses(
        (status = 200, description = "Ticket accepted", body = RedeemResponse),
        (status = 401, description = "Uniform denial")
    )
)]
pub async fn redeem(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RedeemRequest>,
) -> Result<Json<RedeemResponse>, Error> {
    require_service_key(&state, &headers)?;
    let now = now_unix().map_err(|_| Error::denied())?;
    let now_i64 = i64::try_from(now).map_err(|_| Error::denied())?;
    let hash = bandall_tokens::hash_plaintext(&body.ticket);
    let entry = state
        .store
        .claim_ws_ticket(&hash, now_i64)
        .await?
        .ok_or_else(Error::denied)?;
    if entry.expires_at < now_i64 {
        return Err(Error::denied());
    }
    crate::audit::record(
        &state,
        &entry.tenant_id,
        &entry.subject_id,
        crate::audit::event::WS_TICKET_REDEEMED,
    )
    .await?;
    Ok(Json(RedeemResponse {
        valid: true,
        subject_id: entry.subject_id.clone(),
        tenant_id: entry.tenant_id.clone(),
        session_id: entry.session_id.clone(),
        expires_at: u64::try_from(entry.access_expires_at).map_err(|_| Error::denied())?,
    }))
}

/// Re-checks a session that an established connection is bound to (S2S,
/// ADR-0017). Uniform 401 on unknown or revoked sessions.
#[utoipa::path(
    post,
    path = "/v1/ws/ticket/recheck",
    responses(
        (status = 200, description = "Session state", body = RecheckResponse),
        (status = 401, description = "Uniform denial")
    )
)]
pub async fn recheck(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RecheckRequest>,
) -> Result<Json<RecheckResponse>, Error> {
    require_service_key(&state, &headers)?;
    let now = now_unix().map_err(|_| Error::denied())?;
    gates::acquire(&state, &[gates::tenant_key("ws-recheck")], now).await?;
    let live = state
        .store
        .get_session(&body.session_id)
        .await?
        .is_some_and(|s| s.revoked_at.is_none());
    if !live {
        return Err(Error::denied());
    }
    Ok(Json(RecheckResponse { live: true }))
}

/// Bearer token from the `Authorization` header.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

/// Constant-time service-key gate (imported from the S2S paths).
fn require_service_key(state: &AppState, headers: &HeaderMap) -> Result<(), Error> {
    let candidate = headers
        .get("x-service-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if state.check_service_key(candidate) {
        Ok(())
    } else {
        Err(Error::denied())
    }
}
