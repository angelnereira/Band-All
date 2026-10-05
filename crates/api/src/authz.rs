//! Forward-auth endpoint for nginx `auth_request`, Envoy `ext_authz` and
//! Traefik: validates the caller's Bearer access token offline (plus session
//! liveness and a minimum AAL) and answers 200 with identity headers or 401.

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::error::Error;
use crate::state::AppState;

/// `GET /v1/authz/check` query.
#[derive(Debug, Deserialize, IntoParams)]
pub struct AuthzParams {
    /// Minimum assurance level (default 1).
    #[serde(default = "default_min_aal")]
    pub min_aal: u8,
}

fn default_min_aal() -> u8 {
    1
}

/// `GET /v1/authz/check` response body (proxies mostly care about the 200).
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthzResponse {
    /// Subject id.
    pub subject: String,
    /// Tenant id.
    pub tenant: String,
}

/// Checks a Bearer access token: signature, issuer, audience, expiry,
/// session liveness and minimum AAL. Uniform 401 on anything else.
#[utoipa::path(
    get,
    path = "/v1/authz/check",
    params(AuthzParams),
    responses(
        (status = 200, description = "Allowed", body = AuthzResponse),
        (status = 401, description = "Uniform denial")
    )
)]
pub async fn check(
    State(state): State<AppState>,
    Query(params): Query<AuthzParams>,
    headers: HeaderMap,
) -> Result<(StatusCode, HeaderMap, Json<AuthzResponse>), Error> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(Error::denied)?;
    let now = crate::enroll::now_unix().map_err(|_| Error::denied())?;
    let claims = bandall_tokens::verify(&state.keys, token, &state.issuer, &state.audience, now)
        .map_err(|_| Error::denied())?;
    if claims.aal < params.min_aal {
        return Err(Error::denied());
    }
    let live = state
        .store
        .get_session(&claims.sid)
        .await?
        .is_some_and(|session| session.revoked_at.is_none());
    if !live {
        return Err(Error::denied());
    }
    let mut out = HeaderMap::new();
    out.insert(
        "x-bandall-subject",
        HeaderValue::from_str(&claims.sub).map_err(|_| Error::denied())?,
    );
    out.insert(
        "x-bandall-tenant",
        HeaderValue::from_str(&claims.tenant).map_err(|_| Error::denied())?,
    );
    out.insert(
        "x-bandall-sid",
        HeaderValue::from_str(&claims.sid).map_err(|_| Error::denied())?,
    );
    Ok((
        StatusCode::OK,
        out,
        Json(AuthzResponse {
            subject: claims.sub,
            tenant: claims.tenant,
        }),
    ))
}
