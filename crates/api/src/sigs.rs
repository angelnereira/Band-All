//! HMAC API signatures: `POST /v1/sigs/verify` validates a client-signed
//! request against its sealed key. Scope enforcement is included; nonce
//! replay storage is process-local (`AppState.nonces`).

use axum::{Json, extract::State};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::Error;
use crate::state::AppState;

/// `POST /v1/sigs/verify` body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SigsVerifyRequest {
    /// Public key identifier.
    pub key_id: String,
    /// Uppercase HTTP method of the signed request.
    pub method: String,
    /// Request path of the signed request.
    pub path: String,
    /// Raw query string (empty when none).
    #[serde(default)]
    pub query: String,
    /// Raw body of the signed request.
    #[serde(default)]
    pub body: String,
    /// Unix seconds claimed by the signer.
    pub timestamp: u64,
    /// Unique nonce.
    pub nonce: String,
    /// Presented signature (`v1=<hex>`).
    pub signature: String,
    /// Required scope (empty skips the check).
    #[serde(default)]
    pub scope: String,
}

/// `POST /v1/sigs/verify` response.
#[derive(Debug, Serialize, ToSchema)]
pub struct SigsVerifyResponse {
    /// Always `true` on success.
    pub valid: bool,
    /// Key identifier that verified.
    pub key_id: String,
    /// Owning tenant.
    pub tenant_id: String,
}

/// Validates an HMAC-signed request. Unknown keys, revoked clients, stale
/// timestamps and reused nonces all answer uniformly.
#[utoipa::path(
    post,
    path = "/v1/sigs/verify",
    request_body = SigsVerifyRequest,
    responses(
        (status = 200, description = "Signature accepted", body = SigsVerifyResponse),
        (status = 400, description = "Malformed signature envelope"),
        (status = 401, description = "Uniform denial")
    )
)]
pub async fn verify_signature(
    State(state): State<AppState>,
    Json(body): Json<SigsVerifyRequest>,
) -> Result<Json<SigsVerifyResponse>, Error> {
    let client = state
        .store
        .find_api_client(&body.key_id)
        .await?
        .ok_or_else(Error::denied)?;
    if client.revoked_at.is_some() {
        return Err(Error::denied());
    }
    if !body.scope.is_empty() && !client.scopes.split(' ').any(|scope| scope == body.scope) {
        return Err(Error::denied());
    }
    let sealed = bandall_vault::SealedSecret::reassemble(
        u8::try_from(client.sealed_version).map_err(|_| Error::denied())?,
        client.kek_id.clone(),
        bandall_vault::WrappedDek::new(
            client
                .wrapped_nonce
                .clone()
                .try_into()
                .map_err(|_| Error::denied())?,
            client.wrapped_dek.clone(),
        ),
        client
            .nonce
            .clone()
            .try_into()
            .map_err(|_| Error::denied())?,
        client.ciphertext.clone(),
    );
    let opened = state
        .vault
        .open(&sealed, "api-clients", &client.tenant_id, &client.key_id)
        .map_err(|_| Error::denied())?;
    let request = bandall_sigs::SignedRequest {
        method: body.method,
        path: body.path,
        query: body.query,
        body: body.body.into_bytes(),
        timestamp: body.timestamp,
        nonce: body.nonce,
    };
    let now = crate::enroll::now_unix().map_err(|_| Error::denied())?;
    let mut nonces = state.nonces.lock().unwrap_or_else(|e| e.into_inner());
    match bandall_sigs::verify(
        opened.expose_secret(),
        &request,
        &body.signature,
        now,
        &mut nonces,
    ) {
        Ok(()) => Ok(Json(SigsVerifyResponse {
            valid: true,
            key_id: client.key_id,
            tenant_id: client.tenant_id,
        })),
        Err(bandall_sigs::Error::Malformed) => Err(Error::BadRequest(
            "malformed signature envelope".to_string(),
        )),
        Err(_) => Err(Error::denied()),
    }
}
