//! Enrolment: `start` provisions a pending factor and returns the `otpauth://`
//! URI once; `confirm` activates it with the first code and issues recovery
//! codes. Failures on `confirm` are uniform (`denied`) so factor existence,
//! expiry and code validity stay indistinguishable.

use axum::{Json, extract::State, http::HeaderMap};
use bandall_store::{NewFactor, new_factor_id};
use bandall_totp_core::{Algorithm, Otpauth, Period, Secret, TotpParams};
use secrecy::zeroize::Zeroize;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::state::AppState;

/// Pending enrolments expire after 10 minutes.
const PENDING_EXPIRY_SECS: u64 = 600;
/// Maximum field length for tenant, subject, issuer and account names.
const MAX_NAME_LEN: usize = 256;

/// Current Unix time in seconds (server clock; the math core stays pure).
pub(crate) fn now_unix() -> Result<u64, Error> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::internal("clock failure"))
}

/// Wraps opened plaintext as a TOTP secret, zeroing the transient copy.
pub(crate) fn wrap_secret(plaintext: &[u8]) -> Result<Secret, Error> {
    let mut transient = plaintext.to_vec();
    let secret = Secret::new(transient.clone())?;
    transient.zeroize();
    Ok(secret)
}

/// Constant-time service-key gate for S2S endpoints.
pub(crate) fn require_service_key(state: &AppState, headers: &HeaderMap) -> Result<(), Error> {
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

fn non_empty(name: &'static str, value: &str) -> Result<(), Error> {
    if value.is_empty() || value.len() > MAX_NAME_LEN {
        return Err(Error::BadRequest(format!("invalid {name}")));
    }
    Ok(())
}

/// `POST /v1/factors/enroll/start` body (S2S-authenticated).
#[derive(Debug, Deserialize)]
pub struct EnrollStartRequest {
    /// Tenant id (must exist).
    pub tenant_id: String,
    /// Caller-stable subject identifier (created on first use).
    pub subject_external_id: String,
    /// Issuer shown in the authenticator app.
    pub issuer: String,
    /// Account shown in the authenticator app.
    pub account: String,
    /// `SHA1`/`SHA256`/`SHA512` (default `SHA256`).
    pub algorithm: Option<String>,
    /// 6-8 (default 6).
    pub digits: Option<u8>,
    /// Seconds (default 30).
    pub period: Option<u64>,
}

/// `POST /v1/factors/enroll/start` response. The URI carries the secret and
/// is never returned again.
#[derive(Debug, Serialize)]
pub struct EnrollStartResponse {
    /// New factor id.
    pub factor_id: String,
    /// `otpauth://` URI for the QR code.
    pub otpauth_uri: String,
    /// Unix time when the pending factor expires.
    pub expires_at: u64,
}

/// Starts enrolment: seals a fresh secret and returns the QR payload.
pub async fn start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<EnrollStartRequest>,
) -> Result<Json<EnrollStartResponse>, Error> {
    require_service_key(&state, &headers)?;
    non_empty("tenant_id", &body.tenant_id)?;
    non_empty("subject_external_id", &body.subject_external_id)?;
    non_empty("issuer", &body.issuer)?;
    non_empty("account", &body.account)?;

    let algorithm = body
        .algorithm
        .as_deref()
        .map(Algorithm::from_name)
        .transpose()
        .map_err(|_| Error::BadRequest("invalid algorithm".to_string()))?
        .unwrap_or(Algorithm::Sha256);
    let digits = body.digits.unwrap_or(6);
    let period = Period::new(body.period.unwrap_or(30))
        .map_err(|_| Error::BadRequest("invalid period".to_string()))?;
    let params =
        TotpParams::new(algorithm, digits, period).map_err(|e| Error::BadRequest(e.to_string()))?;

    let now = now_unix()?;
    let now_i64 = i64::try_from(now).map_err(|_| Error::internal("clock failure"))?;
    let subject = match state
        .store
        .find_subject(&body.tenant_id, &body.subject_external_id)
        .await?
    {
        Some(subject) => subject,
        None => {
            state
                .store
                .create_subject(&body.tenant_id, &body.subject_external_id, now_i64)
                .await?
        }
    };

    let secret = Secret::generate_for(algorithm)?;
    let factor_id = new_factor_id();
    let sealed = state.vault.seal(
        &body.tenant_id,
        &subject.id,
        &factor_id,
        secret.expose_secret_bytes(),
    )?;
    state
        .store
        .create_factor(NewFactor {
            id: factor_id.clone(),
            tenant_id: body.tenant_id.clone(),
            subject_id: subject.id.clone(),
            status: "pending".to_string(),
            secret_version: 1,
            kek_id: state.vault.kek_id().to_string(),
            wrapped_dek: sealed.wrapped_dek().ciphertext().to_vec(),
            wrapped_nonce: sealed.wrapped_dek().nonce().to_vec(),
            nonce: sealed.nonce().to_vec(),
            ciphertext: sealed.ciphertext().to_vec(),
            algorithm: algorithm.name().to_string(),
            digits: i16::from(digits),
            period: i64::try_from(period.as_u64()).map_err(|_| Error::internal("period range"))?,
            created_at: now_i64,
        })
        .await?;

    let uri = Otpauth::new(params, secret, body.issuer, body.account)?.to_uri();
    Ok(Json(EnrollStartResponse {
        factor_id,
        otpauth_uri: uri,
        expires_at: now.saturating_add(PENDING_EXPIRY_SECS),
    }))
}

/// `POST /v1/factors/enroll/confirm` body.
#[derive(Debug, Deserialize)]
pub struct EnrollConfirmRequest {
    /// Tenant id.
    pub tenant_id: String,
    /// Subject id (returned at enrolment time by the S2S caller).
    pub subject_id: String,
    /// Pending factor id.
    pub factor_id: String,
    /// First code from the authenticator app.
    pub code: String,
}

/// `POST /v1/factors/enroll/confirm` response. Recovery codes are shown once.
#[derive(Debug, Serialize)]
pub struct EnrollConfirmResponse {
    /// Activated factor id.
    pub factor_id: String,
    /// One-time recovery codes.
    pub recovery_codes: Vec<String>,
}

/// Confirms enrolment with the first code and issues recovery codes.
pub async fn confirm(
    State(state): State<AppState>,
    Json(body): Json<EnrollConfirmRequest>,
) -> Result<Json<EnrollConfirmResponse>, Error> {
    let factor = state
        .store
        .get_factor(&body.tenant_id, &body.subject_id, &body.factor_id)
        .await?
        .ok_or_else(Error::denied)?;
    if factor.status != "pending" {
        return Err(Error::denied());
    }
    let now = now_unix()?;
    let created = u64::try_from(factor.created_at).map_err(|_| Error::denied())?;
    if now.saturating_sub(created) > PENDING_EXPIRY_SECS {
        return Err(Error::denied());
    }

    let opened = state
        .vault
        .open(
            &sealed_from_row(&factor)?,
            &body.tenant_id,
            &body.subject_id,
            &body.factor_id,
        )
        .map_err(|_| Error::denied())?;
    let secret = {
        use secrecy::ExposeSecret;
        wrap_secret(opened.expose_secret()).map_err(|_| Error::denied())?
    };
    let params = params_from_row(&factor).map_err(|_| Error::denied())?;
    let step = bandall_totp_core::totp::verify(&secret, params, &body.code, now, 1, None)
        .map_err(|_| Error::denied())?;
    if !state
        .store
        .cas_last_step(&factor.id, step.get())
        .await
        .map_err(|_| Error::denied())?
    {
        return Err(Error::denied());
    }
    let now_i64 = i64::try_from(now).map_err(|_| Error::denied())?;
    state.store.confirm_factor(&factor.id, now_i64).await?;

    let codes = bandall_vault::recovery::generate()?;
    let mut hashes = Vec::with_capacity(codes.len());
    let mut displays = Vec::with_capacity(codes.len());
    for code in &codes {
        hashes.push(bandall_vault::recovery::hash(code)?);
        displays.push(code.display());
    }
    state.store.add_recovery_codes(&factor.id, &hashes).await?;

    Ok(Json(EnrollConfirmResponse {
        factor_id: factor.id,
        recovery_codes: displays,
    }))
}

/// Rebuilds the sealed secret from a factor row.
pub(crate) fn sealed_from_row(
    factor: &bandall_store::Factor,
) -> Result<bandall_vault::SealedSecret, Error> {
    use bandall_vault::{SealedSecret, WrappedDek};
    let version = u8::try_from(factor.secret_version).map_err(|_| Error::denied())?;
    let wrap_nonce: [u8; 24] = factor
        .wrapped_nonce
        .clone()
        .try_into()
        .map_err(|_| Error::denied())?;
    let nonce: [u8; 24] = factor
        .nonce
        .clone()
        .try_into()
        .map_err(|_| Error::denied())?;
    Ok(SealedSecret::reassemble(
        version,
        factor.kek_id.clone(),
        WrappedDek::new(wrap_nonce, factor.wrapped_dek.clone()),
        nonce,
        factor.ciphertext.clone(),
    ))
}

/// TOTP parameters from a factor row.
pub(crate) fn params_from_row(factor: &bandall_store::Factor) -> Result<TotpParams, Error> {
    let algorithm = Algorithm::from_name(&factor.algorithm)?;
    let digits = u8::try_from(factor.digits).map_err(|_| Error::denied())?;
    let period_secs = u64::try_from(factor.period).map_err(|_| Error::denied())?;
    TotpParams::new(algorithm, digits, Period::new(period_secs)?).map_err(|_| Error::denied())
}
