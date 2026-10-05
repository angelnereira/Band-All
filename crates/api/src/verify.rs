//! Second-factor verification: `mfa/verify` (user-facing), `verify` (S2S)
//! and `mfa/recover` (recovery codes). All failures are uniform (`denied`):
//! unknown factor, inactive factor, wrong code, replay and lockout-outside
//! scope all answer identically.

use axum::{Json, extract::State, http::HeaderMap};
use bandall_totp_core::Step;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::enroll::{now_unix, params_from_row, require_service_key, sealed_from_row, wrap_secret};
use crate::error::Error;
use crate::gates;
use crate::state::AppState;

/// Steps of slack on each side of the stored drift: the verification window is
/// exactly three steps wide (remediation T3). Before this, `WINDOW=1` plus
/// `DRIFT_RADIUS=2` probed up to seven steps (±90 s) and learned the drift from
/// a single hit.
const SLACK_STEPS: u64 = 1;
/// Hard drift clamp.
const DRIFT_MAX: i64 = 5;

/// `POST /v1/mfa/verify` body (step two of login; primary credential already
/// checked by the caller or IdP).
#[derive(Debug, Deserialize, ToSchema)]
pub struct MfaVerifyRequest {
    /// Tenant id.
    pub tenant_id: String,
    /// Subject id.
    pub subject_id: String,
    /// Active factor id.
    pub factor_id: String,
    /// Code from the authenticator app.
    pub code: String,
}

/// `POST /v1/mfa/verify` response. Tokens are issued inline so the login
/// completes in one round trip.
#[derive(Debug, Serialize, ToSchema)]
pub struct MfaVerifyResponse {
    /// Always `true` on success (uniform denial otherwise).
    pub valid: bool,
    /// JWT access token (10-minute life).
    pub access_token: String,
    /// Opaque refresh token (shown once).
    pub refresh_token: String,
    /// Access token lifetime in seconds.
    pub expires_in: u64,
}

/// Verifies a login second factor with drift learning and atomic anti-replay.
#[utoipa::path(
    post,
    path = "/v1/mfa/verify",
    request_body = MfaVerifyRequest,
    responses(
        (status = 200, description = "Code accepted, session issued", body = MfaVerifyResponse),
        (status = 401, description = "Uniform denial")
    )
)]
pub async fn mfa_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: gates::PeerAddr,
    Json(body): Json<MfaVerifyRequest>,
) -> Result<Json<MfaVerifyResponse>, Error> {
    let now = now_unix().map_err(|_| Error::denied())?;
    let mut keys = vec![
        gates::factor_key(&body.tenant_id, &body.subject_id, &body.factor_id),
        gates::tenant_key(&body.tenant_id),
    ];
    if let Some(ip) = gates::client_ip(&state.trusted_proxies, peer.0, &headers) {
        keys.push(gates::ip_key(ip));
    }
    gates::acquire(&state, &keys, now).await?;
    let outcome = verify_code(
        &state,
        &body.tenant_id,
        &body.subject_id,
        &body.factor_id,
        &body.code,
    )
    .await;
    gates::record(&state, &keys, outcome.is_ok()).await?;
    state.metrics.mfa(outcome.is_ok());
    let event = if outcome.is_ok() {
        crate::audit::event::MFA_VERIFIED
    } else {
        crate::audit::event::MFA_DENIED
    };
    crate::audit::record(&state, &body.tenant_id, &body.subject_id, event).await?;
    outcome?;
    let keys = state.keys.clone();
    let pair = crate::token::issue_session(&state, &keys, &body.tenant_id, &body.subject_id, now)
        .await
        .map_err(|_| Error::denied())?;
    Ok(Json(MfaVerifyResponse {
        valid: true,
        access_token: pair.access_token,
        refresh_token: pair.refresh_token,
        expires_in: pair.expires_in,
    }))
}

/// `POST /v1/verify` body (S2S-authenticated).
#[derive(Debug, Deserialize, ToSchema)]
pub struct S2sVerifyRequest {
    /// Tenant id.
    pub tenant_id: String,
    /// Subject id.
    pub subject_id: String,
    /// Active factor id.
    pub factor_id: String,
    /// Code to check.
    pub code: String,
}

/// `POST /v1/verify` response.
#[derive(Debug, Serialize, ToSchema)]
pub struct S2sVerifyResponse {
    /// Always `true` on success.
    pub valid: bool,
    /// Consumed step counter.
    pub step: u64,
}

/// S2S verification for existing systems.
#[utoipa::path(
    post,
    path = "/v1/verify",
    params(("x-service-key" = String, Header, description = "S2S service key")),
    request_body = S2sVerifyRequest,
    responses(
        (status = 200, description = "Code accepted", body = S2sVerifyResponse),
        (status = 401, description = "Uniform denial")
    )
)]
pub async fn s2s_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: gates::PeerAddr,
    Json(body): Json<S2sVerifyRequest>,
) -> Result<Json<S2sVerifyResponse>, Error> {
    require_service_key(&state, &headers)?;
    let now = now_unix().map_err(|_| Error::denied())?;
    let mut keys = vec![
        gates::factor_key(&body.tenant_id, &body.subject_id, &body.factor_id),
        gates::tenant_key(&body.tenant_id),
    ];
    if let Some(ip) = gates::client_ip(&state.trusted_proxies, peer.0, &headers) {
        keys.push(gates::ip_key(ip));
    }
    gates::acquire(&state, &keys, now).await?;
    let outcome = verify_code(
        &state,
        &body.tenant_id,
        &body.subject_id,
        &body.factor_id,
        &body.code,
    )
    .await;
    gates::record(&state, &keys, outcome.is_ok()).await?;
    let event = if outcome.is_ok() {
        crate::audit::event::S2S_VERIFIED
    } else {
        crate::audit::event::S2S_DENIED
    };
    crate::audit::record(&state, &body.tenant_id, &body.subject_id, event).await?;
    let step = outcome?;
    Ok(Json(S2sVerifyResponse {
        valid: true,
        step: step.get(),
    }))
}

/// `POST /v1/mfa/recover` body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RecoverRequest {
    /// Tenant id.
    pub tenant_id: String,
    /// Subject id.
    pub subject_id: String,
    /// Active factor id.
    pub factor_id: String,
    /// One recovery code (`XXXX-XXXX-XXXX-XXXX`).
    pub recovery_code: String,
}

/// `POST /v1/mfa/recover` response. The factor is consumed: the caller must
/// re-enrol afterwards.
#[derive(Debug, Serialize, ToSchema)]
pub struct RecoverResponse {
    /// Always `true` on success.
    pub valid: bool,
    /// The caller must start a fresh enrolment.
    pub must_reenroll: bool,
}

/// Consumes a recovery code and retires the factor (forces re-enrolment).
#[utoipa::path(
    post,
    path = "/v1/mfa/recover",
    request_body = RecoverRequest,
    responses(
        (status = 200, description = "Recovery accepted", body = RecoverResponse),
        (status = 401, description = "Uniform denial")
    )
)]
pub async fn recover(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: gates::PeerAddr,
    Json(body): Json<RecoverRequest>,
) -> Result<Json<RecoverResponse>, Error> {
    let now = now_unix().map_err(|_| Error::denied())?;
    let mut keys = vec![
        gates::factor_key(&body.tenant_id, &body.subject_id, &body.factor_id),
        gates::tenant_key(&body.tenant_id),
    ];
    if let Some(ip) = gates::client_ip(&state.trusted_proxies, peer.0, &headers) {
        keys.push(gates::ip_key(ip));
    }
    gates::acquire(&state, &keys, now).await?;
    let outcome = recover_inner(&state, &body).await;
    gates::record(&state, &keys, outcome.is_ok()).await?;
    let event = if outcome.is_ok() {
        crate::audit::event::RECOVERY_USED
    } else {
        crate::audit::event::RECOVERY_DENIED
    };
    crate::audit::record(&state, &body.tenant_id, &body.subject_id, event).await?;
    outcome
}

async fn recover_inner(
    state: &AppState,
    body: &RecoverRequest,
) -> Result<Json<RecoverResponse>, Error> {
    let factor = state
        .store
        .get_factor(&body.tenant_id, &body.subject_id, &body.factor_id)
        .await?
        .ok_or_else(Error::denied)?;
    if factor.status != "active" {
        return Err(Error::denied());
    }
    let hashes = state.store.list_recovery_hashes(&factor.id).await?;
    let mut matched: Option<String> = None;
    for entry in &hashes {
        if entry.used_at.is_some() {
            continue;
        }
        match bandall_vault::recovery::verify(&body.recovery_code, &entry.code_hash) {
            Ok(true) => {
                matched = Some(entry.code_hash.clone());
                break;
            }
            Ok(false) => {}
            Err(_) => return Err(Error::denied()),
        }
    }
    let hash = matched.ok_or_else(Error::denied)?;
    let now = now_unix().map_err(|_| Error::denied())?;
    let now_i64 = i64::try_from(now).map_err(|_| Error::denied())?;
    if !state
        .store
        .use_recovery_code(&factor.id, &hash, now_i64)
        .await
        .map_err(|_| Error::denied())?
    {
        return Err(Error::denied());
    }
    state.store.delete_factor(&factor.id).await?;
    Ok(Json(RecoverResponse {
        valid: true,
        must_reenroll: true,
    }))
}

/// Core verification shared by user and S2S paths. Returns the consumed step.
async fn verify_code(
    state: &AppState,
    tenant_id: &str,
    subject_id: &str,
    factor_id: &str,
    code: &str,
) -> Result<Step, Error> {
    let factor = match state
        .store
        .get_factor(tenant_id, subject_id, factor_id)
        .await?
    {
        Some(factor) => factor,
        None => {
            gates::dummy_verify();
            return Err(Error::denied());
        }
    };
    if factor.status != "active" {
        return Err(Error::denied());
    }
    let sealed = sealed_from_row(&factor).map_err(|_| Error::denied())?;
    let opened = state
        .vault
        .open(&sealed, tenant_id, subject_id, factor_id)
        .map_err(|_| Error::denied())?;
    let secret = wrap_secret(opened.expose_secret()).map_err(|_| Error::denied())?;
    let params = params_from_row(&factor).map_err(|_| Error::denied())?;
    let last = factor
        .last_step_u64()
        .map_err(|_| Error::denied())?
        .map(Step::new);
    let now = now_unix().map_err(|_| Error::denied())?;

    let period = params.period().as_u64();
    // Only the three steps around the stored drift are probed, and the drift
    // is re-learned from the offset actually observed on success.
    for candidate in candidate_steps(now, factor.drift(), period).ok_or_else(Error::denied)? {
        let at = candidate.checked_mul(period).ok_or_else(Error::denied)?;
        match bandall_totp_core::totp::verify(&secret, params, code, at, 0, last) {
            Ok(step) => {
                if !state
                    .store
                    .cas_last_step(&factor.id, step.get())
                    .await
                    .map_err(|_| Error::denied())?
                {
                    return Err(Error::denied());
                }
                let observed = observed_drift(step.get(), now, period).ok_or_else(Error::denied)?;
                if observed != factor.drift() {
                    state.store.record_drift(&factor.id, observed).await?;
                }
                return Ok(step);
            }
            Err(bandall_totp_core::Error::CodeMismatch) => {}
            Err(_) => return Err(Error::denied()),
        }
    }
    Err(Error::denied())
}

/// The only steps a code may match: the stored drift plus one step of slack on
/// each side, exactly three candidates.
///
/// Pure and fail-closed: `None` when the arithmetic would leave the range of a
/// step counter (zero period, near the epoch, overflow), so a corrupted row
/// denies instead of probing wrapped values.
fn candidate_steps(now: u64, drift: i64, period: u64) -> Option<[u64; 3]> {
    let period = i64::try_from(period).ok().filter(|p| *p > 0)?;
    let now_step = i64::try_from(now).ok()? / period;
    let base = now_step.checked_add(drift)?;
    let slack = i64::try_from(SLACK_STEPS).ok()?;
    let first = base.checked_sub(slack)?;
    let last = base.checked_add(slack)?;
    Some([
        u64::try_from(first).ok()?,
        u64::try_from(base).ok()?,
        u64::try_from(last).ok()?,
    ])
}

/// Offset of the matched step relative to `now`, in steps and clamped to
/// ±`DRIFT_MAX` so a tampered row cannot push the window far away.
fn observed_drift(step: u64, now: u64, period: u64) -> Option<i64> {
    let period = i64::try_from(period).ok().filter(|p| *p > 0)?;
    let now_step = i64::try_from(now).ok()? / period;
    let step = i64::try_from(step).ok()?;
    Some(step.checked_sub(now_step)?.clamp(-DRIFT_MAX, DRIFT_MAX))
}

#[cfg(test)]
mod tests {
    use super::{DRIFT_MAX, candidate_steps, observed_drift};

    const PERIOD: u64 = 30;
    const NOW: u64 = 1_700_000_000;

    #[test]
    fn exactly_three_distinct_candidates() {
        let base = NOW / PERIOD;
        let steps = candidate_steps(NOW, 0, PERIOD).unwrap();
        assert_eq!(steps.len(), 3);
        assert_eq!(steps, [base - 1, base, base + 1]);
        assert!(steps[0] < steps[1] && steps[1] < steps[2]);
    }

    #[test]
    fn candidates_follow_the_stored_drift() {
        let base = NOW / PERIOD;
        // Stored drift 2 ⇒ candidates are steps +1, +2 and +3 only.
        assert_eq!(
            candidate_steps(NOW, 2, PERIOD).unwrap(),
            [base + 1, base + 2, base + 3]
        );
        // Stored drift 0 never reaches a step three away: that was the ±90 s
        // span T3 removed.
        let zero = candidate_steps(NOW, 0, PERIOD).unwrap();
        assert!(!zero.contains(&(base + 3)));
        assert!(zero.contains(&base));
    }

    #[test]
    fn fails_closed_on_impossible_inputs() {
        // Zero period, near the epoch and a drift that would go negative.
        assert!(candidate_steps(NOW, 0, 0).is_none());
        assert!(candidate_steps(0, 0, PERIOD).is_none());
        assert!(candidate_steps(1, 0, PERIOD).is_none());
        assert!(candidate_steps(NOW, i64::MAX, PERIOD).is_none());
    }

    #[test]
    fn observed_drift_is_clamped_to_the_hard_limit() {
        let base = NOW / PERIOD;
        assert_eq!(observed_drift(base + 1, NOW, PERIOD), Some(1));
        assert_eq!(observed_drift(base, NOW, PERIOD), Some(0));
        assert_eq!(observed_drift(base - 1, NOW, PERIOD), Some(-1));
        assert_eq!(observed_drift(base + 99, NOW, PERIOD), Some(DRIFT_MAX));
        assert_eq!(observed_drift(base - 99, NOW, PERIOD), Some(-DRIFT_MAX));
        assert!(observed_drift(base, NOW, 0).is_none());
    }
}
