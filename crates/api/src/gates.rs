//! Verification gates: rate limiting and timing-uniform denial.
//!
//! Every user-facing verification path checks the factor and tenant keys
//! first (429 on abuse) and records the outcome afterwards. Unknown factors
//! cost a dummy verification so misses and mismatches take similar time.

use bandall_policy::Decision;
use bandall_totp_core::{Secret, TotpParams};

use crate::error::Error;
use crate::state::AppState;

/// Builds the per-factor policy key.
#[must_use]
pub fn factor_key(tenant_id: &str, subject_id: &str, factor_id: &str) -> String {
    format!("factor:{tenant_id}:{subject_id}:{factor_id}")
}

/// Builds the per-tenant policy key.
#[must_use]
pub fn tenant_key(tenant_id: &str) -> String {
    format!("tenant:{tenant_id}")
}

/// Denies the attempt when any key is over its limit.
pub fn check(state: &AppState, keys: &[String], now_secs: u64) -> Result<(), Error> {
    for key in keys {
        if state.policy.check(key, now_secs) != Decision::Allow {
            return Err(Error::RateLimited);
        }
    }
    Ok(())
}

/// Records the attempt outcome on every key.
pub fn record(state: &AppState, keys: &[String], now_secs: u64, success: bool) {
    for key in keys {
        state.policy.record(key, now_secs, success);
    }
}

/// Timing ballast for unknown factors: runs the same HMAC math as a real
/// check so misses cost roughly like mismatches.
pub fn dummy_verify() {
    let params = TotpParams::default_params();
    if let Ok(secret) = Secret::new(vec![7u8; 32]) {
        match bandall_totp_core::totp::verify(&secret, params, "000000", 0, 1, None) {
            Ok(_) | Err(_) => {}
        }
    }
}
