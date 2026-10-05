//! Append-only audit log with a SHA-256 hash chain.
//!
//! `record` appends `SHA256(prev_hash || event || ts_be)`; `verify_chain`
//! recomputes every link so `bandall audit verify` (and this module's test)
//! detects any tampered row.

use bandall_store::AuditEntry;
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::state::AppState;

/// Genesis previous hash (32 zero bytes).
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// Security event names (stable contract for operators).
pub mod event {
    /// Enrolment started (S2S).
    pub const ENROLL_STARTED: &str = "factor.enroll.started";
    /// Enrolment confirmed.
    pub const ENROLL_CONFIRMED: &str = "factor.enroll.confirmed";
    /// Enrolment denied.
    pub const ENROLL_DENIED: &str = "factor.enroll.denied";
    /// Login second factor accepted.
    pub const MFA_VERIFIED: &str = "mfa.verified";
    /// Login second factor denied (uniform, no reason stored).
    pub const MFA_DENIED: &str = "mfa.denied";
    /// S2S verification accepted.
    pub const S2S_VERIFIED: &str = "s2s.verified";
    /// S2S verification denied.
    pub const S2S_DENIED: &str = "s2s.denied";
    /// Refresh rotation completed.
    pub const TOKEN_REFRESHED: &str = "token.refreshed";
    /// Refresh denied (expired, revoked or reused).
    pub const TOKEN_REFRESH_DENIED: &str = "token.refresh_denied";
    /// Refresh family revoked.
    pub const TOKEN_REVOKED: &str = "token.revoked";
    /// Recovery code consumed (factor retired).
    pub const RECOVERY_USED: &str = "recovery.used";
    /// Recovery denied.
    pub const RECOVERY_DENIED: &str = "recovery.denied";
}

/// Computes the chain hash for one entry.
#[must_use]
pub fn chain_hash(prev_hash: &[u8], event: &str, ts_secs: i64) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash);
    hasher.update(event.as_bytes());
    hasher.update(ts_secs.to_be_bytes());
    hasher.finalize().to_vec()
}

/// Appends an event. Audit failures fail the request (fail closed).
pub async fn record(
    state: &AppState,
    tenant_id: &str,
    subject_id: &str,
    event: &str,
) -> Result<(), Error> {
    let now = crate::enroll::now_unix().map_err(|_| Error::internal("clock failure"))?;
    let now_i64 = i64::try_from(now).map_err(|_| Error::internal("clock range"))?;
    let prev = state
        .store
        .last_audit_hash()
        .await?
        .unwrap_or_else(|| GENESIS_HASH.to_vec());
    let hash = chain_hash(&prev, event, now_i64);
    state
        .store
        .append_audit(now_i64, tenant_id, subject_id, event, &prev, &hash)
        .await?;
    Ok(())
}

/// Verifies a full chain in sequence order. Returns the first bad sequence
/// number, or `Ok` when every link recomputes.
pub fn verify_chain(entries: &[AuditEntry]) -> Result<(), i64> {
    let mut prev = GENESIS_HASH.to_vec();
    for entry in entries {
        if entry.prev_hash != prev {
            return Err(entry.seq);
        }
        let recomputed = chain_hash(&entry.prev_hash, &entry.event, entry.ts);
        if recomputed != entry.hash {
            return Err(entry.seq);
        }
        prev = entry.hash.clone();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{chain_hash, verify_chain};
    use bandall_store::AuditEntry;

    fn entry(seq: i64, prev: Vec<u8>, event: &str, ts: i64) -> AuditEntry {
        let hash = chain_hash(&prev, event, ts);
        AuditEntry {
            seq,
            ts,
            tenant_id: "t".to_string(),
            subject_id: "s".to_string(),
            event: event.to_string(),
            prev_hash: prev,
            hash,
        }
    }

    #[test]
    fn detects_tampering() {
        let first = entry(1, vec![0u8; 32], "mfa.verified", 100);
        let second = entry(2, first.hash.clone(), "token.revoked", 200);
        assert!(verify_chain(&[first.clone(), second.clone()]).is_ok());
        let mut tampered = second;
        tampered.event = "mfa.verified".to_string();
        assert_eq!(verify_chain(&[first, tampered]), Err(2));
    }
}
