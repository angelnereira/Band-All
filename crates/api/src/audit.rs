//! Append-only audit log with a **keyed** hash chain (v2).
//!
//! # Why v2
//!
//! The legacy chain (v1) hashed `SHA256(prev ‖ event ‖ ts)` with no key and
//! left `tenant_id`/`subject_id` outside the hash. Anyone able to write to the
//! table could recompute the whole chain offline, and rewriting the tenant or
//! subject of a row did not break verification at all.
//!
//! v2 computes `HMAC-SHA-256(audit_key, framed(record))` where the frame is
//! length-prefixed and covers version, timestamp, tenant, subject, event and
//! the previous hash. Without the key (held outside the database) a tamperer
//! cannot produce a chain that verifies.
//!
//! # Concurrency
//!
//! The append is a single transaction owned by the store
//! ([`Store::append_audit_chained`]): the tip is read under a lock and the row
//! is inserted before releasing it. Computing the hash outside that
//! transaction would let two concurrent writers chain from the same tip and
//! fork the log, so the store calls back into [`AuditChain`] *inside* the
//! transaction.
//!
//! # Compatibility
//!
//! [`verify_chain`] verifies v1 and v2 rows independently using each row's
//! `chain_version`, so logs written before this change still verify.
//!
//! [`Store::append_audit_chained`]: bandall_store::Store::append_audit_chained

use bandall_store::Error as StoreError;
use bandall_store::{AuditEntry, AuditHasher, NewAudit};
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::Error;
use crate::state::AppState;

/// Genesis previous hash (32 zero bytes).
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// HMAC-SHA-256.
type HmacSha256 = Hmac<Sha256>;

/// Length of the audit key in bytes.
const AUDIT_KEY_LEN: usize = 32;

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

/// The audit-chain key. Holds the 32 raw bytes in a `SecretBox` (zeroed on
/// drop, redacted in `Debug`), like the vault's DEK handling.
pub struct AuditChain {
    key: SecretBox<Vec<u8>>,
}

impl std::fmt::Debug for AuditChain {
    /// Opaque on purpose: the struct holds chain key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditChain").finish_non_exhaustive()
    }
}

impl AuditChain {
    /// Builds a chain from exactly 32 raw bytes.
    pub fn from_bytes(key: [u8; AUDIT_KEY_LEN]) -> Self {
        Self {
            key: SecretBox::new(Box::new(key.to_vec())),
        }
    }

    /// Builds a chain from a 32-byte key file.
    ///
    /// The file must be `0600` or stricter on Unix: the same rule the local
    /// KMS applies to its KEK. Ownership of that file (and of the secret
    /// carrying it in a deployment) is what keeps the chain tamper-evident, so
    /// a world-readable key is rejected outright rather than warned about.
    pub fn from_file(path: &std::path::Path) -> Result<Self, Error> {
        crate::config::require_owner_only_file(path)?;
        // `Zeroizing`: the transient read buffer holds key material and must
        // not linger in freed heap memory.
        let raw = Zeroizing::new(
            std::fs::read(path).map_err(|_| Error::Config("cannot read audit_key_file".into()))?,
        );
        // Fail closed on a wrong-length key: it is always a deployment
        // mistake, and starting with one would silently produce a chain that
        // nobody can verify later.
        let bytes = <[u8; AUDIT_KEY_LEN]>::try_from(&raw[..])
            .map_err(|_| Error::Config("audit_key_file must hold exactly 32 bytes".into()))?;
        Ok(Self::from_bytes(bytes))
    }

    /// Computes the v2 chain hash over `entry`, chained to `prev_hash`.
    pub fn link(&self, entry: &NewAudit, prev_hash: &[u8]) -> Result<Vec<u8>, StoreError> {
        let mut mac = HmacSha256::new_from_slice(self.key.expose_secret())
            .map_err(|_| StoreError::ChainHash)?;
        mac.update(&frame(entry, prev_hash));
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

impl AuditHasher for AuditChain {
    fn link(&self, entry: &NewAudit, prev_hash: &[u8]) -> Result<Vec<u8>, StoreError> {
        AuditChain::link(self, entry, prev_hash)
    }
}

/// Length-prefixed encoding of one record.
///
/// Each field is framed as `u32 length || bytes`, so no combination of values
/// can be reinterpreted as a different record (the ambiguity that made the
/// unkeyed v1 concatenation forgeable beyond just the missing key).
fn frame(entry: &NewAudit, prev_hash: &[u8]) -> Vec<u8> {
    let version = entry.chain_version.to_be_bytes();
    let ts = entry.ts.to_be_bytes();
    let fields: [&[u8]; 7] = [
        &version,
        &ts,
        entry.tenant_id.as_bytes(),
        entry.subject_id.as_bytes(),
        entry.event.as_bytes(),
        prev_hash,
        GENESIS_HASH.as_slice(),
    ];
    let mut out = Vec::with_capacity(fields.iter().map(|f| f.len() + 4).sum());
    for field in fields {
        let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// Legacy v1 hash: unkeyed `SHA256(prev ‖ event ‖ ts_be)`.
///
/// Kept only to verify rows written before v2. Never used to append.
#[must_use]
pub fn chain_hash_v1(prev_hash: &[u8], event: &str, ts_secs: i64) -> Vec<u8> {
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
    let entry = NewAudit {
        ts: now_i64,
        tenant_id: tenant_id.to_string(),
        subject_id: subject_id.to_string(),
        event: event.to_string(),
        chain_version: NewAudit::CHAIN_V2,
    };
    state
        .store
        .append_audit_chained(entry, state.audit.as_ref())
        .await?;
    Ok(())
}

/// Verifies a full chain in sequence order.
///
/// Each row is verified against its own `chain_version`, so a log that mixes
/// legacy v1 rows with keyed v2 rows verifies end to end. Returns the first
/// bad sequence number, or `Ok` when every link recomputes.
pub fn verify_chain(entries: &[AuditEntry], chain: &AuditChain) -> Result<(), i64> {
    let mut prev = GENESIS_HASH.to_vec();
    for entry in entries {
        if entry.prev_hash != prev {
            return Err(entry.seq);
        }
        let recomputed = match entry.chain_version {
            // Legacy rows keep verifying so operators can audit a log written
            // before the keyed chain existed.
            1 => chain_hash_v1(&entry.prev_hash, &entry.event, entry.ts),
            // Keyed. Matched against the store's constant, not a literal, and
            // an unknown format falls through to `_`: refuse rather than
            // silently accept a chain we cannot interpret.
            version if version == NewAudit::CHAIN_V2 => chain
                .link(
                    &NewAudit {
                        ts: entry.ts,
                        tenant_id: entry.tenant_id.clone(),
                        subject_id: entry.subject_id.clone(),
                        event: entry.event.clone(),
                        chain_version: version,
                    },
                    &entry.prev_hash,
                )
                // A hash we cannot compute is not a verification pass.
                .map_err(|_| entry.seq)?,
            _ => return Err(entry.seq),
        };
        if !bool::from(recomputed.ct_eq(&entry.hash)) {
            return Err(entry.seq);
        }
        prev = entry.hash.clone();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AuditChain, chain_hash_v1, frame, verify_chain};
    use bandall_store::{AuditEntry, NewAudit};

    fn chain(byte: u8) -> AuditChain {
        AuditChain::from_bytes([byte; 32])
    }

    fn entry(ts: i64, tenant: &str, subject: &str, event: &str) -> NewAudit {
        NewAudit {
            ts,
            tenant_id: tenant.to_string(),
            subject_id: subject.to_string(),
            event: event.to_string(),
            chain_version: NewAudit::CHAIN_V2,
        }
    }

    fn stored(chainer: &AuditChain, new: &NewAudit, prev: &[u8]) -> AuditEntry {
        AuditEntry {
            seq: 1,
            ts: new.ts,
            tenant_id: new.tenant_id.clone(),
            subject_id: new.subject_id.clone(),
            event: new.event.clone(),
            prev_hash: prev.to_vec(),
            hash: chainer.link(new, prev).unwrap(),
            chain_version: new.chain_version,
        }
    }

    #[test]
    fn chain_verifies() {
        let chainer = chain(9);
        let first = stored(&chainer, &entry(100, "t", "s", "mfa.verified"), &[0u8; 32]);
        let second = stored(
            &chainer,
            &entry(200, "t", "s", "token.revoked"),
            &first.hash,
        );
        assert!(verify_chain(&[first.clone(), second], &chainer).is_ok());
    }

    #[test]
    fn tampering_with_tenant_breaks_the_chain() {
        // The v1 hash ignored tenant and subject entirely; v2 covers both.
        let chainer = chain(9);
        let mut row = stored(&chainer, &entry(100, "t", "s", "mfa.verified"), &[0u8; 32]);
        row.tenant_id = "other-tenant".to_string();
        assert_eq!(verify_chain(&[row.clone()], &chainer), Err(row.seq));
    }

    #[test]
    fn tampering_with_subject_breaks_the_chain() {
        let chainer = chain(9);
        let mut row = stored(&chainer, &entry(100, "t", "s", "mfa.verified"), &[0u8; 32]);
        row.subject_id = "someone-else".to_string();
        assert_eq!(verify_chain(&[row], &chainer), Err(1));
    }

    #[test]
    fn tampering_with_event_or_ts_breaks_the_chain() {
        let chainer = chain(9);
        let mut event = stored(&chainer, &entry(100, "t", "s", "mfa.verified"), &[0u8; 32]);
        event.event = "mfa.denied".to_string();
        assert_eq!(verify_chain(&[event], &chainer), Err(1));

        let mut ts = stored(&chainer, &entry(100, "t", "s", "mfa.verified"), &[0u8; 32]);
        ts.ts = 101;
        assert_eq!(verify_chain(&[ts], &chainer), Err(1));
    }

    #[test]
    fn wrong_key_cannot_recompute_the_chain() {
        let honest = chain(9);
        let attacker = chain(10);
        let first = stored(&honest, &entry(100, "t", "s", "mfa.verified"), &[0u8; 32]);
        // Without the key, rehashing the same record yields a different value.
        assert_eq!(
            verify_chain(std::slice::from_ref(&first), &attacker),
            Err(1)
        );
        // Even with the right key, edited fields do not verify.
        let forged = stored(
            &attacker,
            &entry(100, "evil", "s", "mfa.verified"),
            &[0u8; 32],
        );
        assert_eq!(verify_chain(&[forged], &honest), Err(1));
    }

    #[test]
    fn legacy_v1_rows_still_verify() {
        // A log written before the keyed chain must remain auditable: v1 rows
        // verify with the legacy hash and need no key.
        let chainer = chain(9);
        let first = AuditEntry {
            seq: 1,
            ts: 100,
            tenant_id: "t".to_string(),
            subject_id: "s".to_string(),
            event: "mfa.verified".to_string(),
            prev_hash: vec![0u8; 32],
            hash: chain_hash_v1(&[0u8; 32], "mfa.verified", 100),
            chain_version: 1,
        };
        let second = AuditEntry {
            seq: 2,
            ts: 200,
            tenant_id: "t".to_string(),
            subject_id: "s".to_string(),
            event: "token.revoked".to_string(),
            prev_hash: first.hash.clone(),
            hash: chain_hash_v1(&first.hash, "token.revoked", 200),
            chain_version: 1,
        };
        assert!(verify_chain(&[first.clone(), second], &chainer).is_ok());
        // And the v1 weakness is still visible: editing tenant does not break it.
        let mut edited = first.clone();
        edited.tenant_id = "other".to_string();
        assert!(verify_chain(&[edited], &chainer).is_ok());
    }

    #[test]
    fn mixed_v1_and_v2_logs_verify() {
        let chainer = chain(9);
        let legacy = AuditEntry {
            seq: 1,
            ts: 100,
            tenant_id: "t".to_string(),
            subject_id: "s".to_string(),
            event: "mfa.verified".to_string(),
            prev_hash: vec![0u8; 32],
            hash: chain_hash_v1(&[0u8; 32], "mfa.verified", 100),
            chain_version: 1,
        };
        let modern = stored(
            &chainer,
            &entry(200, "t", "s", "token.revoked"),
            &legacy.hash,
        );
        let modern = AuditEntry { seq: 2, ..modern };
        assert!(verify_chain(&[legacy, modern], &chainer).is_ok());
    }

    #[test]
    fn unknown_chain_version_is_refused() {
        let chainer = chain(9);
        let row = AuditEntry {
            seq: 1,
            ts: 100,
            tenant_id: "t".to_string(),
            subject_id: "s".to_string(),
            event: "mfa.verified".to_string(),
            prev_hash: vec![0u8; 32],
            hash: vec![7u8; 32],
            chain_version: 99,
        };
        assert_eq!(verify_chain(&[row], &chainer), Err(1));
    }

    #[test]
    fn broken_link_is_detected() {
        let chainer = chain(9);
        let first = stored(&chainer, &entry(100, "t", "s", "mfa.verified"), &[0u8; 32]);
        let mut orphan = stored(&chainer, &entry(200, "t", "s", "token.revoked"), &[3u8; 32]);
        orphan.seq = 2;
        assert_eq!(verify_chain(&[first, orphan], &chainer), Err(2));
    }

    #[test]
    fn frame_is_unambiguous_across_field_boundaries() {
        // Concatenating without length prefixes would let these two records
        // collide; the framing must keep them apart.
        let a = entry(100, "ab", "c", "mfa.verified");
        let b = entry(100, "a", "bc", "mfa.verified");
        assert_ne!(frame(&a, &[0u8; 32]), frame(&b, &[0u8; 32]));
        // And the version is part of the frame.
        let mut other = a.clone();
        other.chain_version = 1;
        assert_ne!(frame(&a, &[0u8; 32]), frame(&other, &[0u8; 32]));
    }

    #[test]
    fn link_depends_on_the_previous_hash() {
        let chainer = chain(9);
        let new = entry(100, "t", "s", "mfa.verified");
        assert_ne!(
            chainer.link(&new, &[0u8; 32]).unwrap(),
            chainer.link(&new, &[1u8; 32]).unwrap()
        );
    }
}
