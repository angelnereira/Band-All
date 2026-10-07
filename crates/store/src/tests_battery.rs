//! Shared conformance battery: every backend must pass it identically.
//! Executed by CI (SQLite in-memory always, Postgres via service container).

use std::sync::Arc;

use crate::error::Error;
use crate::store::Store;
use crate::types::{AuditHasher, NewApiClient, NewAudit, NewFactor, NewRefresh, new_factor_id};

fn dummy_factor(tenant_id: &str, subject_id: &str) -> NewFactor {
    NewFactor {
        id: new_factor_id(),
        tenant_id: tenant_id.to_string(),
        subject_id: subject_id.to_string(),
        status: "pending".to_string(),
        secret_version: 1,
        kek_id: "kek-1".to_string(),
        wrapped_dek: vec![1u8; 48],
        wrapped_nonce: vec![2u8; 24],
        nonce: vec![3u8; 24],
        ciphertext: vec![4u8; 48],
        algorithm: "SHA256".to_string(),
        digits: 6,
        period: 30,
        created_at: 1_700_000_000,
    }
}

/// Test hasher: the shape production uses (a key plus a hash over a
/// length-prefixed frame), with a deterministic key so the battery can assert
/// exact hashes. Production code uses HMAC-SHA-256 (`bandall-api`); what the
/// store must guarantee is that the link is derived inside the transaction.
struct BatteryChain {
    key: u8,
}

impl AuditHasher for BatteryChain {
    fn link(&self, entry: &NewAudit, prev_hash: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        for field in [
            entry.chain_version.to_be_bytes().as_slice(),
            entry.ts.to_be_bytes().as_slice(),
            entry.tenant_id.as_bytes(),
            entry.subject_id.as_bytes(),
            entry.event.as_bytes(),
            prev_hash,
        ] {
            // u32 length, like the production frame: a narrow length would
            // make the framing itself lossy for long fields.
            let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(field);
        }
        out.push(self.key);
        Ok(out)
    }
}

/// Full lifecycle: tenants, subjects, factors, atomic CAS, confirmation,
/// single-use recovery codes and tenant/subject scoping.
pub async fn full_cycle<S: Store>(store: &S) -> Result<(), Error> {
    store.health().await?;
    let tenant = store.create_tenant("acme", 1_700_000_000).await?;
    let subject = store
        .create_subject(&tenant.id, "alice", 1_700_000_000)
        .await?;

    let factor = store
        .create_factor(dummy_factor(&tenant.id, &subject.id))
        .await?;
    assert_eq!(factor.status, "pending");
    assert_eq!(factor.last_step_u64()?, None);

    // Scoped reads: wrong tenant or subject yields nothing.
    assert!(
        store
            .get_factor(&tenant.id, &subject.id, &factor.id)
            .await?
            .is_some()
    );
    assert!(
        store
            .get_factor("nope", &subject.id, &factor.id)
            .await?
            .is_none()
    );
    assert!(
        store
            .get_factor(&tenant.id, "nope", &factor.id)
            .await?
            .is_none()
    );

    // Atomic compare-and-set: first wins, replay and older steps lose.
    assert!(store.cas_last_step(&factor.id, 100).await?);
    assert!(!store.cas_last_step(&factor.id, 100).await?);
    assert!(!store.cas_last_step(&factor.id, 50).await?);
    assert!(store.cas_last_step(&factor.id, 101).await?);
    let reloaded = store
        .get_factor(&tenant.id, &subject.id, &factor.id)
        .await?
        .ok_or(Error::CorruptRow)?;
    assert_eq!(reloaded.last_step_u64()?, Some(101));

    // Confirmation flips status with timestamp.
    store.confirm_factor(&factor.id, 1_700_000_100).await?;
    let confirmed = store
        .get_factor(&tenant.id, &subject.id, &factor.id)
        .await?
        .ok_or(Error::CorruptRow)?;
    assert_eq!(confirmed.status, "active");
    assert_eq!(confirmed.confirmed_at, Some(1_700_000_100));

    // Recovery codes are single-use.
    store
        .add_recovery_codes(&factor.id, &["hash-a".to_string(), "hash-b".to_string()])
        .await?;
    assert!(
        store
            .use_recovery_code(&factor.id, "hash-a", 1_700_000_200)
            .await?
    );
    assert!(
        !store
            .use_recovery_code(&factor.id, "hash-a", 1_700_000_201)
            .await?
    );
    assert!(
        !store
            .use_recovery_code(&factor.id, "missing", 1_700_000_202)
            .await?
    );
    assert!(
        store
            .use_recovery_code(&factor.id, "hash-b", 1_700_000_203)
            .await?
    );

    // Subject lookup, drift persistence and factor deletion.
    assert!(store.find_subject(&tenant.id, "alice").await?.is_some());
    assert!(store.find_subject(&tenant.id, "nobody").await?.is_none());
    store.record_drift(&factor.id, -2).await?;
    let drifted = store
        .get_factor(&tenant.id, &subject.id, &factor.id)
        .await?
        .ok_or(Error::CorruptRow)?;
    assert_eq!(drifted.drift(), -2);
    store.delete_factor(&factor.id).await?;
    assert!(
        store
            .get_factor(&tenant.id, &subject.id, &factor.id)
            .await?
            .is_none()
    );
    assert!(store.list_recovery_hashes(&factor.id).await?.is_empty());

    // Sessions: create, refresh rotation, reuse signal, family revocation.
    let session = store
        .create_session(&tenant.id, &subject.id, 1_700_000_300)
        .await?;
    assert!(store.get_session(&session.id).await?.is_some());
    assert!(store.get_session("missing").await?.is_none());
    store
        .store_refresh(NewRefresh {
            code_hash: "rh-1".to_string(),
            family_id: "fam-1".to_string(),
            session_id: session.id.clone(),
            created_at: 1_700_000_300,
            expires_at: 1_700_000_300 + 604_800,
        })
        .await?;
    let entry = store.find_refresh("rh-1").await?.ok_or(Error::CorruptRow)?;
    assert_eq!(entry.family_id, "fam-1");
    assert!(store.find_refresh("missing").await?.is_none());
    assert!(store.use_refresh("rh-1", 1_700_000_301).await?);
    assert!(!store.use_refresh("rh-1", 1_700_000_302).await?);
    store.revoke_family("fam-1", 1_700_000_303).await?;
    let revoked = store.find_refresh("rh-1").await?.ok_or(Error::CorruptRow)?;
    assert!(revoked.revoked_at.is_some());
    store.revoke_session(&session.id, 1_700_000_304).await?;
    let dead = store
        .get_session(&session.id)
        .await?
        .ok_or(Error::CorruptRow)?;
    assert!(dead.revoked_at.is_some());

    // Audit log: the store chains each append to the current tip itself, so
    // the caller never supplies a hash. Genesis row comes first.
    let chainer = BatteryChain { key: 0xAB };
    store
        .append_audit_chained(
            NewAudit {
                ts: 1_700_000_400,
                tenant_id: tenant.id.clone(),
                subject_id: subject.id.clone(),
                event: "mfa.verified".to_string(),
                chain_version: NewAudit::CHAIN_V2,
            },
            &chainer,
        )
        .await?;
    store
        .append_audit_chained(
            NewAudit {
                ts: 1_700_000_401,
                tenant_id: tenant.id.clone(),
                subject_id: subject.id.clone(),
                event: "token.revoked".to_string(),
                chain_version: NewAudit::CHAIN_V2,
            },
            &chainer,
        )
        .await?;
    let entries = store.list_audit(100).await?;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].event, "mfa.verified");
    // First row chains to genesis; the second to the first row's hash.
    assert_eq!(entries[0].prev_hash, vec![0u8; 32]);
    assert_eq!(entries[1].prev_hash, entries[0].hash);
    assert_ne!(entries[0].hash, entries[1].hash);
    assert_eq!(entries[0].chain_version, NewAudit::CHAIN_V2);
    assert_eq!(entries[1].chain_version, NewAudit::CHAIN_V2);
    // The hash is the store's, derived inside the transaction.
    let expected = chainer.link(
        &NewAudit {
            ts: 1_700_000_400,
            tenant_id: tenant.id.clone(),
            subject_id: subject.id.clone(),
            event: "mfa.verified".to_string(),
            chain_version: NewAudit::CHAIN_V2,
        },
        &[0u8; 32],
    )?;
    assert_eq!(entries[0].hash, expected);

    // API clients: create, lookup, revoke.
    let client = store
        .create_api_client(NewApiClient {
            key_id: "key-1".to_string(),
            tenant_id: tenant.id.clone(),
            sealed_version: 1,
            kek_id: "kek-1".to_string(),
            wrapped_dek: vec![1u8; 48],
            wrapped_nonce: vec![2u8; 24],
            nonce: vec![3u8; 24],
            ciphertext: vec![4u8; 48],
            scopes: "verify".to_string(),
            created_at: 1_700_000_500,
        })
        .await?;
    assert!(client.revoked_at.is_none());
    assert!(store.find_api_client("key-1").await?.is_some());
    assert!(store.find_api_client("missing").await?.is_none());
    store.revoke_api_client("key-1", 1_700_000_501).await?;
    let dead_client = store
        .find_api_client("key-1")
        .await?
        .ok_or(Error::CorruptRow)?;
    assert!(dead_client.revoked_at.is_some());

    Ok(())
}

/// Appends under concurrency must produce one linear chain (T4).
///
/// The old two-call `last_audit_hash` + `append_audit` let two writers read
/// the same tip and fork the log. `append_audit_chained` reads the tip under a
/// lock, so a concurrent burst serializes: no two rows may share a
/// `prev_hash`, and every row must be reachable from the previous one.
pub async fn audit_chain_concurrency<S: Store + Send + Sync + 'static>(
    store: &Arc<S>,
) -> Result<(), Error> {
    const WRITERS: usize = 50;
    let chainer = Arc::new(BatteryChain { key: 0x11 });

    // `full_cycle` may already have appended rows to this store, so the burst
    // is checked from the tip it started at rather than from genesis.
    let before = store.list_audit(1_000).await?;
    let baseline = before.len();

    // Genuinely concurrent: every writer is polled as its own task, so they
    // contend for the tip instead of running one after another.
    let mut tasks = Vec::with_capacity(WRITERS);
    for index in 0..WRITERS {
        let entry = NewAudit {
            ts: 1_700_001_000 + i64::try_from(index).unwrap_or(0),
            tenant_id: format!("tenant-{index}"),
            subject_id: format!("subject-{index}"),
            event: "mfa.verified".to_string(),
            chain_version: NewAudit::CHAIN_V2,
        };
        let store = Arc::clone(store);
        tasks.push(tokio::spawn({
            let chainer = Arc::clone(&chainer);
            async move { store.append_audit_chained(entry, &chainer).await }
        }));
    }
    for task in tasks {
        task.await.map_err(|_| Error::CorruptRow)??;
    }

    let all = store.list_audit(1_000).await?;
    assert_eq!(all.len(), baseline + WRITERS);
    let burst = &all[baseline..];

    // Linear: every new row chains to its immediate predecessor, and the first
    // chains to whatever the tip was before the burst.
    let mut prev = before
        .last()
        .map_or_else(|| vec![0u8; 32], |entry| entry.hash.clone());
    for (index, entry) in burst.iter().enumerate() {
        assert_eq!(entry.prev_hash, prev, "fork or gap at row {index}");
        prev = entry.hash.clone();
    }
    // A forked chain repeats a predecessor; a linear one never does.
    let mut seen: Vec<Vec<u8>> = burst.iter().map(|e| e.prev_hash.clone()).collect();
    seen.sort();
    let distinct = seen.len();
    seen.dedup();
    assert_eq!(
        distinct,
        seen.len(),
        "two rows share a predecessor: the chain forked"
    );

    Ok(())
}

/// Shared rate-limit state (ADR-0008, T2): windowed counting, atomic
/// reservation, derived lockout and clear-on-success.
pub async fn auth_failures<S: Store>(store: &S) -> Result<(), Error> {
    use bandall_policy::{Decision, Limits};

    let limits = Limits {
        max_attempts: 2,
        window_secs: 1000,
        base_backoff_secs: 10,
        max_backoff_secs: 100,
        lockout_after: 4,
        lockout_secs: 500,
    };

    // Two attempts in the same second must both count: bursts must not
    // collapse into a single row.
    assert_eq!(
        store.reserve_auth_attempt("af", 1000, limits).await?,
        Decision::Allow
    );
    assert_eq!(
        store.reserve_auth_attempt("af", 1000, limits).await?,
        Decision::Allow
    );
    assert_eq!(store.count_auth_failures("af", 0).await?, 2);
    // Third within the window: backoff measured from the last attempt.
    assert_eq!(
        store.reserve_auth_attempt("af", 1000, limits).await?,
        Decision::RetryAfter(10)
    );
    // Refused attempts are not recorded.
    assert_eq!(store.count_auth_failures("af", 0).await?, 2);
    // Window filtering: nothing is newer than `since = 1000`.
    assert_eq!(store.count_auth_failures("af", 1000).await?, 0);
    // Success clears the key.
    store.clear_auth_failures("af").await?;
    assert_eq!(store.count_auth_failures("af", 0).await?, 0);
    assert_eq!(
        store.reserve_auth_attempt("af", 1000, limits).await?,
        Decision::Allow
    );

    // The single-append contract from ADR-0008 stays available.
    store.record_auth_failure("direct", 1000).await?;
    assert_eq!(store.count_auth_failures("direct", 0).await?, 1);
    store.clear_auth_failures("direct").await?;

    // Sustained abuse derives a lockout from the window.
    let strict = Limits {
        max_attempts: 1,
        window_secs: 1000,
        base_backoff_secs: 5,
        max_backoff_secs: 50,
        lockout_after: 2,
        lockout_secs: 500,
    };
    assert_eq!(
        store.reserve_auth_attempt("lk", 1000, strict).await?,
        Decision::Allow
    );
    assert_eq!(
        store.reserve_auth_attempt("lk", 1010, strict).await?,
        Decision::Allow
    );
    let locked = store.reserve_auth_attempt("lk", 1020, strict).await?;
    assert!(
        matches!(locked, Decision::Locked(_)),
        "expected lockout, got {locked:?}"
    );
    if let Decision::Locked(remaining) = locked {
        assert_eq!(remaining, 490);
    }

    // Concurrent burst: exactly `max_attempts` callers may proceed. Lockout
    // is disabled so the burst only measures the window ceiling.
    let burst = Limits {
        max_attempts: 5,
        lockout_after: 0,
        ..limits
    };
    let results = tokio::join!(
        store.reserve_auth_attempt("burst", 5000, burst),
        store.reserve_auth_attempt("burst", 5000, burst),
        store.reserve_auth_attempt("burst", 5000, burst),
        store.reserve_auth_attempt("burst", 5000, burst),
        store.reserve_auth_attempt("burst", 5000, burst),
        store.reserve_auth_attempt("burst", 5000, burst),
        store.reserve_auth_attempt("burst", 5000, burst),
        store.reserve_auth_attempt("burst", 5000, burst),
    );
    let decisions = [
        results.0?, results.1?, results.2?, results.3?, results.4?, results.5?, results.6?,
        results.7?,
    ];
    let allowed = decisions
        .iter()
        .filter(|decision| **decision == Decision::Allow)
        .count();
    assert_eq!(allowed, 5, "burst decisions: {decisions:?}");
    assert_eq!(store.count_auth_failures("burst", 4999).await?, 5);

    Ok(())
}
