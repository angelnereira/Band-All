//! Shared conformance battery: every backend must pass it identically.
//! Executed by CI (SQLite in-memory always, Postgres via service container).

use crate::error::Error;
use crate::store::Store;
use crate::types::{NewApiClient, NewFactor, NewRefresh, new_factor_id};

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

    // Audit log: append-only with genesis hash.
    assert!(store.last_audit_hash().await?.is_none());
    store
        .append_audit(
            1_700_000_400,
            &tenant.id,
            &subject.id,
            "mfa.verified",
            &[0u8; 32],
            &[1u8; 32],
        )
        .await?;
    let tip = store.last_audit_hash().await?.ok_or(Error::CorruptRow)?;
    assert_eq!(tip, vec![1u8; 32]);
    store
        .append_audit(
            1_700_000_401,
            &tenant.id,
            &subject.id,
            "token.revoked",
            &[1u8; 32],
            &[2u8; 32],
        )
        .await?;
    let entries = store.list_audit(100).await?;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].event, "mfa.verified");
    assert_eq!(entries[1].prev_hash, vec![1u8; 32]);

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

    // Concurrent burst: exactly `max_attempts` callers may proceed.
    let burst = Limits {
        max_attempts: 5,
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
