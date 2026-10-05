//! Shared conformance battery: every backend must pass it identically.
//! Executed by CI (SQLite in-memory always, Postgres via service container).

use crate::error::Error;
use crate::store::Store;
use crate::types::{NewFactor, NewRefresh, new_factor_id};

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

    Ok(())
}
