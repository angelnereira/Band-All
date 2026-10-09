//! WebSocket ticket semantics (ADR-0017): hash-only, atomic single claim,
//! expiry checked by the caller after the claim.
//!
//! Shared by both backends via `tests_battery::ws_tickets`; every property
//! here is a property each engine must hold.

use std::sync::Arc;

use crate::error::Error;
use crate::store::Store;
use crate::types::NewWsTicket;

pub async fn ws_tickets<S: Store + Send + Sync + 'static>(store: &Arc<S>) -> Result<(), Error> {
    // Tickets reference a real session, which references a real tenant and
    // subject: both backends enforce the foreign keys, so the whole chain is
    // created instead of assumed.
    let tenant = store.create_tenant("ws-test", 1_700_000_000).await?;
    let subject = store
        .create_subject(&tenant.id, "ws-test-subject", 1_700_000_000)
        .await?;
    let session = store
        .create_session(&tenant.id, &subject.id, 1_700_000_000)
        .await?;

    let new_ticket = |hash: &str, expires_at: i64| NewWsTicket {
        code_hash: hash.to_string(),
        session_id: session.id.clone(),
        tenant_id: tenant.id.clone(),
        subject_id: subject.id.clone(),
        access_expires_at: 1_700_002_000,
        created_at: 1_700_000_000,
        expires_at,
    };

    // Store and claim once: the winner comes back whole.
    let hash_a = "ticket-hash-a";
    store
        .store_ws_ticket(new_ticket(hash_a, 1_700_000_060))
        .await?;
    let claimed = store
        .claim_ws_ticket(hash_a, 1_700_000_030)
        .await?
        .ok_or(Error::CorruptRow)?;
    assert_eq!(claimed.code_hash, hash_a);
    assert_eq!(claimed.session_id, session.id);
    assert_eq!(claimed.access_expires_at, 1_700_002_000);
    assert_eq!(claimed.used_at, Some(1_700_000_030));

    // A spent ticket is gone: no second winner.
    assert!(
        store
            .claim_ws_ticket(hash_a, 1_700_000_031)
            .await?
            .is_none(),
        "a ticket can only be claimed once"
    );

    // Unknown tickets claim nothing.
    assert!(
        store
            .claim_ws_ticket("no-such-ticket", 1_700_000_032)
            .await?
            .is_none()
    );

    // The claim stays single across genuinely concurrent callers: 25 readers
    // try the same ticket and exactly one returns a row.
    let hash_b = "ticket-hash-b";
    store
        .store_ws_ticket(new_ticket(hash_b, 1_700_000_090))
        .await?;
    let mut tasks = Vec::with_capacity(25);
    for _ in 0..25 {
        let store = Arc::clone(store);
        tasks.push(tokio::spawn(async move {
            store.claim_ws_ticket(hash_b, 1_700_000_040).await
        }));
    }
    let mut winners = 0usize;
    for task in tasks {
        if task.await.map_err(|_| Error::CorruptRow)??.is_some() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1, "exactly one concurrent claim must win");

    Ok(())
}
