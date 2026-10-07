//! H2 gate: "ningún secreto aparece en claro en la DB ni en logs".
//!
//! The gate had no test behind it. This file closes that: it runs the real
//! enrolment and verification path against a **file-backed** SQLite database,
//! then scans the raw database bytes for anything that should only ever exist
//! sealed.
//!
//! Scanning the file (rather than querying columns) is deliberate: it also
//! catches a future column, index, WAL frame or error message that happens to
//! carry plaintext, which a per-column assertion would miss.
//!
//! Test-only unwraps are allowed here by policy (see crate `AGENTS.md`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use axum::{Json, extract::State, http::HeaderMap};
use bandall_api::{
    AppState, AuditChain,
    config::TrustedProxies,
    enroll::{EnrollConfirmRequest, EnrollStartRequest, confirm, start},
    gates::PeerAddr,
    state::PolicyHandle,
    verify::{MfaVerifyRequest, mfa_verify},
};
use bandall_policy::Policy;
use bandall_store::{SqliteStore, Store};
use bandall_tokens::KeyManager;
use bandall_totp_core::{Secret, TotpParams, totp};
use bandall_vault::{LocalKms, Vault};

const SERVICE_KEY: &str = "at-rest-service-key-0123456789abcdef";
/// 32-byte KEK for the throwaway vault of this test.
const KEK: [u8; 32] = [0x5A; 32];
/// 32-byte audit key for the throwaway chain of this test.
const AUDIT_KEY: [u8; 32] = [0x3C; 32];

/// A database file that removes itself on drop, so a failing assertion still
/// cleans up.
struct TempDb {
    path: std::path::PathBuf,
}

impl TempDb {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("bandall-at-rest-{tag}-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        Self { path }
    }

    fn url(&self) -> String {
        format!("sqlite:{}", self.path.display())
    }

    /// Raw bytes of the database file, plus its sidecars. SQLite in WAL mode
    /// keeps recent writes in `-wal`, so scanning only the main file would
    /// miss exactly the rows this test is about.
    fn all_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let candidate = std::path::PathBuf::from(format!("{}{suffix}", self.path.display()));
            if let Ok(part) = std::fs::read(&candidate) {
                bytes.extend_from_slice(&part);
            }
        }
        assert!(
            !bytes.is_empty(),
            "database file is empty: nothing was scanned"
        );
        bytes
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.path.display()));
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Extracts the `secret` query value from an `otpauth://` URI.
fn uri_secret(uri: &str) -> String {
    uri.split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string()
}

/// True when `haystack` contains any non-trivial substring of `needle`.
///
/// A raw `contains` is the right check for the Base32 form and for the
/// recovery codes. For raw secret bytes it is still valid, but a short needle
/// could match by chance in a multi-megabyte file, so callers pass values long
/// enough that a hit is meaningful.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

async fn state_with(db: &TempDb) -> AppState {
    let sqlite = SqliteStore::connect(&db.url()).await.unwrap();
    sqlite.migrate().await.unwrap();
    let store: Arc<dyn Store> = Arc::new(sqlite);
    let kms = LocalKms::from_bytes("kek-at-rest".to_string(), KEK.to_vec()).unwrap();
    let vault = Arc::new(Vault::new(Arc::new(kms)));
    let keys = Arc::new(KeyManager::generate().unwrap());
    let policy = PolicyHandle::Memory(Arc::new(Policy::default()));
    let audit = Arc::new(AuditChain::from_bytes(AUDIT_KEY));
    AppState::new(
        store,
        vault,
        keys,
        policy,
        audit,
        Arc::new(TrustedProxies::default()),
        "https://bandall.example".to_string(),
        "at-rest".to_string(),
        SERVICE_KEY.to_string(),
    )
}

/// The TOTP secret, its Base32 form and the recovery codes must never hit the
/// database in the clear: the gate H2 exists for.
#[tokio::test]
async fn no_secret_material_reaches_the_database_in_clear() {
    let db = TempDb::new("secrets");
    let state = state_with(&db).await;
    let tenant = state
        .store
        .create_tenant("at-rest", 1_700_000_000)
        .await
        .unwrap();

    // Real enrolment: the same handlers the API serves.
    let started = start(
        State(state.clone()),
        {
            let mut headers = HeaderMap::new();
            headers.insert("x-service-key", SERVICE_KEY.parse().unwrap());
            headers
        },
        Json(EnrollStartRequest {
            tenant_id: tenant.id.clone(),
            subject_external_id: "alice".to_string(),
            issuer: "BandAll".to_string(),
            account: "alice@example.com".to_string(),
            algorithm: None,
            digits: None,
            period: None,
        }),
    )
    .await
    .unwrap()
    .0;

    let secret_base32 = uri_secret(&started.otpauth_uri);
    let secret = Secret::from_base32(&secret_base32).unwrap();
    let subject = state
        .store
        .find_subject(&tenant.id, "alice")
        .await
        .unwrap()
        .unwrap();

    let params = TotpParams::default_params();
    let code = totp::generate(&secret, params, now_unix()).unwrap();
    let confirmed = confirm(
        State(state.clone()),
        HeaderMap::new(),
        PeerAddr(None),
        Json(EnrollConfirmRequest {
            tenant_id: tenant.id.clone(),
            subject_id: subject.id.clone(),
            factor_id: started.factor_id.clone(),
            code: code.clone(),
        }),
    )
    .await
    .unwrap()
    .0;

    assert_eq!(
        confirmed.recovery_codes.len(),
        10,
        "the test needs real codes"
    );

    // A successful verification writes session, refresh and audit rows too, so
    // the scan covers every table a login touches.
    let verified = mfa_verify(
        State(state.clone()),
        HeaderMap::new(),
        PeerAddr(None),
        Json(MfaVerifyRequest {
            tenant_id: tenant.id.clone(),
            subject_id: subject.id.clone(),
            factor_id: started.factor_id.clone(),
            // One step ahead: the current step was consumed at confirmation.
            code: totp::generate(&secret, params, now_unix() + 30).unwrap(),
        }),
    )
    .await;
    assert!(
        verified.is_ok(),
        "verification must succeed so more rows exist"
    );

    let bytes = db.all_bytes();

    // 1. The raw secret bytes. 20 bytes is long enough that a match in the
    //    file cannot be a coincidence.
    assert!(
        !contains(&bytes, secret.expose_secret_bytes()),
        "raw TOTP secret found in the database file"
    );
    // 2. The Base32 form, which is what a QR leak would expose.
    assert!(
        !contains(&bytes, secret_base32.as_bytes()),
        "Base32 secret found in the database file"
    );
    // 3. Recovery codes, which are bearer credentials: only their hashes may
    //    be stored.
    for recovery in &confirmed.recovery_codes {
        assert!(
            !contains(&bytes, recovery.as_bytes()),
            "recovery code found in the database file"
        );
    }
    // 4. The audit-chain key, which must live outside the database.
    assert!(
        !contains(&bytes, &AUDIT_KEY),
        "audit key found in the database file"
    );

    // Sanity check the other direction: the scan must be able to find things
    // that ARE stored, or the assertions above would pass on a broken scan.
    assert!(
        contains(&bytes, tenant.id.as_bytes()),
        "the scan cannot even find a tenant id: it is not scanning the file"
    );
}

/// The sealed material must actually be present, so the test above is not
/// passing because nothing was written.
#[tokio::test]
async fn sealed_material_is_stored_and_decrypts() {
    let db = TempDb::new("sealed");
    let state = state_with(&db).await;
    let tenant = state
        .store
        .create_tenant("at-rest", 1_700_000_000)
        .await
        .unwrap();
    let subject = state
        .store
        .create_subject(&tenant.id, "alice", 1_700_000_000)
        .await
        .unwrap();

    // Seal a recognizable secret and store it exactly as the enrolment path
    // does, then prove the ciphertext is real (not the plaintext) and that the
    // vault can open it back to the original bytes.
    let plaintext = b"at-rest-known-plaintext-secret";
    let sealed = state
        .vault
        .seal(&tenant.id, &subject.id, "factor-1", plaintext)
        .unwrap();
    assert!(
        !contains(sealed.ciphertext(), plaintext),
        "the vault returned the plaintext as ciphertext"
    );

    let factor = bandall_store::NewFactor {
        id: "factor-1".to_string(),
        tenant_id: tenant.id.clone(),
        subject_id: subject.id.clone(),
        status: "active".to_string(),
        secret_version: 1,
        kek_id: state.vault.kek_id().to_string(),
        wrapped_dek: sealed.wrapped_dek().ciphertext().to_vec(),
        wrapped_nonce: sealed.wrapped_dek().nonce().to_vec(),
        nonce: sealed.nonce().to_vec(),
        ciphertext: sealed.ciphertext().to_vec(),
        algorithm: "SHA1".to_string(),
        digits: 6,
        period: 30,
        created_at: 1_700_000_000,
    };
    state.store.create_factor(factor).await.unwrap();

    let stored = state
        .store
        .get_factor(&tenant.id, &subject.id, "factor-1")
        .await
        .unwrap()
        .unwrap();

    // Ciphertext on disk, plaintext only after unwrapping.
    let on_disk = db.all_bytes();
    assert!(
        !contains(&on_disk, plaintext),
        "plaintext secret found in the database file"
    );

    // Reassemble exactly what was persisted and open it: proof that the row is
    // recoverable, so the scan above is not passing because nothing usable was
    // stored.
    let nonce: [u8; 24] = stored
        .nonce
        .as_slice()
        .try_into()
        .expect("24-byte data nonce");
    let wrapped_nonce: [u8; 24] = stored
        .wrapped_nonce
        .as_slice()
        .try_into()
        .expect("24-byte wrap nonce");
    let sealed = bandall_vault::SealedSecret::reassemble(
        u8::try_from(stored.secret_version).expect("version fits in u8"),
        stored.kek_id.clone(),
        bandall_vault::WrappedDek::new(wrapped_nonce, stored.wrapped_dek.clone()),
        nonce,
        stored.ciphertext.clone(),
    );
    let opened = state
        .vault
        .open(&sealed, &stored.tenant_id, &stored.subject_id, &stored.id)
        .unwrap();
    use secrecy::ExposeSecret;
    assert_eq!(
        opened.expose_secret().as_slice(),
        plaintext,
        "round trip lost the secret"
    );
}
