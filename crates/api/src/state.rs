//! Shared application state: store, vault and service-key verifier.

use std::sync::{Arc, Mutex};

use subtle::ConstantTimeEq;

use bandall_policy::{Policy, PolicyConfig};
use bandall_sigs::NonceCache;
use bandall_store::Store;
use bandall_tokens::KeyManager;
use bandall_vault::Vault;

use crate::config::TrustedProxies;
use crate::metrics::Metrics;

/// Selected failure-tracker backend (ADR-0008).
#[derive(Clone)]
pub enum PolicyHandle {
    /// Process-local tracker: single replica, embedded mode, tests.
    Memory(Arc<Policy>),
    /// Shared `auth_failures` table: multi-replica service deployments.
    Database(PolicyConfig),
}

/// Application state shared by all handlers.
#[derive(Clone)]
pub struct AppState {
    /// Persistence backend.
    pub store: Arc<dyn Store>,
    /// Envelope vault.
    pub vault: Arc<Vault>,
    /// Signing keys (current plus rotation overlap).
    pub keys: Arc<KeyManager>,
    /// Failure tracker (rate limit, backoff, lockout).
    pub policy: PolicyHandle,
    /// Reverse proxies trusted to set `X-Forwarded-For`.
    pub trusted_proxies: Arc<TrustedProxies>,
    /// Process metrics (Prometheus exposition).
    pub metrics: Arc<Metrics>,
    /// Single-use HMAC nonces (process-local; Redis in H8 for multi-replica).
    pub nonces: Arc<Mutex<NonceCache>>,
    /// Token issuer (`iss`).
    pub issuer: String,
    /// Token audience (`aud`).
    pub audience: String,
    /// Static S2S service key (constant-time compared).
    service_key: Arc<str>,
}

impl AppState {
    /// Builds state. The service key lives in an `Arc<str>` (no `String`
    /// clones on the hot path, never logged).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<dyn Store>,
        vault: Arc<Vault>,
        keys: Arc<KeyManager>,
        policy: PolicyHandle,
        trusted_proxies: Arc<TrustedProxies>,
        issuer: String,
        audience: String,
        service_key: String,
    ) -> Self {
        Self {
            store,
            vault,
            keys,
            policy,
            trusted_proxies,
            metrics: Arc::new(Metrics::new()),
            nonces: Arc::new(Mutex::new(NonceCache::new())),
            issuer,
            audience,
            service_key: Arc::from(service_key),
        }
    }

    /// Constant-time service-key check for S2S endpoints.
    #[must_use]
    pub fn check_service_key(&self, candidate: &str) -> bool {
        let expected = self.service_key.as_bytes();
        let got = candidate.as_bytes();
        expected.len() == got.len() && bool::from(expected.ct_eq(got))
    }
}
