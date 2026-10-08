//! How a presented token is checked, for the grpc interceptor.
//!
//! The verifier is a small trait so the interceptor can be tested with a
//! canned document instead of a network call to a live JWKS endpoint. The real
//! implementation fetches the document once and caches it, exactly like
//! `bandall-sdk-axum`'s `JwksVerifier` (ADR-0013).

use bandall_tokens::{Claims, Jwks, verify_with_jwks};

/// Errors the interceptor turns into `UNAUTHENTICATED`. The message is never
/// sent to the caller: the interceptor answers uniformly.
#[derive(Debug)]
pub enum VerifyError {
    /// No `authorization` metadata, not a `Bearer` form, unparseable.
    Missing,
    /// Presented, but the token itself is not valid (algorithm, signature,
    /// `iss`/`aud`/`exp`).
    Invalid,
    /// The gRPC metadata channel failed (should not happen; fail closed).
    Transport,
}

/// Wraps the strict `verify_with_jwks` semantics, adjusted for gRPC.
pub trait Verifier: Send + Sync + 'static {
    /// Verifies `token` against `iss`/`aud` at `now_secs`.
    fn verify(
        &self,
        token: &str,
        issuer: &str,
        audience: &str,
        now_secs: u64,
    ) -> Result<Claims, VerifyError>;
}

/// Verifies strictly against a JWKS document held in memory.
///
/// The document is provided by the caller (typically fetched once at startup,
/// or kept up to date beside the SDK); `verify_with_jwks` is the same code
/// path the server and the axum SDK use.
pub struct StaticJwks {
    jwks: Jwks,
}

impl std::fmt::Debug for StaticJwks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticJwks")
            .field("keys", &self.jwks.keys.len())
            .finish()
    }
}

impl StaticJwks {
    /// Wraps a document (e.g. from `GET /.well-known/jwks.json` at startup).
    #[must_use]
    pub fn new(jwks: Jwks) -> Self {
        Self { jwks }
    }
}

impl Verifier for StaticJwks {
    fn verify(
        &self,
        token: &str,
        issuer: &str,
        audience: &str,
        now_secs: u64,
    ) -> Result<Claims, VerifyError> {
        verify_with_jwks(&self.jwks, token, issuer, audience, now_secs)
            .map_err(|_| VerifyError::Invalid)
    }
}

/// Refreshing cache: fetches the document on first use (or after TTL) via a
/// callback the integration supplies, so this crate stays network-free. A
/// failed refresh keeps serving the previous document; a failed first fetch
/// fails the request (fail closed).
pub struct CachedJwks {
    inner: std::sync::Mutex<Option<(Jwks, std::time::Instant)>>,
    ttl: std::time::Duration,
    fetch: Box<dyn Fn() -> std::result::Result<Jwks, ()> + Send + Sync>,
}

impl std::fmt::Debug for CachedJwks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedJwks")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl CachedJwks {
    /// `fetch` must be cheap to call and may do whatever the integration needs
    /// (an HTTP GET, a file read, a probe) — it is called at most once per TTL.
    #[must_use]
    pub fn new(
        ttl: std::time::Duration,
        fetch: Box<dyn Fn() -> std::result::Result<Jwks, ()> + Send + Sync>,
    ) -> Self {
        Self {
            inner: std::sync::Mutex::new(None),
            ttl,
            fetch,
        }
    }
}

impl Verifier for CachedJwks {
    fn verify(
        &self,
        token: &str,
        issuer: &str,
        audience: &str,
        now_secs: u64,
    ) -> Result<Claims, VerifyError> {
        let now = std::time::Instant::now();
        let mut guard = self.inner.lock().map_err(|_| VerifyError::Transport)?;
        let refresh = match guard.as_ref() {
            None => true,
            Some((_, fetched)) => fetched.elapsed() >= self.ttl,
        };
        if refresh {
            if let Ok(jwks) = (self.fetch)() {
                *guard = Some((jwks, now));
            } else if guard.is_none() {
                // First fetch failed and there is nothing to trust: deny.
                return Err(VerifyError::Transport);
            }
        }
        let (jwks, _) = guard.as_ref().ok_or(VerifyError::Transport)?;
        verify_with_jwks(jwks, token, issuer, audience, now_secs).map_err(|_| VerifyError::Invalid)
    }
}
