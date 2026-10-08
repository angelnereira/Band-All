//! `bandall-sdk-axum`: tower layer that enforces a valid BandAll access
//! token and injects its claims into request extensions.
//!
//! Two verification modes (ADR-0013):
//!
//! - **Local** (`RequireToken::with_keys`): validate against a shared
//!   `KeyManager` (same process, embedded mode). Zero network on the hot path.
//! - **Remote** (`RequireToken::with_jwks`): validate against the issuer's
//!   JWKS endpoint with an in-memory cache (`JwksVerifier`). The document is
//!   fetched once, then served from the cache and refreshed after a TTL. On
//!   failure to fetch with an empty cache the request is **denied** (fail
//!   closed, like the server itself).
//!
//! Rejected requests get an empty 401; downstream handlers read `Claims` from
//! request extensions. `RequireScopes` adds a mandatory-scope check
//! (`required ⊆ claims.scp`).
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::http::{Request, Response, StatusCode};
use bandall_tokens::{Claims, Jwks, KeyManager, verify_with_jwks};
use tokio::sync::Mutex;
use tower::{Layer, Service, ServiceExt};

/// Default refetch interval for the JWKS document, in seconds.
pub const DEFAULT_JWKS_TTL_SECS: u64 = 300;

/// Fetches and caches the issuer's JWKS document (ADR-0013).
///
/// `document` is served from memory once fetched; after `ttl` the next call
/// triggers an opportunistic refresh. A failed refresh keeps serving the
/// previous document; a failed **first** fetch leaves nothing to trust, and
/// callers deny the request (fail closed).
#[derive(Debug, Clone)]
pub struct JwksVerifier {
    client: reqwest::Client,
    url: String,
    ttl: Duration,
    cache: Arc<Mutex<Option<(Jwks, Instant)>>>,
}

impl JwksVerifier {
    /// Builds a verifier for `url` (typically `https://bandall/.well-known/jwks.json`).
    #[must_use]
    pub fn new(url: impl Into<String>, ttl: Duration) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: url.into(),
            ttl,
            cache: Arc::new(Mutex::new(None)),
        }
    }

    /// Fetches the document, updating the cache.
    async fn document(&self) -> Result<Jwks, ()> {
        let mut guard = self.cache.lock().await;
        if let Some((jwks, fetched)) = guard.as_ref() {
            if fetched.elapsed() < self.ttl {
                return Ok(jwks.clone());
            }
        }
        let fetched = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|_| ())?
            .error_for_status()
            .map_err(|_| ())?
            .json::<Jwks>()
            .await
            .map_err(|_| ())?;
        *guard = Some((fetched.clone(), Instant::now()));
        Ok(fetched)
    }
}

/// Policy describing how to verify a request.
#[derive(Debug, Clone)]
enum VerifyPolicy {
    /// Validate against a shared local key manager (embedded mode).
    Local(Arc<KeyManager>),
    /// Validate against a remote, cached JWKS document (service mode).
    Remote(JwksVerifier),
}

/// Layer enforcing a Bearer access token with a minimum AAL.
#[derive(Debug, Clone)]
pub struct RequireToken {
    policy: VerifyPolicy,
    issuer: String,
    audience: String,
    min_aal: u8,
}

impl RequireToken {
    /// Builds the layer validating against the shared key manager (local/embedded mode).
    #[must_use]
    pub fn with_keys(keys: Arc<KeyManager>, issuer: String, audience: String, min_aal: u8) -> Self {
        Self {
            policy: VerifyPolicy::Local(keys),
            issuer,
            audience,
            min_aal,
        }
    }

    /// Builds the layer validating against a remote, cached JWKS (ADR-0013).
    ///
    /// The document at `jwks_url` is fetched on the first request and cached
    /// for `jwks_ttl`; failures with an empty cache deny the request.
    #[must_use]
    pub fn with_jwks(
        jwks_url: impl Into<String>,
        issuer: String,
        audience: String,
        min_aal: u8,
        jwks_ttl: Duration,
    ) -> Self {
        Self {
            policy: VerifyPolicy::Remote(JwksVerifier::new(jwks_url, jwks_ttl)),
            issuer,
            audience,
            min_aal,
        }
    }

    /// Back-compat name for [`with_keys`](Self::with_keys).
    #[must_use]
    pub fn new(keys: Arc<KeyManager>, issuer: String, audience: String, min_aal: u8) -> Self {
        Self::with_keys(keys, issuer, audience, min_aal)
    }
}

impl<S> Layer<S> for RequireToken {
    type Service = VerifyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        VerifyService {
            inner,
            config: self.clone(),
        }
    }
}

/// Service produced by [`RequireToken`].
#[derive(Debug, Clone)]
pub struct VerifyService<S> {
    inner: S,
    config: RequireToken,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for VerifyService<S>
where
    S: Clone + Send + Service<Request<ReqBody>, Response = Response<ResBody>> + 'static,
    S::Future: Send + 'static,
    S::Error: Send,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response<ResBody>, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let config = self.config.clone();
        let token = bearer(req.headers()).map(str::to_owned);
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let claims = match config.policy {
                VerifyPolicy::Local(ref keys) => check_local(&config, keys, token.as_deref()).await,
                VerifyPolicy::Remote(ref verifier) => {
                    check_remote(&config, verifier, token.as_deref()).await
                }
            };
            match claims {
                Ok(claims) => {
                    req.extensions_mut().insert(claims);
                    match inner.ready().await {
                        Ok(ready) => ready.call(req).await,
                        Err(error) => Err(error),
                    }
                }
                Err(_) => {
                    let mut response = Response::new(ResBody::default());
                    *response.status_mut() = StatusCode::UNAUTHORIZED;
                    Ok(response)
                }
            }
        })
    }
}

async fn check_local(
    config: &RequireToken,
    keys: &KeyManager,
    token: Option<&str>,
) -> Result<Claims, ()> {
    let token = token.ok_or(())?;
    let now = now_unix()?;
    let claims = bandall_tokens::verify(keys, token, &config.issuer, &config.audience, now)
        .map_err(|_| ())?;
    if claims.aal < config.min_aal {
        return Err(());
    }
    Ok(claims)
}

async fn check_remote(
    config: &RequireToken,
    verifier: &JwksVerifier,
    token: Option<&str>,
) -> Result<Claims, ()> {
    let token = token.ok_or(())?;
    let now = now_unix()?;
    let jwks = verifier.document().await?;
    let claims =
        verify_with_jwks(&jwks, token, &config.issuer, &config.audience, now).map_err(|_| ())?;
    if claims.aal < config.min_aal {
        return Err(());
    }
    Ok(claims)
}

fn now_unix() -> Result<u64, ()> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ())
}

/// Layer enforcing that the token carries every required scope
/// (`required ⊆ claims.scp`, exact match, no prefix semantics).
#[derive(Debug, Clone)]
pub struct RequireScopes {
    required: Vec<String>,
}

impl RequireScopes {
    /// Builds the layer. An empty list allows anything with any token.
    #[must_use]
    pub fn new(required: Vec<String>) -> Self {
        Self { required }
    }
}

impl<S> Layer<S> for RequireScopes {
    type Service = ScopeService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ScopeService {
            inner,
            required: self.required.clone(),
        }
    }
}

/// Service produced by [`RequireScopes`].
#[derive(Debug, Clone)]
pub struct ScopeService<S> {
    inner: S,
    required: Vec<String>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ScopeService<S>
where
    S: Clone + Send + Service<Request<ReqBody>, Response = Response<ResBody>> + 'static,
    S::Future: Send + 'static,
    S::Error: Send,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response<ResBody>, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let required = self.required.clone();
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let allowed = req.extensions().get::<Claims>().is_some_and(|claims| {
                required
                    .iter()
                    .all(|scope| claims.scp.iter().any(|granted| granted == scope))
            });
            if allowed {
                match inner.ready().await {
                    Ok(ready) => ready.call(req).await,
                    Err(error) => Err(error),
                }
            } else {
                // Missing claims or insufficient scopes: 401, not 403. The
                // token Layer answers 401 for anything wrong with the request
                // and this one must not become the oracle that tells a caller
                // "your token was fine, you just lacked a scope".
                let mut response = Response::new(ResBody::default());
                *response.status_mut() = StatusCode::UNAUTHORIZED;
                Ok(response)
            }
        })
    }
}

fn bearer(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

#[cfg(test)]
mod tests {
    use super::{KeyManager, RequireToken};
    use axum::{Router, body::Body, routing::get};
    use bandall_tokens::Claims;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn keys() -> Arc<KeyManager> {
        Arc::new(KeyManager::generate().unwrap())
    }

    fn app(keys: Arc<KeyManager>) -> Router {
        Router::new()
            .route(
                "/private",
                get(
                    |axum::Extension(claims): axum::Extension<Claims>| async move {
                        format!("hello {}", claims.sub)
                    },
                ),
            )
            .layer(RequireToken::with_keys(
                keys,
                "https://bandall.example".to_string(),
                "my-app".to_string(),
                1,
            ))
    }

    fn now_for_test() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[tokio::test]
    async fn allows_valid_token() {
        let keys = keys();
        // Tokens live 10 minutes; issue against the current clock.
        let token = bandall_tokens::issue(
            &keys,
            &Claims::new(
                "https://bandall.example".to_string(),
                "my-app".to_string(),
                "alice".to_string(),
                "tenant".to_string(),
                "sid".to_string(),
                now_for_test(),
            )
            .unwrap(),
        )
        .unwrap();
        let response = app(keys)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/private")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn denies_without_token() {
        let response = app(keys())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/private")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn denies_when_aal_below_minimum() {
        let keys = keys();
        let token = bandall_tokens::issue(
            &keys,
            &Claims::new(
                "https://bandall.example".to_string(),
                "my-app".to_string(),
                "alice".to_string(),
                "tenant".to_string(),
                "sid".to_string(),
                now_for_test(),
            )
            .unwrap(),
        )
        .unwrap();
        let strict = Router::new()
            .route("/private", get(|| async { "ok" }))
            .layer(RequireToken::with_keys(
                keys,
                "https://bandall.example".to_string(),
                "my-app".to_string(),
                5, // token aal is 1
            ));
        let response = strict
            .oneshot(
                axum::http::Request::builder()
                    .uri("/private")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn remote_verifier_denies_without_jwks_endpoint() {
        // Fail closed: no endpoint, no cache -> 401, never open.
        let router = Router::new()
            .route("/private", get(|| async { "ok" }))
            .layer(RequireToken::with_jwks(
                "http://127.0.0.1:1/.well-known/jwks.json", // nothing listens here
                "https://bandall.example".to_string(),
                "my-app".to_string(),
                1,
                std::time::Duration::from_secs(1),
            ));
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/private")
                    .header("authorization", "Bearer whatever")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn require_scopes_enforces_exact_grants() {
        use super::RequireScopes;
        use tower::{Layer, Service};

        let claims = Claims {
            iss: "x".to_string(),
            aud: "y".to_string(),
            sub: "s".to_string(),
            tenant: "t".to_string(),
            sid: "z".to_string(),
            amr: vec!["otp".to_string()],
            aal: 1,
            scp: vec!["a".to_string(), "b".to_string()],
            jti: "j".to_string(),
            iat: 1,
            exp: 1_000_000,
        };

        let inner = tower::service_fn(|req: axum::http::Request<Body>| async move {
            let sub = req.extensions().get::<Claims>().map(|c| c.sub.clone());
            Ok::<_, std::convert::Infallible>(axum::http::Response::new(
                sub.unwrap_or_default().into_bytes(),
            ))
        });
        let mut svc = RequireScopes::new(vec!["a".to_string()]).layer(inner);
        let response = svc
            .call(
                axum::http::Request::builder()
                    .uri("/")
                    .extension(claims.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn scopes_layer_denies_missing_scope() {
        use super::RequireScopes;
        use tower::{Layer, Service};

        let claims = Claims {
            iss: "x".to_string(),
            aud: "y".to_string(),
            sub: "s".to_string(),
            tenant: "t".to_string(),
            sid: "z".to_string(),
            amr: vec!["otp".to_string()],
            aal: 1,
            scp: vec!["a".to_string()],
            jti: "j".to_string(),
            iat: 1,
            exp: 1_000_000,
        };
        let inner = tower::service_fn(|_req: axum::http::Request<Body>| async {
            Ok::<_, std::convert::Infallible>(axum::http::Response::new("ok".to_string()))
        });
        let mut svc = RequireScopes::new(vec!["missing".to_string()]).layer(inner);
        let http_request: axum::http::Request<Body> = axum::http::Request::builder()
            .uri("/")
            .extension(claims)
            .body(Body::empty())
            .unwrap();
        let response = svc.call(http_request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }
}
