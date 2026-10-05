//! `bandall-sdk-axum`: tower layer that enforces a valid BandAll access
//! token and injects its claims into request extensions.
//!
//! Services behind BandAll validate offline with the shared `KeyManager`
//! (JWKS snapshot): zero network hops on the hot path. Rejected requests get
//! an empty 401; downstream handlers read `Claims` from extensions.
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

use axum::http::{Request, Response, StatusCode};
use bandall_tokens::{Claims, KeyManager};
use tower::{Layer, Service};

/// Layer enforcing a Bearer access token with a minimum AAL.
#[derive(Debug, Clone)]
pub struct RequireToken {
    keys: Arc<KeyManager>,
    issuer: String,
    audience: String,
    min_aal: u8,
}

impl RequireToken {
    /// Builds the layer. `keys` is the JWKS snapshot shared with the API.
    pub fn new(keys: Arc<KeyManager>, issuer: String, audience: String, min_aal: u8) -> Self {
        Self {
            keys,
            issuer,
            audience,
            min_aal,
        }
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
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + 'static,
    S::Future: Send + 'static,
    ReqBody: 'static,
    ResBody: Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response<ResBody>, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        match check(&self.config, req.headers(), now_unix().unwrap_or(0)) {
            Ok(claims) => {
                req.extensions_mut().insert(claims);
                Box::pin(self.inner.call(req))
            }
            Err(_) => {
                let mut response = Response::new(ResBody::default());
                *response.status_mut() = StatusCode::UNAUTHORIZED;
                Box::pin(async move { Ok(response) })
            }
        }
    }
}

fn check(
    config: &RequireToken,
    headers: &axum::http::HeaderMap,
    now_secs: u64,
) -> Result<Claims, ()> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(())?;
    let claims = bandall_tokens::verify(
        &config.keys,
        token,
        &config.issuer,
        &config.audience,
        now_secs,
    )
    .map_err(|_| ())?;
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
            .layer(RequireToken::new(
                keys,
                "https://bandall.example".to_string(),
                "my-app".to_string(),
                1,
            ))
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

    fn now_for_test() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}
