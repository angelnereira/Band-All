//! The `tonic` interceptor: one layer over a gRPC service.

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

use tonic::{Status, metadata::MetadataMap, service::Interceptor};

use crate::verify::{Verifier, VerifyError};

/// Minimal accepted claims, read from request extensions after the interceptor
/// accepts the token: what the handler may trust without re-verifying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcClaims {
    /// Subject id.
    pub sub: String,
    /// Tenant id.
    pub tenant: String,
    /// Session id (revocation handle).
    pub sid: String,
    /// Token expiry (Unix seconds): hard ceiling for long-lived streams.
    pub exp: u64,
}

/// Validates `authorization: Bearer …` on every gRPC request.
///
/// Attach it to a server with `Server::builder().interceptor(...)`, or to a
/// `Router`/`Grpc` route in tower service stacks.
pub struct RequireTokenInterceptor {
    verifier: std::sync::Arc<dyn Verifier>,
    issuer: String,
    audience: String,
}

impl RequireTokenInterceptor {
    /// `verifier` validates tokens (typically a `StaticJwks` built at startup
    /// or a `CachedJwks` over the issuer's `/.well-known/jwks.json`).
    #[must_use]
    pub fn new(verifier: std::sync::Arc<dyn Verifier>, issuer: &str, audience: &str) -> Self {
        Self {
            verifier,
            issuer: issuer.to_string(),
            audience: audience.to_string(),
        }
    }
}

impl Interceptor for RequireTokenInterceptor {
    fn call(&mut self, mut request: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let token = bearer(request.metadata()).ok_or_else(deny)?;
        let claims = self
            .verifier
            .verify(token, &self.issuer, &self.audience, now)
            .map_err(|err| match err {
                VerifyError::Transport => {
                    // The verifier could not even reach the document: that is
                    // an unavailable dependency, and the server must fail
                    // closed rather than let the request through.
                    Status::unavailable("authentication service unavailable")
                }
                _ => deny(),
            })?;

        // Stamp the claims + hard ceiling into the request so each handler
        // risks nothing. The ceiling is the point of this crate: a stream must
        // not outlive the credential that opened it.
        request.extensions_mut().insert(GrpcClaims {
            sub: claims.sub,
            tenant: claims.tenant,
            sid: claims.sid,
            exp: claims.exp,
        });
        Ok(request)
    }
}

/// Validates `authorization: Bearer …` from gRPC metadata.
fn bearer(metadata: &MetadataMap) -> Option<&str> {
    let value = metadata.get("authorization")?.to_str().ok()?;
    value.strip_prefix("Bearer ")
}

/// Uniform gRPC denial: `UNAUTHENTICATED` with a message that carries no
/// internals. Like the HTTP paths, "wrong token", "no token" and "unknown
/// service" all look the same.
fn deny() -> Status {
    Status::unauthenticated("authentication required")
}

impl std::fmt::Debug for RequireTokenInterceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequireTokenInterceptor")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::StaticJwks;
    use bandall_tokens::{KeyManager, issue};

    fn layer(keys: &KeyManager) -> RequireTokenInterceptor {
        let manager = std::sync::Arc::new(StaticJwks::new(bandall_tokens::document(keys)));
        RequireTokenInterceptor::new(manager, "https://bandall.example", "grpc-app")
    }

    fn request_with(token: Option<&str>) -> tonic::Request<()> {
        let mut request = tonic::Request::new(());
        if let Some(token) = token {
            request
                .metadata_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
        }
        request
    }

    #[test]
    fn accepts_a_valid_token_and_stamps_the_ceiling() {
        let keys = KeyManager::generate().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = bandall_tokens::Claims::new(
            "https://bandall.example".to_string(),
            "grpc-app".to_string(),
            "alice".to_string(),
            "acme".to_string(),
            "session-1".to_string(),
            now,
        )
        .unwrap();
        let token = issue(&keys, &claims).unwrap();

        let accepted = layer(&keys).call(request_with(Some(&token))).unwrap();
        let stamped = accepted.extensions().get::<GrpcClaims>().unwrap();
        assert_eq!(stamped.sub, "alice");
        assert_eq!(stamped.tenant, "acme");
        assert_eq!(stamped.sid, "session-1");
        assert!(stamped.exp > now, "the ceiling is `exp`, in the future");
    }

    #[test]
    fn denies_without_a_token() {
        let denied = layer(&KeyManager::generate().unwrap()).call(request_with(None));
        assert_eq!(denied.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn denies_a_forged_or_tampered_token() {
        let denied =
            layer(&KeyManager::generate().unwrap()).call(request_with(Some("not-a-token")));
        assert_eq!(denied.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn denies_a_token_for_another_audience() {
        let keys = KeyManager::generate().unwrap();
        let claims = bandall_tokens::Claims::new(
            "https://bandall.example".to_string(),
            "other-app".to_string(),
            "alice".to_string(),
            "acme".to_string(),
            "s".to_string(),
            1_700_000_000,
        )
        .unwrap();
        let token = issue(&keys, &claims).unwrap();

        let denied = layer(&KeyManager::generate().unwrap()).call(request_with(Some(&token)));
        assert_eq!(denied.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn denies_an_expired_token() {
        let keys = KeyManager::generate().unwrap();
        let expired = bandall_tokens::Claims::new(
            "https://bandall.example".to_string(),
            "grpc-app".to_string(),
            "alice".to_string(),
            "acme".to_string(),
            "s".to_string(),
            1_699_900_000, // ten minutes ago
        )
        .unwrap();
        let token = issue(&keys, &expired).unwrap();

        let denied = layer(&keys).call(request_with(Some(&token)));
        assert_eq!(denied.unwrap_err().code(), tonic::Code::Unauthenticated);
    }
}
