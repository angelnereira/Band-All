//! Router assembly and server startup.
//!
//! Middleware order (outside in): request tracing, body limit, timeout.
//! Graceful shutdown drains in-flight requests on SIGTERM/SIGINT.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    http::StatusCode,
    routing::{get, post},
};
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer, trace::TraceLayer};

use crate::authz;
use crate::config::{Config, PolicyBackendKind, TrustedProxies};
use crate::enroll;
use crate::error::Error;
use crate::health;
use crate::metrics;
use crate::openapi;
use crate::sigs;
use crate::state::{AppState, PolicyHandle};
use crate::token;
use crate::verify;

/// Builds the router. MFA endpoints land here in later H3 commits.
pub fn router(state: AppState, body_limit_bytes: usize) -> Router {
    Router::new()
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
        .route("/openapi.json", get(openapi::spec))
        .route("/v1/factors/enroll/start", post(enroll::start))
        .route("/v1/factors/enroll/confirm", post(enroll::confirm))
        .route("/v1/mfa/verify", post(verify::mfa_verify))
        .route("/v1/mfa/recover", post(verify::recover))
        .route("/v1/verify", post(verify::s2s_verify))
        .route("/v1/token/refresh", post(token::refresh))
        .route("/v1/token/revoke", post(token::revoke))
        .route("/v1/sigs/verify", post(sigs::verify_signature))
        .route("/v1/authz/check", get(authz::check))
        .route("/metrics", get(metrics::metrics))
        .route("/.well-known/jwks.json", get(token::jwks))
        .fallback(health::not_found)
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(body_limit_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(10),
        ))
        .with_state(state)
}

/// Runs the server until SIGTERM/SIGINT, then shuts down gracefully.
pub async fn serve(config: &Config, state: AppState) -> Result<(), Error> {
    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .map_err(|e| Error::Config(format!("cannot bind {}: {e}", config.listen)))?;
    tracing::info!(listen = %config.listen, "bandall listening");
    axum::serve(
        listener,
        router(state, config.body_limit_bytes).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(|e| Error::Config(format!("server error: {e}")))?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => signal.recv().await,
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}

/// Builds shared state from configuration: store, vault and service key.
pub async fn build_state(config: &Config) -> Result<(AppState, StoreKind), Error> {
    use bandall_policy::{Limits, Policy, PolicyConfig};
    use bandall_store::{PgStore, SqliteStore};
    use bandall_tokens::KeyManager;
    use bandall_vault::{LocalKms, Vault};

    let kms = Arc::new(
        LocalKms::from_file(
            config.kek_id.clone(),
            std::path::Path::new(&config.kms_key_file),
        )
        .map_err(|_| Error::Config("cannot load KMS key".to_string()))?,
    );
    let vault = Arc::new(Vault::new(kms));
    let keys = Arc::new(
        KeyManager::load_or_generate(std::path::Path::new(&config.keys_dir))
            .map_err(|_| Error::Config("cannot load signing keys".to_string()))?,
    );
    let policy_config = PolicyConfig {
        factor: Limits {
            max_attempts: config.policy_max_attempts,
            lockout_after: config.policy_lockout_after,
            ..Limits::default()
        },
        tenant: Limits::ingress(config.policy_tenant_max_attempts),
        ip: Limits::ingress(config.policy_ip_max_attempts),
        ..PolicyConfig::default()
    };
    let policy = match config.policy_backend {
        PolicyBackendKind::Memory => PolicyHandle::Memory(Arc::new(Policy::new(policy_config))),
        PolicyBackendKind::Database => PolicyHandle::Database(policy_config),
    };
    let trusted_proxies = Arc::new(
        TrustedProxies::parse(&config.trusted_proxies)
            .map_err(|_| Error::Config("invalid trusted_proxies".to_string()))?,
    );
    let service_key = config.service_key.clone();
    let issuer = config.token_issuer.clone();
    let audience = config.token_audience.clone();
    match config.database {
        crate::config::DatabaseKind::Sqlite => {
            let store = SqliteStore::connect(&config.database_url).await?;
            store.migrate().await?;
            Ok((
                AppState::new(
                    Arc::new(store),
                    vault,
                    keys,
                    policy,
                    trusted_proxies,
                    issuer,
                    audience,
                    service_key,
                ),
                StoreKind::Sqlite,
            ))
        }
        crate::config::DatabaseKind::Postgres => {
            let store = PgStore::connect(&config.database_url).await?;
            store.migrate().await?;
            Ok((
                AppState::new(
                    Arc::new(store),
                    vault,
                    keys,
                    policy,
                    trusted_proxies,
                    issuer,
                    audience,
                    service_key,
                ),
                StoreKind::Postgres,
            ))
        }
    }
}

/// Which backend was wired (for startup logs, no secrets).
#[derive(Debug, Clone, Copy)]
pub enum StoreKind {
    /// Embedded SQLite.
    Sqlite,
    /// Postgres service.
    Postgres,
}
