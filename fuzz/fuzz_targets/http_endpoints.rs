//! Fuzz target: the HTTP surface (H5, roadmap item 5).
//!
//! Every byte of the input is attacker-controlled: routes, JSON bodies and
//! headers. The invariant is that the router never panics and never answers
//! 500 on *malformed input*: a 500 means a handler leaked an `Internal` error
//! where validation should have caught it (or worse, a panic reached a
//! response).
//!
//! The sample keeps one state per process (SQLite in memory; the rate limiter
//! is per-factor so a flood of distinct factor ids keeps it out of the way),
//! which also means the fuzzer explores the parser layers that run before
//! handlers: routing, JSON extraction, typed enums.
//!
//! A crash here is a handler panic; a corpus item on the 500 path is a handler
//! that treats malformed input as an internal condition.

#![no_main]

use std::sync::OnceLock;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use libfuzzer_sys::fuzz_target;
use tower::ServiceExt as _;

use bandall_api::config::TrustedProxies;
use bandall_api::{AppState, AuditChain};
use bandall_policy::Policy;
use bandall_store::{SqliteStore, Store};
use bandall_tokens::KeyManager;
use bandall_vault::{LocalKms, Vault};

/// A path the router accepts; the first byte picks one, so coverage reaches
/// every handler. Lengths vary to keep the JSON bodies away from the
/// single-candidate window.
const ROUTES: &[&str] = &[
    "/v1/factors/enroll/start",
    "/v1/factors/enroll/confirm",
    "/v1/mfa/verify",
    "/v1/mfa/recover",
    "/v1/verify",
    "/v1/token/refresh",
    "/v1/token/revoke",
    "/v1/sigs/verify",
    "/v1/authz/check",
    "/metrics",
];

struct Fixture {
    router: axum::Router,
    rt: tokio::runtime::Runtime,
}

static FIXTURE: OnceLock<Fixture> = OnceLock::new();

fn fixture() -> &'static Fixture {
    FIXTURE.get_or_init(|| {
        // A real state: the same wiring `bandall serve` builds, minus config
        // files. `KeyManager::generate` keeps the process deterministic enough
        // for the fuzzer while still exercising the JWKS and verification
        // paths.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime must build");
        let state = rt.block_on(async {
            let sqlite = SqliteStore::in_memory()
                .await
                .expect("in-memory sqlite must open");
            sqlite.migrate().await.expect("migrations must run");
            let store: std::sync::Arc<dyn Store> = std::sync::Arc::new(sqlite);
            let kms = LocalKms::from_bytes("kek-fuzz".to_string(), [9u8; 32].to_vec())
                .expect("kek must build");
            let vault = std::sync::Arc::new(Vault::new(std::sync::Arc::new(kms)));
            AppState::new(
                store,
                vault,
                std::sync::Arc::new(KeyManager::generate().expect("keys must generate")),
                bandall_api::state::PolicyHandle::Memory(std::sync::Arc::new(Policy::default())),
                std::sync::Arc::new(AuditChain::from_bytes([7u8; 32])),
                std::sync::Arc::new(TrustedProxies::default()),
                "fuzz".to_string(),
                "fuzz".to_string(),
                "fuzz-service-key-0123456789abcdef".to_string(),
            )
        });
        let router = bandall_api::server::router(state, 64 * 1024);
        Fixture { router, rt }
    })
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let route_index = usize::from(data[0]) % ROUTES.len();
    let route = ROUTES[route_index];
    // The rest of the input is the body for a JSON endpoint; for the GET
    // routes it is a query string that should be ignored harmlessly.
    let body = if data.len() > 1 { &data[1..] } else { &[] };

    let request = Request::builder()
        .method(Method::POST)
        .uri(route)
        .header("content-type", "application/json")
        .header("x-service-key", "fuzz-service-key-0123456789abcdef")
        .body(Body::from(body.to_vec()))
        .expect("request must construct");

    // A handler panic aborts the fuzz target (crash -> artifact). A 500 on
    // malformed input is a behavioural bug: fail without a crash so the
    // minimal input is reported as a test failure.
    let fixture_owned = fixture();
    let response = fixture_owned.rt.block_on(async {
        fixture_owned
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("router must not panic on any input")
    });
    assert!(
        response.status() != StatusCode::INTERNAL_SERVER_ERROR,
        "500 on malformed input for route {route}"
    );
});