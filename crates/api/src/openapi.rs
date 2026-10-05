//! Generated OpenAPI document, served at `GET /openapi.json`.
//!
//! SDK codegen (H6) consumes this contract; the test below pins every route
//! so handlers and spec cannot drift apart.

use axum::Json;
use utoipa::OpenApi;

/// Versioned API document.
#[derive(OpenApi)]
#[openapi(
    paths(
        crate::health::healthz,
        crate::health::readyz,
        crate::openapi::spec,
        crate::enroll::start,
        crate::enroll::confirm,
        crate::verify::mfa_verify,
        crate::verify::s2s_verify,
        crate::verify::recover,
    ),
    components(schemas(
        crate::health::Health,
        crate::health::Ready,
        crate::error::Problem,
        crate::enroll::EnrollStartRequest,
        crate::enroll::EnrollStartResponse,
        crate::enroll::EnrollConfirmRequest,
        crate::enroll::EnrollConfirmResponse,
        crate::verify::MfaVerifyRequest,
        crate::verify::MfaVerifyResponse,
        crate::verify::S2sVerifyRequest,
        crate::verify::S2sVerifyResponse,
        crate::verify::RecoverRequest,
        crate::verify::RecoverResponse,
    )),
    tags((name = "bandall", description = "TOTP security service"))
)]
pub struct ApiDoc;

/// `GET /openapi.json`: the full contract as JSON.
#[utoipa::path(
    get,
    path = "/openapi.json",
    responses((status = 200, description = "OpenAPI 3.1 document"))
)]
pub async fn spec() -> Json<serde_json::Value> {
    Json(serde_json::to_value(ApiDoc::openapi()).unwrap_or(serde_json::Value::Null))
}

#[cfg(test)]
mod tests {
    use super::ApiDoc;
    use utoipa::OpenApi;

    #[test]
    fn spec_lists_every_route() {
        let json = serde_json::to_string(&ApiDoc::openapi()).unwrap();
        for path in [
            "/healthz",
            "/readyz",
            "/openapi.json",
            "/v1/factors/enroll/start",
            "/v1/factors/enroll/confirm",
            "/v1/mfa/verify",
            "/v1/mfa/recover",
            "/v1/verify",
        ] {
            assert!(json.contains(path), "spec is missing {path}");
        }
    }
}
