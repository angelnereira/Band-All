# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado [SemVer](https://semver.org/lang/es/).

## [Unreleased]

### Added

- H0: workspace Cargo con los crates `bandall-*`, lints de seguridad, CI (fmt, clippy, tests, MSRV, cargo-deny, cargo-audit, cobertura y build de imagen).
- Docker: imagen distroless no-root y stack de desarrollo con Postgres 16.
- `justfile` con el gate `just check` y la política `deny.toml`.
- Documentación base: `SECURITY.md`, `CONTRIBUTING.md`, ADR-0001, ADR-0002 y modelo de amenazas v0.
- H1: `totp-core` puro (HOTP/TOTP RFC 4226/6238, Base32 estricto, `otpauth://`, verificación con ventana ±N y antirreplay matemático). Tests delegados al CI.
- H2 (parcial): `vault` con cifrado envolvente (KEK en `LocalKms`, DEK por factor, AAD por fila, `rewrap` para rotación) y códigos de recuperación Argon2id.
- H2: `store` con trait de persistencia, backends Postgres/SQLite, migraciones y batería de conformidad compartida (SQLite en memoria + Postgres en CI).
- H3 (parcial): fundación del API HTTP (config TOML+env, estado compartido, probes `/healthz`+`/readyz`, errores RFC 7807, serve con apagado ordenado) y CLI `serve`/`migrate`/`init-config`.
- H3: enrolamiento (`enroll/start`+`confirm` con expiración y códigos de recuperación) y verificación (`mfa/verify`, `verify` S2S, `recover`) con antirreplay atómico, deriva acotada y E2E en CI.
- H3: contrato OpenAPI generado (`utoipa`, servido en `/openapi.json`) con test de rutas para SDKs de H6.
- H4 (parcial): `tokens` (JWT EdDSA estricto, refresh opaco, JWKS, ADRs 0004/0005) y sesiones en `store`.
- H5 (parcial): `policy` (ventana deslizante, backoff exponencial, lockout) aplicado a verificación/enrolamiento/recuperación, negación uniforme con lastre temporal y 429.
- H5: auditoría encadenada por hash (migración 4, eventos de seguridad, `bandall audit verify` con detección de manipulación).
- H6 (parcial): `sigs` (firmas HMAC de requests/webhooks: cadena canónica, tolerancia ±5 min, nonces de un uso, comparación constante).
- H6: verificación de firmas por cliente (`/v1/sigs/verify` con claves selladas y scopes), forward-auth (`/v1/authz/check` para nginx/Envoy/Traefik) y CLI `apikey create/revoke`.
- H6: `sdk-axum` (Layer `RequireToken` con verificación offline y claims en extensiones).
- H6: vectores de conformidad compartidos + SDKs TypeScript y Python (JWT offline y firmas HMAC, job `sdks` en CI).
- H6: demo legacy sin modificar (compose + nginx `auth_request`), guía de forward-auth y ejemplo embebido offline.
- H7 (núcleo): `authenticator-core` (cuentas, códigos con cuenta atrás, aviso de deriva, backup cifrado opcional, ADR-0006 nativo+UniFFI).
- H8: `/metrics` Prometheus, chart Helm, compose de observabilidad, script k6, runbooks, escaneo Trivy en CI y política de releases. Pendiente de entorno real: SLOs medidos, DR ensayado, `cargo-vet`/SBOM/`cosign`, TLS a Postgres/KMS, pentest y WebAuthn (H9).
- Revisión pre-producción: `deny.toml` endurecido, lints de casts/prints, perfiles con `overflow-checks`, CI con runner y acciones fijadas por SHA, `README.md`, tablero de gates (`docs/ROADMAP_STATUS.md`), ADR-0008 (estado compartido de rate-limit; TLS a Postgres en rama `feat/pg-tls-enforcement` pendiente de verificar) y diagnóstico de verificación (`docs/VERIFICATION.md`).
- Endurecimiento de configuración (ADR-0007): `deny.toml` con `yanked`/`wildcards` en `deny`, lints de casts y `print_*`/`todo`/`dbg` en el workspace, `overflow-checks` en release y test, CI en `ubuntu-24.04` con `timeout-minutes` y `--locked`, y `README.md`.

### Fixed

- H0: runtime Docker cambiado de distroless `cc` a `debian:12-slim` (ver ADR-0002).
- H0: Postgres de desarrollo escucha en el puerto de host 5433 por defecto para no chocar con otros proyectos locales.
- T1: `ci.yml` era **inválido**: `defaults.run.timeout-minutes` no existe en el esquema (GitHub creaba el run con 0 jobs). Timeouts por job, `concurrency` por ref, `totp-core` con umbral de cobertura del 90 % y los 12 SHAs re-verificados contra tags exactos con `git ls-remote`.
