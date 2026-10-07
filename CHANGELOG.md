# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado [SemVer](https://semver.org/lang/es/).

## [Unreleased]

### Added

- T4: **cadena de auditoría con clave** (ADR-0010, migración 7). HMAC-SHA-256 sobre un registro con prefijo de longitud que cubre versión, `ts`, `tenant_id`, `subject_id`, `event` y `prev_hash`; clave de 32 B en `audit_key_file` (obligatoria, `0600`) fuera de la base de datos; `bandall audit verify` la usa. El append pasa a `Store::append_audit_chained`, una transacción que lee el tip bajo bloqueo y calcula el enlace dentro, así que dos escritores ya no pueden bifurcar la cadena. `chain_version` permite verificar filas v1 y v2 en el mismo log. Postgres revoca `UPDATE`/`DELETE`/`TRUNCATE` sobre `audit_log` a `PUBLIC` y al rol `bandall_app` cuando existe.
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

### Changed

- T4: **rompe la configuración**: `audit_key_file` es obligatoria y el arranque
  falla sin ella. Exponer `/metrics` sin cambio. Quien despliegue debe generar
  el archivo (32 B) junto al de la KEK y montarlo con permisos `0600`. Compose
  y Helm lo montan ya.

### Fixed

- T4: la auditoría era recalculable por cualquiera con escritura en `audit_log`
  (hash sin clave), `tenant_id` y `subject_id` quedaban fuera del prehash (cambiar de titular una fila no rompía la verificación) y los campos iban concatenados sin prefijo de longitud. Los tres están cerrados; ver "Added".
- H0: runtime Docker cambiado de distroless `cc` a `debian:12-slim` (ver ADR-0002).
- H0: Postgres de desarrollo escucha en el puerto de host 5433 por defecto para no chocar con otros proyectos locales.
- T1: `ci.yml` era **inválido**: `defaults.run.timeout-minutes` no existe en el esquema (GitHub creaba el run con 0 jobs). Timeouts por job, `concurrency` por ref, `totp-core` con umbral de cobertura del 90 % y los 12 SHAs re-verificados contra tags exactos con `git ls-remote`.
- T2: rate limit **atómico** y con scopes (ADR-0008). `Policy::acquire` decide y registra el intento bajo un único lock (una ráfaga concurrente se detiene en el límite); límites altos por ámbito `tenant`/`ip` sin lockout larga (un atacante ya no puede bloquear a todo un tenant) y configurables; tope de 100 000 entradas con barrido de expiradas; la IP de cliente sale del socket y solo se acepta `X-Forwarded-For` desde `trusted_proxies` (cadena recorrida de derecha a izquierda); backend `database` con `reserve_auth_attempt` transaccional (lock por clave: advisory en Postgres, `BEGIN IMMEDIATE` en SQLite) y migración 6 `auth_failures` con clave sustituta para que varios fallos en el mismo segundo cuenten por separado. La ventana por defecto se alinea con la lockout (900 s) para conservar el bloqueo completo ahora que se deriva de la ventana.
- T3: ventana de verificación y deriva. Se probaban hasta **siete pasos** (`WINDOW=1` × `DRIFT_RADIUS=2`, ±90 s) y la deriva se guardaba del primer candidato que casara. Ahora `candidate_steps` devuelve exactamente **tres pasos** alrededor de la deriva guardada, la verificación usa `window = 0` sobre ellos y un acierto registra el desfase realmente observado (limitado a ±5). Un reloj a +30 s entra y actualiza la deriva; a +90 s se rechaza. La resincronización fuera de ventana queda como decisión abierta en ADR-0009 (recomendación: dos códigos consecutivos).
- Bugs de `main` destapados al ejecutar por fin la batería de `store`: `bandall-store` usaba `url` sin declararlo (no compilaba), su test de TLS no esperaba el `async`, y `cas_last_step` de SQLite tenía un bind de menos: la comparación quedaba `last_step < NULL` y tras el primer código aceptado **ningún paso posterior casaba**. Corregidos, junto con los avisos de `Debug`/docs que rompían `clippy -D warnings`.
