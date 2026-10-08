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
- **Verificación del contenedor** (`tests/container/`): empaqueta el proyecto con `deploy/Dockerfile` y somete **el artefacto** a una batería de 45 tests funcionales y de seguridad, 16 de firmas HMAC, las defensas de runtime y la cadena de auditoría alterada a propósito. Sin argumentos va contra SQLite; `--postgres` levanta un Postgres desechable con TLS; `--bench` añade carga simulada con clientes mock que nacen y mueren con la ejecución. Todo lo que crea (contenedores, red, volúmenes, tenant, usuarios, claves) se destruye al salir. Ver `docs/ROADMAP_STATUS.md` §Verificación del contenedor.
- H6: **ADR-0013** cierra el bloqueo que el tablero señalaba: `sdk-axum` verifica contra el JWKS remoto con caché y fallo-cerrado, y existe `RequireScopes` (Layer aparte, porque el `Layer` de token no puede responder 403 sin romper el contrato de 401 de los demás).
- H7 (núcleo): `authenticator-core` (cuentas, códigos con cuenta atrás, aviso de deriva, backup cifrado opcional, ADR-0006 nativo+UniFFI).
- H8: `/metrics` Prometheus, chart Helm, compose de observabilidad, script k6, runbooks, escaneo Trivy en CI y política de releases. Pendiente de entorno real: SLOs medidos, DR ensayado, `cargo-vet`/SBOM/`cosign`, TLS a Postgres/KMS, pentest y WebAuthn (H9).
- Revisión pre-producción: `deny.toml` endurecido, lints de casts/prints, perfiles con `overflow-checks`, CI con runner y acciones fijadas por SHA, `README.md`, tablero de gates (`docs/ROADMAP_STATUS.md`), ADR-0008 (estado compartido de rate-limit; TLS a Postgres en rama `feat/pg-tls-enforcement` pendiente de verificar) y diagnóstico de verificación (`docs/VERIFICATION.md`).
- Endurecimiento de configuración (ADR-0007): `deny.toml` con `yanked`/`wildcards` en `deny`, lints de casts y `print_*`/`todo`/`dbg` en el workspace, `overflow-checks` en release y test, CI en `ubuntu-24.04` con `timeout-minutes` y `--locked`, y `README.md`.

### Changed

- **Toolchain 1.98.1 → 1.99.0** en `rust-toolchain.toml` y en los dos jobs de CI que la fijan. El SHA de `dtolnay/rust-toolchain` para la rama `1.99.0` se resolvió con `git ls-remote`, no de memoria. Los otros 10 pins del workflow se re-verificaron igual y siguen correctos.
- **Dependencias internas del workspace centralizadas** en `[workspace.dependencies]` con versión explícita, y cada crate usa `{ workspace = true }`. Motivo: `bans.wildcards = "deny"` marcaba las 10 aristas internas, porque una dependencia solo-`path` no declara versión y Cargo la lee como `*`. Se arregla la causa, **no se relaja la regla**. Al subir la versión hay que mover `[workspace.package]` y `[workspace.dependencies]` juntos.
- Licencias: `CDLA-Permissive-2.0` añadida a la lista permitida de `deny.toml` (permisiva: atribución y límites de responsabilidad, sin copyleft ni restricción de uso). La trae `webpki-roots`, de forma transitiva por rustls en sqlx; la pila TLS no puede prescindir de ella mientras siga sobre rustls.
- `cargo audit`: se ignora `RUSTSEC-2023-0071` (Marvin Attack) **con la razón documentada en el `justfile` y en el job de CI**. Solo llega al grafo por `rsa` <- `sqlx-mysql`, una feature opcional que `crates/store` nunca activa: `cargo tree` no muestra ningún nodo `rsa` con las features habilitadas, así que el código no se compila. No hay arreglo upstream. Hay que revisarlo si algún día se activa MySQL.
- `just sdks`: Python se ejecuta primero (no depende de Node) y el paso de TypeScript se omite con un motivo explícito cuando el Node no tiene *type stripping* nativo, en vez de dejar un gate rojo engañoso. El job de CI no cambia: sigue fijando Node 24.
- T4: **rompe la configuración**: `audit_key_file` es obligatoria y el arranque
  falla sin ella. Exponer `/metrics` sin cambio. Quien despliegue debe generar
  el archivo (32 B) junto al de la KEK y montarlo con permisos `0600`. Compose
  y Helm lo montan ya.

### Fixed

- T4: la auditoría era recalculable por cualquiera con escritura en `audit_log`
  (hash sin clave), `tenant_id` y `subject_id` quedaban fuera del prehash (cambiar de titular una fila no rompía la verificación) y los campos iban concatenados sin prefijo de longitud. Los tres están cerrados; ver "Added".
- **`otpauth` perdía caracteres al encodear**: el percent-encoder emitía `XX` sin el `%`, así que `alice+bob@example.com` se enrolaba como `alice2Bbob40example.com`. El test de round-trip era tautológico (comparaba URI contra URI); ahora compara campo a campo y ha dejado de serlo.
- **`otpauth` con dos puntos**: el parser decodificaba el label antes de partir en `:`, así que un emisor con `:` (`ACME:Corp`) devoraba el separador y devolvía el account con el `:` pegado. Ahora parte primero y decodifica cada lado.
- **`SqliteStore::connect` no creaba el archivo**: una instalación nueva (y el demo) fallaba al arrancar porque el archivo `bandall.db` no existía; había que hacer `touch` a mano. Ahora `create_if_missing(true)`, y un directorio inexistente sigue fallando (fail closed).
- **El `service_key` de ejemplo no pasaba su propia validación**: `"change-me-to-at-least-32-chars"` tiene 30 caracteres y el arranque lo rechazaba, así que el demo nunca había podido arrancar. Corregido a `demo-service-key-0123456789abcdef` en `Config::example()`, `demo-bandall.toml`, `obs-bandall.toml` y los dos compose.
- **`bandall` sin subcomando ignoraba `BANDALL_CONFIG`**: el contenedor (`ENTRYPOINT ["bandall"]`) arrancaba `serve` leyendo `bandall.toml` del CWD en vez del config montado, y moría con "no such file". Ahora el `serve` por defecto honra `BANDALL_CONFIG` (extraído a `default_serve`, testeable).
- **El demo apuntaba a Postgres con backend SQLite**: `demo-bandall.toml` declara `database = "sqlite"` pero el compose sobrescribía `BANDALL_DATABASE_URL` con una URL de Postgres. El demo vuelve a SQLite, que es lo que prometía el README; quien quiera Postgres cambia el `database` y usa URL TLS.
- **La batería de Postgres no era re-ejecutable**: fallaba con `duplicate key` en la segunda ejecución porque asumía el contenedor limpio de CI. Ahora hace `DROP SCHEMA` / `CREATE SCHEMA` antes de migrar, así que un desarrollador puede correr los tests tantas veces como necesite.

### H1–H5: propiedades, fuzz, distroless y pruebas de la ronda

- [H1] Proptest en `totp-core` (tests `properties.rs`): round-trip de Base32 y `otpauth` campo a campo, totalidad de los parsers, monotonía del paso, dígitos exactos, ventana exacta y antirreplay del paso consumido. Los dos bugs de `otpauth` salieron de aquí.
- [H1] Harness de `cargo-fuzz` (`fuzz/`, workspace propio, nightly): targets `base32_decode`, `otpauth_parse`, `secret_from_base32` — **1 h cada uno sin crashes** (≈660 M ejecuciones combinadas, verificado aquí) — y `http_endpoints` (router axum real; 10 min sin hallazgos en la ronda, 1 h completada más tarde en el entorno).
- [H1] Benchmarks `criterion` de los caminos calientes (generate/verify/base32), fuera del gate.
- [H2] Prueba del gate "nada en claro en la DB" (`api/tests/at_rest.rs`): escanea bytes del archivo SQLite (incluido `-wal`) buscando secretos, códigos de recuperación y la clave de auditoría, tras enrolar y verificar de verdad.
- [H5] Prueba del gate "sin secretos en logs" (`api/tests/no_secrets_in_logs.rs`): captura el log real con un subscriber inyectado, recorre todos los handlers (éxitos y fallos) y exige ausencia de secretos, códigos, KEK y tokens. Comprobado que detecta una fuga inyectada.
- [H5] Docker runtime **distroless `cc-debian12:nonroot`** fijado por digest del índice multi-arch (reenvío de ADR-0002, ver el ADR): verificado extrayendo capas del registro y confirmando `NEEDED` del binario; build real y arranque comprobados en este entorno. Los compose de demo y obs ganan hardening: rootfs read-only, `cap_drop ALL`, `no-new-privileges`, tmpfs y `ulimits core=0`.
- [H5] Fuzz de endpoints HTTP (`fuzz/fuzz_targets/http_endpoints.rs`): el router axum real recibe cuerpos arbitrarios; un 500 o un pánico en entrada malformada es un fallo. 10 min completos sin hallazgos; corrida de 1 h en curso en el entorno.
- [H6] **Cuatro SDKs finos sobre los mismos vectores de conformidad**: TS y Python existentes, y **Go** (`sdks/go`, stdlib crypto) y **C#** (`sdks/csharp`, `.NET 8`, Ed25519 vía BouncyCastle — verificación, nunca firma) añadidos con tests que pasan `conformance/vectors.json`. El job `sdks` del CI (setup-go v5.5.0, setup-dotnet v4.3.0, ambos con SHA verificado) y `just sdks` los ejecutan todos.
- [H6] **Modo embebido**: ejemplo `cargo run -p bandall-store --example embedded` — totp-core + vault + store SQLite en un binario único, sin red ni HTTP: enrula con el secreto cifrado, verifica un código con antirreplay atómico y rechaza el replay.
- Demo forward-auth **funcionando por primera vez**: `GET /` → 401 sin token; enrolar, confirmar y verificar MFA; con `Bearer` la app legacy responde 200 con los headers `X-Bandall-*`.
- Guía de sesiones web y móvil (`docs/guides-web-and-mobile-sessions.md`) y ADR-0011: BandAll no emite cookies (decisión propuesta: patrón BFF); el móvil guarda en Keystore/Keychain con los requisitos documentados. Revisión STRIDE del modelo de amenazas con cada control enlazado a su prueba.
- H0: runtime Docker cambiado de distroless `cc` a `debian:12-slim` (ver ADR-0002).
- H0: Postgres de desarrollo escucha en el puerto de host 5433 por defecto para no chocar con otros proyectos locales.
- T1: `ci.yml` era **inválido**: `defaults.run.timeout-minutes` no existe en el esquema (GitHub creaba el run con 0 jobs). Timeouts por job, `concurrency` por ref, `totp-core` con umbral de cobertura del 90 % y los 12 SHAs re-verificados contra tags exactos con `git ls-remote`.
- T2: rate limit **atómico** y con scopes (ADR-0008). `Policy::acquire` decide y registra el intento bajo un único lock (una ráfaga concurrente se detiene en el límite); límites altos por ámbito `tenant`/`ip` sin lockout larga (un atacante ya no puede bloquear a todo un tenant) y configurables; tope de 100 000 entradas con barrido de expiradas; la IP de cliente sale del socket y solo se acepta `X-Forwarded-For` desde `trusted_proxies` (cadena recorrida de derecha a izquierda); backend `database` con `reserve_auth_attempt` transaccional (lock por clave: advisory en Postgres, `BEGIN IMMEDIATE` en SQLite) y migración 6 `auth_failures` con clave sustituta para que varios fallos en el mismo segundo cuenten por separado. La ventana por defecto se alinea con la lockout (900 s) para conservar el bloqueo completo ahora que se deriva de la ventana.
- T3: ventana de verificación y deriva. Se probaban hasta **siete pasos** (`WINDOW=1` × `DRIFT_RADIUS=2`, ±90 s) y la deriva se guardaba del primer candidato que casara. Ahora `candidate_steps` devuelve exactamente **tres pasos** alrededor de la deriva guardada, la verificación usa `window = 0` sobre ellos y un acierto registra el desfase realmente observado (limitado a ±5). Un reloj a +30 s entra y actualiza la deriva; a +90 s se rechaza. La resincronización fuera de ventana queda como decisión abierta en ADR-0009 (recomendación: dos códigos consecutivos).
- Bugs de `main` destapados al ejecutar por fin la batería de `store`: `bandall-store` usaba `url` sin declararlo (no compilaba), su test de TLS no esperaba el `async`, y `cas_last_step` de SQLite tenía un bind de menos: la comparación quedaba `last_step < NULL` y tras el primer código aceptado **ningún paso posterior casaba**. Corregidos, junto con los avisos de `Debug`/docs que rompían `clippy -D warnings`.
