# AGENTS.md — BandAll

Guía para agentes que trabajan en este repo. Manda sobre cualquier suposición: si algo choca con estas reglas, **detente y pregunta** (§ Cuándo detenerse).

## Estado del repo
- **Solo hay documentación.** No existe código, `Cargo.toml`, CI, Docker ni `justfile`: todo se construye desde H0 siguiendo `BANDALL_ROADMAP.md`.
- Canónicos: `BANDALL_BLUEPRINT.md` (diseño) y `BANDALL_ROADMAP.md` (hitos H0–H9 y gates).
- `Blueprint — Servicio de seguridad TOTP en Rust.md` es un borrador obsoleto (nombre interno `sentinel`): **no usarlo ni tomarlo como referencia**; se elimina en H0.
- Trabaja **solo en el hito activo**. MVP = H0–H4; H5 es obligatoria antes de producción.

## Proyecto
BandAll: servicio de seguridad TOTP (RFC 6238/4226) en Rust con autenticador offline, emisión/verificación de tokens, verificación S2S y firmas HMAC. Tres modos: servicio independiente, sidecar/forward-auth y librería embebida.

## Estructura objetivo (workspace Cargo)
`crates/<x>` = paquete `bandall-<x>`; binario `bandall`.
- `totp-core`: matemática HOTP/TOTP, base32, otpauth. **Puro**: sin red, sin DB y sin `SystemTime::now()` (el tiempo se inyecta).
- `vault`, `tokens`, `policy`, `store` (Postgres/SQLite), `sigs`, `api` (axum), `sdk-axum`, `authenticator-core`, `cli`.
- `docs/adr/`, `docs/threat-model.md`, `deploy/` (Dockerfile, compose, Helm).
- Las dependencias fluyen **hacia** `totp-core`, nunca al revés. No crear crates sin ADR.

## Comandos
Aún no existen (H0 crea `justfile` y CI). Objetivo, en este orden:
```
just check        # = lo mismo que CI: fmt + clippy + tests + deny + audit
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo test -p bandall-totp-core             # un solo crate
cargo test -p bandall-api <filtro>          # tests cuyo nombre coincide
cargo deny check && cargo audit
docker build -f deploy/Dockerfile .
docker compose -f deploy/compose/compose.yaml up --build
```
Esta máquina ya tiene `cargo`/`rustc` 1.98.1 y `docker` 29.8.1; **`just`, `cargo-deny` y `cargo-audit` no están instalados** (`cargo install just cargo-deny cargo-audit`).

## Docker (decidido: dev + tests + CI + prod)
- Builder `rust` + cargo-chef → runtime `gcr.io/distroless/cc-debian12:nonroot` fijado por digest.
- non-root, rootfs read-only, `cap_drop: [ALL]`, `no-new-privileges`, límites de recursos.
- La imagen no tiene shell ni curl: el healthcheck es el subcomando `bandall healthcheck`.
- Secretos vía docker secrets o archivo con permisos 0400; nunca horneados en la imagen ni en `.env` versionados.
- Compose en `deploy/compose/` (base, dev, test, demo, obs). Postgres 16 en contenedor para dev/tests.
- Desde H5: escaneo (trivy/grype), SBOM (syft) y firma (cosign) en CI.

## Seguridad (innegociables)
1. `#![forbid(unsafe_code)]` en todos los crates.
2. No inventar criptografía: solo RustCrypto o `aws-lc-rs`. Comparar códigos/MAC/tokens solo con `subtle`; aleatoriedad solo del CSPRNG del SO.
3. Secretos TOTP cifrados (envelope + AAD); en memoria `secrecy`/`zeroize`; nunca en claro, logs, errores, métricas ni en tests con valores reales.
4. Antirreplay atómico: `UPDATE ... WHERE last_step < $step`; un OTP se acepta una sola vez.
5. Fail-closed ante error de DB, KMS, reloj o configuración; respuestas uniformes ante usuario inexistente o código erróneo.
6. Tokens con algoritmo fijo y `iss`/`aud`/`exp` obligatorios; refresh opaco, hasheado, con rotación y detección de reutilización.
7. Nunca subir secretos, claves ni `.env` reales al repo.

## Código
- Prohibido `unwrap()`, `expect()`, `panic!`, indexado directo y `as` con pérdida fuera de tests; errores tipados (`thiserror`).
- Tiempo inyectado (`Clock`); sin estado global mutable; tipos fuertes (`Step`, `Secret`, `TenantId`).
- `async` solo en `api`, `store` y `sdk-axum`; el núcleo es síncrono.
- Errores al cliente: RFC 7807 sin detalles internos. `rustdoc` en toda API pública.
- Dependencias: justificar antes de añadirlas (mantenimiento, licencia, tamaño); `cargo deny` y `cargo audit` deben pasar.

## Pruebas
- Todo cambio de lógica trae tests; todo bug, un test de regresión.
- `totp-core`: vectores RFC 4226/6238 + `proptest`; parsers con `cargo-fuzz`.
- Cada regla de seguridad lleva al menos una prueba negativa (replay, token alterado, AAD incorrecto, refresh reutilizado, etc.).
- Concurrencia: el mismo código verificado en paralelo → exactamente un éxito. Cobertura del núcleo > 90 %.

## Proceso
- Un hito = milestone; una rama por issue; PR pequeño; **Conventional Commits en inglés**.
- ADRs en `docs/adr/NNNN-titulo.md` (decisiones abiertas en `BANDALL_ROADMAP.md` §5); actualizar `docs/threat-model.md` antes de cada hito.
- Cambios en cripto, tokens, vault o policy requieren revisión humana explícita.
- Definition of done: código + tests (incl. negativos) + docs + CHANGELOG + `just check` verde + sin `unsafe` + sin secretos en logs + ADR si aplica.
- No abrir el siguiente hito sin cerrar el gate del actual.

## Cuándo detenerse y preguntar
Tarea fuera del hito activo · elección entre seguridad y comodidad · requisito faltante · dependencia o crate nuevo · cambio de formato persistido (ciphertext, esquema DB, claims de token) · documentos en conflicto. **No improvisar**: proponer opciones con pros/contras.

## Idioma
Documentación y comunicación en español; identificadores, comentarios de código y commits en inglés.
