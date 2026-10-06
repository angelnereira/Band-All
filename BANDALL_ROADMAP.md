# BandAll — Guía de desarrollo paso a paso
*De la primera línea de código hasta la versión 1.0 madura. Léela junto a `BANDALL_BLUEPRINT.md` (qué se construye) y `AGENTS.md` (reglas de trabajo).*

## 1. Mapa de hitos

| Hito | Versión | Resultado | Estimación (1 dev) |
|---|---|---|---|
| **H0** Cimientos | — | Repo, CI y políticas listas | 1 sem |
| **H1** Núcleo TOTP | 0.1 | `totp-core` verificado con vectores RFC | 1–2 sem |
| **H2** Bóveda y persistencia | 0.2 | Secretos cifrados + DB Postgres/SQLite | 2 sem |
| **H3** API enrolar/verificar | 0.3 (alfa) | Flujo MFA completo de extremo a extremo | 2 sem |
| **H4** Tokens y sesiones | 0.4 | Access/refresh + JWKS + revocación | 2 sem |
| **H5** Hardening | 0.5 (beta privada) | Defensas activas, auditoría, cadena de suministro | 2 sem |
| **H6** Integración | 0.6 | Forward-auth, SDKs, firmas HMAC, modo embebido | 2–3 sem |
| **H7** App autenticadora | 0.7 | App móvil funcionando en modo avión | 3–4 sem |
| **H8** Operación y escala | 0.9 (RC) | Despliegue, observabilidad, carga, DR | 2 sem |
| **H9** Certificación | **1.0** | Pentest, WebAuthn, documentación pública | continuo |

**MVP útil = H0 → H4.** H5 es obligatoria antes de cualquier producción. Las estimaciones son orientativas; los *gates* mandan, no las fechas.

## 2. Reglas del proceso

1. Cada hito = un *GitHub Milestone* con issues pequeñas (≤ 1 día).
2. Una rama por issue → PR pequeño → CI verde → revisión → *squash merge*.
3. Decisiones importantes se registran como **ADR** en `docs/adr/NNNN-titulo.md`.
4. **Definición de hecho (global):** código + pruebas + docs + CI verde + sin `unsafe` + sin secretos en logs + CHANGELOG actualizado.
5. Un hito se cierra solo cuando su **Gate** se cumple por completo. Etiqueta Git `vX.Y.0` al cerrar.
6. Antes de cada hito, revisa `docs/threat-model.md` y actualízalo.

## 3. Hitos detallados

### H0 — Cimientos
**Objetivo:** que nada posterior se construya sobre terreno blando.
1. Crear el workspace Cargo y los crates vacíos de la estructura del blueprint (`bandall-*`).
2. Fijar `rust-toolchain.toml` (versión estable concreta) y `rustfmt.toml`.
3. En `[workspace.lints]`: `unsafe_code = "forbid"`, y `clippy::unwrap_used`, `expect_used`, `panic`, `indexing_slicing` en `deny` (permitidos solo en tests).
4. CI (GitHub Actions): `fmt`, `clippy -D warnings`, tests, `cargo deny`, `cargo audit`, comprobación de MSRV y cobertura.
5. `deny.toml` con licencias permitidas, fuentes de crates permitidas y *bans* explícitos.
6. Crear `justfile` con `just check` que ejecute exactamente lo mismo que el CI.
7. Escribir `SECURITY.md` (cómo reportar), `CONTRIBUTING.md`, `AGENTS.md`, ADR-0001 (workspace Rust) y `docs/threat-model.md` v0.
8. Proteger `main`: PR obligatorio, CI obligatorio, commits firmados.

**Gate:** `just check` pasa en local y en CI; PR de prueba bloqueado si falla clippy.

### H1 — Núcleo TOTP (`totp-core`)
**Objetivo:** la matemática correcta, pura y auditable.
1. Base32 (RFC 4648) estricto: encode/decode, mayúsculas, padding opcional, errores tipados.
2. HOTP (RFC 4226): HMAC + truncamiento dinámico. Probar con el Apéndice D (secreto ASCII `12345678901234567890`: contador 0 → `755224`, 1 → `287082`, 2 → `359152`).
3. TOTP (RFC 6238): `paso = floor(t / periodo)`; SHA-1, SHA-256 y SHA-512. Probar con el Apéndice B (t = 59, SHA-1, 8 dígitos → `94287082`) y los demás vectores del RFC.
4. API de verificación **pura**: `verify(secreto, código, ahora, ventana, last_step) -> Result<paso, Error>`. El tiempo entra como parámetro (nunca `SystemTime` dentro del núcleo).
5. Constructor/parser de URI `otpauth://` (issuer, account, algorithm, digits, period) con escape correcto.
6. Generador de secretos con CSPRNG del SO; tamaño según algoritmo (20 B para SHA-1, 32 B para SHA-256).
7. Comparación con `subtle`; secretos en tipos con `zeroize`/`secrecy`.
8. Pruebas: vectores, `proptest` (round-trip, monotonía de pasos, bordes de ventana), `cargo-fuzz` sobre base32 y otpauth, benchmarks con `criterion`.
9. Documentación `rustdoc` con ejemplos ejecutables.

**Gate:** 100 % de vectores RFC; 1 h de fuzz sin fallos; cobertura del núcleo > 90 %; cero `unsafe`.

### H2 — Bóveda y persistencia
**Objetivo:** que robar la base de datos no sirva de nada.
1. Definir el trait `KmsProvider` (`wrap`, `unwrap`, `key_id`). Implementar `LocalKms` (clave maestra desde archivo con permisos 0600 o variable inyectada). Dejar adaptadores de Azure Key Vault / AWS KMS para después, tras el mismo trait.
2. Formato versionado del secreto cifrado: `v1 | kek_id | nonce | ciphertext`. AEAD con **AAD** `tenant_id|subject_id|factor_id`.
3. Operación `rewrap` para rotar la KEK sin downtime.
4. Migraciones con `sqlx` para Postgres y SQLite (tablas del blueprint §12). Trait `Store` con transacciones y operación **compare-and-set** de `last_step`.
5. Argon2id para códigos de recuperación (parámetros documentados y ajustados al hardware objetivo).
6. Pruebas de integración: Postgres con contenedor de pruebas y SQLite en memoria; copiar un ciphertext a otra fila **debe fallar**; rotación de KEK sin pérdida de datos.

**Gate:** ambos motores pasan la misma batería de tests; ningún secreto aparece en claro en la DB ni en logs.

### H3 — API de enrolamiento y verificación
**Objetivo:** el flujo completo funcionando de punta a punta.
1. Esqueleto `axum`: configuración TOML + variables de entorno validada al arrancar (falla rápido), `tracing`, apagado ordenado, límites de tamaño de body y *timeouts*.
2. Autenticación de clientes servicio-a-servicio: API key con firma HMAC o mTLS.
3. Endpoints: `enroll/start`, `enroll/confirm` (con expiración de 10 min), `mfa/verify`, `verify` (S2S) y recuperación.
4. Antirreplay (`last_step` atómico) y aprendizaje de deriva (`drift_steps` acotado).
5. Errores RFC 7807 y respuestas uniformes.
6. OpenAPI generado (`utoipa`) y *contract tests* contra el esquema.
7. Prueba E2E: un "autenticador simulado" (usa `totp-core`, reloj controlado, sin red) que enrola y verifica.

**Gate:** flujo E2E verde; 100 verificaciones concurrentes del mismo código → exactamente 1 éxito; códigos de ventanas fuera de tolerancia rechazados.

### H4 — Tokens y sesiones
**Objetivo:** emitir identidad verificable sin consultar al servidor en cada petición.
1. Claves de firma Ed25519 con `kid`; endpoint JWKS; rotación con solape de claves.
2. Access token (PASETO v4.public o JWT EdDSA), vida 5–10 min; claims `sub, tenant, sid, amr, aal, jti, iss, aud, exp`. Validación estricta: algoritmo fijo, `iss`/`aud` obligatorios, *leeway* mínimo.
3. Refresh token opaco de 256 bits, guardado como hash, **rotación en cada uso** y **detección de reutilización** (revoca la familia completa).
4. Revocación por `sid` e introspección.
5. Web: cookies `__Host-` + `HttpOnly` + `Secure` + `SameSite=Strict` + CSRF. Móvil: guía de almacenamiento en Keystore/Keychain.
6. Pruebas negativas: confusión de algoritmo, token alterado, expirado, `aud` incorrecto, refresh reutilizado.

**Gate:** todas las pruebas negativas fallan "bien" (rechazo, sin pánico, sin fuga de información); reuse detection demostrada.

### H5 — Hardening
**Objetivo:** pasar de "funciona" a "resiste".
1. Motor de políticas: límites por factor, IP y tenant; *lockout* con backoff exponencial; todo configurable.
2. Anti-enumeración: respuestas idénticas y tiempo uniforme (hash ficticio cuando el usuario no existe).
3. Auditoría encadenada por hash (`prev_hash`) y comando `bandall audit verify` que detecta alteraciones.
4. Higiene de secretos: sin secretos en logs (prueba automática que busca patrones), *core dumps* desactivados, contenedor *distroless*, usuario no root, FS de solo lectura.
5. Modelo de amenazas STRIDE revisado; fuzz de endpoints HTTP.
6. Cadena de suministro: `cargo vet`, SBOM (CycloneDX), builds reproducibles, artefactos firmados (cosign).
7. Revisión contra la lista OWASP ASVS (niveles relevantes) y registro de brechas.

**Gate:** 0 hallazgos altos/críticos abiertos; ASVS revisado y documentado; auditoría detecta una fila alterada a propósito.

### H6 — Integración con sistemas existentes
**Objetivo:** que BandAll se pegue a casi cualquier sistema.
1. `GET /v1/authz/check` (forward-auth) y guías de configuración para nginx `auth_request`, Envoy `ext_authz` y Traefik.
2. `bandall-sdk-axum`: `Layer` que valida JWT con JWKS en caché, exige `scopes` y `aal` mínimo.
3. SDKs finos (TypeScript, Python, Go, C#) generados desde OpenAPI: verificación de JWT y de firmas HMAC. **Vectores de conformidad compartidos** (JSON) que todos los SDKs deben pasar.
4. Firmas HMAC de requests/webhooks (blueprint §10): cadena canónica, `key_id`, nonce de un solo uso, tolerancia ±5 min.
5. Demo: proteger una app "legacy" detrás de nginx sin modificarla.
6. Modo embebido: ejemplo con `bandall-totp-core` + `bandall-store` (SQLite) en un binario único, sin red.

**Gate:** demo legacy funcionando; todos los SDKs pasan los mismos vectores; modo embebido verifica códigos sin conexión.

### H7 — App autenticadora (cliente offline)
**Objetivo:** el "teléfono en modo avión" del concepto original.
1. `authenticator-core`: gestión de cuentas, generación de códigos, parseo de `otpauth://`, importación por QR.
2. Enlaces nativos con UniFFI (Swift/Kotlin). *Decisión abierta (ADR):* nativo por plataforma vs. Flutter con `flutter_rust_bridge`.
3. Secreto en Secure Enclave / Android Keystore (StrongBox si existe); acceso con biometría local.
4. UI mínima: lista de cuentas, código con cuenta regresiva, escáner QR, aviso de reloj desfasado.
5. Pruebas en dispositivos reales: modo avión, reloj adelantado/atrasado (±45 s), reinicio y desinstalación.
6. Seguridad de la app: `FLAG_SECURE`, sin backup en la nube por defecto, backup cifrado opcional (Argon2id); revisión contra OWASP MASVS.

**Gate:** enrola con QR, genera códigos 100 % offline y el servidor los acepta; secreto no extraíble sin biometría.

### H8 — Operación y escala
**Objetivo:** que sobreviva a producción.
1. Imagen *distroless*, Helm/compose, `readyz`/`healthz`, secretos por el orquestador.
2. Observabilidad: métricas Prometheus, trazas OpenTelemetry, dashboards y alertas (tasa de fallos, latencia p99, errores de KMS).
3. Pruebas de carga con `k6`/`oha` y *flamegraphs*. Fijar SLOs **medidos** (por ejemplo, p99 de `verify`), no supuestos.
4. Postgres en alta disponibilidad, backups cifrados, **restauración ensayada**, ensayo de rotación de KEK.
5. Caos: caída de DB o KMS → **fail-closed** (nunca "abrir" por error).
6. Runbooks: fuga de secretos, revocación masiva, rotación de claves, restauración.

**Gate:** SLOs cumplidos en carga sostenida; DR ensayado; runbooks revisados por otra persona.

### H9 — Certificación y versión 1.0
**Objetivo:** confianza demostrable, no declarada.
1. Pentest externo; remediar todo hallazgo alto/crítico.
2. Segundo tipo de factor: **WebAuthn/passkeys** (resistente al phishing) con su propio ADR.
3. Build opcional con cripto FIPS (`aws-lc-rs`) si el cliente lo exige.
4. Documentación pública, política de divulgación responsable, política de versiones y soporte (SemVer).
5. Congelar API v1; lanzar `1.0.0`.

**Gate:** informe de pentest sin críticos abiertos; documentación completa; API v1 estable.

## 4. Checklist de salida a producción

- [ ] H0–H5 cerrados y gates cumplidos
- [ ] KEK en KMS/HSM real (no archivo local) y rotación ensayada
- [ ] Backups restaurados con éxito al menos una vez
- [ ] Alertas probadas (disparar una a propósito)
- [ ] Pentest externo realizado
- [ ] Runbooks y contacto de seguridad publicados
- [ ] Plan de reversión (rollback) probado

## 5. Decisiones abiertas (a resolver pronto, con ADR)

1. **Credencial primaria:** ¿BandAll solo hace el segundo factor (detrás de tu IdP) o también emite sesiones completas?
2. **KMS:** Azure Key Vault, AWS KMS, HSM o `LocalKms` solo para entornos aislados.
3. **SHA-1 vs SHA-256:** SHA-256 con tu app propia; SHA-1 solo si necesitas compatibilidad con Google/Microsoft Authenticator.
4. **Multi-tenant desde el día 1** o por fases.
5. **App móvil:** nativa por plataforma o Flutter.
6. **Base de datos por defecto:** Postgres (servicio) y SQLite (embebido).
7. **Resincronización de deriva** (ADR-0009, T3): reenrolado, dos códigos
   consecutivos, ventana amplia con presupuesto o resync remota S2S.
   Recomendación: dos códigos consecutivos, sin sesión en el primero.
