# Revisión OWASP ASVS (objetivo L3) — estado H5

Alcance: servicio BandAll (`api`, `vault`, `tokens`, `policy`, `store`, `sigs`), CLI y despliegue Docker. La app móvil (H7) y WebAuthn (H9) tienen su propia revisión pendiente. Convención: ✅ implementado · 🟡 parcial · ⬜ pendiente (con hito).

## V1 Arquitectura y ciclo de vida

| Control | Estado | Evidencia |
|---|---|---|
| 1.1 Ciclo de vida seguro (diseño, amenazas, gates) | ✅ | Blueprint, modelo de amenazas, gates por hito, ADRs |
| 1.2 Autenticación y sesión documentadas | ✅ | ADR-0005, claims `amr`/`aal` honestos |
| 1.4 Controles en el servidor, nunca solo en cliente | ✅ | Toda verificación es servidora; SDKs solo verifican firmas |
| 1.14 Secretos fuera del código | ✅ | Docker secrets/archivo 0600, `.env` ignorado, `deny` de secretos en repo |

## V2 Autenticación

| Control | Estado | Evidencia |
|---|---|---|
| 2.1 Credenciales anti-automatización | ✅ | `policy` (backoff, lockout), ventana TOTP ±1 |
| 2.2 Segundo factor (TOTP AAL1) | ✅ | `totp-core` + antirreplay atómico |
| 2.3 Recuperación con re-enrolamiento | ✅ | Códigos Argon2id de un uso que retiran el factor |
| 2.8 Autenticadores de un uso / fuera de banda | 🟡 | TOTP implementado; WebAuthn en H9 |
| 2.10 Anti-enumeración | ✅ | Negación uniforme + lastre temporal en `verify_code` |

## V3 Sesiones

| Control | Estado | Evidencia |
|---|---|---|
| 3.1 Tokens con expiración y revocación | ✅ | Access 10 min, refresh con rotación y revocación por familia/sesión |
| 3.2 Tokens aleatorios e impredecibles | ✅ | CSPRNG del SO, 256 bits |
| 3.3 Reutilización / fijación de sesión | ✅ | Detección de reutilización quema la familia |
| 3.4 Cierre de sesión | ✅ | `token/revoke` + revocación por `sid` |
| 3.5 Cookies seguras | ⬜ | Transporte web (cookies `__Host-` + CSRF) pendiente de guía H6 |

## V4 Control de acceso

| Control | Estado | Evidencia |
|---|---|---|
| 4.1 Denegación por defecto | ✅ | Fail-closed en DB/KMS/reloj/config; scopes por `key_id` (H6) |
| 4.2 Separación por tenant | ✅ | Todas las lecturas llevan ámbito tenant+subject |

## V5 Validación y codificación

| Control | Estado | Evidencia |
|---|---|---|
| 5.1 Entradas validadas en servidor | ✅ | DTOs validados, Base32/`otpauth` estrictos, límites de body |
| 5.3 Salida codificada / sin inyección | ✅ | Sin HTML, JSON tipado, SQL parametrizado, sin `format!` en SQL |

## V6 Criptografía

| Control | Estado | Evidencia |
|---|---|---|
| 6.1 Algoritmos estándar, sin inventos | ✅ | RustCrypto/`aws-lc-rs` vía dependencias, `forbid(unsafe)` |
| 6.2 Aleatoriedad del SO | ✅ | Solo `getrandom`/`OsRng`-equivalente |
| 6.3 Gestión de claves | ✅ | Envolvente KEK→DEK, AAD por fila, `kid` con solape, rotación sin downtime |

## V7 Errores y logs

| Control | Estado | Evidencia |
|---|---|---|
| 7.1 Errores genéricos al cliente | ✅ | RFC 7807 sin detalles internos |
| 7.2 Sin secretos en logs | ✅ | Tipos con `Debug` redactado, sin `secret` en `tracing` |
| 7.4 Auditoría de seguridad | ✅ | Log encadenado con HMAC y clave fuera de la DB (ADR-0010), append atómico, `bandall audit verify` (`crates/api/src/audit.rs`, `store/src/tests_battery.rs::audit_chain_concurrency`) |

## V8 Datos sensibles

| Control | Estado | Evidencia |
|---|---|---|
| 8.1 Cifrado en reposo de secretos | ✅ | AEAD envolvente, Argon2id para recuperación |
| 8.2 Secretos en memoria | ✅ | `secrecy`/`SecretBox`, copias transitorias a cero |

## V9 Comunicaciones

| Control | Estado | Evidencia |
|---|---|---|
| 9.1 TLS en tránsito | 🟡 | Terminación en proxy/orquestador (documentado); TLS a Postgres/KMS en H8 |
| 9.2 Certificados / HSTS | ⬜ | Configuración del despliegue, runbook H8 |

## V10 Código y configuración

| Control | Estado | Evidencia |
|---|---|---|
| 10.1 Lints y dependencias auditadas | ✅ | `forbid(unsafe)`, clippy `-D warnings`, `cargo-deny`+`audit` en CI |
| 10.3 Actualizaciones / SBOM / firmas | ⬜ | `cargo-vet`, SBOM y `cosign` en el pipeline de release H8 |

## V11 Lógica de negocio

| Control | Estado | Evidencia |
|---|---|---|
| 11.1 Límites anti-abuso | ✅ | `policy` por factor/tenant, nonces de un solo uso (firmas H6) |
| 11.2 Antirreplay | ✅ | `last_step` atómico, refresh de un uso, nonces HMAC |

## V12 Archivos y API

| Control | Estado | Evidencia |
|---|---|---|
| 12.1 Subida de archivos | N/A | El servicio no acepta archivos |
| 12.2 Contratos de API versionados | ✅ | `/v1`, OpenAPI generado con test de rutas |

## V13 Configuración y despliegue

| Control | Estado | Evidencia |
|---|---|---|
| 13.1 Endurecimiento de imagen | 🟡 | nonroot, read-only recomendado; distroless diferido (ADR-0002) |
| 13.2 Secretos del despliegue | ✅ | Secrets/archivos 0600, validación fail-fast |

## V14 Controles de cliente

| Control | Estado | Evidencia |
|---|---|---|
| 14.1 Lógica crítica en servidor | ✅ | El cliente (H7) solo genera códigos, nunca verifica |

## Brechas abiertas (van a H8/H9)

1. Pentest externo (H9) — sin él no hay L3 certificable, solo autoevaluación.
2. WebAuthn/passkeys (H9) — resistencia real al phishing.
3. `cargo-vet`, SBOM, firmas `cosign`, builds reproducibles (H8).
4. TLS a Postgres/KMS y guía de cookies web (H6/H8).
5. FIPS opcional `aws-lc-rs` (H9, si el cliente lo exige).
