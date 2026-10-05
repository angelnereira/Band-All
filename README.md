# BandAll

Servicio de seguridad **TOTP** en Rust: autenticación de segundo factor
(RFC 6238 sobre HOTP RFC 4226), emisión de tokens de sesión, verificación
servicio-a-servicio y firmas HMAC para APIs y webhooks. Tres modos de uso:
servicio independiente, sidecar/forward-auth y librería embebida.

> **Estado: en desarrollo (H0–H8 implementados, H9 pendiente).** Consulta
> [`docs/VERIFICATION.md`](docs/VERIFICATION.md) para saber qué está
> verificado y qué no: **ningún hito puede declararse cerrado todavía**.

## Documentos

| Documento | Para qué |
|---|---|
| [`BANDALL_BLUEPRINT.md`](BANDALL_BLUEPRINT.md) | Diseño: arquitectura, crates, API, amenazas |
| [`BANDALL_ROADMAP.md`](BANDALL_ROADMAP.md) | Hitos H0–H9, gates y checklist de producción |
| [`AGENTS.md`](AGENTS.md) | Reglas de trabajo para agentes (manda sobre suposiciones) |
| [`docs/VERIFICATION.md`](docs/VERIFICATION.md) | Estado real de tests y del entorno |
| [`docs/ROADMAP_STATUS.md`](docs/ROADMAP_STATUS.md) | Tablero de gates por hito (qué está cerrado de verdad) |
| [`docs/threat-model.md`](docs/threat-model.md) | Amenazas, mitigaciones y brechas |
| [`docs/asvs-l3-review.md`](docs/asvs-l3-review.md) | Autoevaluación OWASP ASVS L3 |
| [`docs/guides-forward-auth.md`](docs/guides-forward-auth.md) | nginx / Envoy / Traefik, SDKs, firmas |
| [`docs/runbooks/`](docs/runbooks) | Fuga de secretos, revocación, rotación, restauración |
| [`docs/RELEASING.md`](docs/RELEASING.md) | SemVer y pipeline de release |
| [`docs/adr/`](docs/adr) | Decisiones de diseño (workspace, runtime, JWT, FIPS…) |

## Estructura

```
crates/totp-core            HOTP/TOTP, Base32, otpauth:// (puro, sin IO)
crates/vault                Cifrado envolvente de secretos + Argon2id
crates/store                Persistencia: Postgres y SQLite + migraciones
crates/tokens               JWT EdDSA, refresh opaco, JWKS
crates/policy               Rate limit, backoff exponencial, lockout
crates/sigs                 Firmas HMAC de requests/webhooks
crates/api                  Servicio HTTP (axum), errores RFC 7807
crates/sdk-axum             Layer/guard para verificación offline
crates/authenticator-core   Lógica de la app autenticadora offline
crates/cli                  Binario `bandall`
sdks/{ts,python}            SDKs finos sobre vectores de conformidad
deploy/                     Dockerfile, compose (dev/demo/obs), chart Helm
tests/load                  Perfil de carga k6
```

## Comandos

```bash
just check            # gate local completo (= CI)
just install-tools    # just, cargo-deny, cargo-audit, cargo-llvm-cov
cargo test -p bandall-totp-core          # un crate
cargo test -p bandall-api --test e2e     # E2E del flujo MFA
docker build -f deploy/Dockerfile .      # imagen de producción
docker compose -f deploy/compose/compose.yaml up -d   # Postgres local
```

## Demo: proteger una app sin tocarla

```bash
head -c 32 /dev/urandom > deploy/compose/demo-kek.bin && chmod 600 deploy/compose/demo-kek.bin
docker compose -f deploy/compose/compose.demo.yaml up --build
curl -i http://127.0.0.1:8080/          # 401 sin token
# tras enrolar y verificar, con Bearer → 200 y la app legacy responde
```

Detalle en [`docs/guides-forward-auth.md`](docs/guides-forward-auth.md).

## Seguridad

- Sin `unsafe` (`#![forbid(unsafe_code)]`), criptografía solo de
  RustCrypto/`aws-lc-rs`, comparación en tiempo constante con `subtle`.
- Secretos TOTP cifrados con envolvente KEK→DEK y AAD por fila: un robo de la
  base de datos no sirve de nada.
- Antirreplay atómico (`UPDATE … WHERE last_step < $step`): un OTP vale una vez.
- Refresh tokens opacos con rotación y detección de reutilización; auditoría
  encadenada por hash (`bandall audit verify`).
- **Fail-closed**: ante error de DB, KMS, reloj o configuración se deniega.

Informa de vulnerabilidades según [`SECURITY.md`](SECURITY.md).
Contribuye según [`CONTRIBUTING.md`](CONTRIBUTING.md).