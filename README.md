# BandAll

Servicio de autenticación de segundo factor **TOTP** (RFC 6238 sobre HOTP
RFC 4226) con tres formas de despliegue y una app móvil propia:

| Superficie | Qué es | Dónde vive |
|---|---|---|
| **Servicio** | API HTTP que emite tokens, verifica factores y responde preguntas de autorización | `crates/api` → binario `bandall` |
| **Sidecar / forward-auth** | Proxy delante de tus apps: no hay que tocar su código | `deploy/compose/compose.demo.yaml`, `docs/guides-forward-auth.md` |
| **Librería embebida** | La misma lógica sin red ni HTTP, dentro de tu proceso | `crates/embedded` |
| **App autenticadora** | Cliente final de TOTP, 100 % offline | `apps/authenticator` (Flutter) |

Además: SDKs para **TypeScript, Python, Go y C#**, un interceptor **gRPC**
(`crates/sdk-grpc`) y soporte de **conexiones largas** (WebSocket) mediante
tickets de un solo uso.

---

## Índice

- [Estado real del proyecto](#estado-real-del-proyecto)
- [Requisitos y versiones](#requisitos-y-versiones)
- [Instalación](#instalación)
- [Uso](#uso) — [servidor](#1-servidor) · [demo forward-auth](#2-demo-forward-auth-proteger-una-app-sin-tocarla) · [como librería](#3-como-librería-embebida) · [app móvil](#4-app-móvil) · [SDKs](#5-sdks)
- [Arquitectura](#arquitectura)
- [Configuración](#configuración)
- [API](#api)
- [CLI](#cli)
- [Stack](#stack)
- [Verificación y pruebas](#verificación-y-pruebas)
- [Qué falta](#qué-falta)
- [Documentos](#documentos)

---

## Estado real del proyecto

**En desarrollo. Nada puede declararse cerrado todavía.**

El motivo no es la calidad del código, que está verificado artifact-first, sino
una dependencia externa: **la cuenta de GitHub está bloqueada por facturación**,
así que los runners de Actions no arrancan nunca (los jobs se crean y mueren en
3-4 s con `steps=[]`). Todo lo que CI haría se ejecuta hoy en local con
`just check`, que está en verde.

| Hito | Estado |
|---|---|
| **H0** Cimientos (workspace, CI, compose, docs) | ⚠️ abierto — el código está; CI no arranca por el bloqueo externo |
| **H1** `totp-core` | ✅ verificado (RFC 4226/6238, fuzz 1 h × 4 targets, cobertura **93,95 %**) |
| **H2** Vault + store | ✅ verificado (batería de conformidad idéntica en SQLite **y** Postgres) |
| **H3** API MFA | ✅ verificado |
| **H4** Tokens | ✅ verificado, salvo la entrega web (ver [Qué falta](#qué-falta)) |
| **H5** Hardening | ✅ verificado (fail-closed, endurecimiento de runtime, cadena de auditoría) |
| **H6** SDKs, JWKS, contenedor, DR | ✅ verificado (50 tests contra la imagen; ensayo de DR con RTO 37 s) |
| **H7** App autenticadora | ✅ código completo; ⚠️ falta dispositivo real e iOS |
| **H8** Operaciones | ✅ DR ensayado, caos ensayado, reversión ensayada; ⚠️ falta revisión cruzada de los runbooks y un destino real de entrega de alertas |
| **H9** Pentest, WebAuthn, FIPS, docs públicas | ❌ no empezado |

El detalle por hito está en [`docs/ROADMAP_STATUS.md`](docs/ROADMAP_STATUS.md);
qué está verificado y con qué evidencia, en
[`docs/VERIFICATION.md`](docs/VERIFICATION.md).

---

## Requisitos y versiones

Las versiones exactas están fijadas en el repo, no en este documento: si algo
cambia, cambia el fichero.

### Para el servidor

| Componente | Versión | Fijado en |
|---|---|---|
| **Rust** | **1.99.0** (estable) | `rust-toolchain.toml` |
| **MSRV** (mínimo soportado) | 1.85.0 | `rust-version` en `Cargo.toml`, job `msrv` de CI |
| **Postgres** | 16 | `deploy/compose/compose.yaml` |
| **SQLite** | ≥ 3.35 | el claim atómico de `cas_last_step` usa `UPDATE … RETURNING`, que es de 3.35 (2021) |
| **Docker** | ≥ 24 (Engine 29.x probado) | imagen `rust:1.99.0-bookworm` |

Herramientas del gate: `just`, `cargo-deny`, `cargo-audit`, `cargo-llvm-cov`,
`cargo-fuzz`. `just install-tools` las instala.

### Para la app móvil

| Componente | Versión | Nota |
|---|---|---|
| **Flutter** | 3.47.6 (stable) | instalado por `tests/mobile/install_toolchain.sh` |
| **Dart** | el que venga con Flutter 3.47.6 | |
| **JDK** | 17 (Adoptium) | Flutter 3.47 lo exige como mínimo |
| **Android SDK** | 36, build-tools 36.0.0 | |
| **NDK** | 27.2.12479018 | compila el crate Rust del puente |
| **cmake** | 3.22.1 | |
| `flutter_rust_bridge_codegen` | 2.13.0 | debe coincidir con el `flutter_rust_bridge` del `pubspec.yaml` |
| `cargo-ndk` | (via `cargo install`) | |

**Todo se instala en `$HOME`, sin `sudo`.** El script escribe además
`~/.config/bandall-flutter-env.sh` con los `export` necesarios para Android:

```bash
source tests/mobile/install_toolchain.sh   # descarga, compila, escribe el env
source ~/.config/bandall-flutter-env.sh    # en cada terminal nueva
```

**iOS no es posible en Linux**: requiere macOS y Xcode. La configuración está
escrita pero **nunca compilada**.

---

## Instalación

### 1. Herramientas del gate

```bash
git clone https://github.com/angelnereira/Band-All.git
cd Band-All
just install-tools    # just, cargo-deny, cargo-audit, cargo-llvm-cov
```

`rustup` lee `rust-toolchain.toml` solo: no hace falta fijar la versión a mano.

### 2. El servicio, con Docker (recomendado)

```bash
docker build -f deploy/Dockerfile .
docker compose -f deploy/compose/compose.yaml up --build
```

La imagen de runtime es **distroless** (`gcr.io/distroless/cc-debian12:nonroot`,
fijada por digest): sin shell, sin `curl`, sin gestor de paquetes. Por eso el
healthcheck es el subcomando `bandall healthcheck`, no un `curl`.

### 3. El servicio, desde el código

```bash
cargo build --release -p bandall-cli
./target/release/bandall init-config > bandall.toml   # plantilla comentada
```

Genera **dos secretos** que hay que crear antes de arrancar:

```bash
head -c 32 /dev/urandom > kek.bin && chmod 600 kek.bin      # KEK de la vault
head -c 32 /dev/urandom > audit-key.bin && chmod 600 audit-key.bin  # clave de la cadena de auditoría
```

### 4. La app móvil

```bash
source tests/mobile/install_toolchain.sh
source ~/.config/bandall-flutter-env.sh
cd apps/authenticator
flutter test                                   # 52 tests, sin dispositivo
flutter build apk --release                    # APK de producción
```

El APK sale en `build/app/outputs/flutter-apk/app-release.apk` (~66 MB, tres
ABIs). `just verify-app` hace todo el ciclo y además **comprueba el APK que
sale**, no el código:

- que **no** declare `INTERNET` ni `ACCESS_NETWORK_STATE`;
- que la librería Rust esté dentro para las tres ABIs;
- que el manifiesto traiga `allowBackup=false` y reglas de extracción;
- que `FLAG_SECURE` se aplique de verdad en `MainActivity`.

---

## Uso

### 1. Servidor

El flujo completo son cuatro pasos HTTP. Todo con `curl`, sin SDK:

```bash
BANDALL=http://127.0.0.1:8080
SVC='-H "x-service-key: demo-service-key-0123456789abcdef"'

# 1) Enrolar: el servidor devuelve la URI otpauth:// y el factor queda pendiente
curl -sX POST $BANDALL/v1/factors/enroll/start -H "x-service-key: ..." \
  -H 'content-type: application/json' \
  -d '{"tenant_id":"...","subject_external_id":"alice",
       "issuer":"BandAll","account":"alice@example.com"}'
# -> {"factor_id":"...","otpauth_uri":"otpauth://totp/..."}

# 2) Confirmar con el primer código (consume el paso que acepta)
curl -sX POST $BANDALL/v1/factors/enroll/confirm -H 'content-type: application/json' \
  -d '{"tenant_id":"...","subject_id":"...","factor_id":"...","code":"123456"}'

# 3) Verificar el segundo factor -> tokens de sesión
curl -sX POST $BANDALL/v1/mfa/verify -H 'content-type: application/json' \
  -d '{"tenant_id":"...","subject_id":"...","factor_id":"...","code":"123456"}'
# -> {"access_token":"eyJ...","refresh_token":"...","expires_in":600,...}

# 4) Refrescar (el refresh es de un solo uso: rotar y reutilizar revoca la familia)
curl -sX POST $BANDALL/v1/token/refresh \
  -d '{"refresh_token":"..."}'
```

Puntos que sorprenden y conviene saber:

- **`enroll/confirm` consume el paso que acepta.** Si confirmas con el código de
  este segundo y luego verificas con el *mismo* código, es un replay y se
  deniega. Es el comportamiento correcto (un OTP vale una vez), pero un cliente
  de pruebas tiene que avanzar 30 s.
- **Los códigos se ocultan por defecto en la app**, y `revealSecret` /
  `exportBackup` piden biometría. Ver `docs/adr/0016-flutter-end-user-app.md`.
- **El `ACCESS_TTL` son 10 minutos**; el refresh, 7 días, y rota en cada uso.

### 2. Demo: forward-auth (proteger una app sin tocarla)

La demo levanta BandAll + nginx + una app legacy que **no sabe que BandAll
existe**. nginx hace de proxy y delega la decisión:

```bash
head -c 32 /dev/urandom > deploy/compose/demo-kek.bin
chmod 600 deploy/compose/demo-kek.bin
docker compose -f deploy/compose/compose.demo.yaml up --build

curl -i http://127.0.0.1:8080/          # 401, sin token
# tras enrolar y verificar:
curl -i http://127.0.0.1:8080/ -H "Authorization: Bearer eyJ..."
                                      # 200 y la app legacy responde
```

Detalle para nginx, Envoy y Traefik en
[`docs/guides-forward-auth.md`](docs/guides-forward-auth.md).

### 3. Como librería embebida

Sin HTTP, sin red: la misma lógica dentro de tu proceso.

```rust
use bandall_embedded::Embedded;

let bandall = Embedded::sqlite_in_memory().await?;
let factor  = bandall.enroll_start(/* … */).await?;
bandall.enroll_confirm(/* … */).await?;
let tokens  = bandall.mfa_verify(/* … */).await?;
```

Útil cuando el proceso ya tiene su propio servidor y no quieres una llamada de
red por cada verificación. Decisión y límites en
`docs/adr/0014-bandall-embedded-crate.md`.

### 4. App móvil

1. `flutter build apk --release` (o `flutter run` con un dispositivo conectado).
2. Escanea el QR que muestra el servicio al enrolar, o pega el enlace
   `otpauth://`.
3. El código aparece al tocar la cuenta y se oculta a los 15 s.
4. Botón de reloj (arriba a la derecha) → *Clock check*: si un código acaba de
   ser aceptado en otro sitio, se indica la hora y la app compara.

Propiedades de la app, todas con prueba:

- **Cero red.** La app **no pide permiso `INTERNET`**, y el manifiesto de
  release lo *elimina* explícitamente (`tools:node="remove"`) porque ML Kit lo
   añade por telemetría a través de `mobile_scanner`. Una dependencia que
  quisiera llamar a casa falla en vez de poder hacerlo en silencio.
- **La criptografía solo existe en Rust.** No hay una segunda implementación de
  TOTP en Dart: dos implementaciones significan que una de ellas nunca se
  verifica contra la otra. Los vectores RFC se comprueban en el puente
  (12 tests) y contra el servidor real en la suite del contenedor.
- **`FLAG_SECURE`.** Sin capturas de pantalla, sin grabación, sin miniatura en
  recientes. El coste es deliberado: el usuario tampoco puede capturar sus
  propios códigos.
- **Sin backup en la nube** (`allowBackup=false` + reglas de extracción que
  excluyen todo). El backup manual es explícito, con passphrase (Argon2id) y
  biometría.
- **Los códigos no saltan a mitad de sesión.** El reloj se ancla una vez y
  avanza con un `Stopwatch` monótono, así que una corrección NTP o un cambio de
  zona horaria no cambia los 8 códigos visibles de golpe.

### 5. SDKs

Cuatro SDKs finos (TypeScript, Python, Go, C#) sobre los vectores de
conformidad, más un crate de Rust para axum y otro para gRPC:

```rust
// axum: verifica el token sin llamar a BandAll, contra el JWKS cacheado
use bandall_sdk_axum::{JwksVerifier, RequireToken};
let verifier = JwksVerifier::new("https://bandall.example/.well-known/jwks.json");
```

```rust
// gRPC: mismo contrato sobre metadatos (ADR-0017)
use bandall_sdk_grpc::{RequireTokenInterceptor, StaticJwks};
Server::builder()
    .interceptor(RequireTokenInterceptor::new(verifier, iss, aud))
    .add_service(MyService);
```

---

## Arquitectura

### Dónde está cada cosa

```
crates/totp-core            HOTP/TOTP, Base32, otpauth://  (puro, sin IO)
crates/vault                envolvente KEK→DEK, AES-GCM + AAD, Argon2id
crates/store                Postgres y SQLite + migraciones (8 por motor)
crates/tokens               JWT EdDSA, refresh opaco, tickets de conexión, JWKS
crates/policy               rate limit, backoff exponencial, lockout
crates/sigs                 firmas HMAC de requests y webhooks
crates/api                  servicio HTTP (axum), errores RFC 7807
crates/sdk-axum             verificación en proceso con JWKS cacheado
crates/sdk-grpc             interceptor tonic para gRPC
crates/embedded             la misma lógica sin HTTP ni sockets
crates/authenticator-core   lógica de la app offline
crates/cli                  binario `bandall`

apps/authenticator          app Flutter (ADR-0016) + su crate Rust del puente
sdks/{ts,python,go,csharp}  SDKs finos sobre los vectores de conformidad
sdks/conformance            vectores compartidos que todos deben cumplir

deploy/Dockerfile           imagen de producción (distroless, por digest)
deploy/compose/             base, dev, test, demo y observabilidad
deploy/helm/bandall         chart de Kubernetes
docs/                       verificación, amenazas, ASVS, MASVS, guías, runbooks
docs/adr/                   decisiones de diseño, una por fichero
tests/container/            50 tests contra la imagen construida
tests/dr/                   ensayo de backup → destruir → restaurar → login
tests/mobile/               instalación del toolchain y verificación de la app
tests/load/                 perfil de carga k6
```

### Flujo de una verificación

```
   cliente
     │  POST /v1/mfa/verify {tenant, subject, factor, code}
     ▼
┌─────────────────────────────────────────────────────────────┐
│  crates/api  (axum)                                        │
│    gates::acquire ──► policy  (rate limit + lockout)       │
│    tokens::verify (firma, iss/aud/exp, algoritmo fijo)      │
│    vault::open  ──►  KEK ──► DEK ──► AES-GCM  (AAD por fila)│
│    totp_core    ──►  HOTP/TOTP con el paso inyectado        │
│    store::cas_last_step  ──► UPDATE … WHERE last_step < $step│
└─────────────────────────────────────────────────────────────┘
     │  200 {access_token, refresh_token}
     ▼
   cliente  ──►  Authorization: Bearer eyJ…  ──►  tu app (SDK)
```

**El antirreplay es una única sentencia atómica.** `cas_last_step` no es
"leer el paso y luego escribir": es un `UPDATE … WHERE last_step < $step` y
solo gana un escritor. Con 25 verificaciones simultáneas del mismo código,
exactamente una sale con éxito. Está en la batería de conformidad, y la batería
se ejecuta **idéntica en SQLite y en Postgres**.

### Capas y dirección de las dependencias

```
        cli ──► api ──► ┌─► policy          ┐
                         ├─► store           ├─► vault ──► totp-core
        sdk-axum ──────► ├─► tokens ─────────┤
        sdk-grpc  ──────► └───────────────────┘
        embedded ───────► (todo lo anterior, sin HTTP)
```

Las dependencias fluyen **siempre hacia dentro, hacia `totp-core`**, que es puro:
sin red, sin base de datos y **sin `SystemTime::now()`** — el tiempo se inyecta.
Por eso cada test de TOTP es determinista y por eso el fuzzer puede probar
millones de entradas sin que ninguna dependa del reloj.

### Modelo de datos de un secreto

```
KEK (fichero 0400 / KMS externo)
  └─► DEK por fila, envuelta con RSA-OAEP / AES-KW
        └─► secreto TOTP, cifrado con AES-GCM y AAD ligado a la fila
```

Consecuencia práctica: **robar la base de datos no sirve de nada** sin el KEK, y
un ciphertext movido a otra fila no descifra porque el AAD ya no encaja.

### Los tres modos de despliegue

| Modo | Cuándo | Coste |
|---|---|---|
| **Servicio** | varios servicios comparten factor | una llamada de red por verificación |
| **Forward-auth** | quieres MFA sin tocar el código de tu app | debe pasar por el proxy (nada puede llamar al backend sin pasar) |
| **Embebido** | un solo proceso, latencia importa | acopla tu proceso al esquema de la BBD |

### Conexiones largas (WebSocket / gRPC)

Un WebSocket y un stream gRPC sobreviven al token que los abrió, que es
exactamente el hueco que rompe el modelo de "verificar por petición". ADR-0017
lo cierra con tres piezas:

```
POST /v1/ws/ticket          (Bearer)  ──► ticket opaco, 30 s, un solo uso
      │                                  (un navegador no puede poner cabeceras
      │                                   en un Upgrade; y el token en la URL
      ▼                                   acaba en logs de proxy y en el historial)
POST /v1/ws/ticket/redeem   (S2S)     ──► identidad + techo duro de conexión (= exp)
POST /v1/ws/ticket/recheck  (S2S)     ──► "¿sigue viva la sesión?"  401 uniforme
```

El claim del ticket es un `UPDATE … WHERE used_at IS NULL`: un solo uso
garantizado también bajo concurrencia. Y revocar la sesión **corta conexiones
ya establecidas**, que era el agujero que quedaba abierto.

---

## Configuración

Fichero TOML (por defecto `bandall.toml`, o `BANDALL_CONFIG`). Plantilla
completa con `bandall init-config`:

```toml
listen            = "127.0.0.1:8080"
database          = "sqlite"                    # o "postgres"
database_url      = "sqlite:bandall.db"         # o postgres://…
kms_key_file      = "/run/secrets/bandall-kek"  # 32 B, 0400
kek_id            = "kek-1"
audit_key_file    = "/run/secrets/bandall-audit-key"   # 32 B, 0400
service_key       = "…"                         # la credencial S2S
token_issuer      = "bandall"
token_audience    = "bandall"
keys_dir          = "keys"                      # claves Ed25519 del JWT
policy_backend    = "memory"                    # o "redis"
trusted_proxies   = []                          # obligatorio si detrás de proxy
body_limit_bytes  = 65536
```

Variables de entorno que respeta el compose:
`BANDALL_CONFIG`, `BANDALL_DATABASE_URL`, `BANDALL_KMS_KEY_FILE`,
`BANDALL_AUDIT_KEY_FILE`, `BANDALL_SERVICE_KEY`.

Reglas que no son sugerencias:

- **`trusted_proxies` vacío = el peer es la IP remota.** Si hay un proxy delante
  y no lo declaras, el rate limit por IP se aplica al proxy y todos los usuarios
  comparten una sola cuota.
- **Postgres remoto sin TLS se rechaza antes de abrir el socket.** Un host que
  no sea loopback exige `sslmode=require`.
- **Los secretos van por fichero 0400 o por docker secrets**, nunca horneados en
  la imagen ni en un `.env` versionado.

---

## API

17 rutas. El contrato completo, con esquemas, se sirve en
`GET /openapi.json` y hay un test que lo fija, de modo que el spec y los handlers
no pueden separarse sin romper la suite.

| Ruta | Auth | Para qué |
|---|---|---|
| `GET /healthz` | — | vivo (siempre 200) |
| `GET /readyz` | — | **listo**: comprueba el esquema, no solo que hay socket |
| `GET /metrics` | — | Prometheus |
| `GET /openapi.json` | — | contrato |
| `GET /.well-known/jwks.json` | — | claves públicas |
| `POST /v1/factors/enroll/start` | S2S | empieza el enrolado |
| `POST /v1/factors/enroll/confirm` | — | confirma con el primer código |
| `POST /v1/mfa/verify` | — | segundo factor → tokens |
| `POST /v1/mfa/recover` | — | código de recuperación |
| `POST /v1/verify` | S2S | verificación servicio-a-servicio |
| `POST /v1/token/refresh` | — | rota el refresh |
| `POST /v1/token/revoke` | — | revoca sesión y familia |
| `POST /v1/sigs/verify` | S2S | firma HMAC de request/webhook |
| `GET /v1/authz/check` | Bearer | "¿esta sesión sigue viva y con estos scopes?" |
| `POST /v1/ws/ticket` | Bearer | ticket de conexión (ADR-0017) |
| `POST /v1/ws/ticket/redeem` | S2S | canjea el ticket, devuelve el techo |
| `POST /v1/ws/ticket/recheck` | S2S | revalida la sesión |

Los errores son **RFC 7807** y uniformes: usuario inexistente y código erróneo
devuelven el mismo `401`, sin distinguishable por tiempo ni por cuerpo.

---

## CLI

```
bandall serve         Levanta el servidor HTTP (por defecto)
bandall migrate       Aplica las migraciones pendientes y sale
bandall audit         Operaciones del log de auditoría (incluye `verify`)
bandall apikey        Operaciones de cliente HMAC
bandall tenant        Operaciones de tenant (bootstrap del operador)
bandall init-config   Imprime una configuración de ejemplo
bandall version       Versión
bandall healthcheck   Sonda de vida para el healthcheck del contenedor
```

La imagen no tiene `curl`, así que `healthcheck` es un subcomando a propósito.

---

## Stack

### Workspace de Rust (11 crates)

| Crate | Responsabilidad | IO |
|---|---|---|
| `bandall-totp-core` | HOTP/TOTP, Base32, `otpauth://` | **ninguno** (tiempo inyectado) |
| `bandall-vault` | envolvente KEK→DEK, AES-GCM con AAD, Argon2id | solo ficheros |
| `bandall-store` | persistencia + migraciones | Postgres, SQLite |
| `bandall-tokens` | JWT EdDSA, refresh opaco, JWKS | ninguno |
| `bandall-policy` | rate limit, backoff, lockout | memoria, Redis |
| `bandall-sigs` | firmas HMAC de requests y webhooks | ninguno |
| `bandall-api` | servicio HTTP (axum), errores RFC 7807 | red |
| `bandall-sdk-axum` | verificación en proceso, JWKS cacheado | red (al descargar el JWKS) |
| `bandall-sdk-grpc` | interceptor `tonic` | ninguno |
| `bandall-embedded` | fachada sin HTTP | como la API |
| `bandall-authenticator-core` | lógica de la app offline | ninguno |
| `bandall-cli` | binario `bandall` | — |

Dependencias de terceros, y por qué están (regla de `AGENTS.md`):

- `axum` + `tower-http` — servidor HTTP y su middleware.
- `sqlx` — acceso a Postgres/SQLite tipado, con migraciones versionadas.
- `ed25519-dalek` (RustCrypto) — firma de los tokens; **EdDSA, no RSA ni HMAC**,
  por tamaño de clave y por no arrastrar la gestión de claves certificadas
que hace RSA.
- `aes-gcm`, `argon2`, `rsa` / `sha2` — RustCrypto.
- `subtle` — **toda** comparación de códigos, MAC y tokens.
- `tonic` 0.12 — transporte gRPC estándar sobre tokio; la única forma sancionada
  de leer metadatos por RPC.
- `serde`/`serde_json`/`toml`, `tracing`, `utoipa`/`axum-extra` (OpenAPI),
  `uuid`, `time`.

---

## Verificación y pruebas

La regla del proyecto es que **se verifica el artefacto, no el árbol de
fuentes**. Cinco niveles:

```bash
just check            # gate completo = CI: fmt + clippy + tests + deny + audit
```

| Nivel | Qué prueba | Tamaño |
|---|---|---|
| **Unidad** | vectores RFC 4226/6238, base32, parsers, criptografía | 155 tests Rust |
| **Conformidad del store** | la **misma** batería en SQLite y Postgres, incluida la concurrencia | 2 motores |
| **E2E de API** | flujo MFA completo con vault y store reales | `crates/api/tests/` |
| **Artefacto de contenedor** | 50 tests funcionales + 16 de firmas contra **la imagen** | `tests/container/verify.sh` |
| **Artefacto de la app** | analyze + clippy + tests + APK release + aserciones de empaquetado | `tests/mobile/verify_app.sh` |
| **Reversión** | dos versiones reales, savepoint, forward, rollback documentado, auditoría, forward otra vez | `tests/ops/rehearse_rollback.sh` |
| **App Dart** | 52 tests, incluida la prueba de que funciona sin red | `flutter test` |

Comprobaciones que la experiencia ha demostrado que valen:

- `/readyz` **tenía** un bug: respondía 200 con la base de datos vacía, porque
  hacía `SELECT 1`. Lo encontró el ensayo de DR al destruir el esquema bajo un
  servicio en marcha. Corregido en ambos motores, con test de regresión.
- El APK de release **declaraba `INTERNET`**, arrastrado por la telemetría de
  Google vía ML Kit. Ahora hay un check que falla si vuelve a aparecer.
- El APK **no llevaba dentro** la librería Rust, porque `cargokit` deriva el
  nombre del artefacto del nombre del *package*, y cargo normaliza los guiones.
  El build terminaba bien y la app crasheaba al arrancar. Ahora hay un check
  que verifica la presencia de las tres ABIs.

```bash
tests/container/verify.sh            # 50 tests contra la imagen
tests/container/verify.sh --bench    # + medición de carga
tests/dr/rehearse_restore.sh         # backup → destruir → restaurar → login real
tests/ops/rehearse_rollback.sh       # forward, reversión documentada, auditoría, forward
tests/ops/chaos_drill.sh             # alertas cargadas, disparadas, entregadas y resueltas
just verify-app                      # el ciclo completo de la app
cargo test -p bandall-totp-core      # un crate
```

---

## Qué falta

Concreto, y sin adornos. Ordenado por lo que bloquea más.

### Necesita una decisión tuya

1. **Credencial primaria** (reservado como `docs/adr/0012-primary-credential.md`).
   ¿BandAll solo aporta el segundo factor, o también emite la sesión primaria?
   El rol "entrar con BandAll" de la app depende de esto, y está excluido a
   propósito hasta que se decida.
2. **ADR-0011 — entrega de sesión web.** Cookies propias (con CSRF) frente a
   BFF. La guía y el ADR existen; la elección no.
3. **ADR-0009 — resincronización de deriva.** Cómo recuperar una cuenta cuyo
   reloj se ha desviado fuera de ventana. La recomendación escrita es aceptar
   dos códigos consecutivos.
4. **KMS real.** Hoy `LocalKms` con fichero 0400. Para producción, Azure Key
   Vault / AWS KMS / HSM. Está en el checklist de salida.
5. **Multi-tenant desde el día uno** o por fases.

### Necesita hardware o credenciales

6. **Pruebas en dispositivo real** (H7, punto 5): modo avión, reinicio,
   desinstalación y reloj ±45 s. Todo está automatizado salvo el vuelo.
7. **iOS**: requiere macOS y Xcode. Configurado, nunca compilado.
8. **CI funcional**: la cuenta está bloqueada por facturación.
9. **Biometría real**: los gates se prueban con `AlwaysDenyGate` y
   `AlwaysAllowGate`; lo que falta es el sensor.
10. **Escaneo de la app**: trivy/grype, SBOM y firma de la imagen se planifican
    para H5, y la firma de la app para después.

### Trabajo de código que queda

11. **Alcance de la app**: solo TOTP. Cuando se decida lo del punto 1, la app
    crece hacia "entrar con BandAll".
12. **Importar desde Google Authenticator** (`otpauth-migration://`): **no
    implementado a propósito**. El formato es protobuf no documentado y no hay
    ningún fixture real contra el que verificar un parser. Se decide cuando haya
    uno.
13. **Los tres ensayos de H8 están hechos** (backup→restaurar, caos con
    alertas disparadas y entregadas, y reversión con savepoint). Lo que queda
    del hito no es código: que otra persona revise los runbooks, y que las
    alertas tengan un destino de entrega real —hoy el receptor está **vacío a
    propósito**, para no fingir que alertan.
14. **Linux y web de escritorio** para la app: falta toolchain de Flutter
    (clang/cmake/GTK3) y no hay `sudo` en esta máquina.

---

## Documentos

| Documento | Para qué |
|---|---|
| [`BANDALL_BLUEPRINT.md`](BANDALL_BLUEPRINT.md) | Diseño: arquitectura, crates, API, amenazas |
| [`BANDALL_ROADMAP.md`](BANDALL_ROADMAP.md) | Hitos H0–H9, gates y checklist de producción |
| [`AGENTS.md`](AGENTS.md) | Reglas de trabajo para agentes (manda sobre suposiciones) |
| [`docs/VERIFICATION.md`](docs/VERIFICATION.md) | Qué está verificado, con qué evidencia y cómo reproducirlo |
| [`docs/ROADMAP_STATUS.md`](docs/ROADMAP_STATUS.md) | Tablero de gates: qué está cerrado de verdad |
| [`docs/threat-model.md`](docs/threat-model.md) | Amenazas, mitigaciones y brechas conocidas |
| [`docs/asvs-l3-review.md`](docs/asvs-l3-review.md) | Autoevaluación OWASP ASVS L3 |
| [`docs/masvs-review.md`](docs/masvs-review.md) | Autoevaluación OWASP MASVS (app móvil) |
| [`docs/guides-forward-auth.md`](docs/guides-forward-auth.md) | nginx, Envoy, Traefik, SDKs y firmas |
| [`docs/guides-web-and-mobile-sessions.md`](docs/guides-web-and-mobile-sessions.md) | Sesiones web y móvil |
| [`docs/runbooks/`](docs/runbooks) | Fuga de secretos, revocación, rotación, restauración, **caos** y **reversión** |
| [`docs/RELEASING.md`](docs/RELEASING.md) | SemVer y pipeline de release |
| [`docs/adr/`](docs/adr) | 16 decisiones de diseño, con su porqué (0012 reservada) |

Informa de vulnerabilidades según [`SECURITY.md`](SECURITY.md).
Contribuye según [`CONTRIBUTING.md`](CONTRIBUTING.md).