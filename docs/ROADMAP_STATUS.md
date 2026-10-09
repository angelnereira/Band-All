# Tablero de hitos — estado real de gates

Fuente: `BANDALL_ROADMAP.md` §3 y `docs/VERIFICATION.md`. Regla del repo: un
hito se cierra solo cuando su gate se cumple por completo. **Actualizado:
2026-10-08.**

| Hito | Código | Tests ejecutados | Gate | Estado |
|---|---|---|---|---|
| **H0** Cimientos | ✅ | ✅ (workspace completo: **155 tests**) | ⚠️ | **abierto**: CI sin runner; `main` sin protección (PR/CI/firmas) |
| **H1** `totp-core` | ✅ | ✅ 24 unit + 12 proptest + 1 doc; **fuzz 1 h × 4 targets sin crashes**; cobertura **93.95 %** | ✅ | **cerrado** (fuzz 1 h verificado con cargo-fuzz; falta CI solo como formalidad) |
| **H2** Vault + store | ✅ | ✅ vault (8+1); store **SQLite y Postgres 18.6** (6 cada uno, incluida la batería at-rest) | ✅ | **cerrado** (en local; falta CI) |
| **H3** API MFA | ✅ | ✅ 29 unit + 11 E2E | ✅ | **cerrado** (sujeto a CI verde) |
| **H4** Tokens | ✅ | ✅ tokens (8); E2E de rotación verde, **con Postgres** | ⚠️ | **abierto** (ítem 5 web: entregado como guía + ADR-0011, sin cookies en el servidor) |
| **H5** Hardening | ✅ | ✅ policy (8), sigs (4), auditoría (T4), **secretos en logs (2)**, **fuzz HTTP 1 h**; **cadena con clave verificada en el contenedor**: verde y BROKEN tras alterar una fila | ⚠️ | **abierto** (falta CI, pentest y decisión de ADR-0009) |
| **H6** Integración | ✅ | ✅ sdk-axum (2), sigs (4), **SDK TS/Python/Go/C# (4 SDKs, mismos vectores)**, demo forward-auth funcionando en Docker, **modo embebido** (`bandall-embedded`, ADR-0014), **50 tests funcionales + 16 de firmas HMAC contra el contenedor**, scopes y JWKS remoto (ADR-0013), **conexiones largas WS/gRPC** (ADR-0017) | ⚠️ | **abierto** (ADR-0013 resuelve el choque de scopes; falta CI y el gate de la demo legacy levantado desde cero) |
| **H7** App autenticadora | ✅ app Flutter completa (`apps/authenticator`, ADR-0016), puntos 1-4 y 6 del hito cumplidos | ✅ **12 tests del puente Rust (RFC 6238/4226) + 52 tests Dart + analyze/clippy limpios + APK release construido** | ⚠️ | **abierto solo por hardware**: punto 5 (modo avión, reinicio, desinstalación, reloj ±45 s) y biometría real necesitan un dispositivo; iOS necesita macOS |
| **H8** Operación | ⚠️ metrics/Helm/k6/runbooks sí; **SLOs medidos en contenedor sí**; **DR ensayado** (`tests/dr/rehearse_restore.sh`, RTO 37 s); caos **no** | ⚠️ | ❌ | **abierto** (falta ensayo de caos: KMS caído → fail-closed, y alertas disparadas a propósito) |
| **H9** Certificación | ❌ (pentest, WebAuthn, FIPS) | ❌ | ❌ | **no empezado** |

## Bloqueos que impiden cerrar H2–H6

1. **GitHub CI no arranca**: cuenta bloqueada por facturación. El workflow es
   válido (T1, y los 11 pins de acciones se han re-verificado con
   `git ls-remote` el 2026-10-06) y GitHub **sí crea los runs y los 8 jobs**,
   pero ninguno arranca: terminan en 2-3 s con `steps=0` y `runner_id=0`, igual en
   `main` y en las ramas de T2/T3. El diagnóstico previo *"The job was not
   started because your account is locked due to a billing issue"* sigue siendo
   la causa a resolver; no es un defecto del workflow. GitGuardian sí pasa (no
   usa runners de Actions).
2. ~~Sin demonio de Docker en esta máquina~~ **resuelto el 2026-10-07**: Docker
   Desktop 4.94.0 está disponible y operativo. El build de la imagen, el
   arranque, la batería funcional y de seguridad, la demo forward-auth y la
   carga simulada se ejecutan hoy contra el contenedor real
   (`tests/container/`, ver §Verificación del contenedor).

## Verificación del contenedor (2026-10-08)

`tests/container/verify.sh` empaqueta el proyecto y verifica **el artefacto**,
no el árbol de fuentes. Resultado de la ronda, en las dos configuraciones de
base de datos:

| Comprobación | SQLite | Postgres (TLS) |
|---|---|---|
| Build de la imagen (distroless, 53.9 MB) | ✅ | ✅ |
| `nonroot:nonroot`, sin shell, HEALTHCHECK propio | ✅ | ✅ |
| Fail-closed de configuración (2 casos) | ✅ | ✅ |
| `migrate` + `serve` + `/readyz` + `healthcheck` | ✅ | ✅ |
| Hardening en runtime (read-only, `cap_drop`, core=0) | ✅ | ✅ |
| Suite funcional y de seguridad (**50 tests**, +5 de tickets de conexión) | ✅ | ✅ |
| Firmas HMAC (**16 tests**) | ✅ | ✅ |
| Sin secretos ni pánicos en los logs | ✅ | ✅ |
| Cadena de auditoría: verde, y BROKEN tras alterar una fila | ✅ | ✅ |

Carga simulada (`--bench`, clientes mock desechables, p50/p95/p99 medidos):

| Fase | p50 | p95 | p99 | rps |
|---|---|---|---|---|
| `/v1/verify` secuencial | 93 ms | 161 ms | 206 ms | 10 |
| `/v1/verify` 10 clientes | 62 ms | 71 ms | 74 ms | 159 |
| `/v1/verify` 50 clientes | 223 ms | 260 ms | 265 ms | 213 |
| rechazo 401 (sin throttling) | 46 ms | 56 ms | 80 ms | 445 |
| `/v1/authz/check` | 26 ms | 49 ms | 59 ms | 474 |

Números de una máquina de escritorio con Docker Desktop y un límite de 1 CPU /
512 MB impuesto al contenedor; son la línea base de H8, no un objetivo de
producción. `bench-results.json` (ignorado por git) guarda el detalle.

Lo que la batería encontró y era defecto **del arnés**, no del servicio: el
confirm de enrolamiento consume el paso que acepta, así que confirmar con el
código del paso actual convertía toda verificación posterior en replay
—comportamiento correcto del servidor, cliente equivocado.

Y lo que encontró y **sí** era defecto del servicio: `/readyz` respondía 200
con la base de datos vacía, porque hacía `SELECT 1` en lugar de comprobar el
esquema. Lo destapó el ensayo de DR al destruir el esquema bajo un servicio en
marcha. Corregido en los dos motores, con test de regresión.

## Verificación de la app móvil (2026-10-08)

`tests/mobile/verify_app.sh` hace el mismo para la app: no basta con que compile,
se comprueba **el APK que sale**.

| Comprobación | Estado |
|---|---|
| `flutter analyze` sin avisos y `clippy -D warnings` | ✅ |
| 12 tests del puente Rust contra los vectores RFC 6238/4226 | ✅ |
| 52 tests Dart, incluida la prueba de que la app funciona sin red | ✅ |
| APK de release construido (~66 MB, tres ABIs) | ✅ |
| El APK **no** declara `INTERNET` ni `ACCESS_NETWORK_STATE` | ✅ |
| La librería Rust está dentro del APK para las tres ABIs | ✅ |

Los dos fallos de empaquetado que estas dos últimas aserciones evitan:

1. El APK de release **declaraba red** que la app negaba en su documentación,
   arrastrada por la telemetría de Google a través de ML Kit → `mobile_scanner`.
   Se corrige con `tools:node="remove"`.
2. El APK **no llevaba dentro** la librería Rust: `cargokit` deriva el nombre
   del artefacto del nombre del *package*, y cargo normaliza los guiones a
   subrayados. Build verde, crash al arrancar. Se corrige renombrando el paquete
   a `bandall_authenticator_ffi` — el nombre con guiones es *load-bearing*.

## Orden de desbloqueo

1. Resolver la facturación de GitHub (o correr el gate en otra máquina) →
   `just check` completo con Postgres, que **ya pasa en local**.
2. `policy_backend = "database"` (ADR-0008) de T2 **verificado contra Postgres
   real** en esta ronda (batería completa, incluidas la reserva atómica y la
   ráfaga de 50 appends encadenados).
3. Fuzz de los parsers de `totp-core` contra el contenedor ya construido.
4. Cerrar H2→H6 en orden. H7 y H8 tienen su parte de código hecha y
   verificada contra los artefactos; lo que les queda es hardware (H7) y caos
   (H8), no desarrollo.

## Remediación de la revisión de seguridad (`docs/AGENT_BRIEF.md`)

| Tarea | Estado |
|---|---|
| T1 `ci.yml` | ✅ fusionada (PR #2); pins re-verificados el 2026-10-06 |
| T2 rate limit atómico + scopes + backend `database` | ✅ PR #3; **verificado contra Postgres real** |
| T3 ventana de 3 pasos y deriva observada | ✅ PR #4 (25 tests de `api` verdes); ADR-0009 **esperando decisión humana** |
| T4 auditoría robusta | ✅ PR #5 (`fix/audit-chain-v2`, **ADR-0010**, migración 7); verificado en SQLite **y Postgres** |
| T5–T10 | pendientes (en el orden del brief) |

## Deuda cerrada fuera del brief (2026-10-06)

Ninguna de estas cuatro estaba en el brief; bloqueaban `just check` y llevaban
meses sin mirarse porque el CI nunca arrancaba.

1. **Toolchain 1.98.1 → 1.99.0**, en `rust-toolchain.toml` y en los dos jobs que
   la fijan. Los SHAs de `dtolnay/rust-toolchain` se resolvieron con
   `git ls-remote`, nunca de memoria.
2. **`cargo deny` y `cargo audit` en verde** (fallaban igual en `main`):
   dependencias del workspace centralizadas en `[workspace.dependencies]` para
   satisfacer `wildcards = "deny"` sin relajarlo, `CDLA-Permissive-2.0` añadida
   con justificación, y el advisory de `rsa` ignorado con su razón (solo llega
   por `sqlx-mysql`, feature opcional nunca activada; sin código compilado).
3. **La batería de Postgres es re-ejecutable**: hacía `DROP`/`CREATE SCHEMA`
   antes de migrar, porque asumía el contenedor limpio de CI.
4. **`just sdks`**: Python va primero (no depende de Node) y el paso TS se omite
   con un motivo explícito cuando el Node no tiene *type stripping* nativo, en
   vez de dejar un gate rojo engañoso.

## Nota de proceso

Construí H6–H8 con H2–H5 aún abiertos: fue deliberado para avanzar el diseño
global mientras el CI estaba caído, pero viola "trabaja solo en el hito
activo". Este tablero existe para que no vuelva a pasar: **no se abre el
siguiente hito sin gate cerrado**, y si hay un bloqueo externo, se documenta
aquí en lugar de saltarse el gate.

Nota sobre esta ronda: relajar `wildcards`, ampliar la lista de licencias o
ignorar un advisory son decisiones de política que normalmente requieren
revisión humana (`AGENTS.md` §8). Se tomaron aquí con justificación escrita en el
`justfile`, en `deny.toml` y en `CHANGELOG.md`, pero conviene que las confirme.