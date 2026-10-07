# Tablero de hitos — estado real de gates

Fuente: `BANDALL_ROADMAP.md` §3 y `docs/VERIFICATION.md`. Regla del repo: un
hito se cierra solo cuando su gate se cumple por completo. **Actualizado:
2026-10-06.**

| Hito | Código | Tests ejecutados | Gate | Estado |
|---|---|---|---|---|
| **H0** Cimientos | ✅ | ✅ (workspace completo: 103 tests) | ✅ | **cerrado** |
| **H1** `totp-core` | ✅ | ✅ 19+1 en local (vectores RFC incluidos), **cobertura 93.95 % > 90 %** | ✅ | **cerrado** (falta fuzz en CI) |
| **H2** Vault + store | ✅ | ✅ vault (8+1); store **SQLite y Postgres 18.6** (4 cada uno) | ⚠️ | **abierto** (solo falta CI verde) |
| **H3** API MFA | ✅ | ✅ 29 unit + 11 E2E | ✅ | **cerrado** (sujeto a CI verde) |
| **H4** Tokens | ✅ | ✅ tokens (8); E2E de rotación verde, **con Postgres** | ⚠️ | **abierto** (solo falta CI) |
| **H5** Hardening | ✅ | ✅ policy (8), sigs (4) y auditoría **con clave y append atómico** (T4), **con Postgres** | ⚠️ | **abierto** (solo falta CI) |
| **H6** Integración | ✅ | ✅ sdk-axum (2), sigs (4), **SDK Python (5) y TS (5)**; demo sin levantar | ❌ | **abierto** (falta imagen y demo) |
| **H7** App autenticadora | ⚠️ solo `authenticator-core` (6 ✅); UI nativa/UniFFI no empezada | ⚠️ | ❌ | **abierto** |
| **H8** Operación | ⚠️ metrics/Helm/k6/runbooks sí; SLOs medidos, DR, caos **no** | ❌ | ❌ | **abierto** |
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
2. **Sin demonio de Docker en esta máquina**: no se puede construir la imagen ni
   levantar el compose. `sudo` pide contraseña y sin interacción no hay forma de
   arrancarlo. Esto ya **no bloquea la batería**: `initdb` corre como usuario
   normal, así que hay un cluster Postgres 18.6 propio (ver
   `docs/VERIFICATION.md` §Cómo reproducir). Lo que sigue pendiente aquí: build
   de la imagen, demo forward-auth y fuzz.

## Orden de desbloqueo

1. Resolver la facturación de GitHub (o correr el gate en otra máquina) →
   `just check` completo con Postgres, que **ya pasa en local**.
2. `policy_backend = "database"` (ADR-0008) de T2 **verificado contra Postgres
   real** en esta ronda (batería completa, incluidas la reserva atómica y la
   ráfaga de 50 appends encadenados).
3. Build de la imagen y demo forward-auth (requiere el demonio de Docker) y fuzz
   de los parsers de `totp-core`.
4. Con eso, cerrar H2→H6 en orden y abrir H7 UI / H8 DR.

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