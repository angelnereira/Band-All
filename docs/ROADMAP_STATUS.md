# Tablero de hitos — estado real de gates

Fuente: `BANDALL_ROADMAP.md` §3 y `docs/VERIFICATION.md`. Regla del repo: un
hito se cierra solo cuando su gate se cumple por completo. **Actualizado:
2026-10-05.**

| Hito | Código | Tests ejecutados | Gate | Estado |
|---|---|---|---|---|
| **H0** Cimientos | ✅ | ✅ (workspace completo: 82 tests) | ✅ | **cerrado** |
| **H1** `totp-core` | ✅ | ✅ 19+1 en local (vectores RFC incluidos) | ✅ | **cerrado** (falta fuzz 1 h en CI) |
| **H2** Vault + store | ✅ | ✅ vault (8+1); store **SQLite** (4) | ⚠️ | **abierto** (falta batería Postgres real) |
| **H3** API MFA | ✅ | ✅ 11 unit + 9 E2E | ✅ | **cerrado** (sujeto a CI verde) |
| **H4** Tokens | ✅ | ⚠️ tokens sí (8); E2E de rotación **sí** (verde local) | ⚠️ | **abierto** (falta CI) |
| **H5** Hardening | ✅ | ⚠️ policy (8, T2) y sigs (4) sí; auditoría encadenada no atómica | ⚠️ | **abierto** (T4 pendiente) |
| **H6** Integración | ✅ | ⚠️ sdk-axum (2) y sigs (4) sí; SDK TS/Python **no**; demo sin levantar | ❌ | **abierto** |
| **H7** App autenticadora | ⚠️ solo `authenticator-core` (6 ✅); UI nativa/UniFFI no empezada | ⚠️ | ❌ | **abierto** |
| **H8** Operación | ⚠️ metrics/Helm/k6/runbooks sí; SLOs medidos, DR, caos **no** | ❌ | ❌ | **abierto** |
| **H9** Certificación | ❌ (pentest, WebAuthn, FIPS) | ❌ | ❌ | **no empezado** |

## Bloqueos que impiden cerrar H2–H6

1. **GitHub CI no arranca**: cuenta bloqueada por facturación. Además, el
   workflow era inválido (`defaults.run.timeout-minutes`), corregido en T1
   (rama `ci/fix-workflow`): GitHub no llegaba a crear ningún job. Falta que
   el humano confirme la facturación y que el primer run arranque.
2. **Entorno sin Postgres ni herramientas**: en el host actual (Android/proot)
   no hay `docker`, `just`, `cargo-deny` ni `cargo-audit`. Sí se ejecutó la
   suite completa del workspace (82 tests verdes), pero la **batería contra
   Postgres real**, `cargo deny`, `cargo audit`, cobertura y fuzz siguen sin
   poder correr aquí. `docs/VERIFICATION.md` tiene el detalle.
3. **Host anterior inestable (histórico)**: `rustc` ICE al enlazar proc-macro
   crates bajo `cargo`. No se reproduce en el host actual, pero no se ha
   descartado como causa de fondo (memoria/disco).

## Orden de desbloqueo

1. Resolver facturación de GitHub (o correr el gate en otra máquina) →
   `just check` + batería Postgres + E2E.
2. `policy_backend = "database"` (ADR-0008) ya implementado en T2 (rama
   `fix/atomic-rate-limit`); verificar contra Postgres real.
3. Batería Postgres + SDK TS/Python + deny/audit/cobertura.
4. Recién entonces cerrar H2→H6 en orden y abrir H7 UI / H8 DR.

## Remediación de la revisión de seguridad (`docs/AGENT_BRIEF.md`)

| Tarea | Estado |
|---|---|
| T1 `ci.yml` | ✅ fusionada (PR #2) |
| T2 rate limit atómico + scopes + backend `database` | ✅ implementada y verificada en local (rama `fix/atomic-rate-limit`, 82 tests verdes); falta CI + Postgres real |
| T3–T10 | pendientes (en el orden del brief) |

## Nota de proceso

Construí H6–H8 con H2–H5 aún abiertos: fue deliberado para avanzar el diseño
global mientras el CI estaba caído, pero viola "trabaja solo en el hito
activo". Este tablero existe para que no vuelva a pasar: **no se abre el
siguiente hito sin gate cerrado**, y si hay un bloqueo externo, se documenta
aquí en lugar de saltarse el gate.