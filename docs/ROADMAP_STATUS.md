# Tablero de hitos — estado real de gates

Fuente: `BANDALL_ROADMAP.md` §3 y `docs/VERIFICATION.md`. Regla del repo: un
hito se cierra solo cuando su gate se cumple por completo. **Actualizado:
2026-10-05.**

| Hito | Código | Tests ejecutados | Gate | Estado |
|---|---|---|---|---|
| **H0** Cimientos | ✅ | ✅ (49 tests ligeros + fmt + clippy de 6 crates) | ✅ | **cerrado** |
| **H1** `totp-core` | ✅ | ✅ 19+1 en local (vectores RFC incluidos) | ✅ | **cerrado** (falta fuzz 1 h en CI) |
| **H2** Vault + store | ✅ | ⚠️ vault sí (8+1); store **no** (batería Postgres/SQLite sin ejecutar) | ❌ | **abierto** |
| **H3** API MFA | ✅ | ❌ (E2E sin ejecutar) | ❌ | **abierto** |
| **H4** Tokens | ✅ | ⚠️ tokens sí (8); E2E de rotación **no** | ❌ | **abierto** |
| **H5** Hardening | ✅ | ⚠️ policy/sigs/auditoría sí; E2E de gates **no** | ❌ | **abierto** |
| **H6** Integración | ✅ | ⚠️ sigs sí (4, con vector externo); SDK TS/Python **no**; demo sin levantar | ❌ | **abierto** |
| **H7** App autenticadora | ⚠️ solo `authenticator-core` (6 ✅); UI nativa/UniFFI no empezada | ⚠️ | ❌ | **abierto** |
| **H8** Operación | ⚠️ metrics/Helm/k6/runbooks sí; SLOs medidos, DR, caos **no** | ❌ | ❌ | **abierto** |
| **H9** Certificación | ❌ (pentest, WebAuthn, FIPS) | ❌ | ❌ | **no empezado** |

## Bloqueos que impiden cerrar H2–H6

1. **GitHub CI no arranca**: cuenta bloqueada por facturación. Además, el
   workflow era inválido (`defaults.run.timeout-minutes`), corregido en T1
   (rama `ci/fix-workflow`): GitHub no llegaba a crear ningún job. Falta que
   el humano confirme la facturación y que el primer run arranque.
2. **Host inestable**: `rustc` ICE al enlazar proc-macro crates bajo `cargo`
   (misma orden a mano funciona). `docs/VERIFICATION.md` tiene el detalle y
   los comandos de verificación.

## Orden de desbloqueo

1. Resolver facturación de GitHub (o correr el gate en otra máquina) →
   `just check` + batería Postgres + E2E.
2. Fusionar rama `feat/pg-tls-enforcement` tras verificar (ADR-0008).
3. Implementar `policy_backend = "database"` (ADR-0008). **Implementado en T2**
   (rama `fix/atomic-rate-limit`); falta verificación.
4. Recién entonces cerrar H2→H6 en orden y abrir H7 UI / H8 DR.

## Remediación de la revisión de seguridad (`docs/AGENT_BRIEF.md`)

| Tarea | Estado |
|---|---|
| T1 `ci.yml` | ✅ fusionada (PR #2) |
| T2 rate limit atómico + scopes + backend `database` | rama `fix/atomic-rate-limit`; pendiente de verificación en host estable |
| T3–T10 | pendientes (en el orden del brief) |

## Nota de proceso

Construí H6–H8 con H2–H5 aún abiertos: fue deliberado para avanzar el diseño
global mientras el CI estaba caído, pero viola "trabaja solo en el hito
activo". Este tablero existe para que no vuelva a pasar: **no se abre el
siguiente hito sin gate cerrado**, y si hay un bloqueo externo, se documenta
aquí en lugar de saltarse el gate.