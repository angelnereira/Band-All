# Estado de verificación y entorno de desarrollo

Actualizado: 2026-10-05 (ejecución completa del workspace). Lee esto antes de
fiarte de "verde" o de "funciona".

## Qué está verificado y qué no

| Grupo | Tests | Estado |
|---|---|---|
| `totp-core` (incl. vectores RFC 4226/6238, Base32, `otpauth`, ventana/antirreplay) | 19 unit + 1 doc | **verde local** |
| `policy` (adquisición atómica, scopes, tope del mapa, lockout, ráfaga 100→5) | 8 | **verde local** |
| `sigs` (round-trip, replay, stale, vector de conformidad externo) | 4 | **verde local** |
| `vault` (envolvente, AAD, rewrap, Argon2id) | 8 + 1 doc | **verde local** |
| `tokens` (JWT EdDSA, rotación, JWKS, confusión de `alg`) | 8 | **verde local** |
| `authenticator-core` (cuentas, backup cifrado) | 6 | **verde local** |
| `sdk-axum` (Layer) | 2 | **verde local** |
| `cli` | 1 | **verde local** |
| `store` (batería completa en **SQLite**) | 4 | **verde local** |
| `store` (batería contra **Postgres real**) | misma batería | **sin ejecutar** (sin `BANDALL_TEST_PG`) |
| `api` (unit) | 11 | **verde local** |
| `api` (E2E: ciclo MFA, carrera de 100, ráfaga 20→5, vecindad de tenant, rotación, firmas, forward-auth) | 9 | **verde local** |
| SDK TS / Python (vectores compartidos) | node/unittest | **sin ejecutar** |
| `cargo deny` / `cargo audit` / cobertura / fuzz | — | **sin ejecutar** (herramientas ausentes) |

**Total en esta ejecución: 82 tests + doctests, 0 fallos.**

## Ejecución completa (2026-10-05, host nuevo)

```bash
CARGO_BUILD_JOBS=1 cargo test --workspace --offline      # 82 verdes
CARGO_BUILD_JOBS=1 cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

Entorno: Android/proot (`aarch64-unknown-linux-gnu`, rustc 1.98.1) con ~3 GB
disponibles, de ahí `-j 1`. **No hay** `docker`, `just`, `cargo-deny` ni
`cargo-audit`: la imagen, la batería Postgres y `just check` siguen sin poder
ejecutarse aquí.

### Defectos de `main` que destapó esta ejecución

Al poder compilar y ejecutar por fin el workspace aparecieron fallos que nadie
podía ver porque el CI nunca arrancaba (bloqueo de facturación) y el host
anterior fallaba al enlazar:

1. `bandall-store` usaba `url::Url` **sin declarar** la dependencia: la
   biblioteca ni sus tests compilaban.
2. `cas_last_step` en SQLite **tenía un bind de menos** que placeholders: la
   comparación quedaba `last_step < NULL` y, tras el primer código aceptado,
   **ningún paso posterior casaba** (el antirreplay rechazaba todo lo demás).
3. El test de TLS de Postgres llamaba a `connect` sin `await` y sin importar
   `Error`; `PgStore`, `SqliteStore` y `NewFactor` tenían avisos de `Debug` y
   de documentación que rompían `clippy -D warnings`.
4. Los tests de `config` compartían un fichero temporal (nombre por PID).
5. El test E2E de la carrera de replay generaba el código 120 s por delante,
   fuera del alcance real de la verificación (±90 s): la aserción de "un único
   ganador" era inalcanzable.

Los cinco están corregidos en la rama de T2 (ver `CHANGELOG.md`).

## Host anterior (histórico)

La regresión descrita antes (ICE de `rustc` al enlazar crates de proc-macro,
`SIGILL` en `docker`) afecta al host previo; **no se reproduce aquí**, pero
tampoco se ha descartado como causa raíz de fondo (memoria/disco):

- `rustc 1.98.1` fallaba con
  *panicked at rustc_serialize: assertion failed: bytes[len] == STR_SENTINEL*.
- `sudo docker ps` reventaba con `SIGILL` dentro de `math/big` de Go.
- Un fichero del registry llegó corrupto
  (`ed25519-dalek-2.2.0/src/signing.rs` lleno de bytes nulos).
- Se probaron y descartaron temporalmente como causa las versiones de `serde`,
  `url`, `syn` y el propio `Cargo.lock`; el lock se restauró a su estado
  commiteado.

## Cómo verificar cuando haya Postgres

```bash
# Tests (usa -j 1 si la RAM es escasa)
CARGO_BUILD_JOBS=1 cargo test --workspace

# Batería contra Postgres real
export BANDALL_TEST_PG=postgres://bandall:bandall-dev-only@127.0.0.1:5433/bandall
cargo test -p bandall-store postgres_battery

# SDKs
(cd sdks/ts && node --test test/vectors.test.ts)
(cd sdks/python && python -m unittest discover -s tests)

# Resto del gate (requiere las herramientas del `just install-tools`)
just check
```

## Qué falta antes de declarar los gates de H2/H3/H6

- [x] Batería de `store` verde en SQLite (el SQL con `format!`/`$1` ya se
      ejecuta de verdad).
- [x] E2E de `api` verdes: ciclo de enrolamiento, carrera de 100 con un único
      ganador, rotación de refresh con detección de reutilización, firmas
      HMAC y forward-auth.
- [ ] Batería de `store` contra **Postgres real** (incluye
      `reserve_auth_attempt` con advisory lock).
- [ ] Suites de SDK TS/Python sobre los vectores compartidos.
- [ ] `cargo deny check`, `cargo audit`, cobertura (`totp-core` > 90 %) y fuzz
      de los parsers.
- [ ] Primer CI verde en `main` (los 9 jobs) tras resolver la facturación.

Nada de esto invalida el diseño, pero **ningún gate de H2 en adelante puede
declararse cerrado** hasta que estas líneas estén en verde.
