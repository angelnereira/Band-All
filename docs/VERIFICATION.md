# Estado de verificación y entorno de desarrollo

Actualizado: 2026-10-05. Lee esto antes de fiarte de "verde" o de "funciona".

## Qué está verificado y qué no

| Grupo | Tests | Estado |
|---|---|---|
| `totp-core` (incl. vectores RFC 4226/6238, Base32, `otpauth`, ventana/antirreplay) | 19 unit + 1 doc | **verde local** |
| `policy` (backoff, lockout, reset) | 3 | **verde local** |
| `sigs` (round-trip, replay, stale, vector de conformidad externo) | 4 | **verde local** |
| `vault` (envolvente, AAD, rewrap, Argon2id) | 8 + 1 doc | **verde local** |
| `tokens` (JWT EdDSA, rotación, JWKS, confusión de `alg`) | 8 | **verde local** |
| `authenticator-core` (cuentas, backup cifrado) | 6 | **verde local** |
| `store` (batería Postgres+SQLite) | batería compartida | **sin ejecutar** |
| `api` (E2E: ciclo MFA, carrera de 100, rotación, firmas, forward-auth) | E2E | **sin ejecutar** |
| `sdk-axum` (Layer) | unit | **sin ejecutar** |
| SDK TS / Python (vectores compartidos) | node/unittest | **sin ejecutar** |

**Regresión posterior:** tras añadir los lints nuevos de ADR-0007, incluso
`totp-core` empezó a fallar con el mismo ICE. Se intentó aislarlo:

- Bajar `serde` a 1.0.228 / 1.0.226 / 1.0.219: ICE en las tres.
- Fijar `url` a 2.5.2 para eliminar la cadena ICU/zerofrom: el ICE se mudó a
  `syn` y luego a `proc-macro2`.
- Cambiar `syn` a la rama 2.x: sigue fallando.
- `cargo clippy` en lugar de `cargo build`: mismo ICE.

El `Cargo.lock` se restauró a su estado commiteado (sin pins experimentales):
no queremos que un workaround del host contamine las versiones del proyecto.

Razonamiento: los seis crates ligeros suman **49 tests verdes**. Los crates pesados
(`store`, `api`, `cli`, `sdk-axum`) **compilan** (`cargo check` y, antes del
incidente del toolchain, `clippy -D warnings`), pero sus tests no llegan a
ejecutarse por dos bloqueos independientes:

1. **CI de GitHub inoperativo**: todos los jobs fallan en segundos con
   *"The job was not started because your account is locked due to a billing issue"*.
   Ningún runner arranca, así que no hay verificación remota posible.
2. **Inestabilidad del host**: `rustc 1.98.1` falla con
   `panicked at rustc_serialize: assertion failed: bytes[len] == STR_SENTINEL`
   al enlazar crates de proc-macro (`syn`, `proc-macro2`, `zerofrom-derive`) y,
   antes, con `SIGILL`. La misma orden `rustc` ejecutada a mano con idénticos
   flags **funciona**; bajo `cargo` falla de forma reproducible.

## Evidencia del problema del host

- Un fichero del registry llegó corrupto: `ed25519-dalek-2.2.0/src/signing.rs`
  estaba lleno de bytes nulos (readthedocs `.crate` re-descargado y limpio).
- El toolchain `1.98.1` se reinstaló por si acaso (512 MB) y el ICE persiste.
- `sudo docker ps` revienta con `SIGILL` dentro de `math/big` de Go (salto a
  memoria cero), o sea: **otro runtime independiente con corrupción de memoria**.
- `indexmap` y `syn 3.0.6` compilan sin problema en un crate aislado, con el
  mismo `rustc` y las mismas fuentes; solo fallan dentro de este workspace.

Conclusión: no es un defecto del código BandAll sino del host (RAM/disco
inestable o cgroup limitado a ~3.9 GB con 2.7 GB disponibles). while tanto, la
verificación heavyweight está bloqueada.

## Cómo verificar cuando se arregle

```bash
# 1. Tests (usa -j 1 si la RAM es escasa; el host actual tiene ~4 GB)
cargo test -j 2 --workspace

# 2. Gate completo
just check

# 3. Batería contra Postgres real (levanta el servicio y pasa BANDALL_TEST_PG)
docker compose -f deploy/compose/compose.yaml up -d
export BANDALL_TEST_PG=postgres://bandall:bandall-dev-only@127.0.0.1:5433/bandall
cargo test -p bandall-store

# 4. SDKs
(cd sdks/ts && node --test test/vectors.test.ts)
(cd sdks/python && python -m unittest discover -s tests)
```

## Qué falta antes de declarar los gates de H2/H3/H6

- [ ] Batería de `store` verde contra **Postgres real** (el SQL con
      `format!`/`$1` nunca se ejecutó).
- [ ] E2E de `api` verde: el ciclo de enrolamiento, la carrera de 100
      verificaciones con exactamente un ganador, rotación de refresh con
      detección de reutilización, firmas HMAC y forward-auth.
- [ ] Suites de SDK TS/Python sobre los vectores compartidos.
- [ ] `cargo deny check` y `cargo audit` (las herramientas no están instaladas
      en esta máquina y el CI no arranca).

Nada de esto invalida el diseño, pero **ningún gate de H2 en adelante puede
declararse cerrado** hasta que estas cuatro líneas estén en verde.