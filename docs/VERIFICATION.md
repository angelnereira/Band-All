# Estado de verificación y entorno de desarrollo

Actualizado: 2026-10-06 (T4, Rust 1.99 y primera ejecución con Postgres real).
Lee esto antes de fiarte de "verde" o de "funciona".

## Qué está verificado y qué no

| Grupo | Tests | Estado |
|---|---|---|
| `totp-core` (incl. vectores RFC 4226/6238, Base32, `otpauth`, ventana/antirreplay) | 19 unit + 1 doc | **verde local**, cobertura **93.95 %** líneas |
| `policy` (adquisición atómica, scopes, tope del mapa, lockout, ráfaga 100→5) | 8 | **verde local** |
| `sigs` (round-trip, replay, stale, vector de conformidad externo) | 4 | **verde local** |
| `vault` (envolvente, AAD, rewrap, Argon2id) | 8 + 1 doc | **verde local** |
| `tokens` (JWT EdDSA, rotación, JWKS, confusión de `alg`) | 8 | **verde local** |
| `authenticator-core` (cuentas, backup cifrado) | 6 | **verde local** |
| `sdk-axum` (Layer) | 2 | **verde local** |
| `cli` (parsing de `serve` y de `audit verify`) | 2 | **verde local** |
| `store` (batería completa en **SQLite**, incluida la ráfaga de 50 appends) | 4 | **verde local** |
| `store` (batería contra **Postgres 18.6 real**) | 4 | **verde local** (ver "Cómo reproducir") |
| `api` (unit, incl. cadena de auditoría: tenant/subject/event/ts alterados, clave errónea, filas v1 y mezcla v1+v2) | 29 | **verde local** |
| `api` (E2E: ciclo MFA, carrera de 100, ráfaga 20→5, vecindad de tenant, rotación, firmas, forward-auth, deriva, auditoría encadenada) | 11 | **verde local** |
| SDK **Python** (vectores compartidos) | 5 | **verde local** |
| SDK **TypeScript** (vectores compartidos) | 5 | **verde local**, con un runner capaz (ver nota de Node) |
| `cargo fmt`, `cargo clippy -D warnings`, MSRV 1.85 | — | **verde local** |
| `cargo deny` (advisories, bans, licenses, sources) | — | **verde local** |
| `cargo audit --deny warnings` | — | **verde local**, con un ignore justificado |
| Cobertura del workspace | — | 85.08 % líneas (el gate solo exige > 90 % en `totp-core`) |
| Build de la imagen Docker | — | **sin ejecutar**: el demonio no arranca sin `sudo` |
| Fuzz (`cargo-fuzz` sobre los parsers de `totp-core`) | — | **sin ejecutar**: `cargo-fuzz` no instalado |
| Jobs `sdks` y `docker` de CI | — | **sin ejecutar**: GitHub no asigna runner |

**Total en esta ejecución: 103 tests + doctests, 0 fallos, con Postgres disponible.**

### Nota de Node para el SDK de TypeScript

`just sdks` ejecuta `node --test` sobre un fichero `.ts`, que necesita el *type
stripping* nativo de Node (activo por defecto desde 23.6; CI fija 24). El Node de
esta máquina es 22.22.1 y viene compilado **sin** soporte de TypeScript, así que
la recipe detecta ese caso y omite el paso diciendo por qué, en vez de dejar un
gate rojo por una carencia del entorno. La lógica del SDK se verificó aparte con
un runner capaz: **5/5**.

## Cómo reproducir la batería con Postgres

`initdb` no corre como root pero sí como cualquier usuario normal, así que no
hace falta `sudo` ni el demonio de Docker:

```bash
PGBIN=/usr/lib/postgresql/18/bin
mkdir -p /tmp/pg && chmod 700 /tmp/pg
$PGBIN/initdb -D /tmp/pg/data -U bandall --auth=trust --encoding=UTF8
$PGBIN/pg_ctl -D /tmp/pg/data -l /tmp/pg/pg.log \
  -o "-p 55432 -k /tmp/pg -c listen_addresses=127.0.0.1" start
$PGBIN/createdb -h 127.0.0.1 -p 55432 -U bandall bandall

BANDALL_TEST_PG="postgres://bandall@127.0.0.1:55432/bandall" just check
```

La batería ahora **se puede repetir**: el test de Postgres hace `DROP SCHEMA` y
`CREATE SCHEMA` antes de migrar. Antes fallaba con `duplicate key` en la segunda
ejecución, porque asumía el contenedor limpio de CI.

## Deuda que impedía el gate, corregida en esta ronda

`just check` fallaba en `deny` y `audit` **en `main`**, no solo en la rama: nadie
lo había visto porque el CI nunca ha arrancado. Las cuatro causas:

1. **Wildcards**: `bans.wildcards = "deny"` marcaba las 10 dependencias internas
   del workspace, porque una dependencia solo-`path` no declara versión y Cargo la
   lee como `*`. Resuelto **sin relajar la regla**: las dependencias se declaran
   una vez en `[workspace.dependencies]` con versión explícita, y cada crate usa
   `{ workspace = true }`.
2. **Licencia**: `webpki-roots` (vía rustls en sqlx) usa `CDLA-Permissive-2.0`,
   que no estaba en la lista permitida. Añadida con su justificación en
   `deny.toml`: es una licencia permisiva (atribución y límites de
   responsabilidad, sin copyleft ni restricción de uso) y la pila TLS no puede
   prescindir de ella mientras siga sobre rustls.
3. **Advisory**: `RUSTSEC-2023-0071` (Marvin Attack) llega por `rsa` <- `sqlx-mysql`,
   una feature opcional que `crates/store` nunca activa; `cargo tree` no muestra
   ningún nodo `rsa` en el grafo de features habilitadas, así que el código no se
   compila. Sin arreglo upstream, se ignora con la justificación en `justfile` y
   en el job de CI.
4. **`audit.toml` es una trampa**: cargo-audit 0.22 **no lee ningún fichero de
   configuración** (una clave inválida en `audit.toml` no produce ningún error).
   Un ignore ahí parecería funcionar y nunca se aplicaría. Por eso el ignore va
   como flag, en `just audit` y en el job de CI.

## Ejecución completa (2026-10-06, host x86_64)

```bash
BANDALL_TEST_PG="postgres://bandall@127.0.0.1:55432/bandall" just check
```

Toolchain 1.99.0 (fijada en `rust-toolchain.toml` y en `ci.yml`), 12 núcleos,
30 GB. El runaway de memoria y los `ICE` de enlace del host Android/proot
anterior **no se reproducen**.

Lo que **sigue sin poder ejecutarse aquí**: el build de la imagen Docker (el
demonio está parado y `sudo` pide contraseña, así que no hay forma de arrancarlo
sin interacción), el fuzz, y los jobs `sdks`/`docker` de CI (GitHub sigue sin
asignar runner).

### T4: qué verifica la batería de la cadena de auditoría

`store/src/tests_battery.rs::audit_chain_concurrency` lanza 50 appends
concurrentes y exige una cadena lineal. Comprobado que **detecta** el defecto:
al mover la lectura del tip fuera de la transacción (el comportamiento v1) el
test falla con `fork or gap at row 1`. **Comprobado en los dos backends**: en
SQLite moviendo el `SELECT` fuera del `BEGIN IMMEDIATE`, y en Postgres
eliminando el `pg_advisory_xact_lock`; en ambos casos la batería falla con
`fork or gap at row 1`.

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

### Defectos de la auditoría que corrigió T4

La cadena v1 (`SHA256(prev ‖ event ‖ ts)`, sin clave y sin `tenant`/`subject`)
era recalculable por cualquiera con escritura en `audit_log`, y cambiar el
titular de una fila no la rompía. Cerrado con HMAC-SHA-256 sobre registro
framing (ADR-0010) y append atómico; los tests negativos están en
`api/src/audit.rs` y en el E2E `audit_log_is_keyed_and_tamper_evident`.

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

## Qué verificar cuando haya Docker

El cluster personal descrito arriba evita Docker; si prefieres el contenedor,
`just docker-up` levanta Postgres 16 en el puerto 5433:

```bash
# Batería contra Postgres real
export BANDALL_TEST_PG=postgres://bandall:bandall-dev-only@127.0.0.1:5433/bandall
just check

# Imagen de producción
just docker-build

# SDKs (el TS necesita Node >= 24)
just sdks
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
