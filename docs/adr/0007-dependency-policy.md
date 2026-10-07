# ADR-0007: Endurecimiento de política de dependencias y perfiles

- **Estado:** aceptado
- **Fecha:** 2026-10-05
- **Decisores:** Angel Nereira

## Contexto

Revisión de configuración detectó que `deny.toml` aceptaba versiones *yanked*
y requisitos con comodín, que el perfil release ignoraba el desbordamiento de
enteros, y que la allow-list de licencias rompería al añadir `aws-lc-rs`/`ring`
para el build FIPS de H9.

## Decisión

1. **`deny.toml`**: `yanked = "deny"` y `bans.wildcards = "deny"`.
2. **Perfiles**: `[profile.release] overflow-checks = true` y `panic = "abort"`.
   Los pasos, contadores y timestamps son valores de dominio acotados donde un
   wrap silencioso sería un fallo de seguridad, no una ganancia de rendimiento.
   `panic = "abort"` evita depender de la tabla de landing pads en runtime.
   `[profile.test] overflow-checks = true` para que los tests sí detectan el
   desbordamiento que el binario sí aborta.
3. **Lints adicionales del workspace**: en `[workspace.lints.clippy]`,
   `cast_possible_truncation`, `cast_sign_loss`, `cast_possible_wrap`,
   `dbg_macro`, `todo`, `unimplemented`, `print_stdout` y `print_stderr` en
   `deny`. En `[workspace.lints.rust]` (son lints de rustc, no de clippy):
   `missing_docs` y `missing_debug_implementations` en `warn`, y
   `trivial_numeric_casts` en `deny`.

   Nota: `dbg_impl` **no existe**; el equivalente correcto es `dbg_macro`.
4. **Excepciones**: `bandall-cli` re-habilita `print_stdout`/`print_stderr`
   (es el único binario y su salida es para el operador). Los tests mantienen
   su excepción via `cfg_attr(test, allow(...))`.

## Consecuencias sobre FIPS (H9)

`aws-lc-rs` y `ring` incluyen código derivado de OpenSSL con licencias ISC /
OpenSSL. Cuando el build FIPS entre, habrá que añadir `"OpenSSL"` (y quizá
`"ISC"`, ya presente) a `licenses.allow` **con justificación en el PR**, y este
ADR se actualizará. No se añaden ahora para no abrir la lista de forma
preventiva sin necessidade.

## Dependencias internas: `[workspace.dependencies]` (2026-10-06)

`bans.wildcards = "deny"` rechazaba las diez aristas internas del workspace: una
dependencia declarada solo con `path` no expresa versión, y Cargo la resuelve
como `*`. La regla existe para que un nombre mal escrito no se convierta en
silenciosamente en otro crate; en una dependencia de un miembro del workspace el
`path` es exacto y un error de nombre no compila, así que la regla no protegía
nada aquí y solo impedía pasar el gate.

Se **arregla la causa en lugar de relajar la regla**: las diez dependencias se
declaran una vez en `[workspace.dependencies]` con `path` **y** `version`, y cada
crate usa `{ workspace = true }`. Efectos secundarios favorables: el grafo se lee
en un único sitio, y no queda el riesgo de que dos crates apunten a versiones
distintas del mismo miembro.

Consecuencia operativa: `[workspace.package].version` y las versiones de
`[workspace.dependencies]` deben moverse juntas en cada release
(`docs/RELEASING.md`).

## Ampliación de `licenses.allow`: `CDLA-Permissive-2.0` (2026-10-06)

`webpki-roots` (0.26 y 1.0, vía rustls dentro de sqlx) se publica bajo
`CDLA-Permissive-2.0`, que `cargo deny` rechazaba. Es una licencia permisiva:
exige atribución y limita la responsabilidad, sin copyleft ni restricción de
campo de uso. No es opcional mientras la pila TLS siga sobre rustls, y
`AGENTS.md` prohíbe `native-tls`/OpenSSL. Se añade con esta justificación, que es
lo que la política exige para ampliar la lista.

## Nota sobre `just check` y el CI

`just check` replica los jobs del CI en el mismo orden (fmt, clippy, test,
msrv, coverage, deny, audit) y **pasa completo** desde el 2026-10-06, con la
batería de Postgres incluida (`BANDALL_TEST_PG`). `sdks` y `docker` quedan
disponibles como recetas locales pero no forman parte del gate por defecto:
requieren Node con *type stripping* nativo (>= 24) y un demonio Docker.