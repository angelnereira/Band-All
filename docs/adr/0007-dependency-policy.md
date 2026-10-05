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

## Nota sobre `just check` y el CI

`just check` replica los jobs del CI en el mismo orden (fmt, clippy, test,
msrv, coverage, deny, audit). `sdks` y `docker` quedan disponibles como
recetas locales pero no forman parte del gate por defecto: requieren Node,
Python y un daemon Docker.