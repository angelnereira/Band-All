# AGENTS.md — Reglas para BandAll

Este archivo manda sobre cualquier suposición. Si algo entra en conflicto con estas reglas, **detente y pregunta**.

## 1. Proyecto
**BandAll** es un servicio de seguridad escrito en Rust: autenticación TOTP (RFC 6238/4226) con autenticador **offline**, emisión de tokens, verificación S2S y firmas HMAC para APIs/webhooks. Se usa de tres formas: servicio independiente, sidecar/forward-auth y librería embebida.
Documentos de referencia: `BANDALL_BLUEPRINT.md` (diseño) y `BANDALL_ROADMAP.md` (hitos H0–H9). Trabaja **solo en el hito activo**.

## 2. Estructura
Workspace Cargo. Directorio `crates/<x>` = paquete `bandall-<x>`. Binario: `bandall`.
- `totp-core`: matemática TOTP/HOTP, base32, otpauth. **Puro: sin red, sin DB, sin reloj propio.**
- `vault`, `tokens`, `policy`, `store`, `sigs`, `api`, `sdk-axum`, `authenticator-core`, `cli`.
Las dependencias fluyen hacia `totp-core`, nunca al revés. No crear crates nuevos sin ADR.

## 3. Comandos (todo debe pasar antes de proponer un PR)
```
just check        # (se crea en H0) ejecuta lo mismo que el CI
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny check && cargo audit
```

## 4. Reglas de seguridad (innegociables)
1. `#![forbid(unsafe_code)]` en todos los crates. Sin excepciones.
2. **No inventes criptografía.** Solo primitivas de crates RustCrypto o `aws-lc-rs`. No implementes HMAC, AEAD, KDF ni comparaciones a mano.
3. Comparar códigos, MAC, hashes y tokens **solo** con `subtle` (tiempo constante). Prohibido `==` sobre secretos.
4. Aleatoriedad solo del CSPRNG del SO (`getrandom`/`OsRng`). Prohibido `rand::thread_rng` para secretos, nonces o tokens.
5. Secretos en `secrecy`/`zeroize`. Nunca en `String` suelto, `Debug`, logs, errores, métricas ni trazas.
6. Los secretos TOTP se guardan **cifrados** (envelope + AAD). Nunca en claro, nunca en archivos de ejemplo, nunca en tests con valores reales.
7. Antirreplay obligatorio: un OTP se acepta una sola vez (`UPDATE ... WHERE last_step < $step`, atómico).
8. **Fail-closed:** ante error de DB, KMS, reloj o configuración, se **deniega**. Nunca "abrir por error".
9. Respuestas uniformes ante usuario inexistente o código erróneo (anti-enumeración, tiempo uniforme).
10. Validación estricta de tokens: algoritmo fijo, `iss`/`aud`/`exp` obligatorios. Prohibido aceptar `alg` desde el token.
11. Refresh tokens: opacos, guardados como hash, con rotación y detección de reutilización.
12. Nunca subir secretos, claves, `.env` reales ni vectores con datos de producción al repo.

## 5. Reglas de código
- Prohibido `unwrap()`, `expect()`, `panic!`, indexado directo e `as` con pérdida fuera de tests. Usa errores tipados (`thiserror`).
- El tiempo se **inyecta** como parámetro/trait (`Clock`); nada de `SystemTime::now()` dentro de la lógica.
- Funciones pequeñas, tipos fuertes (newtypes para `Step`, `Secret`, `TenantId`), sin estado global mutable.
- Código `async` solo en `api`, `store` y `sdk-axum`. El núcleo es síncrono.
- Errores hacia el cliente: RFC 7807, sin detalles internos.
- Comentarios solo para el "por qué"; documenta con `rustdoc` toda API pública.

## 6. Pruebas (obligatorias en cada cambio)
- Todo cambio de lógica trae pruebas. Todo bug corregido trae un test de regresión.
- `totp-core`: vectores oficiales RFC 4226/6238 + `proptest`; parsers con `cargo-fuzz`.
- Seguridad: cada regla de la sección 4 aplicable debe tener al menos una prueba **negativa** (replay, token alterado, AAD incorrecto, refresh reutilizado, etc.).
- Concurrencia: verificar el mismo código en paralelo → exactamente un éxito.
- No bajar la cobertura del núcleo (> 90 %).

## 7. Dependencias
- Antes de añadir una dependencia: justificarla en el PR (qué hace, mantenimiento, licencia, tamaño del árbol). Preferir pocas y conocidas.
- Versiones fijadas por `Cargo.lock`; `cargo deny` y `cargo audit` deben pasar. No usar crates abandonados ni con licencias fuera de `deny.toml`.

## 8. Git y PRs
- Commits en **Conventional Commits** (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`), en inglés.
- Un PR = una issue, pequeño y revisable. Sin cambios ajenos al alcance.
- Descripción del PR: qué cambia, por qué, cómo se probó y **qué reglas de seguridad toca**.
- Cambios en cripto, tokens, vault o policy requieren revisión humana explícita.

## 9. Cuándo detenerte y preguntar
Detente si: la tarea toca algo fuera del hito activo · hay que elegir entre seguridad y comodidad · falta un requisito · una regla de este archivo parece impedir la solución · necesitas una dependencia nueva o un crate nuevo · el cambio altera un formato persistido (ciphertext, esquema DB, claims de token). **No improvises**: propón opciones con pros/contras.

## 10. Definición de hecho
Código + pruebas (incluidas las negativas) + docs + CHANGELOG + `just check` verde + sin `unsafe` + sin secretos en logs + ADR si hubo decisión de diseño.

## 11. Idioma y estilo
Documentación y comunicación en **español**; identificadores, comentarios de código y mensajes de commit en **inglés**. Respuestas del agente: breves, con el cambio hecho, cómo verificarlo y los riesgos pendientes.
