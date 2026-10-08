# Modelo de amenazas

Actualizado: 2026-10-06 (H5, revisión STRIDE). Se revisa antes de cada hito
(`BANDALL_ROADMAP.md` §2).

## Alcance

Servicio BandAll (`api`, `vault`, `tokens`, `policy`, `store`, `sigs`), CLI y
sus despliegues Docker. La app autenticadora móvil y los SDKs se incorporan en
H6/H7.

## Supuestos

- TLS termina en un proxy/orquestador delante de `bandall-api`.
- La base de datos puede comprometerse: los secretos TOTP están cifrados con
  una KEK que vive fuera de ella.
- La deriva de reloj entre cliente y servidor está acotada (T3: deriva guardada
  ±1 paso, `drift_steps` limitado a ±5).
- La imagen Docker se ejecuta sin privilegios, con rootfs de solo lectura.
- La clave de auditoría y la KEK viven fuera de la base de datos, en secretos
  del orquestador con permisos `0600` (ADR-0010).

## STRIDE

<!-- markdownlint-disable MD013 -->
| Categoría | Activo | Escenario | Control | Dónde se prueba |
|---|---|---|---|---|
| **S**poofing | Sesión | Robo de refresh token y uso desde otro cliente | Refresh opaco hasheado, rotación por uso y detección de reutilización que revoca la familia y la sesión | `token_rotation_and_reuse_detection` (e2e) |
| Spoofing | Cliente S2S | Suplantar al servicio llamante | `x-service-key` comparada en tiempo constante + firmas HMAC por cliente con nonce de un solo uso | `hmac_signature_round_trip` (e2e), `sigs` (4 tests) |
| Spoofing | Sujeto | Enumerar usuarios por la respuesta | Denegación uniforme (mismo cuerpo, mismo tiempo, `Error::denied()` en toda ruta) | `neighbor_flood_does_not_block_valid_factor`, `fails_closed_on_impossible_inputs` |
| **T**ampering | Auditoría | Reescribir la historia para borrar un acceso | HMAC-SHA-256 con clave fuera de la DB sobre registro con prefijo de longitud; append atómico; `REVOKE UPDATE/DELETE` en Postgres | `audit_chain_is_keyed_and_tamper_evident` (e2e), `audit::tests` (10), `audit_chain_concurrency` (batería) |
| Tampering | Secretos | Trasplantar el ciphertext de un factor a otro | AEAD con AAD `tenant‖subject‖factor`; copiarlo a otra fila falla al abrir | `transplanted_ciphertext_fails` (vault) |
| Tampering | Antirreplay | Repetir un código ya usado | `UPDATE … WHERE last_step < $step` atómico: exactamente un ganador | `concurrent_replay_single_winner` (e2e, 100 peticiones) |
| Tampering | Cadena de suministro | Dependencia comprometida o con licencia inadmisible | `cargo deny` (advisories, bans, licenses, sources) y `cargo audit` en el gate | `just deny`, `just audit` |
| **R**epudiation | Auditoría | Negar haber hecho una operación | Todo evento de seguridad se audita antes de responder, encadenado por hash | `audit_log_is_keyed_and_tamper_evident`, eventos en `audit::event` |
| **I**nformation disclosure | Secretos | Leer el secret TOTP de la base de datos | Envolvente KEK→DEK, KEK fuera de la DB, `secrecy`/`zeroize` en memoria | `no_secret_material_reaches_the_database_in_clear`, `sealed_material_is_stored_and_decrypts` |
| Information disclosure | Logs | Un secreto o un código acaba en un log y se puede reusar | Regla + **prueba automática** que captura el logging real y busca material secreto | `no_secret_material_reaches_the_logs` |
| Information disclosure | Respuestas | Un error filtra internals (SQL, rutas, versiones) | RFC 7807 sin detalle interno; errores tipados que no formatean el origen | `error.rs` (mapa uniforme), e2e de denegación |
| Information disclosure | Tokens | Access token leído por XSS | El token no va a `localStorage`; patrón BFF con cookie `__Host-`+`HttpOnly`+`Secure`+`SameSite=Strict` | Guía `docs/guides-web-and-mobile-sessions.md` (**no lo implementa el servicio**: ADR-0011) |
| **D**enial of service | Verificación | Ráfaga de intentos contra un factor | Lockout + backoff exponencial por factor | `concurrent_wrong_codes_stop_at_limit`, `policy` (8) |
| Denial of service | Tenant | Un atacante bloquea a todo un tenant desde un endpoint público | Límites altos por `tenant`/`ip` **sin lockout larga**; la clave de factor es la única estricta | `neighbor_flood_does_not_block_valid_factor` |
| Denial of service | Proceso | Cuerpo gigante, petición lenta, JSON malformado | Límite de body, timeout de 10 s, extracción tipada de axum | `router` en `server.rs`, e2e |
| Denial of service | Recuperación | Argon2id caro invocado en bucle desde un endpoint público | Acotado por `policy`; el esquema nuevo (T7) sustituye Argon2id por HMAC con pepper para códigos de alta entropía | Pendiente: T7 (ADR aún no escrito) |
| **E**levation of privilege | Tokens | Alterar `alg`, `aud`, `iss` o `exp` para colarse | Algoritmo fijo EdDSA, `iss`/`aud`/`exp` obligatorios, verificación estricta | `tokens` (8), `rejections` en el SDK Python |
| Elevation of privilege | Sesión revocada | Seguir usando un access token válido tras revocar | `authz/check` consulta la sesión viva en DB | `forward_auth_allows_and_denies` (e2e) |
| Elevation of privilege | S2S | Llamar a un endpoint S2S sin scope | Scopes por cliente; `x-service-key` solo en desarrollo | `authz::tests`, `hmac_signature_round_trip` |
| Elevation of privilege | Host | Escapar del contenedor | no-root, rootfs read-only, `cap_drop: ALL`, `no-new-privileges`, límites de recursos | `deploy/compose/*.yaml`, Helm `securityContext` |
| Elevation of privilege | Conexión larga (WS/gRPC) | Seguir recibiendo datos tras revocar la sesión | Ticket de conexión de un solo uso (30 s) + re-validación: `recheck` niega sesiones revocadas; techo de conexión atado a `exp` | `ws_ticket_e2e` (3), `TestWsTickets` (5), `sdk-grpc` (5) |
<!-- markdownlint-enable MD013 -->

## Brechas conocidas (v0)

- TOTP es phishable; no hay factor resistente a phishing hasta H9.
- `LocalKms` (H2) protege contra robo de DB, pero no contra compromiso total del
  host: producción requiere KMS/HSM real (checklist de `BANDALL_ROADMAP.md` §4).
- La cadena de auditoría v2 (ADR-0010) verifica la integridad **desde la
  migración**, no desde el génesis: las filas escritas con el hash v1 sin clave
  siguen validando, así que un historial manipulado antes de esa migración no
  se detecta. Tampoco hay rotación de la clave de auditoría, porque una sola
  clave firma toda la cadena (ver §Rotación de ADR-0010).
- **Sin pentest externo hasta H9.**
- Sin cifrado del lado del cliente ni backup: la app móvil no existe aún (H7).
- **Los nonces HMAC viven en memoria por proceso** (H6), así que con varias
  réplicas un nonce se puede reusar en otra instancia hasta que T8 los mueva a
  base de datos.
- **`x-service-key` es una clave global** sin scopes ni atribución: T8 la
  sustituye por `api_clients` con `key_id` y rotación.
- **Sin límite de concurrencia ni load-shed** en el servidor (T9): el timeout
  corta peticiones lentas, pero no hay techo de peticiones en vuelo.
- **Auditoría: `audit_key` no rota** y el rol de base de datos que la aplicación
  usa en desarrollo es el dueño de la tabla (el `REVOKE` solo aplica de verdad
  con un rol `bandall_app` separado, que es lo que documenta la migración 7).
- Las cookies de sesión web **no las emite BandAll** (ADR-0011): la guía es el
  contrato, y su cumplimiento depende del integrador.

## Estado de implementación (v1, H0–H8)

- H1–H4: núcleo TOTP, vault, store, API MFA, tokens y sesiones según diseño.
- H5: `policy` (backoff/lockout), negación uniforme, auditoría encadenada con
  clave y append atómico (ADR-0010), prueba automática de secretos en logs,
  revisión STRIDE (este documento) y revisión ASVS
  (`docs/asvs-l3-review.md`).
- H6: firmas HMAC por cliente, forward-auth, `sdk-axum`, SDKs TS/Python sobre
  vectores compartidos, demo legacy, ejemplo embebido.
- H7: `authenticator-core` (cuentas, backup cifrado); UI nativa y UniFFI
  pendientes (ADR-0006).
- H8: `/metrics`, Helm, compose de observabilidad, k6, runbooks. Pendiente de
  entorno real: SLOs medidos, DR ensayado, `cargo-vet`, SBOM, `cosign`, TLS a
  Postgres/KMS.
- Supuestos vigentes: TLS termina en el proxy; la DB puede comprometerse;
  `LocalKms` solo vale para desarrollo/air-gapped.
