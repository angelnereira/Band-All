# Modelo de amenazas (v0)

Versión inicial de H0. Se revisa y actualiza antes de cada hito (`BANDALL_ROADMAP.md` §2).

## Alcance

Servicio BandAll (`api`, `vault`, `tokens`, `policy`, `store`, `sigs`), CLI y sus despliegues Docker. La app autenticadora móvil y los SDKs se incorporan en H6/H7.

## Supuestos

- TLS termina en un proxy/orquestador delante de `bandall-api`.
- La base de datos puede comprometerse: los secretos TOTP están cifrados con una KEK que vive fuera de ella.
- La deriva de reloj entre cliente y servidor está acotada (±1 paso, `drift_steps` limitado).
- La imagen Docker se ejecuta sin privilegios, con rootfs de solo lectura.

## Amenazas y mitigaciones

| Amenaza | Mitigación | Hito |
|---|---|---|
| Robo de la base de datos | Secretos cifrados con KEK fuera de la DB + AAD por fila | H2 |
| Replay de OTP | `UPDATE ... WHERE last_step < $step` atómico | H3 |
| Fuerza bruta | Lockout + backoff exponencial + rate limit por factor/IP/tenant | H5 |
| Phishing en tiempo real | Límite inherente de TOTP; WebAuthn/passkeys como segundo factor | H9 |
| Robo de refresh token | Rotación en cada uso + detección de reutilización + device binding (opcional) | H4 |
| Deriva de reloj | Ventana ±1 + `drift_steps` acotado | H3 |
| Insider / admin | Auditoría encadenada con HMAC y clave fuera de la DB (ADR-0010), append atómico, `REVOKE` de `UPDATE`/`DELETE` en Postgres | H5 |
| Cadena de suministro | `cargo-deny`/`audit`/`vet`, builds reproducibles, SBOM, firmas | H5 |
| DoS | Límites de body/timeouts, rate limit, load-shed | H5 |
| Fuga de secretos en logs | Prohibición por regla + pruebas automáticas de patrones en logs | H5 |
| Imagen comprometida | Distroless, no-root, rootfs read-only, `cap_drop: ALL`, escaneo | H5 |

## Brechas conocidas (v0)

- TOTP es phishable; no hay factor resistente a phishing hasta H9.
- `LocalKms` (H2) protege contra robo de DB, pero no contra compromiso total del host: producción requiere KMS/HSM real (checklist de `BANDALL_ROADMAP.md` §4).
- La cadena de auditoría v2 (ADR-0010) verifica la integridad **desde la
  migración**, no desde el génesis: las filas escritas con el hash v1 sin clave
  siguen validando, así que un historial manipulado antes de esa migración no
  se detecta. Tampoco hay rotación de la clave de auditoría, porque una sola
  clave firma toda la cadena (ver §Rotación de ADR-0010).
- Sin pentest externo hasta H9.
- Sin cifrado del lado del cliente ni backup: la app móvil no existe aún (H7).

## Estado de implementación (v1, H0–H8)

- H1–H4: núcleo TOTP, vault, store, API MFA, tokens y sesiones según diseño.
- H5: `policy` (backoff/lockout), negación uniforme, auditoría encadenada con
  clave y append atómico (ADR-0010), revisión ASVS (`docs/asvs-l3-review.md`).
- H6: firmas HMAC por cliente, forward-auth, `sdk-axum`, SDKs TS/Python
  sobre vectores compartidos, demo legacy, ejemplo embebido.
- H7: `authenticator-core` (cuentas, backup cifrado); UI nativa y UniFFI
  pendientes (ADR-0006).
- H8: `/metrics`, Helm, compose de observabilidad, k6, runbooks. Pendiente
  de entorno real: SLOs medidos, DR ensayado, `cargo-vet`, SBOM, `cosign`,
  TLS a Postgres/KMS.
- Supuestos vigentes: TLS termina en el proxy; la DB puede comprometerse;
  `LocalKms` solo vale para desarrollo/air-gapped.
