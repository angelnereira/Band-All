# ADR-0014: Crate `bandall-embedded` — fachada de integración embebida

- **Estado:** aceptado (H6)
- **Fecha:** 2026-10-07
- **Decisores:** Angel Nereira

## Contexto

El ítem 6 de H6 pide el "modo embebido: ejemplo con `bandall-totp-core` +
`bandall-store` (SQLite) en un binario único, sin red". La entrega inicial fue
`sdk`: un **ejemplo** (`crates/store/examples/embedded.rs`) que demuestra el
ciclo enroll → verify → replay, pero que obliga a quien integra a reensamblar
a mano las piezas (vault, `SealedSecret::reassemble`, `cas_last_step`, AAD)
cada vez. Es correcto de matemática, pero no es "fácil ni robusto": son ~150
líneas de cableado por integrador, con espacio para equivocarse en el
desempaquetado del secreto o en el antirreplay.

El objetivo de este ADR es la primera línea de `AGENTS.md` del modo embebido:
que **cualquiera pueda embeber BandAll en su sistema sin reimplementar el
cableado**, manteniendo las mismas garantías que el servicio HTTP (secreto
cifrado en reposo, AAD por fila, antirreplay atómico, deriva, recovery codes).

## Decisión

Nuevo crate `bandall-embedded` (workspace, `crates/embedded`) que expone una
fachada de alto nivel sobre `bandall-totp-core` + `bandall-vault` +
`bandall-store`, **sin red y sin HTTP**:

```
Embedded::with_sqlite_path(path, kek)           // abrir (o crear) store + vault
  .enroll(tenant_id, subject_external_id, issuer, account)   // ->  (factor_id, otpauth_uri, recovery_codes)
  .verify(tenant_id, subject_id, factor_id, code, unix_secs) // -> Result<(), Error> (antirreplay, deriva)
  .factor_list(tenant_id, subject_id)          // -> Vec<FactorSummary> (sin secretos)
  .delete_factor(tenant_id, subject_id, factor) // para re-enrolar
```

Garantías que la fachada **no deja bajar**:

- El secreto se guarda **cifrado** (misma envolvente KEK→DEK + AAD por fila que
  el servicio). Quien integra nunca maneja plaintext más allá de la invitación
  a mostrar el QR.
- `verify` consagra el paso con `cas_last_step` atómico: un código vale una
  vez (igual que HTTP).
- `verify` aplica la ventana de T3 (tres pasos, deriva aprendida acotada a
  ±5) y la deriva se persiste — idéntico al servicio.
- Todos los errores son tipados (`thiserror`), uniformes y sin detalles de
  secretos.

Regla de dependencias (AGENTS.md: el núcleo nunca depende de los externos):
`bandall-embedded` depende de `totp-core`, `vault`, `store` y `policy`
(ventana/deriva), **no al revés**. No depende de `api` ni de `axum`: lo que el
servicio HTTP hace a mano, la fachada lo hace a mano también, compartiendo los
mismos primitivas.

## Alternativas consideradas

| Alternativa | Motivo de descarte |
|---|---|
| Documentar el ejemplo y nada más | Es lo que había; deja el cableado a cada integrador |
| Mover el código de `api` a una librería reutilizable | `api` está atado a axum/handlers; extraer el flujo de enroll/verify sin arrastrar el HTTP es un refactor mayor y mezcla "servicio" con "embebido" |
| Fachada dentro de `bandall-store` | `store` no debe conocer crypto (hoy no depende de `vault`); rompería la regla de dependencias |
| `authenticator-core` | Ese crate es para la app móvil (H7): cuentas del dispositivo, backup cifrado; la fachada embebida es para el *servidor* del integrador |

## Consecuencias

- El ejemplo `crates/store/examples/embedded.rs` se simplifica para usar la
  fachada (unos 30 líneas), demostrando precisamente "embeber es fácil".
- `bandall-embedded` lleva su batería de tests: enroll→verify→replay, deriva,
  recovery, apertura de un store existente, y las garantías negativas (código
  reusado, factor ajeno, tenant cambiado).
- El fixture `at_rest` (api/tests) ya validaba que el servicio no deja
  secretos en claro; la fachada suma su propia prueba equivalente para el
  recorrido embebido.

## Relación con otros ADR

- ADR-0005 (claim `aal`): la fachada no emite JWT; quien quiera sesiones usa
  el servicio o `bandall-tokens` aparte.
- ADR-0013 (JWKS remoto): la fachada es el modo *local*; `sdk-axum`
  `RequireToken::new` sigue valiendo para embebido y `with_jwks` para remoto.
- ADR-0015 (vectores): sin efecto aquí; `bandall-embedded` no es un SDK de
  conformidad.