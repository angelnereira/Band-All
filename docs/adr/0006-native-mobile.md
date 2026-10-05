# ADR-0006: App móvil nativa con núcleo Rust compartido

- **Estado:** aceptado
- **Fecha:** 2026-10-05
- **Decisores:** Angel Nereira
- **Responde a:** `BANDALL_ROADMAP.md` §5, decisión 5 (app nativa vs Flutter)

## Contexto

La app debe funcionar 100 % offline, guardar el secreto en Secure Enclave /
Keystore y pedir biometría. La lógica compartida vive en
`authenticator-core` (Rust puro, sin red).

## Decisión

Apps **nativas por plataforma** (SwiftUI + Jetpack Compose) con bindings
**UniFFI** al núcleo Rust. Nada de Flutter: se evita un runtime pesado y el
acceso al Keystore/Enclave queda directo y auditable.

## Consecuencias

- `authenticator-core` expone su API por UniFFI en un hito posterior de H7
  (los tipos ya son UniFFI-amigables: structs simples, errores tipados).
- UI duplicada (dos codebases), pero cada una usa los controles de seguridad
  nativos (`FLAG_SECURE`, StrongBox, biometría del SO).
- Sin backup en la nube por defecto; backup cifrado opcional con passphrase
  (Argon2id) ya implementado en el núcleo.
