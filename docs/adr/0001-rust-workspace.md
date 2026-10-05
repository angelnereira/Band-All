# ADR-0001: Workspace Cargo único

- **Estado:** aceptado
- **Fecha:** 2026-10-05
- **Decisores:** Angel Nereira

## Contexto

BandAll se usa de tres formas (servicio independiente, sidecar/forward-auth y librería embebida) y necesita un núcleo TOTP puro, auditable y reutilizable. El equipo es de una persona en la fase inicial.

## Decisión

Un único workspace Cargo con los crates `bandall-*` definidos en `BANDALL_BLUEPRINT.md` §4. Las dependencias fluyen **hacia** `totp-core`, que no depende de red ni de base de datos. El binario único `bandall` vive en `bandall-cli`. Los crates publicables podrán separarse en el futuro sin cambiar la estructura lógica.

## Consecuencias

- Una sola compilación, un solo CI y una sola política de dependencias (`cargo-deny`) para todo el proyecto.
- Los límites entre módulos son explícitos: el núcleo puro es fácil de fuzzear y auditar.
- El modo librería embebida del blueprint §2 es viable sin extraer código.
- Coste: el `Cargo.lock` es único; un cambio de dependencia afecta a todos los crates (deseado: versiones coherentes).

## Alternativas consideradas

| Alternativa | Motivo de descarte |
|---|---|
| Un repositorio por crate | Sobrecarga de coordinación y versionado para un equipo de 1 |
| Un único crate monolítico | Impide el modo embebido y difumina la frontera del núcleo puro |
