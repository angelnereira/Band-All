# ADR-0004: Access tokens como JWT EdDSA (no PASETO)

- **Estado:** aceptado
- **Fecha:** 2026-10-05
- **Decisores:** Angel Nereira

## Contexto

El blueprint (§8) dejaba abierta la elección: PASETO v4.public o JWT con EdDSA (Ed25519).

## Decisión

**JWT con EdDSA**, implementado a mano sobre `ed25519-dalek` (sin crate JWT genérico): algoritmo fijo `EdDSA` (cualquier otro, incluido `none`, se rechaza), claims obligatorios `iss`/`aud`/`sub`/`exp`, `kid` con solape en rotación y JWKS público.

## Consecuencias

- Compatibilidad directa con el ecosistema: filtros JWT de nginx/Envoy/Traefik, SDKs y `forward-auth` (H6) entienden JWT+JWKS; PASETO exigiría código a medida en cada integrador.
- Más superficie de validación propia (confusión de algoritmo, `exp`); mitigada con validación estricta y pruebas negativas obligatorias.
- Vida corta (10 min) + refresh opaco con rotación y detección de reutilización, según diseño.

## Alternativas consideradas

| Alternativa | Motivo de descarte |
|---|---|
| PASETO v4.public | Mejor diseño criptográfico por defecto, pero adopción casi nula en proxies/SDKs: fricción en H6 |
| Crate JWT genérico (`jsonwebtoken`) | Abstrae la validación estricta que necesitamos auditar línea a línea |
