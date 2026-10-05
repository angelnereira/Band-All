# ADR-0003: SHA-256 por defecto para factores nuevos

- **Estado:** aceptado
- **Fecha:** 2026-10-05
- **Decisores:** Angel Nereira
- **Responde a:** `BANDALL_ROADMAP.md` §5, decisión 3 (SHA-1 vs SHA-256)

## Contexto

Google/Microsoft Authenticator ignoran el parámetro `algorithm` del URI `otpauth://` y verifican siempre con HMAC-SHA-1. Nuestra app propia (`authenticator-core`, H7) sí respetará el algoritmo declarado.

## Decisión

- Los factores nuevos usan **SHA-256, 6 dígitos, periodo 30 s** (`TotpParams::default_params`).
- El núcleo acepta y verifica **SHA-1, SHA-256 y SHA-512** (compatibilidad con apps de terceros y vectores RFC 6238).
- SHA-1 solo se emite para factores destinados a autenticadores externos que lo exijan.

## Consecuencias

- Secretos de 32 bytes por defecto (20 para SHA-1, 64 para SHA-512).
- El enrolamiento (H3) debe elegir el algoritmo según el tipo de app del usuario; la API expondrá el parámetro con este valor por defecto.
