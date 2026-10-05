# ADR-0005: BandAll verifica el segundo factor y emite sesión propia

- **Estado:** aceptado
- **Fecha:** 2026-10-05
- **Decisores:** Angel Nereira
- **Responde a:** `BANDALL_ROADMAP.md` §5, decisión 1 (credencial primaria)

## Contexto

¿BandAll solo hace el segundo factor (detrás de un IdP) o también emite sesiones completas?

## Decisión

BandAll **verifica el segundo factor (OTP) y emite sus propios tokens de sesión**, sin gestionar la credencial primaria (password/IdP), que sigue en el llamante. Los claims son honestos: `amr: ["otp"]` y `aal: 1` hasta que exista verificación primaria integrada; entonces `amr` incluirá `"pwd"` y `aal` subirá a 2.

## Consecuencias

- Los integradores deben autenticar la credencial primaria antes de llamar a `mfa/verify`; la confianza queda documentada en el contrato, no asumida.
- `verify` S2S y `authz/check` (H6) exigen como mínimo `amr` con `otp`.
- Sin cambios de esquema cuando llegue la primaria completa: solo cambian los valores de `amr`/`aal`.
