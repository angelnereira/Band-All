# Runbook: rotación de claves (KEK y firma JWT)

## KEK (cifrado de secretos)

1. Genera la KEK nueva (32 bytes) y regístrala como `kek-2` en el KMS/HSM.
2. Despliega BandAll apuntando a `kek-2` para sellar lo nuevo (`kek_id`
   por defecto en config), manteniendo acceso a `kek-1`.
3. Re-envuelve por factor (`Vault::rewrap_with`): lee con la vieja, sella
   con la nueva. Es online y por filas; repite hasta que ningún `factors`
   ni `api_clients` apunte a `kek-1`.
4. Retira `kek-1` del KMS y verifica `bandall audit verify`.

## Firmas JWT

1. Genera el par nuevo y colócalo como `current.key`; mueve el actual a
   `previous.key` (solape: ambas `kid` verifican).
2. Despliega y confirma en JWKS que aparecen las dos `kid`.
3. Tras una ventana (p. ej. 24 h), elimina `previous.key` y redespliega.

## Clave de la cadena de auditoría (T4)

La cadena v2 es un HMAC sobre toda la cadena con **una sola** clave: rotarla
no es un paso online como el de la KEK. Antes de rotarla:

1. Exporta el log completo y verifícalo con la clave actual
   (`bandall audit verify`). Necesitarás ese volcado para verificar el
   histórico después del cambio.
2. Decide si el histórico importa más que la continuidad de la cadena. Las
   opciones están en `docs/adr/0010-audit-chain-v2.md` §Opciones (reencadenar
   conservando filas, o abrir una cadena nueva desde el génesis y verificar el
   histórico por separado).
3. Con la decisión tomada, aplica el procedimiento que describa ese ADR y
   verifica de nuevo con `bandall audit verify` usando la clave nueva.

Mientras no haya decisión humana, **no rotes la clave de auditoría**: hacerlo
deja el log verificable solo con la clave antigua.

## Claves HMAC de API (`key_id`)

Sin solape automático: crea el sucesor (`apikey create`), migra el tráfico
y revoca el anterior (`apikey revoke`). Dos claves activas por diseño.
