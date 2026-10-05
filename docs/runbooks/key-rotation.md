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

## Claves HMAC de API (`key_id`)

Sin solape automático: crea el sucesor (`apikey create`), migra el tráfico
y revoca el anterior (`apikey revoke`). Dos claves activas por diseño.
