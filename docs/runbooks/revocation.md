# Runbook: revocación masiva

## Cuándo

Compromiso de un tenant, abuso masivo o fin de relación con un integrador.

## Procedimiento

1. Lista sesiones vivas del tenant (consulta `sessions` por `tenant_id`
   con `revoked_at IS NULL`).
2. Por cada `sid`: `UPDATE sessions SET revoked_at = <now> WHERE id = ...`.
   Los access vigentes mueren en ≤ 10 min (su `exp`); los refresh, al instante.
3. Quema las familias: `UPDATE refresh_tokens SET revoked_at = <now>
   WHERE session_id IN (...)`.
4. Revoca sus `key_id`: `bandall apikey revoke` por cada uno.
5. Verifica: `authz/check` con un token anterior debe dar 401; `refresh`
   con un token anterior, 401.

## Notas

- La revocación es idempotente: repetir es seguro.
- Los JWT ya emitidos no se pueden "recoger": su vida corta (10 min) es el
  límite de exposición. No alargues `ACCESS_TTL_SECS` sin ADR.
