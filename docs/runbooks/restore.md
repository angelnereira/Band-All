# Runbook: backup y restauración

## Copias

- Postgres en HA con backups cifrados (pgBackRest o el mecanismo de tu
  nube), retención ≥ 30 días. Incluye `keys/` (firmas JWT) y la KEK solo si
  tu KMS la exporta; si no, documenta su recuperación en el HSM.
- SQLite embebido: copia el archivo en caliente (`sqlite3 .backup`) +
  `keys/`.

## Restaurar (ensayar al menos una vez antes de producción)

1. Levanta Postgres vacío y restaura el backup.
2. Apunta `BANDALL_DATABASE_URL` al restaurado y `bandall migrate`
   (idempotente: solo aplica lo pendiente).
3. `bandall audit verify --limit 100000`: debe salir en verde. Si la cadena
   rompe, el backup fue manipulado: no lo uses.
4. `readyz` en 200 y un login de prueba con un factor real.
5. Alertas rearmadas.

## RPO/RTO

- Define RPO/RTO con tu negocio (sugerencia: RPO ≤ 1 h, RTO ≤ 2 h) y ensaya
  el procedimiento cada trimestre. Registra cada ensayo en el CHANGELOG de
  operaciones.
