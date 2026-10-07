# ADR-0010: Cadena de auditoría con clave (v2)

- **Estado:** aceptado (remediación T4)
- **Fecha:** 2026-10-06
- **Decisores:** Angel Nereira
- **Nota de numeración:** T10 (credencial primaria) tenía reservado el
  `0010-primary-credential.md` en el brief; al llegar T4 antes, este ADR toma
  el 0010 y el de T10 pasa a ser `0011-primary-credential.md`.

## Contexto

La cadena de auditoría introducida en H5 era `SHA256(prev ‖ event ‖ ts_be)`,
sin clave y **sin `tenant_id` ni `subject_id`** en el prehash. Tres fallos, en
orden de gravedad:

1. **Sin clave.** Quien tenga permiso de `INSERT` en `audit_log` puede
   recalcular toda la cadena sin ningún secreto: no hace falta alterar una
   fila, basta con reescribir los enlaces. La propiedad era "detecta
   manipulación accidental", no "detecta a un atacante con escritura".
2. **Fuera de cobertura.** Editar `tenant_id` o `subject_id` de una fila no
   rompía la verificación. Es justo el dato que da valor a un registro de
   auditoría: a quién se le concedió el acceso.
3. **Ambigüedad de codificación.** Los campos iban concatenados sin prefijo
   de longitud, así que distintos registros podían producir el mismo prehash.
   Sin clave esto era académico; con clave habría sido una debilidad propia.

Además, el append eran **dos llamadas** (`last_audit_hash` y luego
`append_audit`), de modo que dos escritores concurrentes podían leer el mismo
tipo y bifurcar la cadena. Ambas filas serían válidas y la verificación
lineal fallaría, o peor, una rama quedaría huerfana sin avisar.

## Decisión

Cadena **v2** con `HMAC-SHA-256` sobre un registro framing con prefijo de
longitud, y el append movido al `Store` como una única transacción.

### Formato

```
hmac = HMAC-SHA-256(audit_key, frame)
frame = LP(version ‖ ts ‖ tenant_id ‖ subject_id ‖ event ‖ prev_hash)
LP(x) = u32::to_be_bytes(x.len()) ‖ x
```

`LP` con `u32` elimina la ambigüedad de la v1 y fija el ancho del entero de
versión. La clave (32 B) vive fuera de la base de datos, en `audit_key_file`,
con permisos `0600`: se aplica la misma regla que la KEK del KMS, mediante
`config::require_owner_only_file`. Un archivo legible por el grupo o por otros
se rechaza al arrancar, no se acepta con un aviso.

### Append atómico

`Store::append_audit_chained(entry, hasher)` lee el tip y **calcula el enlace
dentro** de la transacción que inserta:

- Postgres: `pg_advisory_xact_lock` sobre una constante global (la cadena es
  una única secuencia, no una por tenant) y la lectura y el `INSERT` en la
  misma transacción.
- SQLite: `BEGIN IMMEDIATE`, que toma el bloqueo de escritura antes de leer.

El `Store` no recibe `prev_hash` ni `hash`: recibe un `AuditHasher` y lo llama
dentro. Por eso el llamador no puede pasar un tip obsoleto, y una cadena
bifurcada deja de ser representable en la API en lugar de depender de que
todos los llamadores hagan las cosas en el orden correcto.

### Privilegios en Postgres

La migración 7 revokea `UPDATE, DELETE, TRUNCATE` sobre `audit_log` a `PUBLIC`
y, si existe, al rol `bandall_app`, grantingle solo `INSERT, SELECT`. SQLite no
tiene roles: el append-only descansa en la transacción serializada y en los
permisos del archivo de base de datos.

### Compatibilidad

`chain_version` (por defecto 1) dice cómo se derivó cada `hash`.
`verify_chain` verifica v1 y v2 según la versión de **cada** fila, así que un
log escrito antes del cambio sigue siendo auditable y los registros v1 y v2
pueden convivir en la misma cadena. Solo los appends nuevos escriben v2.

## Opciones descartadas

### A. Sololoprar `tenant`/`subject` en el prehash

Arregla el punto 2 con un cambio pequeño, pero mantiene el 1: la cadena
sigue siendo recalculable por cualquiera con escritura, que es el escenario
que un log de auditoría debe resistir.

### B. HMAC por fila en vez de encadenada

Cada fila se firma sola y la cadena se pierde. Se detectaría alterar una fila,
pero **borrar filas enteras del final o del medio** no dejaría rastro, que es
precisamente lo que un atacante con escritura hace primero. La cadena encadenada
es lo que hace que una fila insertada sin su predecesor sea detectable.

### C. Firma digital con clave asimétrica (Ed25519)

Permitiría verificar con la clave pública, sin repartir el secreto de
verificación. Coste: gestión de un par de claves y de su rotación, más un KMS
que firme. Desproporcionado para H5; la clave simétrica de 32 B ya obliga a que
quien lee el log (y quien puede escribir en él) no sean la misma persona en
sentido estricto. Se revisa en H9 junto con FIPS.

### D. DEK de la cadena dentro del KMS

Envolver la clave de auditoría con la KEK y guardarla cifrada en la base de
datos. Evita el archivo, pero quien tenga la KEK puede desenvolverla, así que
**no aporta** frente a quien ya puede escribir en la base de datos. El valor
está en que la clave viva en un sistema de credenciales con control de acceso
propio, no en el cifrado en reposo. Para KMS de producción (decisión abierta
en el roadmap, §5.2), la clave de auditoría debería salir del mismo KMS que
la KEK; ese es el punto donde la opción vuelve a tener sentido.

## Consecuencias

- **Positivo:** alterar `tenant`, `subject`, `event` o `ts` rompe la
  verificación; con la clave, recalcular la cadena es inviable; el append ya
  no puede bifurcar.
- **Coste operativo:** `audit_key_file` es obligatorio y su rotación no es un
  paso online (§Opciones más abajo y `docs/runbooks/key-rotation.md`).
- **Debilidad heredada:** las filas v1 siguen verificando con su hash sin clave,
  así que un histórico reescrito **antes** de esta migración no se detecta.
  Verificar es "no manipulado desde la migración", no "íntegro desde el
  génesis". Lo dice explícitamente el test `legacy_v1_rows_still_verify`.
- **Deuda:** la comparación de la clave en `LocalKms` y en
  `require_owner_only_file` está duplicada. Se unifica cuando T5 haga asíncrono
  el `KmsProvider`.

## Rotación de la clave de auditoría

Una sola clave firma toda la cadena, así que rotarla rompe la verificación del
histórico. Sin decisión humana al respecto, el procedimiento operativo es:
**no rotarla**; y si hay que hacerlo, exportar el log, verificarlo con la clave
antigua, y verificar el histórico por separado frente a la cadena nueva. La
alternativa (reencadenar todas las filas conservando sus `seq` y `ts`) es un
`UPDATE` masivo que contradice el append-only que este mismo ADR refuerza, y
queda como decisión abierta.

## Alternativa de la sección 3 del brief

El brief pedía `bandall audit verify` "reciba la clave". Se implementó
leyéndola de la configuración (igual que la KEK) en vez de añadir un flag
`--audit-key-file`: el subcomando ya toma `--config`, y una clave en línea de
comandos queda en el historial del shell y en `ps`. La clave se pide igualmente
al operador, y sigue siendo obligatoria: sin ella, las filas v2 fallan la
verificación en lugar de pasar.