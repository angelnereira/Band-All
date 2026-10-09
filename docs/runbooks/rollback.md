# Runbook: reversión (rollback)

Los otros runbooks cubren fallos de datos (`restore.md`) y de disponibilidad
(`chaos.md`). Este cubre **yo he desplegado algo y hay que volver atrás**, que es
el escenario en el que menos se piensa y el que más rápido llega.

Antes de seguir, lo que dice `docs/ROADMAP_STATUS.md` sobre este ensayo: la
primera versión de `tests/ops/rehearse_rollback.sh` intentó el rollback obvio
—**volver a desplegar la imagen antigua**— y **no funcionó**. Lo que se encontró
al intentarlo es la razón de este runbook.

## Lo que hay que saber antes de tocar nada

### 1. Revertir el binario **no** revierte el esquema

`bandall serve` ejecuta el migrador al arrancar (`crates/api/src/server.rs`), y
sqlx **se niega** a ejecutar un migrador contra un esquema que contiene
migraciones que el migrador no conoce. Aunque la migración de más sea
puramente aditiva (una tabla nueva).

En la práctica: la versión nueva migra el esquema, y **el binario viejo se
niega a arrancar sobre él**. Se ve así, en medio del incidente:

```
migration error: internal error
```

No es un fallo del servicio: es una negativa deliberada. Un binario que no
conoce una migración podría estar corriendo sobre datos que no entiende, y eso
prefiere no hacerlo.

### 2. Revertir de verdad es restaurar la base de datos

El procedimiento que funciona es el más pesado:

1. **Antes** de desplegar, tomas un savepoint de la base de datos.
2. Desplegar hacia adelante, verificar.
3. Para volver atrás: **restaurar el savepoint** y arrancar el binario viejo,
   que ahora sí ve un esquema que conoce y arranca feliz.

### 3. El coste es real y hay que decirlo

Restaurar el savepoint **descarta todo lo escrito después**. En un servicio con
tráfico, eso es pérdida de datos. El savepoint hay que tomarlo inmediatamente
antes de migrar, y la ventana entre savepoint y migración tiene que ser tan
corta como el despliegue permita.

Consecuencia directa: **una migración hacia adelante es, en la práctica, una
puerta de una sola dirección.** La forma de volver es una restauración, no un
despliegue. Una migración que renombra, borra o retipa una columna es peor
todavía: la vuelta necesitaría una segunda migración, no una restauración.

### 4. Si restauras un fichero SQLite, el dueño lo es todo

El ensayo falló aquí en su primera versión. El contenedor que copia el fichero
de vuelta corre como root, así que el fichero queda `root:root`. El servicio
corre como `nonroot` (uid 65532): puede **leer** un fichero de root, no
**escribirlo**. Todos los inserts fallan con SQLITE_READONLY y el servicio
responde 500.

Siempre:

```bash
chown 65532:65532 /data/bandall.db   # el uid de distroless nonroot
chmod 0640 /data/bandall.db
```

El ensayo de DR ya hacía el `chown` equivalente con el material de claves; esto
es el mismo error, con un fichero distinto.

## Procedimiento

### Antes de desplegar

1. Savepoint de la base de datos.
   - Postgres: `pg_dump -Fc` (lo hace `tests/dr/rehearse_restore.sh`).
   - SQLite: copia del fichero **con el servicio parado**, y `chown 65532:65532`
     al restaurar.
2. Anota la versión que está corriendo. `docker inspect -f '{{.Config.Image}}'`
   es la fuente de verdad, no lo que uno cree que desplegó.

### Si hay que volver atrás

1. Para el servicio.
2. Restaura el savepoint (con el `chown` si es SQLite).
3. Arranca la versión anterior **sin ejecutar `migrate`**.
4. `/readyz` en 200.
5. **Verifica con un login real**, no con el healthcheck: un factor que sigue
   funcionando es la prueba de que el binario y la base de datos se entienden.
6. `bandall audit verify`: la cadena debe salir en verde.

## Ensayo

```bash
tests/ops/rehearse_rollback.sh     # o: just verify-rollback
```

Construye dos versiones reales (el árbol actual, y el árbol actual con una
migración adicional), y pasa por: línea base con login real → savepoint →
forward a v2 → **intento documentado de revertir el binario** (que falla, y se
registra el porqué) → restore del savepoint + arranque de v1 → cadena de
auditoría → forward otra vez.

Todo lo que crea muere con el ensayo; no deja ninguna migración ficticia en el
repositorio, porque esa segunda versión se construye desde una copia.

## Decisión que queda sobre la mesa

Lo que el ensayo **no** decidió, y conviene decidir:

permitir que un binario antiguo tolere un esquema con migraciones más nuevas,
de modo que revertir sea solo "redesplegar la imagen antigua". sqlx lo permite
(`set_ignore_missing`) y convertiría la vuelta en una operación de 30 segundos en
vez de una restauración con pérdida de datos.

Pero el precio es un binario corriendo sobre datos que no entiende del todo,
que es exactamente lo que la negativa actual evita. Es un intercambio entre
**tiempo de recuperación** y **certeza sobre los datos**, y por eso se deja
documentado y sin elegir en lugar de aplicarlo por defecto.
