# ADR-0008: Estado compartido de rate-limit y requisitos de producción

- **Estado:** aceptado (plan definido; implementación bloqueada por el entorno, ver `docs/VERIFICATION.md`)
- **Fecha:** 2026-10-05
- **Decisores:** Angel Nereira

## Contexto

El motor de `policy` (backoff, lockout, ventana deslizante) mantiene su estado
**en memoria por proceso**. Con una sola réplica es correcto; con `N` réplicas
detrás de un balanceador un atacante obtiene `N × max_attempts` intentos antes
del lockout, y el estado se pierde en cada reinicio. La revisión previa a
producción marcó esto como bloqueante (junto con TLS a Postgres y el KMS real).

## Decisión

1. **La fuente de verdad del contador de fallos pasa a la base de datos**
   (tabla compartida por réplicas), manteniendo la decisión de diseño de no
   introducir Redis en el MVP (blueprint §3, §15).
2. **Esquema (migración 6, ambos motores):**

   ```sql
   CREATE TABLE auth_failures (
       policy_key TEXT NOT NULL,      -- "factor:t:s:f" | "tenant:t" | "ip:a"
       failed_at  BIGINT NOT NULL,    -- Unix seconds
       PRIMARY KEY (policy_key, failed_at)
   );
   ```

3. **Métodos nuevos en `Store`** (mismos principios que `cas_last_step`):
   - `count_auth_failures(key, since) -> i64` — fallos en la ventana.
   - `record_auth_failure(key, now)` — un `INSERT`, idempotente por PK.
   - `clear_auth_failures(key, now)` — éxito del usuario borra su historial.
4. **`AppState` elegirá backend por configuración** (`policy_backend =
   "memory" | "database"`, por defecto `memory` para desarrollo y modo
   embebido): `memory` usa el `Policy` actual sin I/O; `database` consulta la
   tabla en el gate de verificación (hot path: 1 SELECT + 1 INSERT, igual que
   `last_step`).
5. **Los umbrales (`Limits`) siguen siendo configurables** y se aplican igual
   en ambos backends, para que tests y producción midan lo mismo.
6. **Redis queda explícitamente fuera** hasta que la carga lo exija; si llega,
   será un tercer backend tras el mismo contrato, no un cambio de diseño.

## Por qué base de datos y no Redis

- Ya es stateful (sesiones, refresh, `last_step`); el hot path ya la toca.
- Consistencia inmediata entre réplicas sin un servicio nuevo.
- `ON CONFLICT`/PK garantiza idempotencia bajo concurrencia, igual que el
  antirreplay.

## Requisitos de producción relacionados (bloqueantes, no opcionales)

| Requisito | Estado | Acción |
|---|---|---|
| TLS a Postgres remoto | rama `feat/pg-tls-enforcement` (sin verificar: host ICE) | verificar con `cargo test` y fusionar |
| KMS/HSM real (no `LocalKms`) | `LocalKms` solo dev/air-gapped | checklist `BANDALL_ROADMAP.md` §4 |
| `policy_backend = "database"` | este ADR | implementar tras verificar TLS |
| Estado de nonces HMAC compartido | en memoria por réplica | mismo patrón (`nonce_seen` table o Redis en H8) |

## Consecuencias

- Con `policy_backend = "database"`, un ataque de fuerza bruta se limita de
  forma global: 5 fallos reales, no `5 × réplicas`.
- Coste: dos sentencias SQL más por verificación fallida (no en la vía feliz).
- El modo embebido (H6) sigue en memoria: es un proceso único sin red.