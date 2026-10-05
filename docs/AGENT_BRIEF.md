# BandAll — Brief para el agente de código
*Remediación de la revisión de seguridad. Guárdalo como `docs/AGENT_BRIEF.md` y pásale al agente la sección 0.*

## 0. Prompt de arranque (pégalo tal cual)

> Lee `AGENTS.md`, `BANDALL_BLUEPRINT.md`, `docs/VERIFICATION.md` y `docs/AGENT_BRIEF.md` completos.
> Trabaja **una tarea a la vez**, en el orden de la sección 2, con **una rama y un PR por tarea**.
> Antes de escribir código en cada tarea, lee los archivos citados y **confirma que el problema existe tal como se describe**; si no existe, dilo y detente.
> No cambies nada fuera del alcance de la tarea. Si una tarea está marcada **[DECISIÓN]**, escribe el ADR con opciones y recomendación y **detente hasta que el humano responda**.
> Si `cargo` falla con ICE, `SIGILL` o archivos corruptos, **detente y repórtalo**: no toques `Cargo.lock` ni versiones para esquivarlo.
> Al terminar cada tarea entrega: qué cambiaste, cómo probarlo, qué reglas de seguridad toca y qué riesgo queda.

## 1. Reglas de trabajo

- `AGENTS.md` manda. `just check` debe pasar antes de cada PR.
- **Nunca edites migraciones existentes.** Crea la siguiente (revisa el último número; ADR-0008 reserva la 6 para `auth_failures`) en `postgres/` **y** `sqlite/`, y amplía `tests_battery.rs`.
- Cada tarea trae **pruebas negativas** (el ataque debe fallar), entrada en `CHANGELOG.md` y actualización de `docs/ROADMAP_STATUS.md`.
- Dependencias nuevas: justificarlas según ADR-0007. Cambios a formatos persistidos (ciphertext, claims, esquema): ADR + compatibilidad hacia atrás.
- No declares un hito como cerrado: los gates los cierra el humano.
- Nada de secretos reales en tests, logs ni ejemplos.

## 2. Orden de PRs

| PR | Tarea | Depende de |
|---|---|---|
| 1 | T1 Arreglar `ci.yml` | — |
| 2 | T2 Rate limit atómico y sin DoS de tenant | — |
| 3 | T3 Ventana y drift | — |
| 4 | T4 Auditoría robusta | — |
| 5 | T5 Vault v2 y KMS async | — |
| 6 | T6 Claves JWT | — |
| 7 | T7 Recovery codes | T5 (pepper) |
| 8 | T8 S2S por cliente + nonces | T2 |
| 9 | T9 Endurecimiento varios | — |
| 10 | T10 Login con credencial primaria | **decisión humana** |

---

## 3. Tareas

### T1 — Arreglar `ci.yml`
**Archivo:** `.github/workflows/ci.yml`
**Problema:** `defaults.run.timeout-minutes` no es válido (`defaults.run` solo admite `shell` y `working-directory`): GitHub rechaza el workflow. Además, los SHAs fijados no coinciden con los tags del comentario (p. ej. `checkout` v4.2.2 es `11bd7190…`, el archivo usa `11d5960a…`).
**Cambio:**
1. Quitar `defaults.run.timeout-minutes`; poner `timeout-minutes: 20` en **cada job**.
2. Resolver **cada** SHA desde el repo oficial (`git ls-remote https://github.com/<owner>/<repo> 'refs/tags/<tag>*'`; si el tag es anotado, usar el commit de `^{}`) y reemplazarlo. Dejar `# vX.Y.Z` junto a cada `uses:`. No te fíes de los SHAs actuales ni de tu memoria.
3. Añadir `concurrency: { group: ci-${{ github.ref }}, cancel-in-progress: true }`.
4. El job `coverage` genera `lcov.info` y no lo usa: súbelo como artefacto o añade un umbral para `totp-core` (> 90 %, regla de `AGENTS.md`).
**Aceptación:** `actionlint` sin errores; el workflow arranca en Actions; el PR lista cada SHA con el comando usado para verificarlo.

### T2 — Rate limit atómico y sin DoS de tenant
**Archivos:** `crates/policy/src/policy.rs`, `crates/api/src/gates.rs`, `verify.rs`, `enroll.rs`, `config.rs`
**Problemas:**
- `check` y `record` son operaciones separadas: una ráfaga concurrente pasa todos los `check` antes de que se registre ningún fallo.
- La clave `tenant:{id}` usa los mismos límites que un factor, en un endpoint público: un atacante bloquea a todo un tenant.
- `entries` crece sin límite con claves que controla el atacante.
**Cambio:**
1. `Policy::acquire(key, now) -> Decision`: decide **y registra** el intento bajo un único lock. `record(success)` al final borra (éxito) o confirma (fallo).
2. `Limits` por ámbito: `factor` (estricto, como hoy); `tenant` e `ip` (techos altos, solo `RetryAfter`/429, **sin lockout largo**). Configurables.
3. Tope de entradas del mapa (p. ej. 100 000) con barrido de expiradas; al llegar al tope, 429 a claves nuevas de ámbito `ip`/`tenant` en vez de crecer.
4. IP: usar `X-Forwarded-For` solo si hay `trusted_proxies` configurado; si no, la IP del socket.
5. Implementar el backend `database` de ADR-0008 (migración 6) con **reserva atómica**: `INSERT` del intento y `COUNT` de la ventana en la misma transacción.
**Pruebas:** 100 peticiones concurrentes con `max_attempts=5` → ≤ 5 llegan a verificar; fallos masivos contra factores inexistentes del tenant A no bloquean un factor válido del mismo tenant; el mapa nunca supera el tope; el lockout por factor sigue funcionando; la batería corre en Postgres y SQLite.

### T3 — Ventana de verificación y drift
**Archivo:** `crates/api/src/verify.rs`
**Problema:** `WINDOW=1` más `DRIFT_RADIUS=2` prueba hasta 7 pasos (±90 s) en lugar de 3, y `record_drift` aprende con un solo acierto.
**Cambio:**
1. Extraer una función pura `candidate_steps(now, drift, period) -> [u64; 3]` con `[now_step + drift − 1, … + 1]` y usar solo esos candidatos. Eliminar `drift_candidates`.
2. Tras un acierto, fijar `drift` al desfase real observado (clamp a ±`DRIFT_MAX`).
3. Si el usuario queda fuera de ±1 de su drift guardado, falla. La resincronización (exigir dos códigos consecutivos) es **[DECISIÓN]**: solo ADR, sin implementar.
**Pruebas:** `candidate_steps` devuelve exactamente 3 pasos distintos; el replay sigue rechazado; un reloj +30 s entra y actualiza el drift; un reloj +90 s no entra.

### T4 — Auditoría robusta
**Archivos:** `crates/api/src/audit.rs`, `crates/store/src/*`, `crates/cli/src/main.rs`, nueva migración
**Problemas:**
- El hash es `SHA-256(prev ‖ event ‖ ts)` sin clave y **sin `tenant`/`subject`**: quien escribe en la DB recalcula toda la cadena, y alterar tenant/subject no se detecta.
- `last_audit_hash` + `append_audit` no son atómicos: bajo concurrencia la cadena se bifurca.
- La tabla permite `UPDATE`/`DELETE` a la app.
**Cambio:**
1. HMAC-SHA-256 con `audit_key` de 32 B **fuera de la DB** (archivo 0600 o KMS; config `audit_key_file`), sobre campos **con prefijo de longitud**: versión, ts, tenant_id, subject_id, event, prev_hash. Columna `chain_version`; `verify_chain` verifica v1 (legado) y v2.
2. Mover el append al `Store` (`append_audit_chained`) en **una transacción** que lea el último hash bajo bloqueo (Postgres: `pg_advisory_xact_lock`; SQLite: `BEGIN IMMEDIATE`) e inserte.
3. Postgres: la app solo con `INSERT, SELECT` en `audit_log` (`REVOKE UPDATE, DELETE, TRUNCATE`); documentar los roles en `deploy/` y la migración.
4. `bandall audit verify` recibe la clave.
**Pruebas:** alterar `tenant`/`subject`/`event`/`ts` rompe la verificación; 50 appends concurrentes dan una cadena lineal sin ramas; con clave errónea no se puede recalcular; las filas v1 siguen verificando.

### T5 — Vault v2 y KMS async
**Archivos:** `crates/vault/src/{vault,kms}.rs` y los llamadores en `api`
**Problemas:** DEK y plaintext intermedios en `Vec<u8>` sin zeroize; `version` y `kek_id` no están en el AAD (se pueden manipular en la fila); `KmsProvider` es síncrono y se llama en cada verificación (bloquearía el runtime con un KMS remoto).
**Cambio:**
1. `Zeroizing<Vec<u8>>` para DEK y buffers de plaintext.
2. `SEAL_VERSION = 2`: el AAD incluye `version` y `kek_id`. `open` acepta v1 y v2; `seal` escribe v2; `rewrap` migra v1 → v2.
3. `KmsProvider` asíncrono (mismo patrón `BoxFuture` que `Store`); actualizar llamadas y tests.
4. **No** implementes proveedores cloud ni cachés de DEK en esta tarea (requieren **[DECISIÓN]** de KMS); deja la nota en un ADR.
**Pruebas:** un ciphertext v1 existente abre; un v2 con `kek_id` alterado falla; `rewrap` v1 → v2; el AAD cambia si cambia `version`.

### T6 — Claves JWT
**Archivos:** `crates/tokens/src/{keys,access}.rs`, `crates/api/src/{config,server}.rs`, `crates/cli`
**Problemas:** `load_or_generate` crea una clave nueva si falta el archivo (con réplicas, cada una firmaría con la suya; un montaje vacío pasa en silencio); la clave privada está en archivo sin sellar por el KMS; la rotación no publica la clave nueva antes de usarla; se usa `verify` en vez de `verify_strict`.
**Cambio:**
1. `Config.environment = "development" | "production"`. En `production`, si falta `current.key` el arranque **falla**; las claves solo se crean con `bandall keys init` / `bandall keys rotate`.
2. `read_key`/`write_key`: exigir modo 0600 como `LocalKms::check_permissions` (verifica si ya lo hacen; si no, añádelo).
3. Rotación en dos fases: `next.key` se publica en el JWKS **antes** de firmar con ella; luego se promueve.
4. Usar `VerifyingKey::verify_strict`.
5. **[DECISIÓN]** sellar la clave en reposo con el KMS vs. firmar en un HSM: documenta opciones en ADR; no implementar hasta aprobación.
**Pruebas:** producción sin clave → error de arranque; permisos 0644 → rechazo; el JWKS incluye `next`; un token firmado con `previous` sigue válido durante el solape; una firma no canónica se rechaza.

### T7 — Recovery codes
**Archivos:** `crates/vault/src/recovery.rs`, `crates/api/src/verify.rs`, store
**Problema:** códigos de 80 bits con Argon2id (19 MiB, t=2) y hasta 10 verificaciones por intento en un endpoint público: DoS de CPU/memoria, y es innecesario para secretos aleatorios de alta entropía.
**Cambio:**
1. Esquema nuevo: `HMAC-SHA256(pepper, normalize(code))` con `pepper` de 32 B fuera de la DB (misma fuente que la clave de auditoría o el KMS). Búsqueda por hash directo en `use_recovery_code` (O(1), sin bucle).
2. `verify` sigue aceptando hashes PHC Argon2id antiguos (bucle acotado) hasta que se migren.
3. Normalizar la entrada (mayúsculas, quitar espacios y guiones); verifica si ya ocurre. Subir `CODE_BYTES` a 16 es opcional.
**Pruebas:** un código se consume una sola vez; 20 usos concurrentes del mismo código → 1 éxito; los hashes Argon2id antiguos siguen funcionando; un código inválido no ejecuta Argon2 en el esquema nuevo.

### T8 — S2S por cliente y nonces compartidos
**Archivos:** `crates/api/src/{state,enroll,sigs}.rs`, `crates/sigs`, store, nueva migración
**Problemas:** `require_service_key` usa **una clave global** (sin scopes, sin rotación, sin atribución en auditoría); `NonceCache` vive en memoria por proceso (las réplicas no la comparten, un reinicio la vacía) y no tiene tope.
**Cambio:**
1. **[DECISIÓN]** ADR: unificar el S2S sobre `api_clients` (migración 5) con `key_id`, scopes (`factors:enroll`, `mfa:verify`, …) y dos claves activas para rotar. `x-service-key` queda solo en `development`, marcado como deprecado.
2. Nonces en tabla `used_nonces(key_id, nonce, expires_at)` con PK; `INSERT … ON CONFLICT DO NOTHING` y comprobar `rows_affected`; purga por expiración. Mientras tanto, tope de tamaño en memoria.
3. La auditoría registra `client_id`.
**Pruebas:** cliente sin scope → denegación uniforme; el mismo nonce en dos instancias de store → rechazado; rotación con dos claves activas.

### T9 — Endurecimiento varios
1. **Postgres TLS:** en hosts no loopback exigir `sslmode=verify-full` (hoy acepta `require`, que no valida el certificado) y `sslrootcert`. Archivo: `crates/store/src/postgres.rs`.
2. **Concurrencia y pánicos:** añadir `ConcurrencyLimitLayer` + *load shed* (503) en `server.rs`. **[DECISIÓN]** `panic = "abort"` vs. `unwind` + `CatchPanicLayer` con métrica; recomendación: `unwind` + `CatchPanicLayer`, porque con `abort` cualquier pánico de una dependencia tumba todo el proceso.
3. **`/metrics`:** no debe ser público. Listener separado (`metrics_listen`, por defecto `127.0.0.1`) o token. Revisa que Helm/compose no lo expongan por el Service o Ingress.
4. **Perfil release:** valorar `lto = "thin"` y `codegen-units = 1` (medir antes).
**Pruebas:** URL remota con `sslmode=require` → rechazo; con `verify-full` → acepta; `/metrics` no responde en el listener público; el límite de concurrencia devuelve 503 bajo carga.

### T10 — Login con credencial primaria **[DECISIÓN obligatoria]**
**Problema:** `POST /v1/mfa/verify` es público y emite access + refresh con **solo un TOTP** (`amr:["otp"]`, `aal:1`). Quien conozca `(tenant, subject, factor)` puede atacar el TOTP y obtener sesión sin contraseña.
**Acción del agente:** escribir `docs/adr/0009-primary-credential.md` con estas opciones y **esperar respuesta**; no implementar nada antes.
- **A. Solo segundo factor (S2S):** `mfa/verify` deja de emitir sesión; el sistema primario llama a `POST /v1/verify` tras validar la contraseña y emite su propia sesión.
- **B. Sesión completa:** `POST /v1/auth/challenge` (S2S, scope `auth:challenge`, lo llama el IdP tras validar la credencial primaria y declara `primary_amr`) devuelve un `challenge_id` opaco, de un solo uso, TTL ≤ 120 s, atado a `(tenant, subject)`. `mfa/verify` exige `challenge_id`; los tokens salen con `amr=[primary_amr,"otp"]` y `aal=2`.
- **Recomendación:** B si BandAll va como servicio independiente; A si se integra en sistemas que ya emiten sesión.

---

## 4. Fuera del alcance del agente (tareas humanas)

- **Entorno de desarrollo:** `VERIFICATION.md` documenta fallos de `rustc`, `SIGILL` en Docker y un archivo del registry lleno de ceros. Pasa memtest y SMART, o compila en otra máquina o Codespaces. Hasta que `cargo test --workspace` corra completo, `store`, los E2E de `api` y `sdk-axum` siguen sin verificar.
- **GitHub:** confirmar que el bloqueo de facturación se resolvió y que el primer CI corre de verdad.
- **LICENSE:** elegirla (no la elige el agente).
- **Decisiones pendientes:** T6 (sellar vs. HSM), T8 (modelo S2S), T9 (panic), T10 (A o B) y el KMS de producción.

## 5. Definición de terminado de toda la remediación

- CI verde en `main` con los 9 jobs.
- Cada tarea con su prueba negativa en el repo.
- ADR-0009 resuelto e implementado.
- Un humano revisó los PRs que tocan cripto, tokens, vault y policy (`AGENTS.md` §8).
- Re-ejecutada la revisión ASVS (`docs/asvs-l3-review.md`) con enlaces a las pruebas, no a afirmaciones.
