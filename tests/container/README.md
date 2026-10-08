# Verificación del contenedor

Verifica el **artefacto**, no el árbol de fuentes: construye la imagen de
`deploy/Dockerfile`, la levanta y le pasa la batería completa por HTTP. Si esto
pasa, lo que se despliega responde bien; si el código pasa sus tests de unidad
pero esto falla, el defecto está en el empaquetado.

```sh
tests/container/verify.sh                  # SQLite en volumen desechable
tests/container/verify.sh --postgres       # la misma batería contra Postgres
tests/container/verify.sh --bench          # además, carga simulada
tests/container/verify.sh --skip-build     # reutiliza una imagen ya construida
tests/container/verify.sh --keep           # deja los contenedores vivos (debug)
```

En el CI, el job `docker` construye la imagen con `build-push-action` (con su
caché) y luego invoca este script con `--skip-build` y `--postgres`, así que el
artefacto que se publica es el mismo que se verifica.

Todo lo que crea el script —contenedores, red, volúmenes, tenant, usuarios
mock, claves— se destruye en la salida. Las claves (KEK y clave de cadena de
auditoría) se generan por ejecución con `openssl rand` y no se versionan.

## Qué comprueba

| Fase | Qué demuestra |
|---|---|
| runtime shape | usuario `nonroot`, HEALTHCHECK propio, sin shell en la imagen |
| configuración | fichero montado; arranque **fail-closed** con `service_key` inválida o sin `audit_key_file` |
| arranque | `migrate` y `serve`, `/readyz`, `bandall healthcheck` |
| hardening | rootfs read-only, `cap_drop=ALL`, `no-new-privileges`, `ulimit core=0`, límites de recursos |
| suite funcional | MFA completo, tokens, refresh con rotación, forward-auth, OpenAPI, JWKS, métricas |
| suite de seguridad | antirreplay (incluido el gate de 100 concurrentes → 1 éxito), ventana de tres pasos, anti-enumeración, `alg=none`, claims alterados, límite de body, rate limit |
| firmas HMAC | cadena canónica, nonce de un uso, tolerancia ±5 min, manipulación de body/path/method/query |
| logs | ni la service key ni un pánico en la salida del contenedor |
| cadena de auditoría | `audit verify` en verde, y **BROKEN** tras alterar una fila a propósito |
| carga simulada | p50/p95/p99 por fase, con clientes mock desechables (`--bench`) |

## Ficheros

- `verify.sh` — orquestador: empaqueta, levanta, ejecuta y limpia.
- `totp_client.py` — mock de autenticador (TOTP RFC 6238 sobre el
  `otpauth://` que devuelve `enroll/start`) y cliente HTTP. Solo stdlib: un
  arnés que necesita instalar dependencias es un arnés que nadie ejecuta.
- `verify_container.py` — 45 tests funcionales y de seguridad.
- `verify_sigs.py` — 16 tests de firmas HMAC.
- `bench_container.py` — carga simulada para SLOs **medidos** (H8).

Los clientes mock no importan código de BandAll: calculan los códigos que
calcularía una app autenticadora, así que el servidor tiene que coincidir con
una implementación independiente.

## Notas de entorno

- Docker Desktop no comparte `/tmp` con la VM, así que los ficheros temporales
  van bajo `$HOME`.
- Con `--postgres`, el Postgres desechable lleva certificado autofirmado y el
  servicio conecta con `sslmode=require`: `PgStore::require_tls_for_remote`
  rechaza el texto claro contra cualquier host que no sea loopback, y un
  nombre de contenedor no lo es. El certificado existe para ejercitar el camino
  TLS, no para ser confiado.
- En `--bench` el límite por IP se sube a un millón: todos los clientes mock
  comparten `127.0.0.1`, y el límite real ya lo comprueba su propio test en la
  suite.
