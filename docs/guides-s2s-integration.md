# Guía de integración S2S: qué esperar de BandAll siendo cliente

Esta guía es para quien integra BandAll desde otro servicio: qué hace la API,
qué **no** hace, y las propiedades del protocolo que un cliente tiene que
conocer antes de escribir código. No habla de ningún integrador concreto: todo
lo de aquí es comportamiento del contrato.

Leela junto a [`guides-forward-auth.md`](guides-forward-auth.md) (proteger una
app sin tocarla) y [`guides-web-and-mobile-sessions.md`](guides-web-and-mobile-sessions.md)
(sesiones web y móvil).

## 0. Qué es BandAll para ti, y qué no

BandAll verifica un **segundo factor**. Por defecto no ve tu credencial
primaria: `POST /v1/mfa/verify` da por hecho que quien llama ya validó la
contraseña (o el mecanismo que sea) y solo quiere comprobar el TOTP
(ADR-0005). Si necesitas que BandAll encadene ambos pasos, mira el flujo de
`challenge` en [`docs/AGENT_BRIEF.md`](AGENT_BRIEF.md) §T5+.

Consecuencia práctica: **quien conoce `(tenant, subject, factor)` y un código
vigente obtiene una sesión**. El `factor_id` no es un secreto, pero trata el
triplete como identificador sensible y pon la llamada dentro de tu red de
confianza.

## 1. El flujo y sus dos trampas

```text
 enroll/start (S2S)  -> pending + otpauth://          el secreto se muestra UNA vez
 enroll/confirm      -> activo + códigos de recuperación
 mfa/verify | verify -> 200 {tokens} | 200 {valid, step}
```

**Trampa 1: `enroll/confirm` consume el paso que acepta.** Confirmar con el
código que está en pantalla y verificar acto seguido con *el mismo* código es
un replay y se deniega: un OTP vale una vez, y el confirm es un uso. Un cliente
correcto confirma con el código actual y **espera al siguiente** para la
primera verificación (en los tests del repo, confirmar con el paso anterior
deja el actual libre).

**Trampa 2: verificar consume.** Lo mismo aplica a `verify`: un código aceptado
queda gastado para siempre. No es un fallo, es el antirreplay atómico
(`UPDATE … WHERE last_step < $step`,ADRs 0008/0009 y el threat-model).

## 2. La denegación es uniforme (y así se queda)

Factor inexistente, factor inactivo, código caducado, código incorrecto y
código ya usado devuelven **lo mismo**: `401` con
`https://bandall.dev/problems/unauthorized` y el mismo cuerpo. Es deliberado:
cualquier distinción por petición es un oráculo de enumeración y de tiempo.

Lo que **sí** puedes hacer como cliente para no frustrar al usuario:

- **Muestra el tiempo restante del código antes de pedirlo.** Es la mitigación
  real al "no sé si me equivoqué o fui lento": si el usuario ve una cuenta
  atrás, introduce el código a tiempo y el problema desaparece.
- **No reconstruyas el motivo en el cliente.** No hay nada que rascar: cuerpo,
  status y tipo de problema son idénticos en todos los casos.
- **Un 401 es un 401.** No reintentes la verificación con el mismo código
  esperando otro resultado (ver §4).

Y lo que puede hacer el **operador** de BandAll (no el cliente): los contadores
`bandall_verify_denied_total{reason=…}` de `/metrics` separan en agregado
`code_mismatch` (typo), `out_of_window` (código correcto fuera de ventana:
  reloj desfasado o usuario lento), `replay`, `unknown_factor`,
`inactive_factor` y `corrupt_factor`. **Agregado a propósito**: no hay etiquetas
por tenant ni por factor, o `/metrics` sería un oráculo de enumeración.

## 3. Reloj: ventana de tres pasos y deriva aprendida

La verificación acepta exactamente tres pasos alrededor de la deriva guardada
para ese factor (±1 paso de holgura; remediación T3, ADR-0009 abierto). Un
acierto dentro de la ventana **aprende** el desfase observado, acotado a ±5
pasos. Es decir:

- Un cliente con el reloj sistemáticamente 30 s adelantado **entra** (y su
  desfase queda registrado).
- Uno con 90 s de desfase **no entra**: la ventana no se mueve para
  acomodarlo.
- Los rechazos por desfase real frente a errores de tecleo ya no son
  invisibles: mira `reason="out_of_window"` frente a
  `reason="code_mismatch"` en `/metrics`. Esos números son los que alimentan
  la decisión de ADR-0009 (cómo resincronizar un reloj que se pasa de la
  ventana).

## 4. Reintentos: la verificación es una operación de consumo

Diseña el cliente sin reintentos ciegos:

| Situación | Qué hace BandAll | Qué debe hacer el cliente |
|---|---|---|
| 5xx o timeout de red | no hubo verificación | reintentar está bien |
| 200 perdido (respuesta que no llega) | el código **sí** se consumió | tratar como éxito: cachear el resultado por `(factor, step)` |
| 401 | denegación uniforme | no reintentar el mismo código |

`/v1/verify` devuelve además el `step` consumido, que es la clave natural para
ese dedupe si lo necesitas.

## 5. Timeouts y plazos

BandAll publica en `/metrics` la latencia de sus dos rutas de verificación:

```
bandall_mfa_verify_latency_ms_bucket{le="…"}   # histograma acumulado, ms
bandall_mfa_verify_latency_ms_sum / _count     # media = suma / cuenta
bandall_s2s_verify_latency_ms_bucket{le="…"}
```

Dimensiona tu timeout contra el plazo de tu propio protocolo (un handshake con
deadline, una sala que se abre…), no al revés. Como referencia medida en este
repo (1 CPU, contenedor): p99 ≈ 200 ms en `/v1/verify` secuencial, ≈ 75 ms con
10 clientes concurrentes. Son la línea base de H8, no un objetivo: **mide las
tuyas**.

## 6. Modelado: sujeto y factor

- Un **sujeto** es una identidad (una persona normalmente); un sujeto tiene
  factores. BandAll es multi-tenant desde el primer día: `tenant_id` viaja en
  todas las llamadas.
- Si varias personas comparten un secreto a propósito (un dispositivo de
  equipo, una sala), estás usando **un factor compartido**, y hereda tres
  propiedades que conviene conocer:
  1. **Un código vale un paso, para todos.** Si dos personas lo presentan a la
     vez, exactamente una gana y la otra recibe el 401 uniforme; la siguiente
     ventana de 30 s da un código nuevo.
  2. **El rate-limit del factor es compartido.** Los fallos de todos cuentan
     en el mismo cubo (`scope=factor`), por diseño.
  3. **Los códigos son intercambiables** entre quienes conocen el secreto: el
     TOTP está autenticando *el momento de entrada*, no a cada persona.

  Alternativas (N usos por paso, verificación sin consumo, o resolverlo con
  autenticación de canal) se sopesan en
  [ADR-0019](adr/0019-shared-factor-semantics.md).

## 7. Red y TLS

Las llamadas son HTTP plano. Entre servicios de la misma red es aceptable;
si BandAll vive en otra red, termina TLS en un proxy/sidecar delante (o
reconsidera el cliente). Para identidad de servicio, la clave S2S
(`x-service-key`) se compara en tiempo constante, pero **no** cifra el canal:
TLS sigue siendo tu problema de despliegue.

## 8. Ejemplo completo

```bash
export BANDALL=http://bandall:8080
export KEY=tu-service-key          # S2S
export TENANT=mi-tenant
export SUBJECT=alice

# Código TOTP con los parámetros por defecto (SHA-256, 6 dígitos, paso 30 s).
# $1 = secreto base32, $2 = pasos de desplazamiento (0 = ahora).
code_at() {
  python3 - "$1" "$2" <<'PY'
import base64, hashlib, hmac, struct, sys, time
secret, offset = sys.argv[1], int(sys.argv[2])
key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
counter = int(time.time() // 30) + offset
digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha256).digest()
value = struct.unpack(">I", digest[digest[-1] & 0x0F:][:4])[0] & 0x7FFFFFFF
print(f"{value % 1000000:06d}")
PY
}

# 1) Enrolar (S2S): el otpauth:// se muestra UNA vez
START=$(curl -sX POST $BANDALL/v1/factors/enroll/start \
  -H "x-service-key: $KEY" -H 'content-type: application/json' \
  -d "{\"tenant_id\":\"$TENANT\",\"subject_external_id\":\"$SUBJECT\",
       \"issuer\":\"MiApp\",\"account\":\"$SUBJECT\"}")
FACTOR=$(echo "$START" | jq -r .factor_id)
SID=$(echo "$START" | jq -r .subject_id)
SECRET=$(echo "$START" | jq -r .otpauth_uri | grep -o 'secret=[^&]*' | cut -d= -f2)

# 2) Confirmar con el paso ANTERIOR: consume el que acepta, y así el actual
#    queda libre para la primera verificación (la trampa 1, evitada)
curl -sX POST $BANDALL/v1/factors/enroll/confirm \
  -H 'content-type: application/json' \
  -d "{\"tenant_id\":\"$TENANT\",\"subject_id\":\"$SID\",\"factor_id\":\"$FACTOR\",
       \"code\":\"$(code_at "$SECRET" -1)\"}"

# 3) Verificar con el paso actual: usuario (mfa/verify -> tokens) o S2S
CODE=$(code_at "$SECRET" 0)
curl -sX POST $BANDALL/v1/mfa/verify -H 'content-type: application/json' \
  -d "{\"tenant_id\":\"$TENANT\",\"subject_id\":\"$SID\",\"factor_id\":\"$FACTOR\",\"code\":\"$CODE\"}"
curl -sX POST $BANDALL/v1/verify -H "x-service-key: $KEY" -H 'content-type: application/json' \
  -d "{\"tenant_id\":\"$TENANT\",\"subject_id\":\"$SID\",\"factor_id\":\"$FACTOR\",\"code\":\"$CODE\"}"
# -> el primero da tokens; el segundo {"valid":true,"step":…} con un código nuevo

# 4) Mirar lo que ve el operador (nunca el cliente)
curl -s $BANDALL/metrics | grep bandall_verify_denied_total
curl -s $BANDALL/metrics | grep bandall_s2s_verify_latency_ms_count
```

## 9. Checklist antes de abrir la PR de integración

- [ ] Confirmas con un código y verificas con **otro** (la siguiente ventana).
- [ ] No reconstruyes el motivo del 401 en el cliente; muestras cuenta atrás
      antes de pedir el código.
- [ ] Sin reintentos ciegos de verificación (dedupe por `(factor, step)` si
      pierdes respuestas).
- [ ] Timeout dimensionado contra el plazo de tu protocolo, con la latencia
      de `/metrics` como referencia.
- [ ] El rate-limit por factor compartido está contemplado si el secreto es
      compartido (ADR-0019).
- [ ] TLS en el despliegue si la llamada cruza redes.
