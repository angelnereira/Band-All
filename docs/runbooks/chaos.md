# Runbook: caos — servicio caído, alertas sin probar

Relación con el resto de runbooks: este cubre el fallo que **no** es un problema
de datos. `restore.md` cubre la pérdida de base de datos (con su ensayo
automatizado, `tests/dr/rehearse_restore.sh`); aquí se cubre "el servicio no
responde" y, sobre todo, "¿nos enteraríamos?".

## Por qué un runbook de esto

Porque un servicio que falla **cerrado** y nadie se da cuenta sigue siendo una
caída, y una alerta que nunca ha disparado no es una alerta: es un comentario
en YAML.

Durante H8 ocurrieron dos cosas que dieron la razón a este runbook:

1. `/readyz` respondía **200 con el esquema destruido**, porque `health()` era
   `SELECT 1`. Lo encontró el ensayo de DR al borrar el esquema bajo un
   servicio en marcha. La alerta de readiness habría mirado para otro lado, pero
   la alerta correcta habría saltado un día antes.
2. `deploy/compose/prometheus.yml` declaraba `rule_files: []` y
   `alertmanagers: []`. Las métricas se exportaban; nadie miraba.
3. La primera versión de `BandAllNoTraffic` era `rate(verified[5m]) == 0`, que
   en un servicio **sin ningún login se cumple igual que en uno al que dejó de
   llegarle el tráfico**. Lo detectó la línea base de este ensayo, no la
   inspección: la regla apareció `pending` antes de romper nada. Por eso la
   línea base se comprueba y no se supone.

La versión que quedó no pregunta "¿lleva rato sin nada?", sino
`increase(...[1h]) == 0 and increase(...[1h] offset 1h) > 0`: *hace una hora
que entraban y desde entonces ninguno*. Es la diferencia entre un servicio
recién desplegado y uno al que le han cortado el tráfico, y sin ella la alerta
es ruido.

## El ensayo

`tests/ops/chaos_drill.sh` levanta la pila de observabilidad completa
(Prometheus + blackbox-exporter + Alertmanager + BandAll real sobre un volumen
real) y comprueba, en orden:

1. **Línea base.** Las reglas están cargadas y **todas en `inactive`**. Esta es
   la comprobación que nunca se hace y la que importa: una regla que dispara
   sin incidencia es ruido, y los operadores aprenden a ignorar el ruido.
2. **El servicio responde antes de romperlo**, para que el ensayo no pueda
   "pasar" porque nunca funcionó.
3. **Caos.** `docker compose stop bandall`.
4. **`BandAllNotReady` pasa a `firing`** dentro de su ventana de 30 s. Se
   espera `firing`, no `pending`: `pending` significa que la condición se vio
   una vez y el `for:` aún no ha vencido, que es el estado que *parece*
   cobertura sin serlo.
5. **La alerta llega a Alertmanager.** Una alerta que dispara en una sala vacía
   no se ha entregado.
6. **La alerta se resuelve.** Un ensayo que deja la alerta disparada ha probado
   que sabe *levantar*, no que sabe *limpiar*. Una alerta que no se limpia es la
   otra que los operadores ignoran.
7. **Fail-closed al arrancar.** Una instancia cuyo fichero de clave no existe
   debe **negarse a arrancar** (exit 2, "configuration error"), no servir a todo
   el que pregunte.

```bash
tests/ops/chaos_drill.sh                       # ventana de 60 s por defecto
BANDALL_CHAOS_FIRE_TIMEOUT=120 tests/ops/chaos_drill.sh
```

## Qué no cubre, y dónde está

- **Destruir el esquema de la base de datos.** El runtime es distroless: sin
  shell ni `sqlite3`, así que no se puede ejecutar SQL dentro del contenedor.
  Eso lo hace `tests/dr/rehearse_restore.sh`, que destruye y reconstruye la base
  de datos de verdad. Este ensayo se queda con la ruta de alertas.
- **`BandAllHighDenialRate`** tiene un `for:` de 10 minutos porque la tasa de
  negación sobre cinco minutos necesita volumen real para significar algo; un
  `for:` corto haría que dispare con dos logins. El ensayo comprueba que la
  regla está **cargada y en silencio**, no que dispara.
- **`BandAllNoTraffic`** no se comprueba disparada: su `for:` son 5 minutos
  sobre ventanas de una hora, así que el ensayo solo puede verificar que está
  cargada y en silencio. Lo hizo, y de ahí salió la corrección del punto 3 de
  arriba, que es exactamente el tipo de defecto que una alerta no dispara
  nunca.

## Alertas que existen y qué hacer cuando disparan

| Alerta | Severidad | Significado | Qué mirar |
|---|---|---|---|
| `BandAllNotReady` | **critical** | El proceso responde pero no puede atender | Base de datos, esquema, fichero de KEK. Los proxies deben dejar de enviarle tráfico ya |
| `BandAllNoTraffic` | warning | Hace una hora entraban segundos factores y en la última hora ninguno | Los proxies delante de él; si el tráfico está, es que el servicio dejó de aceptar. No salta en un despliegue nuevo: para eso compara con la hora anterior |
| `BandAllHighDenialRate` | warning | Negaciones > 20 % de aceptadas durante 10 min | Puede ser un atacante probando códigos o usuarios que no pueden entrar y reintentan. La cadena de auditoría lo distingue por `subject_id` |
| `AlertManagerDeliveryFailing` | warning | Una alerta disparó y no se pudo entregar | Las reglas de arriba solo valen si alguien las oye |

Nota honesta sobre Alertmanager: su receptor `bandall-dev` está **vacío a
propósito**. Acepta la alerta y no hace nada con ella, que es lo correcto para
un stack cuyo objetivo es probar que las reglas disparan. Enchufar un destino
real (PagerDuty, Opsgenie, un relay de correo) es una decisión de despliegue, y
fingirla haría que esto *pareciera* alertar sin hacerlo.

## Después del ensayo

Registrar el resultado en el CHANGELOG de operaciones con la fecha. Si alguna
regla no cargó o no disparó, el ensayo debe **fallar**, no avisar: una alerta que
no dispara cuando debe es exactamente el defecto que este runbook existe para
encontrar, y dejarlo en amarillo lo perdería.