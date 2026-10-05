# ADR-0009: Resincronización de deriva fuera de ventana

- **Estado:** propuesto — **esperando decisión humana** (remediación T3, punto 3)
- **Fecha:** 2026-10-05
- **Decisores:** Angel Nereira
- **Nota de numeración:** T10 (credencial primaria) tenía reservado el
  `0009-primary-credential.md` en el brief; al llegar T3 antes, este ADR toma el
  0009 y el de T10 pasa a ser `0010-primary-credential.md`.

## Contexto

T3 reduce la ventana de verificación a **exactamente tres pasos**: la deriva
guardada más un paso de holgura a cada lado. La deriva se reaprende del
desfase realmente observado en cada acierto (limitado a ±5).

Consecuencia buscada: un atacante que_no conozca la deriva solo dispone de
tres pasos por intento en lugar de siete, y un reloj desviado deja de entrar
"de paso".

El coste es laavailability: si el reloj del usuario se desplaza más de un paso
respecto a la deriva guardada (por ejemplo, un viaje que corrige el reloj del
dispositivo, o una corrección manual de NTP), su código cae fuera de la
ventana y **queda bloqueado hasta reenrolar**. Con la ventana anterior, un
salto de hasta tres pasos se absorbía solo; ahora no.

`docs/AGENT_BRIEF.md` (T3, punto 3) marca esto como **[DECISIÓN]**: este ADR
documenta las opciones y **no implementa ninguna**.

## Opciones

### A. Solo reenrolado (estado actual de la rama)

Un usuario fuera de ventana debe reiniciar el enrolamiento.

- Pros: cero estado nuevo, cero superficie de ataque, coherente con
  fail-closed; el modelo de amenaza ya contempla la pérdida del dispositivo.
- Contras: molesto para el usuario legítimo y caro en soporte; un atacante
  que consiga Provocar la resincronización (por ejemplo, wiping del reloj del
  servidor frente al cliente) cause denegación de servicio al titular.

### B. Exigir dos códigos consecutivos para resincronizar

Un acierto fuera de la ventana **no** entra por la vía normal: actualiza una
deriva "provisional" y exige que el siguiente código (aún sin sesión emitida)
confirme la deriva antes de aceptarlo.

- Pros: recupera al usuario legítimo sin abrir la ventana para un solo código
  adivinado; el atacante necesita dos códigos válidos consecutivos, lo que
  multiplica por el periodo el trabajo por intento y encaja con el
  antirreplay atómico existente.
- Contras: **estado persistido nuevo** (deriva provisional + marca de
  confirmación), por lo que requiere migración; dos verificaciones por
  entrada en juego; hay que decidir el TTL de la deriva provisional para que
  no sirva de ventanaslides.

### C. Ventana amplia con presupuesto de intentos

Volver a ±3 pasos, pero descontando del presupuesto de `policy` por factor
(cada acierto fuera de la deriva guardada cuesta más intentos).

- Pros: sin estado nuevo ni migración; el usuario se recupera solo.
- Contras: **reabre la superficie que T3 acaba de cerrar** (tres veces más
  pasos por intento) y acopla la ventana a la configuración de rate limit;
  contradice el objetivo declarado de T3.

### D. Reenrolado remoto guiado por S2S

Un cliente S2S puede forzar la resync con `auth:resync` scope, dejando
auditoría del evento.

- Pros: recuperable sin que el usuario toque el móvil; auditable.
- Contras: amplía la API y el modelo de permisos antes de cerrar H5; solo
  aplica a despliegues que ya tienen S2S (el modo embebido no).

## Recomendación

**B**, con estas condiciones:

1. La deriva provisional vive en la fila del factor (migración nueva) y
   caduca (TTL ≤ 2 periodos); nunca se acepta un código provisionalmente: el
   primer acierto solo guarda estado y responde denegación uniforme.
2. El segundo código debe ser del **paso siguiente o posterior** al
   provisional y pasar por el mismo antirreplay atómico (`cas_last_step`).
3. Un evento de auditoría propio (`mfa.resync`) para que el operador vea los
   intentos de resync.
4. La provisional **nunca** se aplica al camino S2S sin scope: solo al login de
   usuario final.

Descartada C porque deshace el objetivo de T3. A es el plan de contingencia si
la opción B no entra antes de H5 (los usuarios reencolan). D queda para H6,
cuando el modelo de clientes S2S (T8) esté cerrado.

## Consecuencias

- Con B, H5 necesita una migración más y pruebas de estado parcial
  (provisional caducada, provisional + replay, dos códigos del mismo paso).
- Hasta que haya decisión, la rama de T3 deja el comportamiento en A.
- Nada de esto cambia el modelo de amenaza: la derrota de la deriva sigue
  requiriendo conocer el secreto del factor.
