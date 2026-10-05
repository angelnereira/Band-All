# Runbook: fuga de secretos

## Detectar

- Alerta: ráfaga de `mfa.denied` / `token.refresh_denied` en auditoría.
- `bandall audit verify` falla (cadena rota) → posible manipulación de DB.

## Contener (minutos)

1. Revoca las sesiones afectadas: `token/revoke` por familia o `revoke_session`
   por `sid`. Ante duda, revoca el tenant completo (itera sus sesiones).
2. Revoca los `key_id` comprometidos: `bandall apikey revoke --key-id ...`.
3. Si el KEK puede estar expuesto, prepara rotación (ver runbook
   `key-rotation.md`): no borres la KEK vieja hasta re-envolver todo.

## Erradicar

1. Rota la KEK y re-envuelve (`rewrap` sin downtime por factor).
2. Rota `service_key` y las claves de firma JWT (`keys/previous.key` da
   solape: despliega la nueva como `current`, conserva la vieja una ventana).
3. Obliga re-enrolamiento de los factores tocados (recuperación consume el
   factor: el usuario re-enrola con un secreto nuevo).

## Recuperar

1. `bandall audit verify` en verde; alertas rearmadas (dispara una a propósito).
2. Revisa el informe post-incidente: vector de entrada, ventana de exposición,
   datos afectados. Notifica según tu política de brechas.

## Lecciones

- Nunca hubo secretos en claro en DB ni logs por diseño (§6 blueprint);
  confirma con una búsqueda de patrones sobre el backup antes de restaurar.
