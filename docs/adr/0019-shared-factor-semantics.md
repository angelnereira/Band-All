# ADR-0019: semántica del factor compartido

- **Estado:** propuesto — **esperando decisión humana**
- **Fecha:** 2026-10-09
- **Decisores:** Angel Nereira
- **Responde a:** uso real observado al integrar BandAll en un sistema de
  comunicaciones: un secreto TOTP conocido por varios participantes a la vez.
  Toca `policy` y `verify`, así que exige revisión humana explícita
  (`AGENTS.md` §Proceso). Documento solamente: **no se toca código**.

## Contexto

BandAll asume que un factor TOTP pertenece a un sujeto y que quien presenta un
código es **una** persona con **un** autenticador. El antirreplay atómico
(`cas_last_step`) hace que un código valga exactamente un paso: si dos
peticiones concurrentes presentan el mismo código, exacto un ganador recibe
200 y las demás el 401 uniforme. Es la propiedad que persigue el gate de H3
("100 verificaciones concurrentes del mismo código → exactamente 1 éxito") y
está probada en `e2e` y en la batería de contenedor.

La integración real rompió ese supuesto de forma limpia y genérica: el mismo
secreto lo comparten **varias personas** (una sala, un equipo, un dispositivo
compartido). Con el diseño actual eso tiene tres consecuencias:

| Consecuencia | Efecto observado |
|---|---|
| Un código vale un paso, para todos | Entrando a la vez, solo el primero pasa; los demás deben esperar los siguientes 30 s |
| El rate-limit va por factor | Los fallos de todos comparten cubo (`scope=factor`): unos pocos usuarios torpes pueden acelerar el throttle de todos |
| El código es intercambiable | Quien conoce el secreto puede usarlo en su ventana: el TOTP autentica *el momento de entrada*, no a la persona |

Ninguna de las tres es un defecto del antirreplay — son consecuencias de
compartir el secreto. La pregunta es si BandAll debe **nombrar y soportar** ese
patrón, o solo documentarlo.

## Opciones

### A. Status quo + documentación (recomendada)

No cambiar el comportamiento. BandAll documenta las tres propiedades como
parte del contrato (hecho en `docs/guides-s2s-integration.md` §6) y recomienda,
para el problema de fondo (muchas entradas con un código de 30 s), el patrón de
canal largo: verificar una vez y llevar la sesión con tickets de conexión
(ADR-0017) o autenticación de frame (ADR-0018, propuesto).

- **Pros:** cero superficie nueva; la semántica "un OTP vale una vez" se
  mantiene íntegra; el coste es un párrafo de documentación.
- **Contras:** el integrador con factor compartido se come la fricción
  (un ganador por paso) y tiene que saberlo.

### B. Modo `shared` por factor: N usos por paso

Un flag persistido por factor que permite admitir el mismo paso hasta N veces
(o hasta que el paso cambie).

- **Pros:** elimina la fricción del caso real sin tocar los factores normales.
- **Contras:** cambio de esquema (columna en `factors`), cambio de semántica
  por factor — dos comportamientos que recordar; debilita el antirreplay **en
  ese factor** a "protege contra pasos anteriores", que para un secreto ya
  compartido es margen, no núcleo; requiere ADR de policy propio, migración,
  prueba de concurrencia por modo y amenaza-modelo actualizado.

### C. Verificación sin consumo (modo "contraseña de ventana")

El código deja de consumirse: durante su step, cualquier portador verifica.

- **Pros:** mínima fricción posible.
- **Contras:** es el máximo debilitamiento: convierte el TOTP en una
  contraseña de 30 s reutilizable dentro de la ventana, y borra la propiedad
  que el gate de H3 fija. **No recomendada** salvo que el factor compartido sea
  peor que una contraseña.

### D. Resolverlo por el canal (ADR-0018)

El código de entrada se consume una vez y la sesión larga se sostiene con
claves de canal autenticadas por frame, no re-verificando el OTP.

- **Pros:** ataca la causa (sesiones largas contra códigos cortos) en lugar del
  síntoma; ya está propuesto y medido (ADR-0018 §"Por qué es ligero").
- **Contras:** sigue pendiente de decisión humana; no ayuda al integrador que
  no puede cambiar su transporte.

## Decisión que se propone

**A + D.** Documentar el patrón (A) como contrato, y tratar el problema de
fondo con la autenticación de canal (D) cuando ADR-0018 se apruebe. **B** queda
como opción si aparece demanda repetida de factores genuinamente compartidos,
y entonces con su propio ADR de policy, migración y pruebas de concurrencia.
**C** se descarta.

Lo que se ha hecho ya, sin decidir nada: la guía de integración
(`docs/guides-s2s-integration.md` §6) documenta las tres propiedades, y la
batería de contenedor fija con un comentario que "exactamente un ganador" es
comportamiento diseñado, no un defecto.

## Consecuencias

- Si se acepta A+D: este ADR se cierra al aprobarse ADR-0018, y la guía es el
  entregable permanente.
- Si se acepta B: nueva migración, `policy` gana un modificador por factor,
  `threat-model.md` gana una fila ("factor compartido: el antirreplay protege
  solo contra pasos anteriores") y H5 exige prueba de concurrencia por modo.
- `threat-model.md` debe actualizarse **antes** del hito que implemente
  cualquiera de B/C (regla del repo §2.6).

## Qué necesita aprobación explícita

Tres partes separables, como en ADR-0018:

- **A)** Aceptar A+D y cerrar el tema como documentación.
- **B)** Abrir el trabajo de modo `shared` (esquema + policy + pruebas).
- **C)** Cualquier variante sin consumo (C), que no se recomienda.

Sin esa aprobación no se toca código. Este ADR queda como propuesto.
