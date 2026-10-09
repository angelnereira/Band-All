# ADR-0017: Autenticación en conexiones largas (WebSocket y gRPC)

- **Estado:** aceptado (decisión humana el 2026-10-08: A + B, ticket de
  conexión, TTL atado a `exp` y re-validación con presupuesto)
- **Fecha:** 2026-10-07
- **Decisores:** Angel Nereira
- **Responde a:** requisito de producto (BandAll como capa de autenticación en WebSocket y gRPC)

## Contexto

BandAll hoy verifica por **petición**: un access token llega en `Authorization`,
se valida la firma y los claims, y `authz/check` (H6) además comprueba que la
sesión siga viva en base de datos. Ese modelo encaja con HTTP.

WebSocket y gRPC rompen ese encaje, y no por un detalle de formato: son
**conexiones de larga duración**.

- Un access token vive **10 minutos** (`ACCESS_TTL_SECS`, ADR-0005).
- Una conexión WebSocket puede durar **horas**; un stream gRPC, lo mismo.

Eso deja tres preguntas que no existen en HTTP y que **no se pueden improvisar**,
porque cada respuesta tiene consecuencias de seguridad distintas.

### Pregunta 1 — ¿Cómo llega el token al servidor?

En HTTP es una cabecera. En WebSocket, el navegador **no puede poner
cabeceras** en el `Upgrade`: la API `WebSocket` de JS no lo permite. Las salidas
conocidas y sus problemas:

| Vía | Problema |
|---|---|
| Query string (`?token=…`) | El token acaba en logs de proxies, en `Referer` y en el histórico. Un access token en una URL es un token filtrado |
| Cookie | Necesita la decisión de ADR-0011 (que está abierta) y arrastra CSRF |
| `Sec-WebSocket-Protocol` | Funciona, pero es abusar de un campo para negociar el subprotocolo; algunos proxies lo reescriben |
| Primer mensaje de la conexión | La conexión ya está establecida cuando se autentica: hay que cerrarla si el primero no trae credencial válida, y mientras tanto el server mantiene una conexión no autenticada |
| **Ticket de conexión** (recomendado) | El cliente pide por HTTP un ticket de un solo uso y vida corta, y lo presenta al abrir el WebSocket |

En gRPC no hay problema de transporte: los metadatos sí permiten
`authorization: Bearer …`. Es la misma forma que HTTP.

### Pregunta 2 — ¿Qué pasa cuando el token caduca o se revoca la sesión?

Es **la** pregunta de este ADR. Una conexión viva es una autorización viva: si
se autentica al abrir y nadie vuelve a mirar, entonces:

- Revocar la sesión **no corta la conexión**. El usuario (o el atacante al que
  acabas de expulsar) sigue recibiendo datos hasta que cierre por su cuenta.
- El token expira a los 10 minutos y da igual: nadie lo revisa.

Hay tres posturas:

| Postura | Qué garantiza | Qué cuesta |
|---|---|---|
| **A. TTL de conexión** | La conexión se cierra sola al agotarse el token (≤ 10 min); reconectar es volver a autenticar. Revocación efectiva en ≤ 10 min | Reconexión periódica; el cliente debe manejar el corte y reabrir |
| **B. Re-validación periódica** | Cada N segundos se consulta la sesión; si está revocada, se cierra. Revocación efectiva en ≤ N | Una consulta por conexión cada N segundos: con 10 000 conexiones y N=30, son ~333 consultas/s de fondo |
| **C. Aceptar y documentar** | Nada. La conexión vale mientras dure | Revocación sin efecto sobre conexiones abiertas |

**C no es aceptable** en un sistema cuyo modelo de amenazas declara la
revocación por `sid` como control (STRIDE, Elevation of privilege). Aprobar C
obligaría a corregir el modelo de amenazas y a decirle al usuario que "revocar"
no revoca del todo.

Entre A y B, mi recomendación es **A + B con presupuestos distintos**:

- **TTL de conexión** atado a `exp` del token: es la garantía dura, no depende
  de que un temporizador funcione.
- **Re-validación** en el servidor para las conexiones que el servidor considera
  sensibles, con un intervalo configurable y un **límite de consultas** para que
  no se convierta en un DoS contra la propia base de datos.

### Pregunta 3 — ¿Dónde vive esto?

Dos piezas nuevas, y conviene no mezclarlas:

1. **`bandall-api`: endpoint de ticket** (`POST /v1/ws/ticket`). El cliente
   autenticado por HTTP pide un ticket de un solo uso, ligado a su `sid`, con
   vida corta (≤ 30 s). El ticket es opaco y se guarda hasheado, como el refresh.
   Esto resuelve la pregunta 1 sin poner el access token en una URL.

2. **SDK de servidor para gRPC** (`bandall-sdk-grpc`): un interceptor `tonic`
   que hace lo mismo que `RequireToken` pero sobre metadatos gRPC, y traduce la
   denegación a `Status::unauthenticated`. No es un Layer de axum: `tonic` tiene
   su propio modelo de interceptor y forzar axum aquí sería mentir sobre la
   integración.

Para WebSocket, el servidor de la aplicación protegida usa `bandall-sdk-axum`
(el handshake **sí** es HTTP y sí puede llevar `Authorization`), y el ticket
cubre el caso del navegador.

## Decisión (2026-10-08)

Aprobada la propuesta A + B íntegra:

1. **Ticket de conexión** para WebSocket, implementado como
   `POST /v1/ws/ticket` (el cliente cambia su access token por un ticket
   opaco de un solo uso, 30 s) y `POST /v1/ws/ticket/redeem` (S2S: el
   servicio lo canjea al abrir la conexión y recibe identidad + el techo
   duro de vida de la conexión, tomado de `exp` del token). El navegador
   nunca pone el token en una URL.
2. **TTL de conexión atado a `exp`** (el servicio protegido debe cerrar la
   conexión en `expires_at`, que `redeem` devuelve) más **re-validación
   opcional** con `POST /v1/ws/ticket/recheck` (S2S, uniforme 401 ante
   sesión revocada o desconocida). El presupuesto de consultas del
   re-check es del llamante; el endpoint entra en `policy` (tenant key) y
   en auditoría (eventos `ws.ticket_*`).
3. **Interceptor `tonic`** implementado en `bandall-sdk-grpc` (crate
   nuevo): valida `authorization: Bearer` en metadatos, verifica contra
   JWKS (estático o en caché) y responde `UNAUTHENTICATED` uniforme;
   falla **cerrado** cuando el documento no es alcanzable. Estampa los
   claims y el techo `exp` en las extensiones de cada petición.
4. Todo entra en la batería de tests: unidad (tokens, store, sdk-grpc),
   E2E (`ws_ticket_e2e`) y contenedor (`TestWsTickets`, 5 tests).

## Consecuencias

- Superficie nueva en `bandall-api` (ticket, redeem, recheck), una tabla
  nueva en ambos motores (`ws_tickets`, migración 8, claim atómico por
  `UPDATE … WHERE used_at IS NULL`) y un crate nuevo (`bandall-sdk-grpc`)
  con `tonic` como dependencia justificada: es el transporte gRPC estándar
  y la única vía sancionada para leer metadatos por RPC.
- El modelo de amenazas gana la fila "conexión larga sobrevive a la
  revocación" con su control (`recheck` niega tras revocar) y su prueba.
- `cargo deny`/`cargo audit` aceptan el árbol con `tonic` (verificado).

## Alternativas consideradas

| Alternativa | Motivo de descarte |
|---|---|
| Autenticar solo al abrir y no volver a mirar | Deja la revocación sin efecto sobre conexiones abiertas (postura C) |
| Re-validar en cada mensaje/frame | Coste desproporcionado: convertiría cada mensaje en una consulta |
| Token en query string | Un access token en una URL acaba en logs y en el histórico |
| Ignorar WebSocket/gRPC y responder "usa HTTP" | No es una respuesta: el requisito de producto es explícito |