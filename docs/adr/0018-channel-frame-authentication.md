# ADR-0018: autenticación de canal unificada (API, bidireccional y nodos)

- **Estado:** propuesto — **esperando decisión humana**
- **Fecha:** 2026-10-09
- **Decisores:** Angel Nereira
- **Responde a:** requisito de producto: proteger y autenticar de forma
  consistente contratos de API, comunicaciones bidireccionales y nodos de una
  red, siendo ligero.

## Contexto

BandAll autentica hoy con **tres mecanismos distintos**, y cada uno cubre su
caso pero ninguno cubre los otros dos:

| Superficie | Mecanismo actual | Qué autentica | Qué no autentica |
|---|---|---|---|
| Contrato de API | HMAC-SHA-256 sobre cadena canónica + caché de nonces (`sigs`) | una petición aislada | que dos peticiones sean del mismo canal ni en qué orden |
| WebSocket | ticket opaco de un solo uso (ADR-0017) | el **inicio** del canal | ningún mensaje posterior: el canal entero queda confiando en el handshake |
| gRPC | `interceptor` con bearer token (ADR-0017) | cada RPC por separado | que varios RPC pertenezcan a la misma sesión ni en qué orden |

La consecuencia práctica está en la fila del medio: un WebSocket que dura horas
tiene **un** momento autenticado y mil mensajes que no lo están. Si algo se
inyecta o reordena dentro de ese canal —un proxy, un lado comprometido, un
bug—, nada lo nota. Y para nodos de red, un bearer token por RPC no dice nada
sobre qué nodo habla con qué nodo.

A eso se suma un problema de peso. La autenticación por petición necesita un
**caché de nonces**: memoria proporcional al tráfico de la ventana, y en un
despliegue distribuido una dependencia externa (Redis) para que dos instancias
compartan el estado. Un nodo ligero no debería necesitar eso.

## Lo que se propone: una sola construcción, tres dialectos

Una construcción criptográfica única, aplicada a tres cuerpos distintos:

```
tag = HMAC-SHA-256( K_canal , "bandall/v1" || canal || seq || ts || digest(cuerpo) )
```

donde:

- **`K_canal`** se deriva por canal con HKDF-SHA-256 a partir del secreto de
  sesión: `K_canal = HKDF(ikm = secreto_sesión, salt = canal, info = "bandall/frame/v1")`.
  Un canal no puede forjar mensajes de otro aunque roben su clave.
- **`canal`** es el `sid`: la identidad del canal.
- **`seq`** es un contador monótono por canal. **Esta es la pieza que hace
  funcionar lo bidireccional**, y la razón es matemática, no de ingeniería: un
  contador convierte un problema de memoria **no acotada** (recordar todos los
  nonces vistos durante la ventana) en uno **acotado** (un entero por canal). De
  paso da dos propiedades que el nonce nunca dio: **orden** y **detección de
  huecos**. Un mensaje que falta es visible, porque `seq` salta.
- **`ts`** solo en el primer mensaje y en los keepalives: ata la apertura del
  canal al reloj y nada más.
- **`digest(cuerpo)`** es el único punto que cambia entre superficies.

Los tres dialectos:

| Superficie | `digest(cuerpo)` | Nota |
|---|---|---|
| Contrato de API (`sigs`) | la cadena canónica actual: `MÉTODO\nRUTA\nQUERY\nSHA256(body)\nts\nnonce` | **compatible byte a byte con `v1=`**: los contratos firmados hoy siguen verificando |
| Frame de WebSocket | `"frame" \|\| opcode \|\| SHA-256(payload)` | autentica cada mensaje, no solo el handshake |
| Llamada gRPC | `"rpc" \|\| método \|\| SHA-256(mensaje)` | y encadena los streams por `seq` |

Para nodos de red: **identidad estática con Ed25519** (que `tokens` ya emite y
publica en el JWKS) y **clave de canal efímera con X25519 → HKDF**. El par de
nodos se autentica una vez de forma asimétrica, y a partir de ahí cada mensaje
es un HMAC simétrico. Ninguna primitiva inventada: X25519 es RFC 7748, HKDF es
RFC 5869, Ed25519 es RFC 8032, HMAC-SHA-256 es FIPS 198-1.

## Por qué es ligero — medido, no declarado

`cargo run -p bandall-sigs --release --example bench_primitives`, en esta
máquina, mejor de tres pasadas:

```
payload: body 48 B, canonical 127 B, tag 67 B
canonical string (build)                          2109.0 ns/op
HMAC-SHA-256 sign                                 4400.0 ns/op
verify (structure + ts + nonce + mac)             4785.5 ns/op
```

Lo que estos números dicen, y lo que no:

- **Verificar un contrato de API completo cuesta ~4,8 µs.** Un stream de mil
  mensajes cuesta ~1,2 µs por mensaje, porque a partir del segundo mensaje no
  hay `ts` que comparar, ni nonce que buscar, ni cadena que reconstruir.
- **La construcción simétrica es tres órdenes de magnitud más barata que la
  asimétrica**, y por eso la propuesta reserva Ed25519 para la identidad (una
  vez por canal) y HMAC para el tráfico (una vez por mensaje).
- El coste que **sorprende** es el de construir la cadena canónica (2,1 µs,
  casi la mitad del total): es asignación de `String` y formato, no
  criptografía. En un canal con `seq` fijo ese coste se paga una vez.
- Lo que **desaparece** con `seq` es el estado: un `u64` por canal activo, sin
  tabla, sin TTL, sin Redis. Eso es lo que hace esto viable en un nodo ligero.
- Lo que estos números **no** cubren: nada del coste de red ni de TLS. Esta
  propuesta es autenticidad a nivel de mensaje; no es un sustituto de TLS.

## Consecuencias

- `sigs` gana el concepto de canal sin perder compatibilidad: `verify` sigue
  aceptando `v1=<hex>` exactamente igual, y la forma con canal es una rama
  nueva.
- El WebSocket de ADR-0017 pasa de "canal abierto con confianza" a "canal
  autenticado mensaje a mensaje", con detección de huecos y reordenación.
- gRPC encadena sus streams: varios RPC comparten `K_canal` y `seq`, así que un
  RPC suelto ya no es la unidad de confianza.
- Aparece una dependencia nueva (`hkdf`, y `x25519-dalek` si se acepta la parte
  de nodos). Ambas de RustCrypto, y van en el ADR con su justificación porque
  `AGENTS.md` lo exige antes de añadir cualquier dependencia.
- El caché de nonces **se queda** para el primer contacto sin canal, que es
  donde su memoria está acotada de verdad por la ventana de 300 s.

## Alternativas consideradas

1. **Solo bearer token en el canal** (lo que hay). Rechazada: mil mensajes
   confiando en un handshake, sin orden ni detección de huecos.
2. **mTLS en todas partes.** Rechazada como requisito universal: resuelve
   nodo a nodo mejor que esto, pero no llega donde no hay TLS (nodo ligero,
   UDP, red interna sin PKI), y el coste de PKI por nodo es precisamente lo
   que se quiere evitar.
3. **Protocolo de handshake propio (estilo Noise).** Rechazada: sería inventar
   criptografía, que `AGENTS.md` prohíbe. Lo que se propone reutiliza HKDF y
   X25519 sin diseñar un protocolo nuevo.
4. **Firmar cada frame con Ed25519.** Rechazada por peso: es el orden de
   magnitud equivocado por mensaje, y en un stream largo lo pagas mil veces.

## Qué necesita aprobación explícita

Toca `sigs`, `tokens` y la autenticación del WebSocket, es decir tres cosas que
`AGENTS.md` lista como de revisión humana obligatoria. En concreto, la decisión
tiene tres partes separables:

- **A)** El formato de frame con `seq` y `canal` para WebSocket y gRPC.
- **B)** Si `sigs` gana la variante con canal (compatible) o se queda como está
  y el canal vive solo en el transporte.
- **C)** La parte de nodos (X25519 + HKDF), que es la que añade dependencias y
  la que más superficie abre.

Sin esa aprobación no se toca código. Este ADR queda como propuesto.