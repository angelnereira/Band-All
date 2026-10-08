# ADR-0013: `sdk-axum` — verificación por JWKS remoto con caché y scopes opcionales

- **Estado:** aceptado (H6)
- **Fecha:** 2026-10-07
- **Decisores:** Angel Nereira

## Contexto

El ítem 2 de H6 pide "un `Layer` que valida JWT con JWKS en caché, exige
`scopes` y `aal` mínimo". La implementación inicial validaba contra un
`Arc<KeyManager>` compartido en memoria: sirve cuando BandAll y el servicio
protegido viven en el mismo proceso (modo embebido), pero **no escala ni porta**
a un BandAll remoto — dos réplicas no comparten memoria, y un servicio en
otra máquina no puede "injectar" el `KeyManager`.

Dos huecos concretos:

1. **Sin JWKS en caché**: el único verificador disponible (`bandall_tokens::verify`)
   toma un `KeyManager` local. Un servicio externo no tiene forma de validar
   contra el documento público (`/.well-known/jwks.json`) salvo implementando
   la verificación a mano; y "cachear el JWKS 5–10 min" (lo que recomienda
   `docs/guides-forward-auth.md`) no existía como pieza reutilizable.
2. **Sin scopes**: el access token (ADR-0005) lleva `amr`/`aal` pero no tokens
   de ámbito. Un integrador que quiera exigir "este endpoint solo con scope
   `mfa:verify`" no tiene manera declarada de hacerlo.

## Decisión

### 1. `bandall_tokens`: verificación contra un documento JWKS

- `Jwk`/`Jwks` ganan `Deserialize` (el servidor sigue serializándolos; el SDK
  los lee del endpoint).
- Nueva función pública `verify_with_jwks(jwks, token, iss, aud, now)`: misma
  semántica estricta que `verify` (algoritmo fijo, `kid` conocido, firma,
  `iss`/`aud`/`exp`, leeway mínimo) pero contra el documento, no contra el
  `KeyManager`. `verify` queda como envoltorio sobre la interna compartida.

### 2. `sdk-axum`: `JwksVerifier` con caché y fallo-cerrado

- `JwksVerifier`: construido con la URL del endpoint (`/.well-known/jwks.json`),
  un `ttl` (por defecto 300 s) y un cliente HTTP (reqwest, rustls). Primer
  acceso: fetch síncrono al esperar la resolución (evita una carrera de
  arranque); después, sirve desde caché y refresca oportunista tras el TTL.
- **Fallo-cerrado**: si no hay caché y el fetch falla, la petición se
  **deniega** (401). Nunca "abrir" ante un error de red: idéntico al principio
  del servidor.
- `RequireToken::with_jwks(verifier, issuer, audience, min_aal)` — la vía
  remota; `RequireToken::new` (KeyManager local) se conserva para el modo
  embebido y los tests. Un Layer nuevo, `RequireScopes`, exige que
  `required ⊆ claims.scp` con comparación exacta (no prefijos).

### 3. Claims: campo `scp` opcional y compatible

- `Claims` gana `scp: Vec<String>` con `#[serde(default)]`: los tokens
  emitidos **antes** de este cambio verifican igual (campo ausente → `[]`),
  y los tokens nuevos lo llevan vacío mientras el emisor no emita ámbitos.
- Es un *formato persistido* (claims): la compatibilidad está garantizada por
  el default y se documenta aquí; la **emisión** real de scopes queda para T8
  (S2S por cliente) / T10 (credencial primaria), que son quienes definen qué
  ámbitos y con qué semántica.

## Alternativas consideradas

| Alternativa | Motivo de descarte |
|---|---|
| Seguir solo con `KeyManager` compartido | No porta a BandAll remoto; imposible en dos procesos/réplicas |
| Validar la firma a mano en cada integrador | Duplica lógica sensible (algoritmo fijo, leeway) en cada servicio |
| Caché con refresco por `tokio::time::interval` de fondo | Más piezas móviles que el refresco oportunista al primer uso tras TTL |
| Claim `scope` (string con espacios, estilo OAuth2) | Ambiguo frente a scopes de clientes S2S (T8); `scp` como array es inequívoco |

## Consecuencias

- H6 ítem 2 queda completo: JWKS en caché, `aal` y scopes exigibles.
- Dependencia nueva en `sdk-axum`: `reqwest` con rustls. Se justifica aquí
  mismo: es el cliente HTTP async estándar en el ecosistema axum, y el
  workspace ya usa rustls vía sqlx; no hay OpenSSL en el árbol.
- `bandall-embedded` (ADR-0014) sigue usando `KeyManager` local; el Layer
  remoto no le afecta.
- Los vectores de conformidad de los SDKs ganan `schema_version` (ADR-0015)
  para que la evolución futura del JWKS y de los claims sea detectable.