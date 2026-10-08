# Proteger sistemas existentes con BandAll (H6)

Tres integraciones, de menor a mayor intrusión. En todas, los servicios
validan el JWT **offline** contra el JWKS (`/.well-known/jwks.json`).

## 1. Forward-auth (cero cambios en tu app)

`GET /v1/authz/check` responde 200 con `X-Bandall-Subject/Tenant/Sid` o 401.
El proxy reenvía el `Authorization: Bearer` original.

### nginx (`auth_request`)

```nginx
location = /auth {
    internal;
    proxy_pass http://bandall:8080/v1/authz/check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Authorization $http_authorization;
}

location / {
    auth_request /auth;
    auth_request_set $bandall_subject $upstream_http_x_bandall_subject;
    proxy_set_header X-Bandall-Subject $bandall_subject;
    proxy_pass http://tu-app:80;
}
```

### Envoy (`ext_authz`)

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      http_service:
        server_uri:
          uri: bandall:8080
          cluster: bandall
          timeout: 0.5s
        path_prefix: /v1/authz/check
      include_additional_headers_in_check:
        authorization: {}
```

### Traefik (ForwardAuth)

```yaml
http:
  middlewares:
    bandall-auth:
      forwardAuth:
        address: http://bandall:8080/v1/authz/check
        authRequestHeaders:
          - Authorization
```

### Demo local

```bash
# Clave de desarrollo (32 bytes, solo demo; nunca en producción)
head -c 32 /dev/urandom > deploy/compose/demo-kek.bin
chmod 600 deploy/compose/demo-kek.bin
docker compose -f deploy/compose/compose.demo.yaml up --build

# Sin token -> 401; con token (tras enroll+verify) -> 200 y la app legacy
curl -i http://127.0.0.1:8080/
curl -i -H "Authorization: Bearer $ACCESS" http://127.0.0.1:8080/
```

## 2. `sdk-axum` (una línea en tu servicio Rust)

```rust
use bandall_sdk_axum::RequireToken;

let protected = Router::new()
    .route("/private", get(handler))
    .layer(RequireToken::new(keys, issuer.into(), audience.into(), 1));
// El handler lee `Extension<bandall_tokens::Claims>`.
```

## 3. Firmas HMAC (contratos API y webhooks)

Cada cliente recibe un `key_id` con scopes (`bandall apikey create`):

```bash
bandall apikey create --config bandall.toml --tenant acme --scopes "verify"
# key_id: key-...  key: <hex, se muestra una vez>
```

El cliente firma la cadena canónica (`METHOD\nPATH\nQUERY\nSHA256(body)\ntimestamp\nnonce`)
y envía `X-Signature: v1=<hex>` + `X-Key-Id`, `X-Timestamp`, `X-Nonce`.
El servidor valida en `POST /v1/sigs/verify` (tolerancia ±5 min, nonce de un
solo uso, comparación constante).

## 3bis. Verificación offline dentro de tu servicio Rust (`sdk-axum`)

Dos modos (ADR-0013), ambos con JWKS **en caché** y fallo-cerrado:

```rust
use bandall_sdk_axum::{RequireScopes, RequireToken};

// Modo remoto: tu servicio valida contra el JWKS de BandAll (caché 5 min).
let layer = RequireToken::with_jwks(
    "https://bandall/.well-known/jwks.json",
    "bandall".into(), "my-app".into(), 1,
    std::time::Duration::from_secs(300),
);
// Opcionalmente exige scopes exactos del token:
let scopes = RequireScopes::new(vec!["mfa:verify".into()]);

// Modo local/embebido: el KeyManager compartido en el mismo proceso.
let layer = RequireToken::with_keys(keys, "bandall".into(), "my-app".into(), 1);
```

El handler lee `Extension<Claims>` (incluido `scp`). Si el endpoint de JWKS no
responde y la caché está vacía, la petición se **deniega** (401), nunca se
abre.

## 4. SDKs finos y modo embebido

Cuatro SDKs pasan los **mismos vectores de conformidad** (`sdks/conformance/vectors.json`):
verificación de JWT offline (EdDSA) y firmas HMAC. `just sdks` los ejecuta todos;
el job `sdks` de CI igual (Node 24, Python 3.13, Go 1.25, .NET 8).

| SDK | Verificación JWT | Firmas HMAC | Test |
|---|---|---|---|
| TypeScript (`sdks/ts`) | `verifyJwt(jwks, token, iss, aud, now)` | `sign`/`verifySignature` | `node --test` |
| Python (`sdks/python`) | `bandall_sdk.jwt.verify_jwt` | `bandall_sdk.hmac.*` | `unittest` |
| Go (`sdks/go`) | `bandall.VerifyJWT(jwks, token, iss, aud, now)` | `bandall.Sign`/`VerifySignature` | `go test ./...` |
| C# (`sdks/csharp`) | `BandAll.Jwt.Verify(jwks, token, iss, aud, now)` | `BandAll.Hmac.*` | `dotnet test` |

**Modo embebido**: `bandall-embedded` (ADR-0014) expone la fachada enroll →
confirm → verify → delete para integrar BandAll como librería, con el secreto
cifrado en SQLite (la KEK la aporta el integrador), antirreplay atómico y
deriva acotada — sin red ni HTTP:

```rust
use bandall_embedded::Embedded;

let embedded = Embedded::sqlite_path("/data/bandall.db", kek).await?;
let tenant = embedded.create_tenant("acme").await?;
let enrolled = embedded.enroll(&tenant, "alice", "BandAll", "alice@example.com").await?;
// QR: enrolled.otpauth_uri; códigos de recuperación: tras `confirm`.
let codes = embedded.confirm(&tenant, "alice", &enrolled.factor_id, &code, now).await?;
embedded.verify(&tenant, "alice", &enrolled.factor_id, &next, now).await?;
```

Ver con el ejemplo completo: `cargo run -p bandall-embedded --example embedded`
(y su batería en `crates/embedded/tests/battery.rs`).

## Notas de producción

- `authz/check` consulta la sesión en DB (revocación inmediata); el resto es
  offline. Para latencia mínima, cachea el JWKS 5–10 min en tu SDK.
- Los nonces HMAC viven en memoria por réplica; con varias réplicas usa
  Redis con TTL (H8).
- Las cookies web (`__Host-`, `HttpOnly`, `Secure`, `SameSite=Strict` + CSRF)
  las emite tu frontend/BFF, no BandAll directamente.
