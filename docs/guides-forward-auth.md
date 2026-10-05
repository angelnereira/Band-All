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
solo uso, comparación constante). Los SDKs TS/Python implementan ambas
orillas sobre los mismos vectores (`sdks/conformance`).

## Notas de producción

- `authz/check` consulta la sesión en DB (revocación inmediata); el resto es
  offline. Para latencia mínima, cachea el JWKS 5–10 min en tu SDK.
- Los nonces HMAC viven en memoria por réplica; con varias réplicas usa
  Redis con TTL (H8).
- Las cookies web (`__Host-`, `HttpOnly`, `Secure`, `SameSite=Strict` + CSRF)
  las emite tu frontend/BFF, no BandAll directamente.
