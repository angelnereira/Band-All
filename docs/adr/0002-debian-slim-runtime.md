# ADR-0002: Runtime Docker `debian:12-slim` en lugar de distroless `cc`

- **Estado:** aceptado
- **Fecha:** 2026-10-05
- **Decisores:** Angel Nereira

## Contexto

El plan fijaba `gcr.io/distroless/cc-debian12:nonroot` (por digest) como runtime. Al verificar la imagen construida, el binario no arranca:

```
/usr/local/bin/bandall: error while loading shared libraries: /lib/aarch64-linux-gnu/libgcc_s.so.1: file too short
```

## Investigación

- Reconstrucción con `--pull` (base fresca): mismo error. No era caché local.
- `docker cp` del archivo desde la imagen base **prístina** recién descargada: **0 bytes** en arm64 (esta máquina es `aarch64`).
- La variante `debug-nonroot` (misma familia, compilada después) trae el archivo sano (133 448 bytes).
- La variante **amd64** del mismo digest trae el archivo sano (125 312 bytes).
- Conclusión: el snapshot `cc-debian12:nonroot@sha256:9dac…` tiene un `libgcc_s.so.1` vacío **solo en arm64**. Es un defecto aguas arriba, no de nuestro Dockerfile. El CI (amd64) no lo habría detectado.

## Decisión

Runtime `debian:12-slim` fijado por digest (`sha256:3783cc01…`), con usuario `nonroot` (uid 65532, el mismo que usa distroless) creado en el build y `ca-certificates` instalado (el servicio hará TLS hacia Postgres/KMS/IdP en hitos posteriores). El healthcheck sigue siendo el subcomando `bandall healthcheck`.

## Consecuencias

- Imagen algo mayor (~90 MB frente a ~48 MB) y con shell disponible: aceptable en desarrollo/H0–H4.
- En H5 (hardening) se reevalúa: distroless `cc` con un digest sano, o binario estático musl + `distroless/static`.

## Alternativas consideradas

| Alternativa | Motivo de descarte |
|---|---|
| Esperar a que distroless republique el tag | El tag sigue apuntando al digest roto; sin fecha conocida |
| `debug-nonroot` como runtime | Trae shell y busybox: peor postura de seguridad sin ganar nada |
| Binario estático musl + `distroless/static` | Mejor a largo plazo, pero exige toolchain musl y validar futuros crates criptográficos; se difiere a H5 |
