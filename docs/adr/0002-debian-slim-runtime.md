# ADR-0002: Runtime Docker — distroless `cc` (reenviado desde H5)

- **Estado:** aceptado
- **Fecha:** 2026-10-05 (revisado 2026-10-06 en H5)
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

## Reevaluación en H5 (2026-10-06)

El 2026-10-06 se descargaron las capas reales del **mismo digest** `sha256:9dac…` del tag `nonroot` directamente del registro (sin Docker) y se inspeccionaron:

- `libgcc_s.so.1` **arm64**: 133 448 bytes, ELF `aarch64` válido (`sha256 046856f9…`). Los mismos 133 448 bytes que el ADR registró como "sanos" en `debug-nonroot`.
- `libgcc_s.so.1` **amd64**: 125 312 bytes, ELF válido.
- El binario release (`cargo build --release`) necesita exactamente cuatro librerías (`objdump -p … | NEEDED`): `libgcc_s.so.1`, `libm.so.6`, `libc.so.6`, `ld-linux-x86-64.so.2`. Las cuatro existen en las capas amd64 **y** arm64 del índice.
- `ca-certificates` viene incluido (capa `cacerts_debian12_*`), y el usuario `nonroot` (uid 65532) es el del propio runtime distroless.

**Conclusión: la premisa de esta decisión ya no se sostiene.** El defecto descrito (0 bytes en arm64) coincide con lo que se midió aquí el 5 de octubre, y el 6 de octubre el mismo digest entrega el archivo sano; no se pudieron reconciliar ambas mediciones por la vía del registro, pero la verificación directa de las capas actuales es lo que decide: **el runtime pasa a `cc-debian12:nonroot` fijado por digest del índice (multi-arch)**, en el `deploy/Dockerfile` con su justificación.

Lo que **no** se ha podido hacer en esta máquina es el build multi-stage completo (el demonio Docker está parado y `sudo` pide contraseña). La verificación estática (NEEDED ⊆ librerías presentes en ambas arquitecturas) sostiene el cambio, pero el job `docker` de CI — cuando GitHub asigne runner — es la prueba de fuego: si falla, se vuelve a `debian:12-slim` sin más y se anota aquí.

Queda descartada definitivamente la opción musl: el tamaño (~40 MB en vez de ~90) y la superficie (sin shell, sin curl) que distroless ya cubre no justifican mantener una cadena de compilación alternativa para el runtime.

## Alternativas consideradas

| Alternativa | Motivo de descarte |
|---|---|
| Esperar a que distroless republicara el tag | En 2026-10-06 el tag sirve el archivo sano: la espera terminó, ver reevaluación de H5 |
| `debug-nonroot` como runtime | Trae shell y busybox: peor postura de seguridad sin ganar nada |
| Binario estático musl + `distroless/static` | Mejor a largo plazo, pero exige toolchain musl y validar futuros crates criptográficos; descartada en la reevaluación de H5 |
