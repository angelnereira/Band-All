# ADR-0015: Vectores de conformidad versionados (`schema_version`)

- **Estado:** aceptado (H6)
- **Fecha:** 2026-10-07
- **Decisores:** Angel Nereira

## Contexto

Los cuatro SDKs (TS, Python, Go, C#) pasan los **mismos vectores**
(`sdks/conformance/vectors.json`). Ese fichero es el contrato desnudo con el
que se detectan divergencias entre SDKs, pero **no dice qué versión de
contrato es**: si mañana el JWKS gana un campo (p. ej. `x5c` para WebAuthn en
H9) o un claim cambia de semántica, un SDK viejo seguirá "leyendo" el JSON y
fallará con un mensaje que no explica nada.

También hay una segunda compatibilidad: `sdks/ts/package.json` declara
`engines.node >= 20` pero el test necesita Node ≥ 24 (type stripping). Eso es
una incompatibilidad declarada que un consumidor del paquete (no del repo)
nunca notaría, porque el SDK publicado no requiere strips: el problema se da
al **ejecutar los tests del repo**.

## Decisión

1. `vectors.json` gana `"schema_version": 1` en la raíz. Cada test de cada
   SDK (los cuatro) comprueba que el fichero tiene `schema_version == 1`
   antes de usar los vectores: si un día el contrato cambia, el fallo es
   "vectores versión X, SDK espera 1", no un cast error confuso.
2. Compatibilidad declarada: `sdks/ts/package.json` documenta en `engines` lo
   que el **código** necesita (los consumidores compilan/despliegan con lo
   suyo) y añade una nota `scripts.test` sobre el requisito de Node para
   correr los tests del repo. Lo mismo para `sdks/python` (requiere Python
   ≥ 3.10 y `cryptography`) y para los READMEs de Go (≥ 1.25) y C# (.NET 8).

## Alternativas consideradas

| Alternativa | Motivo de descarte |
|---|---|
| SemVer completo del fichero (major.minor.patch) | No hay aún una política de publicación de los SDKs; un entero de contrato basta hasta que exista |
| Dejar el fichero sin versión | Es el estado actual: los cambios rompen en silencio |
| Solo documentar en README | La comprobación automática en los 4 juegos de tests es lo que convierte la doc en un gate |

## Consecuencias

- Cada SDK añade ≥ 1 test de conformidad de esquema (además de los de JWT y
  HMAC).
- `scripts.test`/READMEs reflejan los requisitos reales; el job `sdks` del CI
  y `just sdks` (que ya saltan los tests de los 4) validan la versión.
- Cuando exista publicación a registries (npm/PyPI/GitHub Packages/NuGet),
  este ADR se reabre para definir el versionado semántico de cada artefacto.