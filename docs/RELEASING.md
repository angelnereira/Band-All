# Publicar versiones (SemVer + pipeline de release)

## Versionado

- `X.Y.Z` SemVer sobre la API v1 (`/v1`, JWKS, claims JWT, esquemas DB
  aplicados por migraciones numeradas). Cambios incompatibles requieren
  major y guía de migración.
- Tags `vX.Y.Z` al cerrar cada hito; `CHANGELOG.md` (Keep a Changelog) es
  la fuente de novedades.
- **Al subir la versión hay que editar dos sitios**: `version` en
  `[workspace.package]` del `Cargo.toml` raíz **y** la `version` de las diez
  entradas de `[workspace.dependencies]`. No se puede usar
  `version.workspace = true` en una dependencia: Cargo lo rechaza. Basta con que
  las dos listas coincidan; que no coincidan rompe la resolución de los miembros.

## Pipeline de release (H8, al publicar 0.9/1.0)

1. CI verde en `main` + `bandall audit verify` sobre un despliegue real.
2. Build multi-arch (`linux/amd64`, `linux/arm64`) con proveniencia
   (buildx + attestations GHA).
3. SBOM CycloneDX por imagen (adjunto al release).
4. Firma `cosign` (keyless con OIDC de GitHub) y verificación en el chart.
5. `cargo vet` en verde (auditorías registradas en `supply-chain/`).
6. Publicar imagen `ghcr.io/<org>/bandall:<versión>` + chart Helm con
   `appVersion` fijado.

## Estado actual

Los pasos 2–5 están documentados pero no cableados: requieren secretos de
registro/firma y acceso a un cluster que esta máquina no tiene. No publiques
`1.0.0` sin ellos (ver checklist de producción en `BANDALL_ROADMAP.md` §4).
