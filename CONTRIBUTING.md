# Contribuir a BandAll

Antes de tocar código, lee `AGENTS.md` (reglas del proyecto) y `BANDALL_ROADMAP.md` (hito activo y gates).

## Requisitos

- Rust stable vía [rustup](https://rustup.rs/) (la versión la fija `rust-toolchain.toml`).
- Docker (para el stack de `deploy/compose/` y la imagen).
- Herramientas locales: `just install-tools` (instala `just`, `cargo-deny` y `cargo-audit`).

## Flujo de trabajo

1. Toda tarea nace de una issue pequeña (≤ 1 día) dentro del hito activo.
2. Rama por issue: `git switch -c <tipo>/<descripcion-corta>`.
3. Antes de pedir revisión: `just check` debe pasar (es exactamente lo que corre el CI).
4. PR pequeño, con: qué cambia, por qué, cómo se probó y qué reglas de seguridad toca.
5. CI verde + revisión + *squash merge*. No se abren cambios ajenos al alcance.

## Commits

- [Conventional Commits](https://www.conventionalcommits.org/) en inglés: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `build:`, `ci:`.

## Decisiones y documentación

- Toda decisión de diseño se registra como ADR en `docs/adr/NNNN-titulo.md`.
- Antes de cerrar un hito, actualiza `docs/threat-model.md` y el `CHANGELOG.md`.

## Seguridad

- Los cambios que tocan cripto, tokens, vault o policy requieren revisión humana explícita.
- No subas secretos, claves ni `.env` reales. Reporta vulnerabilidades según `SECURITY.md`.
