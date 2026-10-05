# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado [SemVer](https://semver.org/lang/es/).

## [Unreleased]

### Added

- H0: workspace Cargo con los crates `bandall-*`, lints de seguridad, CI (fmt, clippy, tests, MSRV, cargo-deny, cargo-audit, cobertura y build de imagen).
- Docker: imagen distroless no-root y stack de desarrollo con Postgres 16.
- `justfile` con el gate `just check` y la política `deny.toml`.
- Documentación base: `SECURITY.md`, `CONTRIBUTING.md`, ADR-0001, ADR-0002 y modelo de amenazas v0.
- H1: `totp-core` puro (HOTP/TOTP RFC 4226/6238, Base32 estricto, `otpauth://`, verificación con ventana ±N y antirreplay matemático). Tests delegados al CI.
- H2 (parcial): `vault` con cifrado envolvente (KEK en `LocalKms`, DEK por factor, AAD por fila, `rewrap` para rotación) y códigos de recuperación Argon2id.
- H2: `store` con trait de persistencia, backends Postgres/SQLite, migraciones y batería de conformidad compartida (SQLite en memoria + Postgres en CI).
- H3 (parcial): fundación del API HTTP (config TOML+env, estado compartido, probes `/healthz`+`/readyz`, errores RFC 7807, serve con apagado ordenado) y CLI `serve`/`migrate`/`init-config`.

### Fixed

- H0: runtime Docker cambiado de distroless `cc` a `debian:12-slim` (ver ADR-0002).
- H0: Postgres de desarrollo escucha en el puerto de host 5433 por defecto para no chocar con otros proyectos locales.
