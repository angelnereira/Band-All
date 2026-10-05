# Política de seguridad

BandAll es un servicio de seguridad: los reportes se tratan con prioridad.

## Cómo reportar

- Usa **GitHub Security Advisories** (pestaña *Security* → *Report a vulnerability*). Es un canal privado.
- **No** abras issues públicos para vulnerabilidades.
- Incluye: descripción, impacto, pasos de reproducción, versión o commit afectado y PoC si existe.

## Alcance

- Código de este repositorio: crates `bandall-*`, API, CLI y configuraciones de `deploy/`.

## Fuera de alcance

- Limitaciones de diseño ya documentadas (por ejemplo, TOTP es phishable; ver `BANDALL_BLUEPRINT.md` §13).
- Vulnerabilidades de dependencias de terceros: repórtalas a su proyecto o vía [RustSec](https://rustsec.org/).

## Compromiso

- Objetivo: acusar recibo en 72 h y acordar un plan de divulgación coordinada (máximo 90 días desde el reporte).
- Los hallazgos críticos se corrigen antes de cualquier release; los detalles permanecen privados hasta que exista parche.
