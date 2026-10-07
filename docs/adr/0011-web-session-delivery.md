# ADR-0011: Entrega de sesiones al navegador (cookies propias vs. BFF)

- **Estado:** propuesto — **esperando decisión humana** (ítem 5 de H4)
- **Fecha:** 2026-10-06
- **Decisores:** Angel Nereira
- **Nota de numeración:** T10 (credencial primaria) tenía reservado el
  `0009-primary-credential.md` en el brief. Al llegar T3 y T4 antes, los ADRs
  0009 (deriva) y 0010 (cadena de auditoría) se llevaron esos números, y este
  0011 ocupa el tercero. El de T10 pasa a ser `0012-primary-credential.md`.

## Contexto

El ítem 5 de H4 dice:

> Web: cookies `__Host-` + `HttpOnly` + `Secure` + `SameSite=Strict` + CSRF.
> Móvil: guía de almacenamiento en Keystore/Keychain.

El móvil está resuelto como documentación porque en el móvil no hay cookie: el
dispositivo guarda el token y el control es *dónde*
(`docs/guides-web-and-mobile-sessions.md`).

En web hay una bifurcación real. BandAll tiene tres modos (servicio
independiente, sidecar/forward-auth y librería embebida) y **hoy no emite
cookies**: `POST /v1/mfa/verify` y `POST /v1/token/refresh` devuelven el par de
tokens en el cuerpo, y quien integra decide dónde los pone. La revisión ASVS ya
aplazaba este punto ("pendiente de guía H6", `docs/asvs-l3-review.md` §3.5).

Las dos opciones no son equivalentes en superficie de ataque:

- Si BandAll emite la cookie, **el CSRF pasa a ser responsabilidad de BandAll**:
  hay que emitir el token CSRF, atarlo a la sesión, exigir cabecera en los
  endpoints que cambian estado y validar `Origin`. Es superficie nueva en el
  servicio, no solo una cabecera `Set-Cookie`.
- Si la emite el integrador (patrón BFF), BandAll mantiene el contrato actual y
  el CSRF vive donde vive la sesión del navegador.

## Opciones

### A. BFF: BandAll no emite cookies (estado actual)

El navegador habla con el servidor de la aplicación, y ese servidor guarda los
tokens y los presenta a BandAll.

- Pros: cero superficie nueva en BandAll; el contrato de la API no cambia; un
  XSS en el frontend no puede exfiltrar el refresh (nunca llega al navegador);
  no hay que resolver CSRF en el servicio.
- Contras: cada integrador debe montar y mantener el BFF; dos saltos de red;
  la guía es un requisito de cumplimiento, no algo que el servidor garantice.

### B. BandAll emite la cookie de sesión

`mfa/verify` y `token/refresh` añaden `Set-Cookie: __Host-...; HttpOnly; Secure;
SameSite=Strict` con el refresh, más un token CSRF por sesión.

- Pros: el navegador no toca el token; una integración simple (sin BFF) queda
  segura por defecto; `__Host-` impide fijación desde un subdominio.
- Contras: **CSRF entra en el modelo de amenazas de BandAll** y hay que
  implementarlo bien (doble envío ligado a sesión + `Origin`); la rotación y la
  detección de reutilización pasan a depender de que el navegador maneje bien la
  cookie; los clientes no-navegador ven cabeceras que no pidieron; y hay que
  decidir qué pasa con `SameSite=None` para integraciones cross-site, que es
  justo el caso donde el CSRF vuelve.

### C. Ambos, tras un flag de configuración

`web_cookies = false` por defecto; quien lo active obtiene B.

- Pros: no rompe a nadie y el camino seguro está disponible.
- Contras: dos caminos que mantener y **dos superficies que auditar**; las
  pruebas de CSRF solo corren con el flag activo, así que en la práctica la ruta
  menos probada es la que ofrece seguridad. Un flag de seguridad suele acabar
  activado sin que nadie revise el resto.

## Recomendación

**A**, con la guía como entregable (`docs/guides-web-and-mobile-sessions.md`),
por tres razones:

1. BandAll no es un IdP y no pretende serlo: el ítem de sesiones completas
   (credencial primaria) está sin decidir en ADR-0010/T10, y emitir cookies
   ahora es resolver la última milla antes de decidir el principio.
2. El patrón BFF mantiene el refresh fuera del navegador, que es una propiedad
   más fuerte que cualquier atributo de cookie. B no puede ofrecerla.
3. B mete CSRF en el servicio antes de H5 cerrado y sin pentest (H9).

**B pasa a ser la decisión natural** el día que BandAll emita sesiones
completas (T10 opción B, `challenge_id`), porque entonces el navegador hablará
con BandAll directamente y el BFF desaparece. En ese momento este ADR se
revisa junto con el de la credencial primaria.

## Consecuencias

- H4 ítem 5 queda entregado como **especificación + guía**, no como código de
  servidor. Se marca así en `docs/ROADMAP_STATUS.md` para que no se lea como
  "implementado".
- La guía es verificable por un integrador (lista de atributos y controles) y
  el servidor ya aporta la parte que le toca: revocación inmediata por `sid` y
  comprobación de sesión viva en `authz/check`.
- Si se elige B o C, hay trabajo nuevo: token CSRF ligado a sesión, validación
  de `Origin`, pruebas negativas de CSRF y actualización del modelo de amenazas.
