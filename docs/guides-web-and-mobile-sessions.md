# Guía: sesiones en web y móvil

Cómo llevar los tokens de BandAll al navegador y al dispositivo sin abrir
CSRF, XSS ni robo por backup. BandAll emite los tokens; **quien los almacena es
la aplicación que integra**, así que esta guía es el contrato que debe cumplir.

Aplica al flujo de `POST /v1/mfa/verify` y `POST /v1/token/refresh`, que
devuelven un `TokenPair` (`access_token` + `refresh_token`).

## Navegador: el token no va a `localStorage`

`localStorage` y `sessionStorage` son legibles por cualquier script de la
página: un solo XSS (una dependencia npm comprometida, un `innerHTML` mal
puesto) exfiltra la sesión completa. El refresh token es el peor de los dos,
porque dura días.

**Patrón recomendado: BFF (backend-for-frontend).** El navegador habla con tu
servidor, y tu servidor guarda los tokens y los presenta a BandAll.

```
navegador ──cookie de sesión──▶ tu BFF ──Bearer/refresh──▶ BandAll
```

Ventajas: los tokens nunca tocan JavaScript, así que un XSS no los roba; el BFF
puede rotar y revocar; y `SameSite=Strict` ya corta el CSRF en la mayoría de
flujos. Coste: un salto de red y una sesión server-side que mantener.

### Cookie de sesión del BFF

| Atributo | Valor | Por qué |
|---|---|---|
| nombre | `__Host-<app>` | El prefijo `__Host-` obliga a `Secure`, `Path=/` y **prohíbe** `Domain`: un subdominio comprometido no puede fijar la cookie. |
| `HttpOnly` | siempre | Invisible para `document.cookie`: un XSS no la lee. |
| `Secure` | siempre | No viaja en claro; sin esto el prefijo `__Host-` es inválido y el navegador la rechaza. |
| `SameSite` | `Strict` | No se envía en peticiones cross-site, lo que corta el CSRF clásico. |
| `Path` | `/` | Requisito del prefijo `__Host-`. |
| `Max-Age` | vida del refresh | Que caduque con la sesión, no antes ni después. |

```
Set-Cookie: __Host-bandall-session=<opaco>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800
```

Reglas que se incumplen más de lo que parece:

- **`Secure` y `HttpOnly` no se compensan entre sí.** `HttpOnly` sin `Secure`
  protege de XSS y no del sniffer de red; `Secure` sin `HttpOnly` es al revés.
- **No pongas el JWT de acceso en la cookie y lo reenvíes tal cual.** Entonces
  la cookie ES una credencial de portador y estás donde empezaste, solo que
  ahora con CSRF añadido. La cookie debe apuntar a una sesión del BFF.
- **`SameSite=None` exige `Secure`, y con `None` vuelve el CSRF.** Si
  necesitas integración cross-site (un iframe, un IdP tercero), `SameSite=None`
  es una decisión deliberada que obliga a CSRF token sí o sí.

### CSRF cuando `SameSite` no basta

`SameSite=Strict` no cubre todo: navegadores antiguos, `None` por necesidad de
integración, o peticiones que no son de navegador. Para endpoints que cambian
estado (`POST /v1/token/refresh`, `POST /v1/token/revoke`):

1. **Doble envío**: emite un token CSRF aleatorio por sesión, entrégalo en el
   cuerpo (no en cookie) y exige que vuelva en la cabecera `X-CSRF-Token`.
   Compara en tiempo constante.
2. **Lígalo a la sesión**, no a un valor global: si no, un atacante con
   cualquier sesión válida puede fabricar el suyo.
3. **Comprueba el `Origin`** además del token. Son controles independientes y
   baratos.

Lo que **no** sirve: confiar en que un XSS no ocurra, o comprobar solo
`Referer` (se puede omitir y hay navegadores que no lo mandan).

### CORS

Si el BFF y el navegador están en orígenes distintos, `Access-Control-Allow-Origin`
debe listar el origen exacto. **Nunca `*` junto con credenciales**: el
navegador lo rechaza, y sortearlo desactivando credenciales te deja sin cookies.

## Móvil: Keystore / Keychain, nunca `SharedPreferences`

| Plataforma | Dónde guardar | Notas |
|---|---|---|
| Android | `EncryptedSharedPreferences` (sobre Android Keystore) o un archivo cifrado con una clave de Keystore | Usa `setUserAuthenticationRequired(true)` para exigir biometría en cada uso. `StrongBox` si el dispositivo lo tiene. |
| iOS | Keychain con `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | `ThisDeviceOnly` impide que la clave viaje en un backup. `Secure Enclave` si el dispositivo lo soporta. |

Reglas:

- **Nada en `SharedPreferences`, `NSUserDefaults`, ficheros planos ni logs.** Ni
  "solo el access token, que dura 10 minutos".
- **Sin backup en la nube por defecto.** Es la vía más fácil de sacar un refresh
  de un dispositivo: un backup de Android o de iCloud se restaura en otro
  aparato. Si el producto lo exige, backup **cifrado con clave derivada
  (Argon2id) de algo que solo el usuario tenga**, y documenta la decisión.
- **Captura de pantalla y multitarea**: `FLAG_SECURE` en Android y la
  ocultación equivalente en iOS mientras se muestra un código, para que el
  secret/QR no acabe en la miniatura de apps recientes.
- **Root/jailbreak**: la app autenticadora (`authenticator-core`) guarda el
  **secreto TOTP**, que no caduca. Ahí el Keychain con biometría no es una
  comodidad, es el control principal.
- **Un solo aviso de deriva**: si el reloj del dispositivo está desviado más de
  un paso, el servidor rechaza el código (ADR-0009). La app debe avisar en vez
  de dejar al usuario reintentando.

## Lo que BandAll sí hace del lado del servidor

- `POST /v1/token/revoke` quema la familia de refresh y **su sesión**: una
  revocación es inmediata, no espera a que expire el access token.
- `GET /v1/authz/check` comprueba **la sesión viva** en base de datos, además
  de la firma y el `aud`/`iss` del token. Es el punto que convierte una
  revocación en efectiva para el tráfico en curso; no te lo saltes confiando
  solo en la verificación offline del JWT.
- La detección de reutilización de refresh (ADR-0005) revoca la familia entera:
  si el usuario ve que "se cerró sesión sola", suele ser esto, no un fallo.

## Qué NO hace este documento

No propone que BandAll emita cookies. Servir sesiones de navegador desde el
propio servicio cambia la superficie (CSRF pasa a ser responsabilidad de
BandAll) y es una decisión de producto: ver ADR-0011.
