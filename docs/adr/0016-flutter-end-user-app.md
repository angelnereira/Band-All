# ADR-0016: App Flutter para el cliente final — sustituye a ADR-0006

- **Estado:** aceptado
- **Fecha:** 2026-10-07
- **Decisores:** Angel Nereira
- **Sustituye a:** ADR-0006 (nativo por plataforma con UniFFI)

## Contexto

ADR-0006 decidió apps **nativas por plataforma** (SwiftUI + Jetpack Compose) con
bindings UniFFI, descartando Flutter explícitamente. Desde entonces el producto
ha cambiado de forma: BandAll deja de ser solo una biblioteca embebible o un
SDK para otros sistemas, y pasa a tener **su propia app de usuario final**, al
estilo de Google Authenticator. El usuario final no integra un SDK: instala una
app y la usa.

Ese giro cambia la ecuación de ADR-0006, que sopesaba el coste de mantener dos
codebases nativas frente al runtime de Flutter. Con dos plataformas ya
planificadas, el argumento que justificaba duplicar la UI se debilita, y aparece
uno nuevo que ADR-0006 no contemplaba: **una sola app que sirve a los dos roles**
del producto.

## Los dos roles de la app

Conviene no confundirlos, porque tienen dependencias distintas:

1. **Autenticador TOTP** (tipo Google Authenticator). La app guarda factores y
   genera códigos offline. Funciona contra cualquier servicio que use BandAll
   como capa de autenticación —incluidos los que verifican vía S2S y exponen
   forward-auth— **sin ningún cambio en el servidor**. Es interoperable con
   otros autenticadores: el factor es un `otpauth://` estándar.

2. **Cliente de login propio de BandAll**. El usuario inicia sesión con
   credencial primaria + MFA y obtiene una sesión para los servicios que
   dependan de BandAll.

**Este ADR solo construye el rol 1.** El rol 2 depende de una decisión que sigue
abierta: la decisión nº 1 del roadmap (¿BandAll solo hace segundo factor, o
también emite sesiones completas?) está reservada como `0012-primary-credential`.
Hoy `POST /v1/mfa/verify` asume que quien llama ya comprobó la credencial
primaria; no hay endpoint de login. Construir el rol 2 sin esa decisión sería
resolver la última milla antes que el principio, exactamente el error que ADR-0011
rehúso cometer con las cookies.

Cuando se decida `0012-primary-credential`, el rol 2 se añade a esta app.

## Decisión

**Flutter** para la app de usuario final, con **flutter_rust_bridge** como
puente a `bandall-authenticator-core`.

### Por qué Flutter y no nativo

- Una sola codebase UI para las dos plataformas, en vez de dos. ADR-0006
  aceptaba ese coste cuando la app era accesoria; deja de aceptarlo cuando la
  app es la superficie de producto de cara al usuario.
- El núcleo criptográfico **no se toca**: `authenticator-core` sigue siendo Rust
  puro, sin red y sin dependencias de plataforma. Flutter es la capa de
  presentación, no la de la lógica.
- Añade una pieza al camino de release, que es el coste real que asumimos.

### Por qué flutter_rust_bridge y no UniFFI

UniFFI sigue siendo válido, pero está orientado a consumidores que esperan tipos
propios (records, enums) y genera bindings en muchos lenguajes. En un proyecto
Flutter, `flutter_rust_bridge` es el camino idiomático: genera Dart desde la
interfaz Rust y gestiona el build hook de Rust para Android. Cambiar de puente
más adelante es trabajo contenido, porque la frontera (`authenticator-core`) ya
está aislada.

### Dónde vive el secreto

El punto donde Flutter **no** es igual de bueno que nativo, y donde no se debe
ceder: el secreto TOTP.

- **Keystore / Keychain mediante `flutter_secure_storage`**, con el almacén
  respaldado por hardware cuando el dispositivo lo ofrece (StrongBox en Android,
  Secure Enclave en iOS). El secreto se guarda cifrado bajo una clave que el SO
  no exporta.
- **Biometría mediante `local_auth`**: la app no abre el secreto sin
  autenticación local. El gate de H7 ("secreto no extraíble sin biometría") se
  cumple contra la API del SO, no contra lógica nuestra.
- **Nunca** en `SharedPreferences`, ni en el estado de Flutter, ni en los
  argumentos de la máquina de estados. `FLAG_SECURE` en Android para que el
  sistema no incluya la app en capturas de pantalla ni en la vista reciente.

Esto es alcanzable con plugins, pero es trabajo real y hay que probarlo en
dispositivo: un plugin que devuelve el secreto en claro a un proceso ajeno
rompe el gate sin que ningún test de Dart lo detecte.

## Consecuencias

- **ADR-0006 queda sustituido.** Se conserva el razonamiento original en el
  fichero para que se vea qué cambió y por qué; no se borra.
- iOS **no** se puede compilar en esta máquina: requiere macOS y Xcode. Se
  entrega código Dart y configuración iOS; la compilación y las pruebas en
  dispositivo iOS quedan para un runner macOS. Android sí se compila y se
  prueba aquí.
- `flutter_secure_storage` y `local_auth` son dependencias nuevas del proyecto
  Flutter (no del workspace Cargo). Se justifican arriba: son los plugins que
  exponen Keystore/KeyChain y la biometría del sistema.
- La app debe seguir funcionando **100 % offline** para el rol 1. Ninguna
  llamada de red en el camino de generación de códigos, y una prueba que lo
  compruebe (no basta con no escribir la llamada).
- Los factores de la app interoperan con el resto del sistema porque el formato
  es `otpauth://` estándar: nada de la app es propietario.

## Notas de implementación (2026-10-08)

Tres cosas que la implementación encontró y que conviene que queden escritas,
porque dos de ellas contradecían lo que este ADR prometía hasta que se
arreglaron:

1. **`cargokit` usa el nombre del *paquete* Cargo tal cual para buscar el
   artefacto**, mientras que Cargo normaliza los guiones a guiones bajos al
   nombrar la biblioteca. Una crate llamada `bandall-authenticator-ffi` produce
   `libbandall_authenticator_ffi.so`; cargokit busca
   `libbandall-authenticator-ffi.so`, no lo encuentra, **no copia nada y el
   build termina en verde**. El APK se construye sin la biblioteca Rust y la app
   arranca hasta la primera llamada al núcleo. Por eso el paquete se llama
   `bandall_authenticator_ffi`, con guiones bajos, y por eso
   `tests/mobile/verify_app.sh` comprueba que el `.so` esté dentro.

2. **El APK de release declaraba `INTERNET` y `ACCESS_NETWORK_STATE`.** No
   venían del código: `mobile_scanner` arrastra ML Kit, que arrastra
   `com.google.android.datatransport:transport-backend-cct`, la librería de
   telemetría de Google, y esa declara ambos permisos para enviar sus datos. Un
   producto de seguridad cuyo autenticador puede subir lo que decida una
   dependencia transitiva no es aceptable, así que el manifiesto los elimina con
   `tools:node="remove"`. Android lo aplica: sin el permiso, ninguna biblioteca
   puede abrir un socket. La comprobación está en `verify_app.sh` y falla el
   build si algún día vuelven.

3. **`unsafe`.** `AGENTS.md` lo prohíbe en todos los crates, y este no puede
   cumplirlo al pie de la letra: cruzar a Dart exige una frontera FFI y el glue
   generado por `flutter_rust_bridge` contiene bloques `unsafe`. Se aplica lo más
   estricto que permite la herramienta: el crate `deny`ea `unsafe_code`,
   `api.rs` (lo escrito a mano) lo `forbid`ea, y el módulo generado es la única
   excepción, nombrada y justificada. Escribir la frontera a mano significaría
   *más* `unsafe`, no menos.

También: la biometría **no** se pide al pintar códigos. Un prompt cada 30
segundos es un prompt que el usuario desactiva, y entonces no protege nada. Se
pide para lo que expone el secreto — exportar un backup, revelar una clave de
alta — que es lo que el gate significa por "no extraíble".

## Lo que falta para cerrar H7

- **iOS no se ha compilado.** Requiere macOS y Xcode; la configuración está
  escrita y sin verificar. Lo mismo para macOS y Windows de escritorio.
- **Nada se ha probado en un dispositivo real.** El gate pide modo avión,
  reinicio, desinstalación y reloj ±45 s. Aquí se prueba el núcleo y el
  empaquetado; el comportamiento en hardware, no.
- **La importación desde Google Authenticator** (`otpauth-migration://`) queda
  fuera a propósito: el formato es un protobuf sin especificación oficial y
  **no hay fixture real** con el que verificar un parser. Implementarlo a ciegas
  sería peor que no tenerlo: un usuario creería haber migrado sus cuentas sin
  haber migrado nada. Necesita un QR exportado de un dispositivo.

## Alternativas consideradas

| Alternativa | Motivo de descarte |
|---|---|
| Nativo con UniFFI (ADR-0006) | Sostiene su razonamiento cuando la app es accesoria; se debilita al ser la superficie de producto |
| App solo-web (PWA) | Sin acceso a Keystore ni biometría del SO: el gate de H7 es inalcanzable |
| Sin app propia, solo SDK | Descartado por el giro de producto: el usuario final no integra un SDK |
| Flutter sin núcleo Rust, rehaciendo TOTP en Dart | Dos implementaciones de criptografía; imposible verificar solo una |