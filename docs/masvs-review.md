# Revisión OWASP MASVS — app autenticadora (H7)

Alcance: `apps/authenticator`, la app Flutter y el crate Rust que la acompaña
(`bandall_authenticator_ffi`). El servicio que verifica esos códigos tiene su
propia revisión en [`asvs-l3-review.md`](asvs-l3-review.md); aquí lo que se
revisa es **el dispositivo que guarda el segundo factor**, que es el objetivo
de cualquier atacante que consiga un factor robado.

Convención: ✅ implementado · 🟡 parcial · ⬜ pendiente (con hito).

La app es deliberadamente estrecha (ADR-0016): guarda factores TOTP y genera
códigos offline. El rol "entrar con BandAll como credencial primaria" **no**
está, porque depende de una decisión abierta (`adr/0012-primary-credential.md`).
Evaluarlo aquí sería evaluarlo al revés.

---

## V1 Almacenamiento seguro de datos

| Control | Estado | Evidencia |
|---|---|---|
| MSTG‑STORAGE‑1: los datos sensibles se guardan en el almacén seguro del sistema | ✅ | `flutter_secure_storage` → Android Keystore (clave AES con envoltura RSA‑OAEP, `AndroidOptions()` por defecto) e iOS Keychain. La lista de cuentas es un único blob cifrado por la plataforma |
| MSTG‑STORAGE‑2: ningún dato sensible en archivos ordinarios | ✅ | No hay `SharedPreferences` ni fichero en claro. `MemoryAccountStore` existe **solo en tests**; en producción, si el keystore falla, la app avisa y pierde los datos en vez de escribir en otro sitio (`_StorageWarning`) |
| MSTG‑STORAGE‑5: la clave de cifrado no se almacena junto a los datos | ✅ | La clave nunca sale del Keystore/Keychain; el blob fuera del dispositivo es indescifrable |
| MSTG‑STORAGE‑6: cifrado con algoritmos aceptados | ✅ | Lo elige la plataforma: AES‑256‑GCM en Android, el modelo de la Keychain en iOS |
| MSTG‑STORAGE‑8: rotación de claves | 🟡 | La rotación es de la plataforma; la del backup manual se deriva con Argon2id. Rotar el factor concreto es manual (`docs/runbooks/key-rotation.md`) |
| MSTG‑STORAGE‑11: la app no hace backup a la nube | ✅ | `android:allowBackup="false"` + `data_extraction_rules.xml` y `backup_rules.xml` excluyendo todos los dominios. El APK de release no lo revierte (`verify_app.sh` lo comprueba) |

## V2 Seguridad de la criptografía

| Control | Estado | Evidencia |
|---|---|---|
| MSTG‑CRYPTO‑1: la app no implementa algoritmos propios | ✅ | **TOTP solo existe en Rust.** No hay una segunda implementación en Dart: dos implementaciones significan que una nunca se verifica contra la otra (ADR‑0016). Los vectores RFC 6238/4226 se comprueban en el puente (12 tests) y contra el servidor real en la suite del contenedor |
| MSTG‑CRYPTO‑2: claves de la app fijadas en el código | ✅ | No hay claves en la app. La clave de cifrado del backup la deriva **Argon2id** de una passphrase que elige el usuario; el backup se genera solo tras autenticación biométrica |
| MSTG‑CRYPTO‑4: la generación aleatoria es criptográficamente segura | ✅ | Del CSPRNG del SO, dentro de Rust. Dart no genera nada que la propia app tenga que adivinar |
| MSTG‑CRYPTO‑5: no se usan primitivas criptográficas de forma insegura | ✅ | `subtle` en toda comparación; el `unsafe` prohibido salvo el módulo generado de `flutter_rust_bridge` (única excepción nombrada, justificada en ADR‑0016: escribir la frontera FFI a mano sería **más** `unsafe`, no menos) |

## V3 Autenticación

| Control | Estado | Evidencia |
|---|---|---|
| MSTG‑AUTH‑1: el usuario se autentica antes de usar la app en datos sensibles | 🟡 | La biometría protege **extracción** (exportar backup, revelar la clave de configuración), no el dibujo del código. Un prompt cada 30 s se apaga, y una función que el usuario desactiva no protege nada. Lo demás lo hace el Keystore |
| MSTG‑AUTH‑3: la autenticación por biometría es resistente al spoofing | ⬜ | `local_auth` delega en BiometricPrompt / Face ID. **Sin hardware no se puede probar**; pendiente del ensayo en dispositivo real |
| MSTG‑AUTH‑7: la sesión de la app caduca | ✅ | No hay sesión persistente. Cada arranque parte de cero, y el estado "códigos visibles" no se persiste entre lanzamientos: se reinicia en cada apertura |
| MSTG‑AUTH‑11: el PIN/biometría requerido por defecto no guarda en el dispositivo | ✅ | No hay ninguna credencial almacenada por la app |

## V4 Managed Code

| Control | Estado | Evidencia |
|---|---|---|
| MSTG‑MANAGED‑1: la app es invulnerable al reversing de código | ✅ | Todo está en Rust, compilado en release, con `strip = "debuginfo"` en el perfil de release del workspace. Lo recuperable de un APK es la lógica Dart de la interfaz, no la criptografía |
| MSTG‑MANAGED‑2: no hay claves ni secretos en los recursos | ✅ | Sin assets con secretos; `pubspec` no declara ninguna fuente de configuración remota |
| MSTG‑MANAGED‑6: la app no expone endpoints de depuración | ✅ | Sin red declarada, no hay a qué exponer; `debuggable` solo en la variante `debug` de Gradle |
| MSTG‑MANAGED‑8: anti‑debug y anti‑tamper solo cuando el riesgo lo pide | ⬜ | No se implementa. Un autenticador no depende de ofuscación, y fingirla da sensación de seguridad sin darla. Decisión consciente, pendiente de revisarla si el cliente la exige |

## V5 Plataforma

| Control | Estado | Evidencia |
|---|---|---|
| MSTG‑PLATFORM‑1: la app pide solo los permisos que necesita | ✅ | `CAMERA` (escanear el QR) y `USE_BIOMETRIC`. **No** `INTERNET`: y no solo se omite, el manifiesto de release lo **elimina** (`tools:node="remove"`), porque ML Kit lo añade por telemetría a través de `mobile_scanner`. Una app que promete no ir de red y depende que puede ir de red es una promesa sin respaldo |
| MSTG‑PLATFORM‑2: los WebViews solo con JavaScript habilitado si hace falta | ✅ | No hay WebView |
| MSTG‑PLATFORM‑3: la UI no expone la app cuando hay riesgo | 🟡 | `FLAG_SECURE` bloquea capturas, grabación y miniatura en recientes. Verificado en el APK por compilación; falta comprobarlo en hardware |
| MSTG‑PLATFORM‑8: la UI puede evitar mostrar datos sensibles en segundo plano | ✅ | El interruptor del app bar es un icono; el código de una cuenta se oculta a los 15 s y al reiniciar la app |

## V6 Código

| Control | Estado | Evidencia |
|---|---|---|
| MSTG‑CODE‑1: la app se valida en cada versión | ✅ | `just verify-app`: analyze + clippy + tests + APK release + aserciones de empaquetado (sin permiso de red, librería Rust presente en las tres ABIs) |
| MSTG‑CODE‑2: las prácticas de codificación seguras están definidas y se usan | ✅ | `AGENTS.md`: sin `unwrap`/`expect`/`panic`/indexado fuera de tests, errores tipados, rustdoc en toda API pública |
| MSTG‑CODE‑4: el código de terceros se revisa | 🟡 | Dependencias declaradas con motivo; `cargo deny` cubre el Rust. **No** hay `pub outdated` gateado ni revisión de las dependencias Dart: pendientes |

---

## Qué está verificado y cómo

```bash
just verify-app            # el ciclo completo
```

Comprueba, en este orden: `flutter analyze` sin avisos · `clippy -D warnings` ·
`cargo test` del crate del puente (vectores RFC) · `flutter test` (52 tests) ·
**APK de release** · y sobre el APK construido:

- ninguna declaración de `INTERNET` ni `ACCESS_NETWORK_STATE`;
- `libbandall_authenticator_ffi.so` presente para `arm64-v8a`, `armeabi-v7a` y
  `x86_64`.

Las dos últimas aserciones existen porque las dos fallaron en silencio una vez:
el APK **no declaraba** red que su propia documentación negaba (telemetría de
Google), y **no llevaba dentro** la librería Rust porque `cargokit` deriva el
nombre del artefacto del nombre del *package* y cargo normaliza los guiones a
subrayados — build verde, crash al arrancar.

## Brechas abiertas

1. **Dispositivo real.** Modo avión, reinicio, desinstalación, reloj ±45 s y
   biometría real: nada de esto se puede afirmar desde un emulador. Es la brecha
   que más pesa de esta lista.
2. **iOS.** Configurado, nunca compilado: requiere macOS y Xcode.
3. **Sensor biométrico real.** Los gates se prueban con `AlwaysDenyGate` y
   `AlwaysAllowGate`; el camino del sensor no.
4. **Antiforense del volcado de memoria** en dispositivos con root. En un
   dispositivo con root un atacante ya tiene lo que quiere; no se ha intentado.
5. **Anti‑tamper / anti‑debug.** Decisión consciente de no implementarlo (V4‑8),
   no una omisión.
6. **SBOM y firma del APK** (`cosign`), junto con trivy/grype: desde H5 para la
   imagen, pendiente para la app.
7. **Imagen del emulador** (`iOS Simulator`) para las pruebas de widgets en
   iOS, en vez de solo el runner de Flutter.