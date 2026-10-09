#!/usr/bin/env bash
# Verify the mobile app the way `tests/container/verify.sh` verifies the
# service: build the artifact and check the properties that matter, rather than
# trusting the source tree.
#
# The two checks that cannot be done any other way:
#
#   * the Rust library is actually inside the APK (cargokit fails silently if
#     the crate name and the artifact name disagree: the APK builds and the app
#     dies on the first call into the core);
#   * the release APK declares no INTERNET permission. The claim "the app is
#     100% offline" is worth nothing as a promise; as a missing permission it is
#     something Android enforces.
#
# Requires the toolchain from `install_toolchain.sh`.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$(cd "$HERE/../../apps/authenticator" && pwd)"

section() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1"; exit 1; }

if [ -f "$HOME/.config/bandall-flutter-env.sh" ]; then
    # shellcheck source=/dev/null
    . "$HOME/.config/bandall-flutter-env.sh"
fi

command -v flutter >/dev/null 2>&1 || fail "flutter is not on PATH; run tests/mobile/install_toolchain.sh"
command -v cargo >/dev/null 2>&1 || fail "cargo is not on PATH"

# --------------------------------------------------------------------------
section "flutter analyze (static analysis, lint as error)"
# --------------------------------------------------------------------------
cd "$APP"
flutter analyze --no-pub

# --------------------------------------------------------------------------
section "rust core of the app (RFC vectors, backup, no secrets in Debug)"
# --------------------------------------------------------------------------
cd "$APP/rust"
cargo test --quiet
cargo clippy --all-targets -- -D warnings

# --------------------------------------------------------------------------
section "dart tests (repository, widgets, offline proof)"
# --------------------------------------------------------------------------
cd "$APP"
flutter test --no-pub

# --------------------------------------------------------------------------
section "release APK"
# --------------------------------------------------------------------------
# --release, not --debug: the debug manifest adds INTERNET for the hot-reload
# channel, so a debug build can never prove the offline property.
flutter build apk --release
APK="$APP/build/app/outputs/flutter-apk/app-release.apk"
[ -f "$APK" ] || fail "no release APK was produced"
echo "apk: $(du -h "$APK" | cut -f1)"

AAPT="$(find "${ANDROID_HOME:-$HOME/Android/Sdk}/build-tools" -name aapt2 -type f 2>/dev/null | sort -V | tail -1)"
[ -n "$AAPT" ] || fail "aapt2 not found; is the Android SDK installed?"

PERMISSIONS="$("$AAPT" dump permissions "$APK")"
echo "$PERMISSIONS" | sed 's/^/  /'

# The property ADR-0016 promises. Android refuses network access to an app
# without INTERNET, so this is enforced rather than documented.
if grep -q "android.permission.INTERNET" <<<"$PERMISSIONS"; then
    fail "the release APK requests INTERNET: the app is not offline, whatever the docs say"
fi
if grep -q "android.permission.ACCESS_NETWORK_STATE" <<<"$PERMISSIONS"; then
    fail "the release APK requests ACCESS_NETWORK_STATE"
fi
echo "  -> no network permission: enforced by the platform"

# The camera must be there (QR enrolment) and the biometrics permission too.
grep -q "android.permission.CAMERA" <<<"$PERMISSIONS" || fail "the APK cannot scan a QR: CAMERA is missing"
grep -q "android.permission.USE_BIOMETRIC" <<<"$PERMISSIONS" || fail "USE_BIOMETRIC is missing"

# --------------------------------------------------------------------------
section "no backup, no screenshots"
# --------------------------------------------------------------------------
# H7 item 6. Both properties are silent when they regress: a missing
# `allowBackup` or an unmapped FLAG_SECURE produces a perfectly healthy build,
# so they are read out of the built APK rather than trusted from the manifest
# in the source tree.
MANIFEST="$("$AAPT" dump xmltree "$APK" --file AndroidManifest.xml)"

# `aapt2` prints attributes as
#   A: http://schemas.android.com/apk/res/android:allowBackup(0x01010280)=false
# so there is no `(Raw: ...)` marker to grep on: the resource id and the value
# are on the same line. An attribute that is absent from the dump is absent
# from the manifest, which is what the failure has to catch.
ALLOW_BACKUP="$(grep -E 'android:allowBackup\(' <<<"$MANIFEST" || true)"
case "$ALLOW_BACKUP" in
    *"=false") echo "  -> android:allowBackup = false" ;;
    *) fail "the release manifest does not set android:allowBackup=false: accounts would be copied to the cloud" ;;
esac

# `allowBackup="false"` is not enough on Android 12+ for device-to-device
# transfer, so the extraction rules have to be referenced too. Whether the
# attribute points at a file, and not at nothing.
EXTRACT="$(grep -E 'android:dataExtractionRules\(' <<<"$MANIFEST" || true)"
case "$EXTRACT" in
    *"=@0x"*) echo "  -> android:dataExtractionRules referenced" ;;
    *) fail "no android:dataExtractionRules: on Android 12+ allowBackup alone does not stop device-to-device transfer" ;;
esac

FULL_BACKUP="$(grep -E 'android:fullBackupContent\(' <<<"$MANIFEST" || true)"
case "$FULL_BACKUP" in
    *"=@0x"*) echo "  -> android:fullBackupContent referenced" ;;
    *) fail "no android:fullBackupContent for the pre-Android-12 path" ;;
esac

# The contents of those rules cannot be read back from the APK: release builds
# rename `res/xml/*.xml` to opaque names, so there is no path to ask aapt2 for.
# What can be asserted is that the source the build consumes really excludes
# everything, which is where a regression would actually happen.
#
# The two files are different formats on purpose: `data_extraction_rules.xml` is
# `<data-extraction-rules>` with `cloud-backup` and `device-transfer` sections
# (Android 12+), while `backup_rules.xml` is the pre-12 `<full-backup-content>`
# form, which has no sections at all. Checking one against the other's shape is
# a mistake, so each is checked against its own.
EXTRACTION_FILE="$APP/android/app/src/main/res/xml/data_extraction_rules.xml"
[ -f "$EXTRACTION_FILE" ] || fail "$EXTRACTION_FILE is missing"
grep -q 'domain="root"' "$EXTRACTION_FILE" \
    || fail "data_extraction_rules.xml does not exclude the root domain: backup could carry the account blob"
grep -q '<cloud-backup>' "$EXTRACTION_FILE" \
    || fail "data_extraction_rules.xml has no cloud-backup section"
grep -q '<device-transfer>' "$EXTRACTION_FILE" \
    || fail "data_extraction_rules.xml has no device-transfer section: Android 12+ transfer would still work"
echo "  -> data_extraction_rules.xml excludes root, cloud-backup and device-transfer"

FULL_FILE="$APP/android/app/src/main/res/xml/backup_rules.xml"
[ -f "$FULL_FILE" ] || fail "$FULL_FILE is missing"
grep -q 'full-backup-content' "$FULL_FILE" \
    || fail "backup_rules.xml is not a <full-backup-content> file: the pre-Android-12 path would back up"
grep -q 'domain="root"' "$FULL_FILE" \
    || fail "backup_rules.xml does not exclude the root domain"
echo "  -> backup_rules.xml is a <full-backup-content> file that excludes root"

# FLAG_SECURE has no manifest attribute: it is a window flag set in
# MainActivity. So the assertion is that the flag is actually set in the code
# that runs, which is the only place it can be.
MAIN_ACTIVITY="$APP/android/app/src/main/kotlin/dev/bandall/bandall_authenticator/MainActivity.kt"
grep -q 'FLAG_SECURE' "$MAIN_ACTIVITY" \
    || fail "MainActivity no longer sets FLAG_SECURE: screenshots and recents thumbnails would show the codes"
grep -q 'setFlags' "$MAIN_ACTIVITY" \
    || fail "FLAG_SECURE is mentioned but never applied"
echo "  -> FLAG_SECURE is applied in MainActivity"

# --------------------------------------------------------------------------
section "the Rust core is inside the APK"
# --------------------------------------------------------------------------
# `cargokit` derives the file it looks for from the Cargo *package* name, while
# cargo normalises dashes to underscores. When the two disagree it copies
# nothing and the build still succeeds, so the presence of the library is
# checked here and not assumed.
LIBS="$(unzip -l "$APK" | awk '{print $4}' | grep -E '^lib/.*libbandall_authenticator_ffi\.so$' || true)"
[ -n "$LIBS" ] || fail "the APK has no libbandall_authenticator_ffi.so: the app would crash on the first call into the core"
echo "$LIBS" | sed 's/^/  /'
for abi in arm64-v8a armeabi-v7a x86_64; do
    grep -q "lib/$abi/libbandall_authenticator_ffi.so" <<<"$LIBS" \
        || fail "no Rust library for $abi"
done
echo "  -> present for every ABI the build targets"

printf '\n\033[1m== result\033[0m\n'
printf '  PASS  analyze + lint\n'
printf '  PASS  rust core tests and clippy\n'
printf '  PASS  dart tests (offline proof included)\n'
printf '  PASS  release APK built\n'
printf '  PASS  no network permission (platform-enforced)\n'
printf '  PASS  no cloud backup and no device transfer\n'
printf '  PASS  FLAG_SECURE applied\n'
printf '  PASS  Rust core bundled for all ABIs\n'