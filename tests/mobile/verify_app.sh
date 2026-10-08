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
printf '  PASS  Rust core bundled for all ABIs\n'