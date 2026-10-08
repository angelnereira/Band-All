/// The biometric gate, and the policy for when it applies.
///
/// The rule this file exists to enforce: **the secret may be shown as a code
/// without a prompt, but it may not leave the device without one.**
///
/// The distinction is not cosmetic. A code is short-lived and useless to
/// whoever reads it after the step rotates; the secret is permanent and
/// produces every future code. Prompting to draw a code would be noisy enough
/// that people would switch it off, and then the prompt would protect nothing;
/// not prompting before an export means one tap on a shared screen mints every
/// future code the user will ever have.
library;

import 'package:local_auth/local_auth.dart';

/// Raised when the user did not authenticate. Carries no secret material.
class NotAuthenticated implements Exception {
  const NotAuthenticated(this.reason);

  final String reason;

  @override
  String toString() => reason;
}

/// Asks the operating system to verify the user.
abstract interface class BiometricGate {
  /// Whether this device can authenticate at all.
  Future<bool> isAvailable();

  /// Prompts for biometrics (or device credential). Returns whether the user
  /// succeeded. A failure to *ask* is a failure, not a pass.
  Future<bool> authenticate(String reason);
}

/// The real gate: `local_auth` over the platform's biometric APIs.
class PlatformBiometricGate implements BiometricGate {
  PlatformBiometricGate({LocalAuthentication? auth})
    : _auth = auth ?? LocalAuthentication();

  final LocalAuthentication _auth;

  @override
  Future<bool> isAvailable() async {
    try {
      return await _auth.isDeviceSupported();
    } on Exception {
      // A platform that cannot answer is a platform we cannot trust to say
      // "yes": treat it as unavailable.
      return false;
    }
  }

  @override
  Future<bool> authenticate(String reason) async {
    try {
      return await _auth.authenticate(
        localizedReason: reason,
        // Biometric first, device PIN as the fallback: a user with wet hands
        // must still be able to export. `persistAcrossBackgrounding: false` so
        // leaving the app cancels the prompt instead of pre-approving the next
        // attempt.
        biometricOnly: false,
        persistAcrossBackgrounding: false,
      );
    } on Exception {
      // Fails closed: an error asking is not a "yes".
      return false;
    }
  }
}

/// A gate that always says yes, for tests of everything *except* the gate.
///
/// Deliberately named so it cannot be mistaken for the real one at a call site.
class AlwaysAllowGate implements BiometricGate {
  const AlwaysAllowGate();

  @override
  Future<bool> isAvailable() async => true;

  @override
  Future<bool> authenticate(String reason) async => true;
}

/// A gate that always refuses, for the negative tests.
class AlwaysDenyGate implements BiometricGate {
  const AlwaysDenyGate();

  @override
  Future<bool> isAvailable() async => true;

  @override
  Future<bool> authenticate(String reason) async => false;
}
