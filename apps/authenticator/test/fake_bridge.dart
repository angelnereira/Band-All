/// A bridge for tests, with **no cryptography in it**.
///
/// ADR-0016 rules out a second TOTP implementation in Dart: two
/// implementations would mean one of them is never verified against the other,
/// and the one users rely on would be the untested one. So this fake does not
/// pretend to compute real codes. It returns deterministic, obviously-fake
/// values that let the storage, the repository and the widgets be tested for
/// what they are responsible for: keeping a list, refusing duplicates,
/// persisting, and rendering.
///
/// Codes are checked against the RFC and against the server by the Rust tests
/// (`rust/src/tests.rs`) and the container suite, where the real core runs.
library;

import 'package:bandall_authenticator/src/bridge.dart';

class FakeBridge implements AuthenticatorBridge {
  FakeBridge({this.failOnBackup = false});

  /// Makes export/import throw, to test how the UI reports a failed backup.
  final bool failOnBackup;

  /// Cards dealt from the URI parser, in order. Lets a test control exactly
  /// which accounts "arrive" without embedding Base32 in every test.
  final List<Account> scripted = [];

  /// Accounts the fake knows how to re-verify on `codeAt`, keyed by storage
  /// key. Anything else throws, which is how the repository's "skip a corrupt
  /// row" behaviour is exercised.
  final Map<String, bool> known = {};

  int parsed = 0;
  int generated = 0;

  @override
  Account parseOtpauth(String uri) {
    parsed++;
    if (scripted.isEmpty) {
      throw const BridgeError('not a valid otpauth URI');
    }
    final account = scripted.removeAt(0);
    known[account.storageKey] = true;
    return account;
  }

  @override
  Account manualAccount({
    required String issuer,
    required String name,
    required String secretBase32,
    required String algorithm,
    required int digits,
    required int periodSecs,
  }) {
    if (name.isEmpty || secretBase32.isEmpty) {
      throw const BridgeError('invalid account');
    }
    final account = Account(
      issuer: issuer,
      name: name,
      secretBase32: secretBase32,
      algorithm: algorithm,
      digits: digits,
      periodSecs: periodSecs,
    );
    known[account.storageKey] = true;
    return account;
  }

  @override
  GeneratedCode codeAt(Account account, int unixSecs) {
    generated++;
    if (known[account.storageKey] != true) {
      throw const BridgeError('invalid account');
    }
    // Deterministic and fake: the last six digits of the instant, so a widget
    // test can assert the exact string without knowing any crypto.
    final code = (unixSecs % 1000000).toString().padLeft(6, '0');
    return GeneratedCode(
      code: code,
      secondsRemaining: account.periodSecs - (unixSecs % account.periodSecs),
    );
  }

  @override
  ClockSkew skew({required int deviceSecs, required int referenceSecs}) {
    final seconds = (deviceSecs - referenceSecs).abs();
    return ClockSkew(seconds: seconds, warns: seconds > 90);
  }

  /// Cards the fake hands back from `importBackup`.
  final List<Account> restored = [];

  @override
  Future<String> exportBackup(List<Account> accounts, String passphrase) async {
    if (failOnBackup) throw const BridgeError('cannot create the backup');
    // Not encryption: just enough structure for a round-trip test.
    return 'FAKE:${accounts.map((a) => a.storageKey).join('|')}:$passphrase';
  }

  @override
  Future<List<Account>> importBackup(String payload, String passphrase) async {
    if (failOnBackup) throw const BridgeError('cannot open the backup');
    if (!payload.startsWith('FAKE:') || !payload.endsWith(':$passphrase')) {
      throw const BridgeError('cannot open the backup');
    }
    for (final account in restored) {
      known[account.storageKey] = true;
    }
    return List.of(restored);
  }
}
