/// The one place the app talks to Rust.
///
/// Everything else in the app depends on this interface and not on the
/// generated bindings, for two reasons: the widget and storage logic can be
/// tested without a native library, and the generated code is machine-written
/// so nothing hand-written should be entangled with its exact shape.
library;

/// One account, as the UI and the storage see it.
///
/// `secretBase32` is the secret. It exists in memory only while it is needed to
/// draw a code, and it is persisted *only* through [AccountStore], which in
/// production is backed by the platform keystore.
class Account {
  const Account({
    required this.issuer,
    required this.name,
    required this.secretBase32,
    this.algorithm = 'SHA256',
    this.digits = 6,
    this.periodSecs = 30,
  });

  final String issuer;
  final String name;
  final String secretBase32;
  final String algorithm;
  final int digits;
  final int periodSecs;

  /// What the user sees as the row title. An account with no issuer is common
  /// enough (some services ship a bare label) that falling back to the name is
  /// better than rendering an empty line.
  String get displayIssuer => issuer.isEmpty ? name : issuer;

  /// Identity used for the duplicate check and the store.
  ///
  /// The separator is a NUL, written as an escape. Both parts are free
  /// text (an issuer can contain spaces, and account labels routinely
  /// do), so any printable separator could be forged: issuer `"a b"`
  /// with name `"c"` and issuer `"a"` with name `"b c"` would collide
  /// on a space.
  String get storageKey => '$issuer\u0000$name';

  Map<String, Object?> toJson() => {
    'issuer': issuer,
    'name': name,
    'secret_base32': secretBase32,
    'algorithm': algorithm,
    'digits': digits,
    'period_secs': periodSecs,
  };

  static Account fromJson(Map<String, Object?> json) => Account(
    issuer: json['issuer'] as String? ?? '',
    name: json['name'] as String,
    secretBase32: json['secret_base32'] as String,
    algorithm: json['algorithm'] as String? ?? 'SHA256',
    digits: (json['digits'] as num?)?.toInt() ?? 6,
    periodSecs: (json['period_secs'] as num?)?.toInt() ?? 30,
  );

  @override
  String toString() =>
      'Account($displayIssuer, $name, ${algorithm.toLowerCase()}, $digits digits)';
}

/// A generated code and how long it stays valid.
class GeneratedCode {
  const GeneratedCode({required this.code, required this.secondsRemaining});

  final String code;
  final int secondsRemaining;
}

/// Clock drift verdict.
class ClockSkew {
  const ClockSkew({required this.seconds, required this.warns});

  final int seconds;
  final bool warns;
}

/// The operations the app needs from the cryptographic core.
abstract interface class AuthenticatorBridge {
  /// Parses an `otpauth://` URI (a QR scan or a pasted string).
  Account parseOtpauth(String uri);

  /// Builds an account from manual entry.
  Account manualAccount({
    required String issuer,
    required String name,
    required String secretBase32,
    required String algorithm,
    required int digits,
    required int periodSecs,
  });

  /// The code for [unixSecs]. The time is passed in, never read from the clock
  /// inside the core: that is what makes every path testable.
  GeneratedCode codeAt(Account account, int unixSecs);

  /// Compares the device clock against a reference.
  ClockSkew skew({required int deviceSecs, required int referenceSecs});

  /// Encrypts accounts under a passphrase.
  ///
  /// Asynchronous because Argon2id is deliberately slow: it must not block the
  /// UI thread while it derives the key.
  Future<String> exportBackup(List<Account> accounts, String passphrase);

  /// Restores accounts from an encrypted backup.
  Future<List<Account>> importBackup(String payload, String passphrase);
}

/// Raised when the core refuses an input. The message is safe to show: it never
/// carries secret material.
class BridgeError implements Exception {
  const BridgeError(this.message);

  final String message;

  @override
  String toString() => message;
}
