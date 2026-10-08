/// The app's logic, with no Flutter widgets in it.
///
/// Everything here is testable without a device, which is where the properties
/// that matter (a duplicate is refused, a code matches the core, the list
/// survives a restart) are actually checked.
library;

import 'bridge.dart';
import 'account_store.dart';
import 'biometric_gate.dart';

/// What the UI renders for one account.
class AccountRow {
  const AccountRow({
    required this.account,
    required this.code,
    required this.secondsRemaining,
  });

  final Account account;
  final String code;
  final int secondsRemaining;

  String get displayIssuer => account.displayIssuer;
  String get displayName => account.name;

  /// The code split for display: `123 456` reads far better than `123456` when
  /// someone is copying it onto a login form under time pressure.
  String get grouped {
    final buffer = StringBuffer();
    for (var i = 0; i < code.length; i += 3) {
      if (i > 0) buffer.write(' ');
      buffer.write(code.substring(i, (i + 3).clamp(0, code.length)));
    }
    return buffer.toString();
  }
}

/// How far through the current step the UI is, for the countdown ring.
double codeProgress(int secondsRemaining, int periodSecs) {
  if (periodSecs <= 0) return 0;
  return (periodSecs - secondsRemaining) / periodSecs;
}

/// Orchestrates the bridge and the store.
///
/// Holds the account list in memory as the source of truth for the UI and
/// writes through to the store on every change, so a crash between "added" and
/// "persisted" cannot leave the UI showing an account the next launch would not
/// have.
class AuthenticatorRepository {
  AuthenticatorRepository({
    required AuthenticatorBridge bridge,
    required AccountStore store,
    BiometricGate gate = const AlwaysAllowGate(),
  }) : _bridge = bridge,
       _store = store,
       _gate = gate;

  final AuthenticatorBridge _bridge;
  final AccountStore _store;
  final BiometricGate _gate;
  final List<Account> _accounts = [];

  /// Raised when the store could not be read or written. The UI shows this and
  /// keeps working for the session; it never silently writes somewhere else.
  SecureStorageUnavailable? storageProblem;

  /// Reads the stored accounts. Call once at startup.
  Future<void> load() async {
    try {
      _accounts
        ..clear()
        ..addAll(await _store.load());
      storageProblem = null;
    } on SecureStorageUnavailable catch (error) {
      // Keep whatever is in memory: the user can still use the app this
      // session. Persisting elsewhere is the one thing we do not do.
      storageProblem = error;
    }
  }

  List<Account> get accounts => List.unmodifiable(_accounts);

  /// Imports from an `otpauth://` URI (a QR scan or a pasted string).
  Future<Account> importUri(String uri) async {
    final account = _bridge.parseOtpauth(uri);
    await _add(account);
    return account;
  }

  /// Adds an account entered by hand.
  Future<Account> addManual({
    required String issuer,
    required String name,
    required String secretBase32,
    String algorithm = 'SHA256',
    int digits = 6,
    int periodSecs = 30,
  }) async {
    final account = _bridge.manualAccount(
      issuer: issuer,
      name: name,
      secretBase32: secretBase32,
      algorithm: algorithm,
      digits: digits,
      periodSecs: periodSecs,
    );
    await _add(account);
    return account;
  }

  Future<void> _add(Account account) async {
    final duplicate = _accounts.any((a) => a.storageKey == account.storageKey);
    if (duplicate) {
      throw const BridgeError('that account is already in the list');
    }
    _accounts.add(account);
    await _persist();
  }

  /// Removes an account by its display identity.
  Future<void> remove(Account account) async {
    _accounts.removeWhere((a) => a.storageKey == account.storageKey);
    await _persist();
  }

  Future<void> _persist() async {
    try {
      await _store.save(_accounts);
      storageProblem = null;
    } on SecureStorageUnavailable catch (error) {
      // The in-memory list stays correct for this session.
      storageProblem = error;
    }
  }

  /// The rows to render for `unixSecs`.
  ///
  /// An account whose code cannot be generated is skipped rather than crashing
  /// the list: one corrupt row must not hide the others, which may be the only
  /// way the user can still log in somewhere.
  List<AccountRow> rowsAt(int unixSecs) {
    final rows = <AccountRow>[];
    for (final account in _accounts) {
      try {
        final generated = _bridge.codeAt(account, unixSecs);
        rows.add(
          AccountRow(
            account: account,
            code: generated.code,
            secondsRemaining: generated.secondsRemaining,
          ),
        );
      } on BridgeError {
        continue;
      }
    }
    return rows;
  }

  /// Clock-drift verdict against a reference time (the server's, when known).
  ClockSkew skewAgainst(int referenceSecs, int deviceSecs) =>
      _bridge.skew(deviceSecs: deviceSecs, referenceSecs: referenceSecs);

  /// The encrypted backup the user can keep.
  ///
  /// Requires the user to authenticate first: the backup holds every secret in
  /// the clear until the passphrase is applied, which makes it the single most
  /// valuable thing this app can produce. The gate runs inside the bridge's
  /// async hop, so the prompt is a spinner to the rest of the app.
  Future<String> exportBackup(String passphrase) async {
    await _requireUser('Authenticate to export your accounts');
    return _bridge.exportBackup(accounts, passphrase);
  }

  /// The setup key of an account, for the "show me the secret" affordance.
  ///
  /// Same rule as the export: a code is ephemeral, a secret is not.
  Future<String> revealSecret(Account account) async {
    await _requireUser('Authenticate to reveal the setup key');
    return account.secretBase32;
  }

  /// Fails closed: a gate that cannot answer, or answers no, denies.
  Future<void> _requireUser(String reason) async {
    if (!await _gate.isAvailable()) {
      throw const NotAuthenticated('this device has no biometrics configured');
    }
    if (!await _gate.authenticate(reason)) {
      throw const NotAuthenticated('authentication was not completed');
    }
  }

  /// Restores accounts from a backup, skipping the ones already present.
  ///
  /// Skipping rather than failing: a user restoring onto a device that already
  /// has some accounts should get the missing ones, not an error that leaves
  /// them choosing between "all" and "nothing".
  ///
  /// No biometric gate here: the user is *adding* secrets they already possess,
  /// and the payload cannot be opened without the passphrase anyway.
  Future<int> importBackup(String payload, String passphrase) async {
    final restored = await _bridge.importBackup(payload, passphrase);
    var added = 0;
    for (final account in restored) {
      if (_accounts.any((a) => a.storageKey == account.storageKey)) continue;
      _accounts.add(account);
      added++;
    }
    if (added > 0) await _persist();
    return added;
  }
}
