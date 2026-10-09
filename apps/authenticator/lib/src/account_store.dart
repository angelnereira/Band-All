/// Where accounts live between launches.
///
/// The interface exists for two reasons that pull in the same direction:
///
/// 1. The production implementation is backed by the platform keystore
///    (Android Keystore / iOS Keychain), and a test cannot open those.
/// 2. A test that *could* open them would be testing the plugin, not this app.
///
/// What must not happen is a silent fallback: if secure storage fails, the app
/// reports it and keeps the account in memory only. Writing the secret to a
/// plain file "so the user does not lose it" is the one behaviour that would
/// turn this app into a way to steal TOTP secrets.
library;

import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'bridge.dart';

/// Thrown when secure storage is unusable. Carries no secret material.
class SecureStorageUnavailable implements Exception {
  const SecureStorageUnavailable(this.reason);

  final String reason;

  @override
  String toString() => 'secure storage unavailable: $reason';
}

/// Reads and writes the account list.
abstract interface class AccountStore {
  /// Every stored account. Never throws for an empty store.
  Future<List<Account>> load();

  /// Replaces the stored list.
  Future<void> save(List<Account> accounts);
}

/// Production storage: the platform keystore.
///
/// One key holds the whole list as JSON. A per-account key would be tidier but
/// makes the "which accounts exist" question require an index somewhere else,
/// and that index is what leaks metadata. The blob is encrypted by the
/// platform, so its contents are not readable at rest even with the device.
///
/// **Biometrics are not required to read.** The code list refreshes every
/// second and every 30-second step, so a per-read prompt would ask for a
/// fingerprint every half minute and users would turn it off. What biometrics
/// gate is *extraction*: exporting a backup, or revealing a setup key. That is
/// the same line the H7 gate draws ("the secret cannot be extracted without
/// biometrics"), and it is enforced in [AuthenticatorRepository], not here.
class SecureAccountStore implements AccountStore {
  SecureAccountStore({FlutterSecureStorage? storage})
    : _storage =
          storage ??
          const FlutterSecureStorage(
            // The default constructor is the hardware-backed path: an AES
            // key in the Keystore wrapped by RSA-OAEP, never leaving the
            // device. `enforceBiometrics` is left off on purpose (see the
            // class docs); `resetOnError` is on so a corrupted keystore entry
            // fails by erasing rather than by wedging the app.
            aOptions: AndroidOptions(),
            iOptions: IOSOptions(
              // The app must not need the device unlocked at *launch* to list
              // accounts; extraction is gated separately.
              accessibility: KeychainAccessibility.first_unlock,
            ),
          );

  final FlutterSecureStorage _storage;

  static const _key = 'bandall.accounts.v1';

  @override
  Future<List<Account>> load() async {
    final String? raw;
    try {
      raw = await _storage.read(key: _key);
    } on Exception catch (error) {
      throw SecureStorageUnavailable(error.toString());
    }
    if (raw == null || raw.isEmpty) return const [];
    final decoded = jsonDecode(raw);
    if (decoded is! List) {
      throw const SecureStorageUnavailable('stored account list is not a list');
    }
    return decoded
        .whereType<Map<String, Object?>>()
        .map(Account.fromJson)
        .toList(growable: false);
  }

  @override
  Future<void> save(List<Account> accounts) async {
    final payload = jsonEncode(accounts.map((a) => a.toJson()).toList());
    try {
      await _storage.write(key: _key, value: payload);
    } on Exception catch (error) {
      throw SecureStorageUnavailable(error.toString());
    }
  }
}

/// In-memory storage for tests, and the fallback when the keystore cannot be
/// opened: the app stays usable for the session and forgets everything on
/// exit, rather than persisting a secret somewhere unsafe.
class MemoryAccountStore implements AccountStore {
  MemoryAccountStore([List<Account> initial = const []])
    : _accounts = List.of(initial);

  final List<Account> _accounts;

  @override
  Future<List<Account>> load() async => List.unmodifiable(_accounts);

  @override
  Future<void> save(List<Account> accounts) async {
    _accounts
      ..clear()
      ..addAll(accounts);
  }
}
