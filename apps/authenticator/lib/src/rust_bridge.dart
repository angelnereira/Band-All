/// The real bridge: the generated bindings, adapted to this app's types.
///
/// Two jobs, both about keeping the rest of the app clean:
///
/// 1. The generated code speaks `BigInt` for Rust's `u64` and named
///    parameters. That noise stops here.
/// 2. The generated code surfaces a Rust `Result::Err(String)` by *throwing
///    that string*. Dart lets you throw anything, so a `catch (e)` on
///    `Exception` would miss it entirely. Everything is wrapped into
///    [BridgeError] at this boundary, which is the only place that has to know.
library;

import 'dart:async';

import 'rust/api.dart' as rust;
import 'rust/frb_generated.dart' show RustLib;
import 'bridge.dart';

/// Adapts the generated `flutter_rust_bridge` API to [AuthenticatorBridge].
class RustAuthenticatorBridge implements AuthenticatorBridge {
  RustAuthenticatorBridge();

  /// Loads the native library. Must run before any other method.
  ///
  /// Kept out of the constructor: loading can fail (a missing `.so`, an
  /// architecture mismatch) and the caller needs to handle that, not discover
  /// it as an exception from an unrelated widget build.
  static Future<void> initialize() => RustLib.init();

  @override
  Account parseOtpauth(String uri) => _guard(() {
    final view = rust.parseOtpauth(uri: uri);
    return _toAccount(view);
  });

  @override
  Account manualAccount({
    required String issuer,
    required String name,
    required String secretBase32,
    required String algorithm,
    required int digits,
    required int periodSecs,
  }) => _guard(() {
    final view = rust.manualAccount(
      issuer: issuer,
      name: name,
      algorithm: algorithm,
      digits: digits,
      periodSecs: BigInt.from(periodSecs),
      secretBase32: secretBase32,
    );
    return _toAccount(view);
  });

  @override
  GeneratedCode codeAt(Account account, int unixSecs) => _guard(() {
    final generated = rust.codeAt(
      view: _toView(account),
      unixSecs: BigInt.from(unixSecs),
    );
    return GeneratedCode(
      code: generated.code,
      secondsRemaining: generated.secondsRemaining.toInt(),
    );
  });

  @override
  ClockSkew skew({required int deviceSecs, required int referenceSecs}) =>
      _guard(() {
        final result = rust.skew(
          deviceSecs: BigInt.from(deviceSecs),
          referenceSecs: BigInt.from(referenceSecs),
        );
        return ClockSkew(seconds: result.seconds.toInt(), warns: result.warns);
      });

  @override
  Future<String> exportBackup(List<Account> accounts, String passphrase) =>
      _guardAsync(
        () => rust.exportBackup(
          accounts: accounts.map(_toView).toList(growable: false),
          passphrase: passphrase,
        ),
      );

  @override
  Future<List<Account>> importBackup(String payload, String passphrase) =>
      _guardAsync(() async {
        final views = await rust.importBackup(
          payload: payload,
          passphrase: passphrase,
        );
        return views.map(_toAccount).toList(growable: false);
      });

  /// Whether a secret and its parameters are usable, for manual entry.
  bool isSecretValid({
    required String secretBase32,
    required String algorithm,
    required int digits,
    required int periodSecs,
  }) => rust.isValidSecret(
    secretBase32: secretBase32,
    algorithm: algorithm,
    digits: digits,
    periodSecs: BigInt.from(periodSecs),
  );

  static Account _toAccount(rust.AccountView view) => Account(
    issuer: view.issuer,
    name: view.name,
    secretBase32: view.secretBase32,
    algorithm: view.algorithm,
    digits: view.digits,
    periodSecs: view.periodSecs.toInt(),
  );

  static rust.AccountView _toView(Account account) => rust.AccountView(
    issuer: account.issuer,
    name: account.name,
    secretBase32: account.secretBase32,
    algorithm: account.algorithm,
    digits: account.digits,
    periodSecs: BigInt.from(account.periodSecs),
  );

  /// Runs [body], converting anything it throws into [BridgeError].
  ///
  /// `catch (error)` with no `on` clause is deliberate: the generated code
  /// throws the raw `String` from Rust's `Result::Err`, which is not an
  /// `Exception` and would slip past a narrower catch.
  static T _guard<T>(T Function() body) {
    try {
      return body();
    } catch (error) {
      throw BridgeError(_safeMessage(error));
    }
  }

  static Future<T> _guardAsync<T>(Future<T> Function() body) async {
    try {
      return await body();
    } catch (error) {
      throw BridgeError(_safeMessage(error));
    }
  }

  /// The message the user sees. The Rust side already sends human-readable,
  /// secret-free text; anything else becomes a generic message rather than
  /// leaking a stack trace or an FFI detail into the UI.
  static String _safeMessage(Object error) {
    if (error is BridgeError) return error.message;
    if (error is String && error.isNotEmpty) return error;
    return 'the authenticator core refused that input';
  }
}
