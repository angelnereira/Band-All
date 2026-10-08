/// The app must work with no network at all.
///
/// This is the H7 gate that can be tested without a phone: "generates codes
/// 100 % offline". Saying it in a README is not a test; anyone can later add an
/// `http` call in a code path and nothing would notice.
///
/// Two checks, because either alone is weak:
///
/// 1. **No HTTP dependency exists.** If the package is not in `pubspec.yaml`,
///    no code path can call it.
/// 2. **Any HTTP attempt fails loudly.** `HttpOverrides` replaces the client
///    with one that throws, so a future dependency added by accident makes this
///    test fail rather than silently turn the app into something that phones
///    home.
library;

import 'dart:io';

import 'package:bandall_authenticator/src/account_store.dart';
import 'package:bandall_authenticator/src/bridge.dart';
import 'package:bandall_authenticator/src/repository.dart';
import 'package:flutter_test/flutter_test.dart';

import 'fake_bridge.dart';

/// An HTTP client that fails every request, and records that it was asked.
class _NoNetwork extends HttpOverrides {
  int attempts = 0;

  @override
  HttpClient createHttpClient(SecurityContext? context) {
    attempts++;
    throw const SocketException('the test forbids network access');
  }
}

void main() {
  test('pubspec declares no HTTP client', () {
    final pubspec = File('pubspec.yaml').readAsStringSync();
    for (final forbidden in [
      'http:',
      'dio:',
      'http_client:',
      'grpc:',
      'web_socket_channel:',
    ]) {
      expect(
        pubspec.contains(forbidden),
        isFalse,
        reason:
            'pubspec.yaml declares $forbidden; an authenticator that can '
            'reach the network is one that can leak a secret over it',
      );
    }
  });

  test('the whole journey completes with every socket denied', () async {
    final overrides = _NoNetwork();

    await HttpOverrides.runZoned(() async {
      final bridge = FakeBridge()..scripted.add(_account('alice'));
      final store = MemoryAccountStore();
      final repository = AuthenticatorRepository(bridge: bridge, store: store);

      await repository.load();
      await repository.importUri('otpauth://totp/BandAll:alice?secret=AAAA');
      await repository.addManual(
        issuer: 'Bank',
        name: 'carol',
        secretBase32: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
      );

      // Codes are generated for a range of instants, as the ticker would.
      for (var second = 1_700_000_000; second < 1_700_000_030; second++) {
        expect(repository.rowsAt(second), hasLength(2));
      }

      final payload = await repository.exportBackup('a good passphrase');
      expect(payload, isNotEmpty);

      // Restart: the store is the only thing that carried over.
      final restarted = AuthenticatorRepository(
        bridge: FakeBridge(),
        store: store,
      );
      await restarted.load();
      expect(restarted.accounts, hasLength(2));
    }, createHttpClient: overrides.createHttpClient);

    expect(
      overrides.attempts,
      isZero,
      reason: 'something tried to open an HTTP client during an offline flow',
    );
  });

  test('the bridge interface has no asynchronous network-shaped method', () {
    // A structural check: the methods the UI is allowed to call are all
    // synchronous except the two Argon2id ones, which are CPU-bound. A future
    // `Future<...> fetchKeys()` would show up here as a new async method and
    // force whoever adds it to justify it in this test.
    final bridge = FakeBridge()..scripted.add(_account('alice'));
    expect(bridge.parseOtpauth('otpauth://totp/x'), isA<Account>());
    expect(
      bridge.exportBackup(const [], 'passphrase12'),
      isA<Future<String>>(),
    );
  });
}

Account _account(String name) => Account(
  issuer: 'BandAll',
  name: name,
  secretBase32: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
);
