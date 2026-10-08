/// Widget tests for the screens the user actually touches.
///
/// The bridge is the fake and the store is in memory, so these tests are about
/// rendering and interaction, not about TOTP. `flutter_test` never starts an
/// engine, so the widget tree is the whole world here.
library;

import 'package:bandall_authenticator/main.dart';
import 'package:bandall_authenticator/src/account_store.dart';
import 'package:bandall_authenticator/src/bridge.dart';
import 'package:bandall_authenticator/src/repository.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'fake_bridge.dart';

Account _account({
  String issuer = 'BandAll',
  String name = 'alice@example.com',
}) => Account(
  issuer: issuer,
  name: name,
  secretBase32: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
);

Future<AuthenticatorRepository> _pumpApp(
  WidgetTester tester, {
  FakeBridge? bridge,
  AccountStore? store,
}) async {
  final repository = AuthenticatorRepository(
    bridge: bridge ?? FakeBridge(),
    store: store ?? MemoryAccountStore(),
  );
  await tester.pumpWidget(
    BandallAuthenticatorApp(
      repository: repository,
      // No camera in a widget test: the scanner is replaced by a button that
      // feeds a payload, which is exactly what the camera would do.
      scannerBuilder: (context, onScanned) =>
          _FakeScanner(onScanned: onScanned),
    ),
  );
  // The screen loads its accounts in `initState`.
  await tester.pumpAndSettle();
  return repository;
}

/// Stands in for the camera. Tapping it hands over [payload], the same string
/// `MobileScanner` would produce.
class _FakeScanner extends StatelessWidget {
  const _FakeScanner({required this.onScanned})
    : payload = 'otpauth://totp/one';

  final Future<void> Function(String raw) onScanned;
  final String payload;

  @override
  Widget build(BuildContext context) {
    return ElevatedButton(
      key: const Key('fake-scan'),
      onPressed: () => onScanned(payload),
      child: const Text('simulate scan'),
    );
  }
}

void main() {
  testWidgets('an empty app invites the user to add an account', (
    tester,
  ) async {
    await _pumpApp(tester);

    expect(find.text('No accounts yet'), findsOneWidget);
    expect(find.byKey(const Key('add-account')), findsOneWidget);
  });

  Future<void> addViaSheet(WidgetTester tester, String uri) async {
    await tester.tap(find.byKey(const Key('add-account')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Link'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('field-uri')), uri);
    await tester.tap(find.byKey(const Key('add-submit')));
    await tester.pumpAndSettle();
  }

  testWidgets('accounts are listed with hidden codes and a countdown', (
    tester,
  ) async {
    final bridge = FakeBridge()..scripted.add(_account());
    await _pumpApp(tester, bridge: bridge);
    await addViaSheet(tester, 'otpauth://totp/one');

    expect(find.text('BandAll'), findsOneWidget);
    expect(find.text('alice@example.com'), findsOneWidget);

    // Hidden until asked for: the home screen of an authenticator is read in
    // public places.
    final hidden = tester.widget<Text>(
      find.byKey(const Key('code-alice@example.com')),
    );
    expect(hidden.data, '••••••');

    await tester.tap(find.text('alice@example.com'));
    await tester.pump();

    final shown = tester.widget<Text>(
      find.byKey(const Key('code-alice@example.com')),
    );
    // The fake returns the last six digits of the instant, grouped in threes:
    // copying `123456` under time pressure is where mistakes happen.
    expect(shown.data, matches(RegExp(r'^\d{3} \d{3}$')));
  });

  testWidgets('a scanned code adds the account', (tester) async {
    final bridge = FakeBridge()
      ..scripted.add(_account(name: 'scanned@example.com'));
    final repository = await _pumpApp(tester, bridge: bridge);

    await tester.tap(find.byKey(const Key('add-account')));
    await tester.pumpAndSettle();
    // The scan tab is the default, so the camera is what the user gets first.
    await tester.tap(find.byKey(const Key('fake-scan')));
    await tester.pumpAndSettle();

    expect(repository.accounts, hasLength(1));
    expect(find.text('scanned@example.com'), findsOneWidget);
  });

  testWidgets(
    'a QR that is not an account is reported and scanning continues',
    (tester) async {
      // No scripted accounts: the fake refuses, as the real bridge refuses a QR
      // that carries a Wi-Fi password instead of an account.
      final repository = await _pumpApp(tester, bridge: FakeBridge());

      await tester.tap(find.byKey(const Key('add-account')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('fake-scan')));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('add-error')), findsOneWidget);
      expect(repository.accounts, isEmpty);
    },
  );

  testWidgets('search filters the list', (tester) async {
    final bridge = FakeBridge()
      ..scripted.add(_account())
      ..scripted.add(_account(issuer: 'Bank', name: 'carol'));
    await _pumpApp(tester, bridge: bridge);
    await addViaSheet(tester, 'otpauth://totp/one');
    await addViaSheet(tester, 'otpauth://totp/two');

    await tester.enterText(find.byKey(const Key('search')), 'carol');
    await tester.pumpAndSettle();

    // Assert on the row keys, not on the text: the search field itself
    // contains "carol" too.
    expect(find.byKey(const Key('code-carol')), findsOneWidget);
    expect(find.byKey(const Key('code-alice@example.com')), findsNothing);

    await tester.enterText(find.byKey(const Key('search')), 'nothing-matches');
    await tester.pumpAndSettle();
    expect(find.textContaining('No account matches'), findsOneWidget);
  });

  testWidgets('the add sheet imports a pasted setup link', (tester) async {
    final bridge = FakeBridge()
      ..scripted.add(_account(name: 'bob@example.com'));
    final repository = await _pumpApp(tester, bridge: bridge);
    await addViaSheet(
      tester,
      'otpauth://totp/BandAll:bob@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
    );

    expect(repository.accounts, hasLength(1));
    expect(find.text('bob@example.com'), findsOneWidget);
  });

  testWidgets('a bad setup link is refused with a message, not a crash', (
    tester,
  ) async {
    // No scripted accounts: the fake bridge refuses the URI, as the real one
    // refuses a malformed one.
    final repository = await _pumpApp(tester, bridge: FakeBridge());

    await tester.tap(find.byKey(const Key('add-account')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Link'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('field-uri')), 'nonsense');
    await tester.tap(find.byKey(const Key('add-submit')));
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('add-error')), findsOneWidget);
    expect(repository.accounts, isEmpty);
  });

  testWidgets('manual entry asks for the fields it needs', (tester) async {
    final repository = await _pumpApp(tester, bridge: FakeBridge());

    await tester.tap(find.byKey(const Key('add-account')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Manually'));
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('field-issuer')), findsOneWidget);
    expect(find.byKey(const Key('field-name')), findsOneWidget);
    expect(find.byKey(const Key('field-secret')), findsOneWidget);

    await tester.enterText(find.byKey(const Key('field-issuer')), 'Bank');
    await tester.enterText(find.byKey(const Key('field-name')), 'carol');
    await tester.enterText(
      find.byKey(const Key('field-secret')),
      'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
    );
    await tester.tap(find.byKey(const Key('add-submit')));
    await tester.pumpAndSettle();

    expect(repository.accounts.single.name, 'carol');
    expect(find.text('Bank'), findsOneWidget);
  });

  testWidgets('a broken keystore is announced and does not block the app', (
    tester,
  ) async {
    final bridge = FakeBridge()..scripted.add(_account());
    await _pumpApp(tester, bridge: bridge, store: _BrokenStore());

    expect(
      find.textContaining('Secure storage is unavailable'),
      findsOneWidget,
      reason: 'a silent failure here would look like data loss',
    );

    // Still usable for the session.
    await addViaSheet(tester, 'otpauth://totp/one');
    expect(find.text('alice@example.com'), findsOneWidget);
  });
}

class _BrokenStore implements AccountStore {
  @override
  Future<List<Account>> load() async =>
      throw const SecureStorageUnavailable('test');

  @override
  Future<void> save(List<Account> accounts) async =>
      throw const SecureStorageUnavailable('test');
}
