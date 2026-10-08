/// Repository and storage behaviour.
///
/// The bridge here is the fake: these tests are about the list, duplicates,
/// persistence and corrupt rows, not about TOTP. The cryptography is tested in
/// `rust/src/tests.rs`, against the RFC vectors, with the real core.
library;

import 'package:bandall_authenticator/src/account_store.dart';
import 'package:bandall_authenticator/src/biometric_gate.dart';
import 'package:bandall_authenticator/src/bridge.dart';
import 'package:bandall_authenticator/src/repository.dart';
import 'package:flutter_test/flutter_test.dart';

import 'fake_bridge.dart';

const _alice = Account(
  issuer: 'BandAll',
  name: 'alice@example.com',
  secretBase32: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
);

const _bob = Account(
  issuer: 'Other',
  name: 'bob@example.com',
  secretBase32: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
);

Account _bank() => const Account(
  issuer: 'Bank',
  name: 'carol',
  secretBase32: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
);

void main() {
  group('adding accounts', () {
    test('an imported account lands in the list and in storage', () async {
      final bridge = FakeBridge()..scripted.add(_alice);
      final store = MemoryAccountStore();
      final repository = AuthenticatorRepository(bridge: bridge, store: store);

      await repository.load();
      expect(repository.accounts, isEmpty);

      await repository.importUri('otpauth://totp/...');

      expect(repository.accounts, hasLength(1));
      expect(repository.accounts.single.name, 'alice@example.com');
      // Written through, not just held in memory.
      expect(await store.load(), hasLength(1));
    });

    test('a duplicate is refused and nothing is written', () async {
      final bridge = FakeBridge()
        ..scripted.add(_alice)
        ..scripted.add(_alice);
      final store = MemoryAccountStore();
      final repository = AuthenticatorRepository(bridge: bridge, store: store);
      await repository.load();

      await repository.importUri('otpauth://totp/one');
      expect(
        () => repository.importUri('otpauth://totp/two'),
        throwsA(isA<BridgeError>()),
      );
      expect(repository.accounts, hasLength(1));
      expect(await store.load(), hasLength(1));
    });

    test('manual entry goes through the bridge validation', () async {
      final bridge = FakeBridge();
      final repository = AuthenticatorRepository(
        bridge: bridge,
        store: MemoryAccountStore(),
      );
      await repository.load();

      final account = await repository.addManual(
        issuer: 'BandAll',
        name: 'dave',
        secretBase32: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
      );
      expect(account.name, 'dave');
      // The core is the validator; the repository does not re-implement it.
      expect(
        () => repository.addManual(issuer: '', name: '', secretBase32: ''),
        throwsA(isA<BridgeError>()),
      );
    });

    test('removing takes it out of storage too', () async {
      final bridge = FakeBridge()..scripted.add(_alice);
      final store = MemoryAccountStore();
      final repository = AuthenticatorRepository(bridge: bridge, store: store);
      await repository.load();
      await repository.importUri('otpauth://totp/one');

      await repository.remove(repository.accounts.single);

      expect(repository.accounts, isEmpty);
      expect(await store.load(), isEmpty);
    });
  });

  group('starting up', () {
    test('accounts stored before are there after a restart', () async {
      final store = MemoryAccountStore([_alice, _bob]);
      final repository = AuthenticatorRepository(
        bridge: FakeBridge(),
        store: store,
      );

      await repository.load();

      expect(repository.accounts.map((a) => a.name), [
        'alice@example.com',
        'bob@example.com',
      ]);
    });

    test('a broken keystore is reported and the app keeps working', () async {
      final repository = AuthenticatorRepository(
        bridge: FakeBridge()..scripted.add(_alice),
        store: _UnavailableStore(),
      );

      await repository.load();
      expect(
        repository.storageProblem,
        isNotNull,
        reason: 'the failure must be visible, not swallowed',
      );
      expect(repository.accounts, isEmpty);

      // Still usable for the session.
      await repository.importUri('otpauth://totp/one');
      expect(repository.accounts, hasLength(1));
    });
  });

  group('drawing rows', () {
    test('every account gets a code and a countdown', () async {
      final bridge = FakeBridge()..scripted.add(_alice);
      final repository = AuthenticatorRepository(
        bridge: bridge,
        store: MemoryAccountStore(),
      );
      await repository.load();
      await repository.importUri('otpauth://totp/one');

      final rows = repository.rowsAt(1_700_000_000);

      expect(rows, hasLength(1));
      expect(rows.single.code, '000000');
      expect(rows.single.secondsRemaining, 10); // 30 - (1700000000 % 30)
    });

    test('a code is grouped for reading', () async {
      final bridge = FakeBridge()..scripted.add(_alice);
      final repository = AuthenticatorRepository(
        bridge: bridge,
        store: MemoryAccountStore(),
      );
      await repository.load();
      await repository.importUri('otpauth://totp/one');

      final row = repository.rowsAt(1_700_000_123).single;
      expect(row.code, '000123');
      expect(
        row.grouped,
        '000 123',
        reason: 'six digits in a row are hard to copy under time pressure',
      );
    });

    test('one unreadable account does not hide the others', () async {
      // The store holds two accounts, but the bridge only knows how to
      // generate a code for one of them: a corrupt row must not take the list
      // down, because the other row may be the only way to log in somewhere.
      final bridge = FakeBridge();
      bridge.known[_alice.storageKey] = true;
      // _bob is deliberately absent from `known`.
      final repository = AuthenticatorRepository(
        bridge: bridge,
        store: MemoryAccountStore([_alice, _bob]),
      );
      await repository.load();

      final rows = repository.rowsAt(1_700_000_000);

      expect(rows, hasLength(1));
      expect(rows.single.account.name, 'alice@example.com');
    });
  });

  group('code progress', () {
    test('runs from empty to full across a step', () {
      expect(codeProgress(30, 30), 0);
      expect(codeProgress(15, 30), 0.5);
      expect(codeProgress(1, 30), closeTo(0.967, 0.001));
    });

    test('a zero period does not divide by zero', () {
      expect(codeProgress(5, 0), 0);
    });
  });

  group('backup', () {
    test('export passes the accounts to the bridge', () async {
      final bridge = FakeBridge()..scripted.add(_alice);
      final repository = AuthenticatorRepository(
        bridge: bridge,
        store: MemoryAccountStore(),
      );
      await repository.load();
      await repository.importUri('otpauth://totp/one');

      final payload = await repository.exportBackup('a good passphrase');

      expect(payload, contains('alice@example.com'));
      expect(payload, contains('BandAll'));
    });

    test('a failed export surfaces as a bridge error', () async {
      final repository = AuthenticatorRepository(
        bridge: FakeBridge(failOnBackup: true),
        store: MemoryAccountStore(),
      );
      await repository.load();

      expect(
        () => repository.exportBackup('a good passphrase'),
        throwsA(isA<BridgeError>()),
      );
    });

    test('import skips accounts that are already present', () async {
      final bridge = FakeBridge()..scripted.add(_alice);
      bridge.restored.addAll([_alice, _bank()]);
      final store = MemoryAccountStore();
      final repository = AuthenticatorRepository(bridge: bridge, store: store);
      await repository.load();
      await repository.importUri('otpauth://totp/one');

      final payload = await repository.exportBackup('passphrase12');
      final added = await repository.importBackup(payload, 'passphrase12');

      expect(added, 1, reason: 'alice is already there; only carol is new');
      expect(
        repository.accounts.map((a) => a.name),
        containsAll(['alice@example.com', 'carol']),
      );
      expect(await store.load(), hasLength(2));
    });
  });

  group('clock skew', () {
    test('a small drift does not warn', () async {
      final repository = AuthenticatorRepository(
        bridge: FakeBridge(),
        store: MemoryAccountStore(),
      );
      final skew = repository.skewAgainst(1_700_000_000, 1_700_000_030);
      expect(skew.seconds, 30);
      expect(skew.warns, isFalse);
    });

    test('a large drift warns, in both directions', () async {
      final repository = AuthenticatorRepository(
        bridge: FakeBridge(),
        store: MemoryAccountStore(),
      );
      expect(
        repository.skewAgainst(1_700_000_000, 1_700_000_200).warns,
        isTrue,
      );
      expect(
        repository.skewAgainst(1_700_000_200, 1_700_000_000).warns,
        isTrue,
      );
    });
  });

  group('the biometric gate', () {
    /// The rule being tested: a code is ephemeral, the secret is not. Drawing a
    /// code must not prompt (it would prompt every 30 s and users would turn
    /// the feature off), but extraction must.
    Future<AuthenticatorRepository> withAccounts(BiometricGate gate) async {
      final repository = AuthenticatorRepository(
        bridge: FakeBridge()..scripted.add(_alice),
        store: MemoryAccountStore(),
        gate: gate,
      );
      await repository.load();
      await repository.importUri('otpauth://totp/one');
      return repository;
    }

    test('drawing codes never asks the user', () async {
      // AlwaysDenyGate would make any prompt fail, so if drawing worked, it
      // did not prompt.
      final repository = await withAccounts(const AlwaysDenyGate());
      expect(repository.rowsAt(1_700_000_000), hasLength(1));
    });

    test(
      'exporting a backup is refused when the user does not authenticate',
      () async {
        final repository = await withAccounts(const AlwaysDenyGate());
        expect(
          () => repository.exportBackup('a good passphrase'),
          throwsA(isA<NotAuthenticated>()),
        );
      },
    );

    test(
      'revealing a setup key is refused when the user does not authenticate',
      () async {
        final repository = await withAccounts(const AlwaysDenyGate());
        expect(
          () => repository.revealSecret(repository.accounts.single),
          throwsA(isA<NotAuthenticated>()),
        );
      },
    );

    test('a device with no biometrics fails closed', () async {
      final repository = await withAccounts(_NoBiometrics());
      expect(
        () => repository.exportBackup('a good passphrase'),
        throwsA(isA<NotAuthenticated>()),
      );
    });

    test('an authenticated user can export and reveal', () async {
      final repository = await withAccounts(const AlwaysAllowGate());
      final payload = await repository.exportBackup('a good passphrase');
      expect(payload, contains('alice@example.com'));
      final secret = await repository.revealSecret(repository.accounts.single);
      expect(secret, _alice.secretBase32);
    });
  });
}

/// A device that cannot authenticate at all (no enrolment, no hardware).
class _NoBiometrics implements BiometricGate {
  @override
  Future<bool> isAvailable() async => false;

  @override
  Future<bool> authenticate(String reason) async =>
      throw StateError('must not be asked when unavailable');
}

/// A store that always fails, standing in for a device whose keystore cannot
/// be opened.
class _UnavailableStore implements AccountStore {
  @override
  Future<List<Account>> load() async =>
      throw const SecureStorageUnavailable('test');

  @override
  Future<void> save(List<Account> accounts) async =>
      throw const SecureStorageUnavailable('test');
}
