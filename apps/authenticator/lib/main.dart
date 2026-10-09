/// BandAll Authenticator: the end-user app.
///
/// Scope (ADR-0016): this is the **TOTP authenticator** role. It holds factors
/// and generates codes offline, and it works against any service that uses
/// BandAll — or any other TOTP implementation — because the factor format is a
/// standard `otpauth://` URI. The "sign in through BandAll with a primary
/// credential" role depends on a decision that is still open (ADR-0012) and is
/// not built here.
///
/// The UI owns no cryptography. Every code comes from the Rust core across the
/// bridge, which is the only implementation of TOTP in this project.
library;

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import 'src/account_store.dart';
import 'src/biometric_gate.dart';
import 'src/bridge.dart';
import 'src/clock.dart';
import 'src/repository.dart';
import 'src/rust_bridge.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustAuthenticatorBridge.initialize();
  runApp(
    BandallAuthenticatorApp(
      repository: AuthenticatorRepository(
        bridge: RustAuthenticatorBridge(),
        store: SecureAccountStore(),
        gate: PlatformBiometricGate(),
      ),
    ),
  );
}

/// Builds the scanner widget for a given callback. Tests inject a placeholder
/// so no widget test has to open a camera.
typedef ScannerBuilder = Widget Function(
  BuildContext context,
  Future<void> Function(String raw) onScanned,
);

/// The application widget. Takes its repository so tests can inject a fake
/// bridge and an in-memory store, and its scanner so widget tests need no
/// camera.
class BandallAuthenticatorApp extends StatelessWidget {
  const BandallAuthenticatorApp({
    super.key,
    required this.repository,
    this.scannerBuilder,
  });

  final AuthenticatorRepository repository;
  final ScannerBuilder? scannerBuilder;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'BandAll Authenticator',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF1F6FEB)),
        useMaterial3: true,
      ),
      home: AccountListScreen(
        repository: repository,
        scannerBuilder: scannerBuilder,
      ),
    );
  }
}

/// The account list: the screen the user actually lives in.
class AccountListScreen extends StatefulWidget {
  const AccountListScreen({
    super.key,
    required this.repository,
    this.scannerBuilder,
  });

  final AuthenticatorRepository repository;
  final ScannerBuilder? scannerBuilder;

  @override
  State<AccountListScreen> createState() => _AccountListScreenState();
}

class _AccountListScreenState extends State<AccountListScreen> {
  Timer? _ticker;

  /// Codes follow this clock, not the wall clock.
  ///
  /// Anchored once at construction and advanced from a monotonic stopwatch, so
  /// an NTP correction or a timezone change in the middle of the session does
  /// not change every visible code while the user is reading one. The anchor is
  /// still the wall clock at launch, which is exactly what the clock warning is
  /// about: see [ClockCheckSheet].
  final MonotonicClock _clock = MonotonicClock();

  /// The time the UI is rendered at, advanced by the ticker, so the whole screen
  /// is a pure function of the time it is given.
  late int _now = _clock.nowSecs();

  /// When the user last reported that a code was accepted at this wall-clock
  /// time elsewhere. Session-scoped: persisting "correct time" across a reboot
  /// would claim a knowledge of elapsed time that an offline app cannot have.
  int? _referenceUnixSecs;

  SkewWarning _clockWarning = SkewWarning.unknown;

  bool _loaded = false;

  /// Codes start hidden and hide themselves again.
  ///
  /// An authenticator's home screen is the one screen people open in public:
  /// a train, a queue, a shared desk. A code that is always on screen is a code
  /// anyone behind you can photograph, and the step is long enough to use it.
  /// It resets on every launch (nothing about "revealed" is persisted, because
  /// a persisted preference would be the wrong default the next time).
  final Set<String> _revealed = {};
  Timer? _hideTimer;

  final _search = TextEditingController();
  String _query = '';

  @override
  void initState() {
    super.initState();
    unawaited(_load());
    // One tick per second: the countdown ring has to move, and a code changes
    // at a step boundary.
    _ticker = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) {
        setState(() => _now = _clock.nowSecs());
      }
    });
  }

  Future<void> _load() async {
    await widget.repository.load();
    if (mounted) setState(() => _loaded = true);
  }

  @override
  void dispose() {
    _ticker?.cancel();
    _hideTimer?.cancel();
    _search.dispose();
    super.dispose();
  }

  /// Shows one account's code for a short while, then hides it again.
  void _reveal(Account account) {
    setState(() => _revealed.add(account.storageKey));
    _hideTimer?.cancel();
    _hideTimer = Timer(const Duration(seconds: 15), () {
      if (mounted) setState(() => _revealed.clear());
    });
  }

  /// The rows to show, after the search filter.
  List<AccountRow> _visibleRows() {
    final rows = widget.repository.rowsAt(_now);
    if (_query.isEmpty) return rows;
    final needle = _query.toLowerCase();
    return rows
        .where(
          (row) =>
              row.account.name.toLowerCase().contains(needle) ||
              row.account.issuer.toLowerCase().contains(needle),
        )
        .toList(growable: false);
  }

  @override
  Widget build(BuildContext context) {
    if (!_loaded) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }

    final rows = _visibleRows();
    final total = widget.repository.accounts.length;
    final storageProblem = widget.repository.storageProblem;

    return Scaffold(
      appBar: AppBar(
        title: const Text('BandAll Authenticator'),
        actions: [
          IconButton(
            key: const Key('clock-check'),
            icon: Icon(
              _clockWarning == SkewWarning.drifted
                  ? Icons.warning_amber
                  : Icons.schedule,
            ),
            tooltip: 'Clock check',
            onPressed: _openClockCheck,
          ),
          IconButton(
            key: const Key('add-account'),
            icon: const Icon(Icons.add),
            tooltip: 'Add account',
            onPressed: () => _openAddSheet(context),
          ),
        ],
      ),
      body: Column(
        children: [
          if (storageProblem != null) const _StorageWarning(),
          // Only a *known* drift interrupts the list. "Unknown" is the normal
          // state for an offline app and belongs in the clock sheet, not as a
          // permanent banner nobody can clear.
          if (_clockWarning == SkewWarning.drifted)
            _ClockDriftBanner(onOpen: _openClockCheck),
          if (total > 0)
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
              child: TextField(
                key: const Key('search'),
                controller: _search,
                decoration: const InputDecoration(
                  prefixIcon: Icon(Icons.search),
                  hintText: 'Search accounts',
                  isDense: true,
                  border: OutlineInputBorder(),
                ),
                onChanged: (value) => setState(() => _query = value.trim()),
              ),
            ),
          Expanded(
            child: rows.isEmpty
                ? (total == 0 ? const _EmptyState() : const _NoMatches())
                : ListView.builder(
                    itemCount: rows.length,
                    itemBuilder: (context, index) {
                      final row = rows[index];
                      return _AccountTile(
                        row: row,
                        revealed: _revealed.contains(row.account.storageKey),
                        onReveal: () => _reveal(row.account),
                        onDelete: () => _delete(row.account),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }

  Future<void> _delete(Account account) async {
    await widget.repository.remove(account);
    if (mounted) setState(() {});
  }

  /// Opens the clock sheet and adopts whatever verdict it comes back with.
  Future<void> _openClockCheck() async {
    final result = await showModalBottomSheet<ClockCheckResult>(
      context: context,
      isScrollControlled: true,
      builder: (_) => ClockCheckSheet(
        repository: widget.repository,
        nowSecs: _clock.nowSecs(),
        referenceUnixSecs: _referenceUnixSecs,
      ),
    );
    if (result != null && mounted) {
      setState(() {
        _referenceUnixSecs = result.referenceUnixSecs;
        _clockWarning = result.warning;
      });
    }
  }

  Future<void> _openAddSheet(BuildContext context) async {
    final added = await showModalBottomSheet<bool>(
      context: context,
      isScrollControlled: true,
      builder: (_) => AddAccountSheet(
        repository: widget.repository,
        scannerBuilder: widget.scannerBuilder,
      ),
    );
    if (added == true && mounted) setState(() {});
  }
}

class _NoMatches extends StatelessWidget {
  const _NoMatches();

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Padding(
        padding: EdgeInsets.all(32),
        child: Text('No account matches that search.'),
      ),
    );
  }
}

/// Banner shown when the keystore could not be opened.
///
/// The app keeps working for the session and says so. It never falls back to
/// writing the secret somewhere unprotected.
class _StorageWarning extends StatelessWidget {
  const _StorageWarning();

  @override
  Widget build(BuildContext context) {
    return Container(
      color: Theme.of(context).colorScheme.errorContainer,
      padding: const EdgeInsets.all(12),
      child: Row(
        children: [
          const Icon(Icons.lock_outline),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              'Secure storage is unavailable. Accounts added now will be '
              'forgotten when you close the app.',
              style: TextStyle(
                color: Theme.of(context).colorScheme.onErrorContainer,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

/// The clock-drift banner, shown only when the drift is known to be bad.
///
/// Amber rather than red, and paired with a button: the fix is in the phone's
/// settings, not in this app, so the banner has to point somewhere.
class _ClockDriftBanner extends StatelessWidget {
  const _ClockDriftBanner({required this.onOpen});

  final VoidCallback onOpen;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      color: scheme.tertiaryContainer,
      padding: const EdgeInsets.fromLTRB(16, 10, 8, 10),
      child: Row(
        children: [
          Icon(Icons.warning_amber, color: scheme.onTertiaryContainer),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              SkewWarning.drifted.text!,
              key: const Key('clock-drift-warning'),
              style: TextStyle(color: scheme.onTertiaryContainer),
            ),
          ),
          TextButton(
            key: const Key('clock-drift-open'),
            onPressed: onOpen,
            child: const Text('Details'),
          ),
        ],
      ),
    );
  }
}

/// Asks the user for the one thing only they can supply.
///
/// The app has no network permission, so it cannot ask a server what time it
/// is, and an offline app cannot measure how much true time passed while it
/// was closed. What it can do is compare this device's clock against a moment
/// the user knows a code was accepted — anywhere, in any authenticator — and
/// report the difference. That is the honest form of the H7 clock warning; the
/// alternative, a green light that means "no news", would be worse.
class ClockCheckSheet extends StatefulWidget {
  const ClockCheckSheet({
    super.key,
    required this.repository,
    required this.nowSecs,
    this.referenceUnixSecs,
  });

  final AuthenticatorRepository repository;
  final int nowSecs;
  final int? referenceUnixSecs;

  @override
  State<ClockCheckSheet> createState() => _ClockCheckSheetState();
}

class _ClockCheckSheetState extends State<ClockCheckSheet> {
  late final TextEditingController _reference = TextEditingController(
    text: widget.referenceUnixSecs == null
        ? ''
        : formatWallClock(widget.referenceUnixSecs!),
  );

  String? _error;
  ClockCheckResult? _result;

  @override
  void dispose() {
    _reference.dispose();
    super.dispose();
  }

  /// Compares the device clock against the reported reference.
  ///
  /// The comparison is the Rust core's, not the UI's: the threshold that
  /// decides whether a code will be rejected lives with the TOTP
  /// implementation, where the step is known.
  void _check() {
    final raw = _reference.text.trim();
    final reference = raw.isEmpty ? null : referenceFromWallClock(raw);
    if (raw.isNotEmpty && reference == null) {
      setState(() {
        _error = 'Write the time as HH:MM, for example 14:32.';
        _result = null;
      });
      return;
    }
    setState(() {
      _error = null;
      _result = ClockCheckResult(
        warning: widget.repository.clockWarning(
          nowSecs: MonotonicClock.wallClockSecs(),
          referenceUnixSecs: reference,
        ),
        referenceUnixSecs: reference,
      );
    });
  }

  @override
  Widget build(BuildContext context) {
    final result = _result;
    return Padding(
      padding: EdgeInsets.only(
        left: 16,
        right: 16,
        top: 16,
        bottom: MediaQuery.of(context).viewInsets.bottom + 16,
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text('Clock check', style: Theme.of(context).textTheme.titleLarge),
          const SizedBox(height: 8),
          Text(
            'This device reads ${formatWallClock(widget.nowSecs)}.',
            key: const Key('clock-device-time'),
            style: Theme.of(context).textTheme.bodyMedium,
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _reference,
            decoration: const InputDecoration(
              labelText: 'Time a code was accepted elsewhere',
              helperText: 'Any service, in any authenticator. Today, HH:MM.',
              prefixIcon: Icon(Icons.schedule),
            ),
            keyboardType: TextInputType.datetime,
            autocorrect: false,
            enableSuggestions: false,
            key: const Key('field-reference'),
            onChanged: (_) => setState(() => _error = null),
          ),
          if (_error != null) ...[
            const SizedBox(height: 8),
            Text(
              _error!,
              key: const Key('clock-error'),
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ],
          const SizedBox(height: 16),
          FilledButton(
            key: const Key('clock-check-submit'),
            onPressed: _check,
            child: const Text('Check'),
          ),
          if (result != null) ...[
            const SizedBox(height: 16),
            Text(
              result.warning.text ?? 'Your clock looks right.',
              key: const Key('clock-verdict'),
              style: result.warning == SkewWarning.drifted
                  ? TextStyle(color: Theme.of(context).colorScheme.error)
                  : Theme.of(context).textTheme.bodyMedium,
            ),
          ],
          const SizedBox(height: 8),
          TextButton(
            onPressed: () => Navigator.of(context).pop(result),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.qr_code_2, size: 64),
            const SizedBox(height: 16),
            Text(
              'No accounts yet',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            const Text(
              'Add one by scanning the QR code a service shows you, or by '
              'pasting the setup link.',
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}

class _AccountTile extends StatelessWidget {
  const _AccountTile({
    required this.row,
    required this.revealed,
    required this.onReveal,
    required this.onDelete,
  });

  final AccountRow row;
  final bool revealed;
  final VoidCallback onReveal;
  final VoidCallback onDelete;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      title: Text(row.displayIssuer),
      subtitle: Text(row.displayName),
      onTap: onReveal,
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              // Hidden by default: the home screen of an authenticator is read
              // in public places, and a code on screen is a code anyone behind
              // you can use within its step.
              Text(
                revealed ? row.grouped : '•' * 6,
                key: Key('code-${row.account.name}'),
                style: TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 22,
                  letterSpacing: 2,
                  color: revealed
                      ? null
                      : Theme.of(context).colorScheme.onSurfaceVariant,
                ),
              ),
              Text(
                revealed ? '${row.secondsRemaining}s' : 'tap to show',
                key: Key('countdown-${row.account.name}'),
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
          ),
          const SizedBox(width: 8),
          SizedBox(
            width: 32,
            height: 32,
            child: CircularProgressIndicator(
              value: codeProgress(row.secondsRemaining, row.account.periodSecs),
              strokeWidth: 3,
            ),
          ),
        ],
      ),
      onLongPress: () => _confirmDelete(context),
    );
  }

  Future<void> _confirmDelete(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Remove account?'),
        content: Text(
          '${row.displayIssuer} (${row.displayName}) will be removed from this '
          'device. If you have not saved the service\'s recovery codes, you may '
          'lose access to it.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
    if (confirmed == true) onDelete();
  }
}

/// Add an account: scan a QR, paste a setup link, or type the details.
class AddAccountSheet extends StatefulWidget {
  const AddAccountSheet({
    super.key,
    required this.repository,
    this.scannerBuilder,
  });

  final AuthenticatorRepository repository;
  final ScannerBuilder? scannerBuilder;

  @override
  State<AddAccountSheet> createState() => _AddAccountSheetState();
}

/// How the user wants to provide the account.
enum _AddMode { scan, link, manual }

class _AddAccountSheetState extends State<AddAccountSheet> {
  final _uri = TextEditingController();
  final _issuer = TextEditingController();
  final _name = TextEditingController();
  final _secret = TextEditingController();

  String? _error;
  _AddMode _mode = _AddMode.scan;

  @override
  void dispose() {
    _uri.dispose();
    _issuer.dispose();
    _name.dispose();
    _secret.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    setState(() => _error = null);
    try {
      switch (_mode) {
        case _AddMode.scan:
          // The sheet stays open until the scanner reports a code.
          return;
        case _AddMode.link:
          await widget.repository.importUri(_uri.text.trim());
        case _AddMode.manual:
          await widget.repository.addManual(
            issuer: _issuer.text.trim(),
            name: _name.text.trim(),
            secretBase32: _secret.text.trim(),
          );
      }
      if (mounted) Navigator.of(context).pop(true);
    } on BridgeError catch (error) {
      if (mounted) setState(() => _error = error.message);
    }
  }

  /// Called with whatever the camera decoded. Kept separate from the widget so
  /// the scanner plumbing can be tested without a camera: the widget only has
  /// to hand the raw string over.
  Future<void> onScanned(String raw) async {
    setState(() => _error = null);
    try {
      await widget.repository.importUri(raw);
      if (mounted) Navigator.of(context).pop(true);
    } on BridgeError catch (error) {
      // A QR that is not an account (a Wi-Fi code, a URL) is a normal event,
      // not a crash: say so and keep scanning.
      if (mounted) setState(() => _error = error.message);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.only(
        left: 16,
        right: 16,
        top: 16,
        bottom: MediaQuery.of(context).viewInsets.bottom + 16,
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text('Add account', style: Theme.of(context).textTheme.titleLarge),
          const SizedBox(height: 16),
          SegmentedButton<_AddMode>(
            segments: const [
              ButtonSegment(
                value: _AddMode.scan,
                label: Text('Scan'),
                icon: Icon(Icons.qr_code_scanner),
              ),
              ButtonSegment(
                value: _AddMode.link,
                label: Text('Link'),
                icon: Icon(Icons.link),
              ),
              ButtonSegment(
                value: _AddMode.manual,
                label: Text('Manually'),
                icon: Icon(Icons.keyboard),
              ),
            ],
            selected: {_mode},
            onSelectionChanged: (selection) =>
                setState(() => _mode = selection.first),
          ),
          const SizedBox(height: 16),
          switch (_mode) {
            _AddMode.scan => SizedBox(
              height: 220,
              child:
                  widget.scannerBuilder?.call(context, onScanned) ??
                  QrScanner(onScanned: onScanned),
            ),
            _AddMode.link => TextField(
              controller: _uri,
              decoration: const InputDecoration(
                labelText: 'otpauth:// link',
                helperText:
                    'The link behind the QR code the service showed you.',
              ),
              maxLines: 3,
              autocorrect: false,
              enableSuggestions: false,
              key: const Key('field-uri'),
            ),
            _AddMode.manual => Column(
              children: [
                TextField(
                  controller: _issuer,
                  decoration: const InputDecoration(
                    labelText: 'Service (optional)',
                  ),
                  key: const Key('field-issuer'),
                ),
                TextField(
                  controller: _name,
                  decoration: const InputDecoration(labelText: 'Account name'),
                  key: const Key('field-name'),
                ),
                TextField(
                  controller: _secret,
                  decoration: const InputDecoration(labelText: 'Setup key'),
                  autocorrect: false,
                  enableSuggestions: false,
                  key: const Key('field-secret'),
                ),
              ],
            ),
          },
          if (_error != null) ...[
            const SizedBox(height: 12),
            Text(
              _error!,
              key: const Key('add-error'),
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ],
          const SizedBox(height: 16),
          if (_mode != _AddMode.scan)
            FilledButton(
              key: const Key('add-submit'),
              onPressed: _submit,
              child: const Text('Add'),
            ),
        ],
      ),
    );
  }
}

/// The camera view.
///
/// Uses `mobile_scanner` (CameraX/ML Kit on Android, AVFoundation on iOS). The
/// scanner is confined to this widget so nothing else in the app has to know
/// about a camera, and so a widget test can substitute it through
/// [ScannerBuilder].
class QrScanner extends StatefulWidget {
  const QrScanner({super.key, required this.onScanned});

  /// Called once per decode, with the raw payload.
  final Future<void> Function(String raw) onScanned;

  @override
  State<QrScanner> createState() => _QrScannerState();
}

class _QrScannerState extends State<QrScanner> with WidgetsBindingObserver {
  final MobileScannerController _controller = MobileScannerController(
    // Only QR: a TOTP setup is never a barcode, and narrowing the formats
    // makes detection faster and avoids matching unrelated codes.
    formats: const [BarcodeFormat.qrCode],
    // One decode per entry: several frames of the same QR must not add the
    // same account repeatedly.
    detectionSpeed: DetectionSpeed.noDuplicates,
  );

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (!_controller.value.hasCameraPermission) return;
    switch (state) {
      case AppLifecycleState.detached:
      case AppLifecycleState.hidden:
      case AppLifecycleState.paused:
        return;
      case AppLifecycleState.resumed:
        unawaited(_controller.start());
      case AppLifecycleState.inactive:
        // Let the camera go when the app is not in front: a live camera the
        // user cannot see is exactly what a malicious background app wants.
        unawaited(_controller.stop());
    }
  }

  @override
  Future<void> dispose() async {
    WidgetsBinding.instance.removeObserver(this);
    await _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ClipRRect(
      borderRadius: BorderRadius.circular(12),
      child: MobileScanner(
        controller: _controller,
        onDetect: (capture) {
          final raw = capture.barcodes.firstOrNull?.rawValue;
          if (raw == null || raw.isEmpty) return;
          unawaited(widget.onScanned(raw));
        },
        errorBuilder: (context, error) =>
            _ScannerUnavailable(message: error.errorDetails?.message),
      ),
    );
  }
}

/// Shown when the camera cannot be used: no permission, no camera, or a
/// platform this build does not support. The user still has the other two ways
/// to add an account, so this is a note, not a dead end.
class _ScannerUnavailable extends StatelessWidget {
  const _ScannerUnavailable({this.message});

  final String? message;

  @override
  Widget build(BuildContext context) {
    return ColoredBox(
      color: Theme.of(context).colorScheme.surfaceContainerHighest,
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.no_photography_outlined, size: 40),
              const SizedBox(height: 8),
              const Text(
                'Camera unavailable',
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 4),
              Text(
                message ?? 'Use the link or manual entry instead.',
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
          ),
        ),
      ),
    );
  }
}
