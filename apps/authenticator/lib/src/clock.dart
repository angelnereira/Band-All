/// Timekeeping for codes, and the clock-drift warning (H7, item 4).
///
/// Two problems meet here, and they have different honest answers.
///
/// **Mid-session jumps.** A TOTP code is a function of the current time, so if
/// the device clock moves — an NTP correction, a timezone change, the user
/// fiddling with settings — every visible code changes at once, in the middle of
/// being read. [MonotonicClock] anchors once and then advances from a monotonic
/// stopwatch, so within a session the codes move smoothly even when the wall
/// clock does not.
///
/// **A persistently wrong clock.** This is the one that actually breaks logins,
/// and an offline app cannot detect it on its own. This app holds no
/// `INTERNET` permission (ADR-0016) on purpose, so it has no trusted time
/// source to compare against, and no amount of local cleverness invents one:
/// across a reboot there is no way to know how much true time passed. So the
/// reference comes from the only party that does know — the user, reporting a
/// moment when a code was accepted. [referenceFromWallClock] and
/// [SkewWarning.render] turn that report into the warning the H7 roadmap asks
/// for, and say out loud when there is nothing to compare against instead of
/// showing a reassuring green light that means nothing.
library;

import 'bridge.dart';

/// A wall-clock reading anchored to a monotonic stopwatch.
///
/// Backed by [Stopwatch], which counts elapsed time and is not affected by the
/// user or the network moving the wall clock underneath it. The anchor is read
/// once, at construction.
class MonotonicClock {
  /// Anchors to [anchorUnixSecs] (default: now) and starts counting.
  MonotonicClock({int? anchorUnixSecs})
    : _anchorUnixSecs =
          anchorUnixSecs ?? DateTime.now().millisecondsSinceEpoch ~/ 1000,
    _stopwatch = Stopwatch()..start();

  final int _anchorUnixSecs;
  final Stopwatch _stopwatch;

  /// Seconds since the epoch, as this clock sees them.
  int nowSecs() => _anchorUnixSecs + _stopwatch.elapsed.inSeconds;

  /// The wall clock's own reading, for comparison against a reference.
  ///
  /// Deliberately separate from [nowSecs]: comparing them is how a clock change
  /// made *during* the session becomes visible at all.
  static int wallClockSecs() => DateTime.now().millisecondsSinceEpoch ~/ 1000;
}

/// What the app can say about clock drift.
enum SkewWarning {
  /// No reference yet: the app cannot tell, and says so.
  unknown,

  /// The clock is close enough that codes will be accepted.
  ok,

  /// The clock is far enough off that codes will be rejected. [SkewWarning.text]
  /// explains it; the threshold is the core's, not the UI's.
  drifted;

  /// The user-facing sentence, or `null` when there is nothing to say.
  String? get text => switch (this) {
    SkewWarning.unknown =>
      'Codes depend on this device being set to the right time. Enable '
          'automatic date and time in your settings.',
    SkewWarning.ok => null,
    SkewWarning.drifted =>
      'This device\'s clock does not match a time a code was accepted at. '
          'Codes will be rejected until the clock is corrected.',
  };
}

/// What the clock sheet hands back: the verdict, plus the reference the user
/// gave so the next check can reuse it instead of asking again.
class ClockCheckResult {
  const ClockCheckResult({required this.warning, this.referenceUnixSecs});

  final SkewWarning warning;
  final int? referenceUnixSecs;
}

/// Interprets what the user reported into a warning.
///
/// [referenceUnixSecs] is the moment the user says a code was accepted
/// elsewhere (any BandAll service, or any other TOTP app), expressed in Unix
/// seconds. `null` means the user has not reported one, which is the normal
/// state and not an error.
SkewWarning skewWarning(ClockSkew skew, {int? referenceUnixSecs}) {
  if (referenceUnixSecs == null) return SkewWarning.unknown;
  return skew.warns ? SkewWarning.drifted : SkewWarning.ok;
}

/// Turns "the clock read 14:32 when that worked" into Unix seconds.
///
/// The user is describing *today*, because a code is only ever valid for the
/// current step: a report about last Tuesday cannot help anybody. Accepts
/// `HH:MM` and `HH:MM:SS`, both local, because that is what a person reads off
/// a lock screen. Returns `null` for anything else rather than guessing.
int? referenceFromWallClock(String text, {DateTime? now}) {
  final trimmed = text.trim();
  final match = RegExp(r'^(\d{1,2}):(\d{2})(?::(\d{2}))?$').firstMatch(trimmed);
  if (match == null) return null;
  final hour = int.tryParse(match.group(1) ?? '');
  final minute = int.tryParse(match.group(2) ?? '');
  final second = int.tryParse(match.group(3) ?? '0');
  if (hour == null || minute == null || second == null) return null;
  if (hour > 23 || minute > 59 || second > 59) return null;

  final today = now ?? DateTime.now();
  final local = DateTime(today.year, today.month, today.day, hour, minute, second);
  return local.millisecondsSinceEpoch ~/ 1000;
}

/// Formats Unix seconds the way [referenceFromWallClock] parses them back, so
/// the sheet can prefill the field with the current device time.
String formatWallClock(int unixSecs) {
  final local = DateTime.fromMillisecondsSinceEpoch(unixSecs * 1000);
  String two(int value) => value.toString().padLeft(2, '0');
  return '${two(local.hour)}:${two(local.minute)}:${two(local.second)}';
}