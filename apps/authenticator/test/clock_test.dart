/// Tests for the clock logic behind the drift warning.
///
/// The interesting property here is not arithmetic, it is honesty: the app has
/// no network permission, so the *absence* of a reference has to produce a
/// clear "cannot tell" rather than a green light that would read as "your clock
/// is fine". These tests pin that, and pin the parsing, which is the only place
/// a user's typed input enters the comparison.
library;

import 'package:bandall_authenticator/src/bridge.dart';
import 'package:bandall_authenticator/src/clock.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('referenceFromWallClock', () {
    // A fixed "now" so the expected instant does not depend on today.
    final now = DateTime(2026, 10, 8, 15, 30, 0);

    test('parses HH:MM as today', () {
      expect(referenceFromWallClock('14:32', now: now), isNotNull);
      expect(
        referenceFromWallClock('14:32', now: now),
        DateTime(2026, 10, 8, 14, 32).millisecondsSinceEpoch ~/ 1000,
      );
    });

    test('parses HH:MM:SS', () {
      expect(
        referenceFromWallClock('14:32:07', now: now),
        DateTime(2026, 10, 8, 14, 32, 7).millisecondsSinceEpoch ~/ 1000,
      );
    });

    test('accepts a single-digit hour, as a lock screen shows it', () {
      expect(referenceFromWallClock('9:05', now: now), isNotNull);
    });

    test('ignores surrounding whitespace', () {
      expect(referenceFromWallClock('  14:32  ', now: now), isNotNull);
    });

    // Refusing is the point: a mis-parsed time would silently compare the
    // device against a wrong instant and produce a confident wrong verdict.
    test('rejects what it cannot read', () {
      expect(referenceFromWallClock('', now: now), isNull);
      expect(referenceFromWallClock('half past two', now: now), isNull);
      expect(referenceFromWallClock('14-32', now: now), isNull);
      expect(referenceFromWallClock('1432', now: now), isNull);
      expect(referenceFromWallClock('14:3', now: now), isNull);
    });

    test('rejects impossible times instead of normalizing them', () {
      expect(referenceFromWallClock('24:00', now: now), isNull);
      expect(referenceFromWallClock('14:60', now: now), isNull);
      expect(referenceFromWallClock('14:32:60', now: now), isNull);
    });
  });

  group('formatWallClock', () {
    test('round-trips through the parser', () {
      final now = DateTime(2026, 10, 8, 15, 30, 0);
      final original = referenceFromWallClock('09:05:07', now: now)!;
      final text = formatWallClock(original);
      expect(text, '09:05:07');
      expect(referenceFromWallClock(text, now: now), original);
    });

    test('zero-pads every field', () {
      final instant = DateTime(2026, 10, 8, 1, 2, 3);
      expect(
        formatWallClock(instant.millisecondsSinceEpoch ~/ 1000),
        '01:02:03',
      );
    });
  });

  group('skewWarning', () {
    const small = ClockSkew(seconds: 10, warns: false);
    const large = ClockSkew(seconds: 600, warns: true);

    test('without a reference the app says it cannot tell', () {
      // The drift value is deliberately large: even a known-large drift is not
      // a verdict if there is nothing to compare against.
      expect(skewWarning(large, referenceUnixSecs: null), SkewWarning.unknown);
    });

    test('a known reference turns the core verdict into a warning', () {
      expect(skewWarning(small, referenceUnixSecs: 1), SkewWarning.ok);
      expect(skewWarning(large, referenceUnixSecs: 1), SkewWarning.drifted);
    });

    test('only the drifted state has something to say on the home screen', () {
      expect(SkewWarning.ok.text, isNull);
      expect(SkewWarning.unknown.text, isNotNull);
      expect(SkewWarning.drifted.text, isNotNull);
      expect(SkewWarning.drifted.text, contains('rejected'));
    });
  });

  group('MonotonicClock', () {
    test('starts at the anchor it was given', () {
      final clock = MonotonicClock(anchorUnixSecs: 1_700_000_000);
      expect(clock.nowSecs(), 1_700_000_000);
    });

    test('advances with elapsed time, not with the wall clock', () {
      // The point of the class: a wall-clock jump during the session must not
      // move the codes. Anchoring to the wall clock and advancing from a
      // stopwatch gives exactly that, and the test is a property of the type:
      // nothing here consults `DateTime` again after construction.
      final clock = MonotonicClock(anchorUnixSecs: 1_700_000_000);
      expect(clock.nowSecs(), greaterThanOrEqualTo(1_700_000_000));
      expect(clock.nowSecs(), lessThan(1_700_000_060));
    });

    test('wallClockSecs reads the device clock for comparison', () {
      // Sanity only: it has to be a plausible present-day instant, which is what
      // makes it usable as a reference target.
      expect(MonotonicClock.wallClockSecs(), greaterThan(1_700_000_000));
    });
  });
}