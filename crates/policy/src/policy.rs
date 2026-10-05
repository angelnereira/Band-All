//! Failure tracking: sliding-window attempts, exponential backoff and
//! temporary lockout. Pure and time-injected (`now_secs`); the API layer
//! maps `Decision` to 429 responses. No async, no I/O.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// Tunable limits. Defaults follow the blueprint (§9): a handful of failures
/// trigger exponential backoff, sustained abuse triggers lockout.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Failures tolerated per window before backoff.
    pub max_attempts: u32,
    /// Sliding window in seconds.
    pub window_secs: u64,
    /// First backoff in seconds (doubles per extra failure).
    pub base_backoff_secs: u64,
    /// Backoff cap in seconds.
    pub max_backoff_secs: u64,
    /// Consecutive failures triggering lockout.
    pub lockout_after: u32,
    /// Lockout duration in seconds.
    pub lockout_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            window_secs: 300,
            base_backoff_secs: 2,
            max_backoff_secs: 300,
            lockout_after: 10,
            lockout_secs: 900,
        }
    }
}

/// Outcome of a policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Proceed with verification.
    Allow,
    /// Wait this many seconds before retrying.
    RetryAfter(u64),
    /// Locked; seconds remaining.
    Locked(u64),
}

#[derive(Debug, Default)]
struct Entry {
    /// Failure timestamps within the window (ascending).
    fails: VecDeque<u64>,
    /// Lockout deadline (0 = not locked).
    locked_until: u64,
}

/// In-memory failure tracker keyed by caller-composed keys
/// (`factor:<ids>`, `ip:<addr>`, `tenant:<id>`).
#[derive(Debug, Default)]
pub struct Policy {
    limits: Limits,
    entries: Mutex<HashMap<String, Entry>>,
}

impl Policy {
    /// Builds with custom limits.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Checks whether `key` may attempt verification at `now_secs`.
    #[must_use]
    pub fn check(&self, key: &str, now_secs: u64) -> Decision {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries.entry(key.to_string()).or_default();
        prune(&mut entry.fails, now_secs, self.limits.window_secs);
        if now_secs < entry.locked_until {
            return Decision::Locked(entry.locked_until - now_secs);
        }
        let recent = entry.fails.len();
        let max = usize::try_from(self.limits.max_attempts).unwrap_or(usize::MAX);
        if recent < max {
            return Decision::Allow;
        }
        let last = entry.fails.back().copied().unwrap_or(now_secs);
        let over = recent.saturating_sub(max);
        let backoff = self.backoff(over);
        let elapsed = now_secs.saturating_sub(last);
        if elapsed < backoff {
            Decision::RetryAfter(backoff - elapsed)
        } else {
            Decision::Allow
        }
    }

    /// Records an attempt outcome. Success clears the key; failure may lock.
    pub fn record(&self, key: &str, now_secs: u64, success: bool) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if success {
            entries.remove(key);
            return;
        }
        let entry = entries.entry(key.to_string()).or_default();
        prune(&mut entry.fails, now_secs, self.limits.window_secs);
        entry.fails.push_back(now_secs);
        if entry.fails.len() >= usize::try_from(self.limits.lockout_after).unwrap_or(usize::MAX) {
            entry.locked_until = now_secs.saturating_add(self.limits.lockout_secs);
        }
    }

    fn backoff(&self, over: usize) -> u64 {
        let mut backoff = self.limits.base_backoff_secs;
        for _ in 0..over.min(16) {
            backoff = backoff.saturating_mul(2).min(self.limits.max_backoff_secs);
        }
        backoff.min(self.limits.max_backoff_secs)
    }
}

fn prune(fails: &mut VecDeque<u64>, now_secs: u64, window_secs: u64) {
    // Keep failures with `ts + window > now`; without enough history to tell,
    // keep everything (checked_sub returns None near the epoch).
    let Some(cutoff) = now_secs.checked_sub(window_secs) else {
        return;
    };
    while fails.front().is_some_and(|first| *first <= cutoff) {
        fails.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::{Decision, Limits, Policy};

    fn policy() -> Policy {
        Policy::new(Limits {
            max_attempts: 2,
            window_secs: 1000,
            base_backoff_secs: 10,
            max_backoff_secs: 100,
            lockout_after: 4,
            lockout_secs: 500,
        })
    }

    #[test]
    fn allows_then_backs_off() {
        let policy = policy();
        assert_eq!(policy.check("k", 0), Decision::Allow);
        policy.record("k", 0, false);
        assert_eq!(policy.check("k", 1), Decision::Allow);
        policy.record("k", 1, false);
        assert_eq!(policy.check("k", 2), Decision::RetryAfter(9));
        assert_eq!(policy.check("k", 11), Decision::Allow);
    }

    #[test]
    fn success_resets() {
        let policy = policy();
        policy.record("k", 0, false);
        policy.record("k", 1, true);
        assert_eq!(policy.check("k", 2), Decision::Allow);
    }

    #[test]
    fn locks_after_sustained_abuse() {
        let policy = policy();
        for t in [0, 20, 40, 60] {
            assert_eq!(policy.check("k", t), Decision::Allow);
            policy.record("k", t, false);
        }
        assert!(matches!(policy.check("k", 61), Decision::Locked(_)));
    }
}
