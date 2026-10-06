//! Failure tracking: sliding-window attempts, exponential backoff and
//! temporary lockout. Pure and time-injected (`now_secs`); the API layer
//! maps `Decision` to 429 responses. No async, no I/O.
//!
//! Two security properties are enforced here (remediation task T2):
//!
//! 1. **Atomic acquire**: [`Policy::acquire`] decides *and* records the
//!    attempt under a single lock. A concurrent burst cannot pass every
//!    check before any attempt is registered.
//! 2. **Scope isolation**: factor, tenant and IP keys carry their own
//!    [`Limits`]. Tenant/IP scopes use high ceilings and never lock out for
//!    long, so an attacker cannot block a whole tenant by hammering public
//!    endpoints.
//!
//! The same decision table is used by the database backend: it calls
//! [`evaluate`] inside the reservation transaction so both backends deny
//! identically.

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
    /// Consecutive failures triggering lockout. `0` disables lockout.
    pub lockout_after: u32,
    /// Lockout duration in seconds. Effective lockout is bounded by
    /// `window_secs`: attempts older than the window stop counting.
    pub lockout_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            // Lockout is derived from the sliding window, so the window must
            // cover it: `window_secs >= lockout_secs` keeps the full lockout.
            window_secs: 900,
            base_backoff_secs: 2,
            max_backoff_secs: 300,
            lockout_after: 10,
            lockout_secs: 900,
        }
    }
}

impl Limits {
    /// High-ceiling ingress limits for shared keys (tenant, IP): tolerate
    /// bursts behind NAT, answer only `RetryAfter`/429 and never enter a long
    /// lockout (remediation T2).
    #[must_use]
    pub fn ingress(max_attempts: u32) -> Self {
        Self {
            max_attempts,
            window_secs: 60,
            base_backoff_secs: 1,
            max_backoff_secs: 30,
            lockout_after: 0,
            lockout_secs: 0,
        }
    }
}

/// Rate-limit scope. Limits and (in the database backend) policy keys are
/// independent per scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// One authenticator factor: strict limits.
    Factor,
    /// A whole tenant: high ceiling, no long lockout.
    Tenant,
    /// One client address: high ceiling, no long lockout.
    Ip,
}

/// Per-scope configuration plus the in-memory entry cap.
#[derive(Debug, Clone, Copy)]
pub struct PolicyConfig {
    /// Limits for [`Scope::Factor`].
    pub factor: Limits,
    /// Limits for [`Scope::Tenant`].
    pub tenant: Limits,
    /// Limits for [`Scope::Ip`].
    pub ip: Limits,
    /// Maximum tracked keys before new keys are refused (fail closed).
    pub max_entries: usize,
}

impl PolicyConfig {
    /// Default entry cap (100k keys).
    pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

    /// Limits selected by scope.
    #[must_use]
    pub fn limits(&self, scope: Scope) -> Limits {
        match scope {
            Scope::Factor => self.factor,
            Scope::Tenant => self.tenant,
            Scope::Ip => self.ip,
        }
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            factor: Limits::default(),
            // Sized for legitimate aggregate traffic; a single actor cannot
            // push a tenant or an IP into a long lockout (T2).
            tenant: Limits::ingress(1_000),
            ip: Limits::ingress(300),
            max_entries: Self::DEFAULT_MAX_ENTRIES,
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

/// Pure decision table shared by both backends.
///
/// `count` and `last_failed_at` describe the attempts already recorded inside
/// the window, **excluding** the one being decided. `Allow` means the caller
/// must record the new attempt.
#[must_use]
pub fn evaluate(limits: Limits, count: u64, last_failed_at: Option<u64>, now: u64) -> Decision {
    if count == 0 {
        return Decision::Allow;
    }
    let last = last_failed_at.unwrap_or(now);
    if limits.lockout_after > 0 && count >= u64::from(limits.lockout_after) {
        let locked_until = last.saturating_add(limits.lockout_secs);
        if now < locked_until {
            return Decision::Locked(locked_until - now);
        }
    }
    let max = u64::from(limits.max_attempts);
    if count >= max {
        let backoff = backoff(limits, count - max);
        let elapsed = now.saturating_sub(last);
        if elapsed < backoff {
            return Decision::RetryAfter(backoff - elapsed);
        }
    }
    Decision::Allow
}

fn backoff(limits: Limits, over: u64) -> u64 {
    let mut backoff = limits.base_backoff_secs;
    for _ in 0..over.min(16) {
        backoff = backoff.saturating_mul(2).min(limits.max_backoff_secs);
    }
    backoff.min(limits.max_backoff_secs)
}

fn prune(attempts: &mut VecDeque<u64>, now_secs: u64, window_secs: u64) {
    // Keep attempts with `ts + window > now`; without enough history to tell,
    // keep everything (checked_sub returns None near the epoch).
    let Some(cutoff) = now_secs.checked_sub(window_secs) else {
        return;
    };
    while attempts.front().is_some_and(|first| *first <= cutoff) {
        attempts.pop_front();
    }
}

#[derive(Debug)]
struct Entry {
    scope: Scope,
    /// Attempt timestamps within the window (ascending).
    attempts: VecDeque<u64>,
}

/// Minimum time between sweeps of expired entries at the cap: bounded work
/// under sustained floods.
const SWEEP_MIN_INTERVAL: u64 = 60;

#[derive(Debug, Default)]
struct State {
    entries: HashMap<String, Entry>,
    /// Last sweep of expired entries (`None` = never swept).
    last_sweep_at: Option<u64>,
}

/// In-memory failure tracker keyed by caller-composed keys
/// (`factor:<ids>`, `ip:<addr>`, `tenant:<id>`).
#[derive(Debug)]
pub struct Policy {
    config: PolicyConfig,
    state: Mutex<State>,
}

impl Default for Policy {
    fn default() -> Self {
        Self::new(PolicyConfig::default())
    }
}

impl Policy {
    /// Builds with custom configuration.
    #[must_use]
    pub fn new(config: PolicyConfig) -> Self {
        Self {
            config,
            state: Mutex::new(State::default()),
        }
    }

    /// Configuration in force.
    #[must_use]
    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// Decides **and records** the attempt in one critical section.
    ///
    /// Recording happens only when the decision is `Allow`: refused attempts
    /// must not extend backoff/lockout indefinitely (a flood would otherwise
    /// pin a victim). Refused attempts for the same key still see every
    /// *allowed* in-flight attempt, so a concurrent burst stops at the limit.
    pub fn acquire(&self, scope: Scope, key: &str, now_secs: u64) -> Decision {
        let limits = self.config.limits(scope);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let (count, last) = match state.entries.get_mut(key) {
            Some(entry) => {
                if entry.scope != scope {
                    entry.scope = scope;
                    entry.attempts.clear();
                }
                prune(&mut entry.attempts, now_secs, limits.window_secs);
                (
                    u64::try_from(entry.attempts.len()).unwrap_or(u64::MAX),
                    entry.attempts.back().copied(),
                )
            }
            None => (0, None),
        };
        let decision = evaluate(limits, count, last, now_secs);
        if decision != Decision::Allow {
            return decision;
        }
        if !state.entries.contains_key(key) && state.entries.len() >= self.config.max_entries {
            let due = match state.last_sweep_at {
                None => true,
                Some(last) => now_secs.saturating_sub(last) >= SWEEP_MIN_INTERVAL,
            };
            if due {
                sweep(&mut state.entries, &self.config, now_secs);
                state.last_sweep_at = Some(now_secs);
            }
            if state.entries.len() >= self.config.max_entries {
                // Fail closed instead of growing without bound.
                return Decision::RetryAfter(1);
            }
        }
        let entry = state
            .entries
            .entry(key.to_string())
            .or_insert_with(|| Entry {
                scope,
                attempts: VecDeque::new(),
            });
        entry.attempts.push_back(now_secs);
        Decision::Allow
    }

    /// Final outcome of an acquired attempt. Success clears the key;
    /// failures were already recorded by [`Policy::acquire`].
    pub fn record(&self, key: &str, success: bool) {
        if !success {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.entries.remove(key);
    }

    /// Tracked key count (tests and future metrics).
    #[must_use]
    pub fn entries(&self) -> usize {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.entries.len()
    }
}

/// Drops entries whose window expired (lockout is derived from the window).
fn sweep(entries: &mut HashMap<String, Entry>, config: &PolicyConfig, now_secs: u64) {
    entries.retain(|_, entry| {
        let window = config.limits(entry.scope).window_secs;
        prune(&mut entry.attempts, now_secs, window);
        !entry.attempts.is_empty()
    });
}

#[cfg(test)]
mod tests {
    use super::{Decision, Limits, Policy, PolicyConfig, Scope, evaluate};

    fn policy() -> Policy {
        Policy::new(PolicyConfig {
            factor: Limits {
                max_attempts: 2,
                window_secs: 1000,
                base_backoff_secs: 10,
                max_backoff_secs: 100,
                lockout_after: 4,
                lockout_secs: 500,
            },
            ..PolicyConfig::default()
        })
    }

    #[test]
    fn allows_then_backs_off() {
        let policy = policy();
        assert_eq!(policy.acquire(Scope::Factor, "k", 0), Decision::Allow);
        assert_eq!(policy.acquire(Scope::Factor, "k", 1), Decision::Allow);
        assert_eq!(
            policy.acquire(Scope::Factor, "k", 2),
            Decision::RetryAfter(9)
        );
        assert_eq!(policy.acquire(Scope::Factor, "k", 11), Decision::Allow);
    }

    #[test]
    fn success_resets() {
        let policy = policy();
        let _ = policy.acquire(Scope::Factor, "k", 0);
        policy.record("k", true);
        assert_eq!(policy.acquire(Scope::Factor, "k", 2), Decision::Allow);
    }

    #[test]
    fn locks_after_sustained_abuse() {
        let policy = policy();
        for t in [0, 20, 40, 60] {
            assert_eq!(policy.acquire(Scope::Factor, "k", t), Decision::Allow);
        }
        assert!(matches!(
            policy.acquire(Scope::Factor, "k", 61),
            Decision::Locked(_)
        ));
    }

    #[test]
    fn concurrent_burst_stops_at_max() {
        use std::sync::Arc;
        let policy = Arc::new(Policy::new(PolicyConfig {
            factor: Limits {
                max_attempts: 5,
                ..Limits::default()
            },
            ..PolicyConfig::default()
        }));
        let mut handles = Vec::new();
        for _ in 0..100 {
            let policy = Arc::clone(&policy);
            handles.push(std::thread::spawn(move || {
                policy.acquire(Scope::Factor, "burst", 1_700_000_000) == Decision::Allow
            }));
        }
        let allowed = handles
            .into_iter()
            .map(|handle| handle.join().unwrap_or(false))
            .filter(|allowed| *allowed)
            .count();
        assert_eq!(allowed, 5);
    }

    #[test]
    fn scopes_are_independent() {
        let policy = Policy::new(PolicyConfig {
            factor: Limits {
                max_attempts: 1,
                ..Limits::default()
            },
            tenant: Limits::ingress(1_000),
            ..PolicyConfig::default()
        });
        // Exhaust one factor.
        assert_eq!(policy.acquire(Scope::Factor, "f1", 0), Decision::Allow);
        assert_eq!(
            policy.acquire(Scope::Factor, "f1", 1),
            Decision::RetryAfter(1)
        );
        // A different factor and the tenant key are unaffected.
        assert_eq!(policy.acquire(Scope::Factor, "f2", 1), Decision::Allow);
        assert_eq!(policy.acquire(Scope::Tenant, "t1", 1), Decision::Allow);
        assert_eq!(policy.acquire(Scope::Ip, "a1", 1), Decision::Allow);
    }

    #[test]
    fn ingress_limits_never_lock_out() {
        let policy = Policy::new(PolicyConfig {
            tenant: Limits::ingress(2),
            ..PolicyConfig::default()
        });
        let mut allowed = 0;
        for t in 0..20 {
            let decision = policy.acquire(Scope::Tenant, "t", t);
            assert!(
                matches!(decision, Decision::Allow | Decision::RetryAfter(_)),
                "tenant scope entered lockout: {decision:?}"
            );
            if decision == Decision::Allow {
                allowed += 1;
            }
        }
        assert!(allowed > 0);
    }

    #[test]
    fn map_is_capped_and_sweeps_expired() {
        let policy = Policy::new(PolicyConfig {
            factor: Limits {
                max_attempts: 10,
                window_secs: 100,
                ..Limits::default()
            },
            max_entries: 2,
            ..PolicyConfig::default()
        });
        assert_eq!(policy.acquire(Scope::Factor, "a", 0), Decision::Allow);
        assert_eq!(policy.acquire(Scope::Factor, "b", 0), Decision::Allow);
        // Cap reached: an existing key still works, a new key is refused.
        assert_eq!(policy.acquire(Scope::Factor, "a", 1), Decision::Allow);
        assert_eq!(
            policy.acquire(Scope::Factor, "c", 1),
            Decision::RetryAfter(1)
        );
        assert_eq!(policy.entries(), 2);
        // Once the old entries expire, the sweep lets a new key in.
        assert_eq!(policy.acquire(Scope::Factor, "c", 200), Decision::Allow);
        assert_eq!(policy.entries(), 1);
    }

    #[test]
    fn evaluate_table() {
        let limits = Limits {
            max_attempts: 2,
            window_secs: 100,
            base_backoff_secs: 4,
            max_backoff_secs: 16,
            lockout_after: 4,
            lockout_secs: 100,
        };
        assert_eq!(evaluate(limits, 0, None, 10), Decision::Allow);
        assert_eq!(evaluate(limits, 1, Some(0), 10), Decision::Allow);
        assert_eq!(evaluate(limits, 2, Some(9), 10), Decision::RetryAfter(3));
        assert_eq!(evaluate(limits, 3, Some(9), 20), Decision::Allow);
        assert_eq!(evaluate(limits, 4, Some(10), 50), Decision::Locked(60));
        assert_eq!(evaluate(limits, 4, Some(10), 200), Decision::Allow);
    }
}
