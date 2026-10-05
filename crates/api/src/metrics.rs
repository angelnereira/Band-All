//! Minimal Prometheus metrics: lock-free counters rendered as exposition
//! text. No external dependency; wiggle room for a full metrics stack in
//! production stays documented in the observability guide.

use std::sync::atomic::{AtomicU64, Ordering};

/// Process metrics. Incremented on the verification hot paths.
#[derive(Debug, Default)]
pub struct Metrics {
    mfa_verified: AtomicU64,
    mfa_denied: AtomicU64,
    enroll_started: AtomicU64,
    token_refreshed: AtomicU64,
}

impl Metrics {
    /// Creates zeroed metrics.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Counts a login verification outcome.
    pub fn mfa(&self, ok: bool) {
        if ok {
            self.mfa_verified.fetch_add(1, Ordering::Relaxed);
        } else {
            self.mfa_denied.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Counts a started enrolment.
    pub fn enrolled(&self) {
        self.enroll_started.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a refresh rotation.
    pub fn refreshed(&self) {
        self.token_refreshed.fetch_add(1, Ordering::Relaxed);
    }

    /// Renders Prometheus exposition format.
    #[must_use]
    pub fn render(&self) -> String {
        let load = |value: &AtomicU64| value.load(Ordering::Relaxed);
        format!(
            "# HELP bandall_mfa_verified_total Accepted login second factors.\n\
             # TYPE bandall_mfa_verified_total counter\n\
             bandall_mfa_verified_total {}\n\
             # HELP bandall_mfa_denied_total Denied login second factors.\n\
             # TYPE bandall_mfa_denied_total counter\n\
             bandall_mfa_denied_total {}\n\
             # HELP bandall_enroll_started_total Started enrolments.\n\
             # TYPE bandall_enroll_started_total counter\n\
             bandall_enroll_started_total {}\n\
             # HELP bandall_token_refreshed_total Refresh rotations.\n\
             # TYPE bandall_token_refreshed_total counter\n\
             bandall_token_refreshed_total {}\n",
            load(&self.mfa_verified),
            load(&self.mfa_denied),
            load(&self.enroll_started),
            load(&self.token_refreshed),
        )
    }
}

/// `GET /metrics`: Prometheus exposition text.
pub async fn metrics(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
) -> String {
    state.metrics.render()
}

#[cfg(test)]
mod tests {
    use super::Metrics;

    #[test]
    fn renders_counters() {
        let metrics = Metrics::new();
        metrics.mfa(true);
        metrics.mfa(false);
        metrics.enrolled();
        let text = metrics.render();
        assert!(text.contains("bandall_mfa_verified_total 1"));
        assert!(text.contains("bandall_mfa_denied_total 1"));
        assert!(text.contains("bandall_enroll_started_total 1"));
    }
}
