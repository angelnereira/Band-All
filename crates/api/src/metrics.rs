//! Minimal Prometheus metrics: lock-free counters rendered as exposition
//! text. No external dependency; wiggle room for a full metrics stack in
//! production stays documented in the observability guide.
//!
//! Denials carry an internal reason ([`crate::verify::Denial`]) because the
//! HTTP response is uniform by design and an operator still needs to tell a
//! typo from a drifted clock. Those counters are **aggregate on purpose**: no
//! tenant or factor labels, or `/metrics` would become an enumeration oracle.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::verify::Denial;

/// Latency histogram bucket upper bounds, in milliseconds.
///
/// Resolution sits where the interesting cases live: the container battery
/// measures a p99 around 200 ms for the verify routes under a 1-CPU cap, so
/// the buckets span 1 ms to 2.5 s and anything slower lands in `+Inf`.
const LATENCY_BUCKETS_MS: [u64; 11] = [1, 2, 5, 10, 25, 50, 100, 250, 500, 1_000, 2_500];

/// Lock-free latency histogram in milliseconds, cumulative as Prometheus
/// expects. Buckets are a fixed compile-time set and cells are reached
/// through iterators (never by an input-derived index), so nothing here can
/// index out of bounds or allocate on the hot path.
#[derive(Debug, Default)]
struct Histogram {
    /// Per-bucket counts. One entry per `LATENCY_BUCKETS_MS` bound; the `+Inf`
    /// bucket is the observation count and is not stored here.
    counts: Vec<AtomicU64>,
    /// Sum of observations, in whole milliseconds.
    sum_ms: AtomicU64,
    /// Total observations (`+Inf` bucket).
    count: AtomicU64,
}

impl Histogram {
    /// Zeroed histogram with one cell per bucket.
    fn new() -> Self {
        Self {
            counts: LATENCY_BUCKETS_MS
                .iter()
                .map(|_| AtomicU64::new(0))
                .collect(),
            sum_ms: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Records one observation. Sub-millisecond durations round down: the
    /// buckets are millisecond-resolution anyway.
    fn observe(&self, elapsed: Duration) {
        let ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_ms.fetch_add(ms, Ordering::Relaxed);
        let cell = self
            .counts
            .iter()
            .zip(LATENCY_BUCKETS_MS.iter())
            .find(|(_, bound)| ms <= **bound);
        if let Some(cell) = cell {
            cell.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Renders the exposition lines (buckets, sum and count) for `name`.
    fn render(&self, name: &str) -> String {
        let mut out = format!(
            "# HELP {name} Request duration in milliseconds.\n\
             # TYPE {name} histogram\n"
        );
        let mut cumulative = 0;
        for (cell, bound) in self.counts.iter().zip(LATENCY_BUCKETS_MS.iter()) {
            cumulative += cell.load(Ordering::Relaxed);
            out.push_str(&format!("{name}_bucket{{le=\"{bound}\"}} {cumulative}\n"));
        }
        let total = self.count.load(Ordering::Relaxed);
        out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {total}\n"));
        out.push_str(&format!(
            "{name}_sum {}\n",
            self.sum_ms.load(Ordering::Relaxed)
        ));
        out.push_str(&format!("{name}_count {total}\n"));
        out
    }
}

/// Process metrics. Incremented on the verification hot paths.
#[derive(Debug, Default)]
pub struct Metrics {
    mfa_verified: AtomicU64,
    mfa_denied: AtomicU64,
    enroll_started: AtomicU64,
    token_refreshed: AtomicU64,
    // Aggregate denial reasons across `/v1/mfa/verify` and `/v1/verify`. The
    // HTTP answers are uniform; only the operator-side breakdown exists.
    denied_mismatch: AtomicU64,
    denied_out_of_window: AtomicU64,
    denied_replay: AtomicU64,
    denied_unknown_factor: AtomicU64,
    denied_inactive_factor: AtomicU64,
    denied_corrupt_factor: AtomicU64,
    /// `/v1/mfa/verify` duration.
    mfa_verify_latency: Histogram,
    /// `/v1/verify` (S2S) duration.
    s2s_verify_latency: Histogram,
}

impl Metrics {
    /// Creates zeroed metrics.
    #[must_use]
    pub fn new() -> Self {
        Self {
            mfa_verify_latency: Histogram::new(),
            s2s_verify_latency: Histogram::new(),
            ..Self::default()
        }
    }

    /// Counts a login verification outcome.
    pub fn mfa(&self, ok: bool) {
        if ok {
            self.mfa_verified.fetch_add(1, Ordering::Relaxed);
        } else {
            self.mfa_denied.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Counts a denied verification by internal reason. Aggregate only: the
    /// client cannot see the difference, an operator needs it.
    pub fn verify_denied(&self, denial: Denial) {
        let cell = match denial {
            Denial::UnknownFactor => &self.denied_unknown_factor,
            Denial::InactiveFactor => &self.denied_inactive_factor,
            Denial::CorruptFactor => &self.denied_corrupt_factor,
            Denial::CodeMismatch => &self.denied_mismatch,
            Denial::OutOfWindow => &self.denied_out_of_window,
            Denial::Replay => &self.denied_replay,
        };
        cell.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one `/v1/mfa/verify` request duration (any outcome).
    pub fn observe_mfa_verify(&self, elapsed: Duration) {
        self.mfa_verify_latency.observe(elapsed);
    }

    /// Records one `/v1/verify` (S2S) request duration (any outcome).
    pub fn observe_s2s_verify(&self, elapsed: Duration) {
        self.s2s_verify_latency.observe(elapsed);
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
             # HELP bandall_mfa_denied_total Denied login second factors (`/v1/mfa/verify`).\n\
             # TYPE bandall_mfa_denied_total counter\n\
             bandall_mfa_denied_total {}\n\
             # HELP bandall_enroll_started_total Started enrolments.\n\
             # TYPE bandall_enroll_started_total counter\n\
             bandall_enroll_started_total {}\n\
             # HELP bandall_token_refreshed_total Refresh rotations.\n\
             # TYPE bandall_token_refreshed_total counter\n\
             bandall_token_refreshed_total {}\n\
             # HELP bandall_verify_denied_total Denied verifications by internal reason, aggregate across `/v1/mfa/verify` and `/v1/verify`.\n\
             # TYPE bandall_verify_denied_total counter\n\
             bandall_verify_denied_total{{reason=\"code_mismatch\"}} {}\n\
             bandall_verify_denied_total{{reason=\"out_of_window\"}} {}\n\
             bandall_verify_denied_total{{reason=\"replay\"}} {}\n\
             bandall_verify_denied_total{{reason=\"unknown_factor\"}} {}\n\
             bandall_verify_denied_total{{reason=\"inactive_factor\"}} {}\n\
             bandall_verify_denied_total{{reason=\"corrupt_factor\"}} {}\n\
             {}\
             {}",
            load(&self.mfa_verified),
            load(&self.mfa_denied),
            load(&self.enroll_started),
            load(&self.token_refreshed),
            load(&self.denied_mismatch),
            load(&self.denied_out_of_window),
            load(&self.denied_replay),
            load(&self.denied_unknown_factor),
            load(&self.denied_inactive_factor),
            load(&self.denied_corrupt_factor),
            self.mfa_verify_latency
                .render("bandall_mfa_verify_latency_ms"),
            self.s2s_verify_latency
                .render("bandall_s2s_verify_latency_ms"),
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
    use super::{Histogram, Metrics};
    use crate::verify::Denial;
    use std::time::Duration;

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

    #[test]
    fn counts_every_denial_reason() {
        let metrics = Metrics::new();
        metrics.verify_denied(Denial::CodeMismatch);
        metrics.verify_denied(Denial::CodeMismatch);
        metrics.verify_denied(Denial::OutOfWindow);
        metrics.verify_denied(Denial::Replay);
        metrics.verify_denied(Denial::UnknownFactor);
        metrics.verify_denied(Denial::InactiveFactor);
        metrics.verify_denied(Denial::CorruptFactor);
        let text = metrics.render();
        for expected in [
            "bandall_verify_denied_total{reason=\"code_mismatch\"} 2",
            "bandall_verify_denied_total{reason=\"out_of_window\"} 1",
            "bandall_verify_denied_total{reason=\"replay\"} 1",
            "bandall_verify_denied_total{reason=\"unknown_factor\"} 1",
            "bandall_verify_denied_total{reason=\"inactive_factor\"} 1",
            "bandall_verify_denied_total{reason=\"corrupt_factor\"} 1",
        ] {
            assert!(text.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn histogram_buckets_are_cumulative_and_sum_matches() {
        let histogram = Histogram::new();
        histogram.observe(Duration::from_millis(3));
        histogram.observe(Duration::from_millis(7));
        histogram.observe(Duration::from_millis(0)); // sub-bucket minimum
        let text = histogram.render("test_latency_ms");
        // 3 ms and 7 ms both fall in le="10"; 0 ms in le="1".
        assert!(text.contains("test_latency_ms_bucket{le=\"1\"} 1"));
        assert!(text.contains("test_latency_ms_bucket{le=\"2\"} 1"));
        assert!(text.contains("test_latency_ms_bucket{le=\"10\"} 3"));
        assert!(text.contains("test_latency_ms_bucket{le=\"25\"} 3"));
        assert!(text.contains("test_latency_ms_bucket{le=\"+Inf\"} 3"));
        assert!(text.contains("test_latency_ms_sum 10"));
        assert!(text.contains("test_latency_ms_count 3"));
    }

    #[test]
    fn histogram_absorbs_durations_beyond_every_bucket() {
        let histogram = Histogram::new();
        histogram.observe(Duration::from_millis(90_000)); // 90 s
        let text = histogram.render("test_latency_ms");
        assert!(text.contains("test_latency_ms_bucket{le=\"2500\"} 0"));
        assert!(text.contains("test_latency_ms_bucket{le=\"+Inf\"} 1"));
    }

    #[test]
    fn zero_histograms_render_as_empty() {
        let text = Metrics::new().render();
        assert!(text.contains("bandall_mfa_verify_latency_ms_count 0"));
        assert!(text.contains("bandall_s2s_verify_latency_ms_count 0"));
        assert!(text.contains("bandall_mfa_verify_latency_ms_bucket{le=\"+Inf\"} 0"));
    }
}
