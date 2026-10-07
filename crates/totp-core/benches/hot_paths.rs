//! Benchmarks for the hot paths (H1, roadmap item 8).
//!
//! Run with `cargo bench -p bandall-totp-core`. These are **not** part of
//! `just check`: the repository has no performance threshold yet, and measured
//! SLOs are an H8 deliverable. They exist so that a regression in the crypto
//! core can be attributed to a change instead of guessed at, and so that H8
//! has a baseline to compare against when it sets a `verify` p99.
//!
//! What is measured, and why these three:
//!
//! - `generate`: every successful verification runs it once per candidate
//!   step, so it is the inner loop of the service.
//! - `verify`: the whole user-facing path (generate per candidate, constant
//!   time compare, window search).
//! - `base32_decode`: runs on every enrolment URI and every recovery code.
#![forbid(unsafe_code)]
// The `criterion_group!`/`criterion_main!` macros generate public functions
// that cannot carry rustdoc; this is a benchmark harness, not shipped API.
#![allow(missing_docs)]
// Benchmarks are a harness, not shipped code: unwraps here assert that the
// fixtures are valid, which is exactly what a benchmark wants.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bandall_totp_core::{Algorithm, Secret, TotpParams, base32, totp};

/// Fixed instant so runs are comparable; the maths does not depend on the
/// actual clock.
const NOW: u64 = 1_700_000_000;

/// Runs every benchmark group.
fn benches(c: &mut Criterion) {
    let params = TotpParams::default_params();
    let sha256 = TotpParams::new(Algorithm::Sha256, 6, params.period()).expect("valid params");

    // 20 bytes: the RFC 4226 minimum and what SHA-1 deployments issue.
    let secret_sha1 = Secret::from_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").expect("valid");
    let secret_sha256 = Secret::generate_for(Algorithm::Sha256).expect("CSPRNG must be available");

    c.bench_function("generate/sha1-6d", |b| {
        b.iter(|| totp::generate(black_box(&secret_sha1), black_box(params), black_box(NOW)));
    });

    c.bench_function("generate/sha256-6d", |b| {
        b.iter(|| totp::generate(black_box(&secret_sha256), black_box(sha256), black_box(NOW)));
    });

    let code = totp::generate(&secret_sha1, params, NOW).expect("valid");
    c.bench_function("verify/sha1-window1", |b| {
        b.iter(|| {
            totp::verify(
                black_box(&secret_sha1),
                black_box(params),
                black_box(&code),
                black_box(NOW),
                black_box(1),
                black_box(None),
            )
        });
    });

    // 20 bytes encodes to 32 Base32 characters, the common secret width.
    let raw = [0xABu8; 20];
    let encoded = base32::encode(&raw);
    c.bench_function("base32/decode-32chars", |b| {
        b.iter(|| base32::decode(black_box(&encoded)));
    });

    c.bench_function("base32/encode-20bytes", |b| {
        b.iter(|| base32::encode(black_box(&raw)));
    });
}

criterion_group!(groups, benches);
criterion_main!(groups);
