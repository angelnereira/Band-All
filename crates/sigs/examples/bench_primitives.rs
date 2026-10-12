//! Measured cost of each authentication primitive, so a design can state
//! numbers instead of adjectives.
//!
//! Not part of any gate: it prints, it does not assert. Run with
//! `cargo run -p bandall-sigs --release --example bench_primitives`.

// An example is the one place in this crate allowed to talk to the terminal,
// and it is allowed to unwrap while setting itself up: it is a measuring
// instrument, not shipped code.
#![allow(clippy::print_stdout, clippy::print_stderr, clippy::unwrap_used)]

use std::time::Instant;

use bandall_sigs::{SignedRequest, canonical, fresh_nonce, sign, verify};

/// Runs `iters` calls and keeps the best of three.
///
/// Each call returns a value the loop accumulates and the optimizer cannot see
/// through. Without that, `--release` deletes the whole loop and every number
/// comes out as 0.000, which is the one result that must never appear in an ADR.
fn bench(label: &str, iters: u32, mut f: impl FnMut() -> u64) {
    f();
    let mut best = f64::MAX;
    for _ in 0..3 {
        let mut acc = 0u64;
        let start = Instant::now();
        for _ in 0..iters {
            acc = acc.wrapping_add(f());
        }
        // Nanoseconds, with one decimal. `{:.3}` on seconds prints 0.000 for
        // anything under a microsecond, which is every number this file is
        // about; the first version of this benchmark reported 0.000 for all
        // three primitives because of that alone.
        let per = start.elapsed().as_nanos() as f64 / f64::from(iters);
        std::hint::black_box(acc);
        if per < best {
            best = per;
        }
    }
    println!("{label:<46} {best:>9.1} ns/op");
}

fn main() {
    let iters = 200_000;
    let key = [7u8; 32];
    let body = b"{\"amount\":1250,\"currency\":\"EUR\",\"to\":\"acct-991\"}";
    let req = SignedRequest {
        method: "POST".to_string(),
        path: "/v1/payments".to_string(),
        query: String::new(),
        body: body.to_vec(),
        timestamp: 1_700_000_000,
        nonce: fresh_nonce().unwrap(),
    };
    let canon = canonical(&req).unwrap();
    let mac = sign(&key, &req).unwrap();

    println!(
        "payload: body {} B, canonical {} B, tag {} B",
        body.len(),
        canon.len(),
        mac.len()
    );
    bench("canonical string (build)", iters, || {
        canonical(&req).map(|c| c.len() as u64).unwrap_or(0)
    });
    bench("HMAC-SHA-256 sign", iters, || {
        sign(&key, &req).map(|m| m.len() as u64).unwrap_or(0)
    });
    // With the nonce store inside, because that is what a verifier actually
    // pays, and the store is the part a per-channel scheme can delete.
    bench("verify (structure + ts + nonce + mac)", 100_000, || {
        let mut cache = bandall_sigs::NonceCache::new();
        verify(&key, &req, &mac, 1_700_000_000, &mut cache)
            .map(|()| 1)
            .unwrap_or(0)
    });
}
