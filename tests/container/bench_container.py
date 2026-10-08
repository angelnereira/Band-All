#!/usr/bin/env python3
"""Simulated load against the running container, using throwaway mock clients.

Nothing here asserts correctness — that is `verify_container.py`. This measures
so the SLO numbers in `docs/OPERATIONS.md` are measured rather than guessed, as
H8 requires. Every "user" is a factor enrolled through the real API, so the
load path includes the real crypto and the real database.

Usage: python3 bench_container.py <base_url> <service_key> <tenant_id>
"""

from __future__ import annotations

import concurrent.futures
import json
import statistics
import sys
import time
import uuid

from totp_client import Client, Session

# Percentiles of the observed latency samples. p99 over a few hundred requests
# is noisy, so each phase runs enough requests to have a usable tail.
PHASES = [
    ("verify_s2s_sequential", "sequential S2S /v1/verify", 1, 200),
    ("verify_s2s_concurrency_10", "10 parallel clients", 10, 400),
    ("verify_s2s_concurrency_50", "50 parallel clients", 50, 500),
    ("denied_wrong_code", "uniform denial path (401 only)", 10, 300),
    ("forward_auth", "offline token check /v1/authz/check", 25, 500),
]

# The rate limiter is per factor/tenant/IP and is a process-local map, so a
# benchmark phase that hammers one tenant eventually trips it. Each phase gets
# its own throwaway tenant, which keeps the phases independent and stops one
# phase's failures from throttling the next.


def percentile(samples: list[float], pct: float) -> float:
    ordered = sorted(samples)
    index = min(len(ordered) - 1, int(round(pct / 100 * (len(ordered) - 1))))
    return ordered[index]


def summarize(name: str, samples: list[float], errors: int) -> dict:
    return {
        "phase": name,
        # Sampled responses, which is fewer than the requests issued whenever
        # the rate limiter refused some.
        "requests": len(samples),
        "errors": errors,
        "p50_ms": round(percentile(samples, 50), 2),
        "p95_ms": round(percentile(samples, 95), 2),
        "p99_ms": round(percentile(samples, 99), 2),
        "max_ms": round(max(samples), 2),
    }


def prepare_users(
    base_url: str,
    service_key: str,
    tenant_id: str,
    count: int,
    prefix: str = "bench",
) -> list[Session]:
    """Enrolls `count` throwaway users through the real API."""
    client = Client(base_url, service_key=service_key)
    users = []
    for index in range(count):
        session = Session(client, tenant_id, f"{prefix}-{uuid.uuid4().hex[:10]}")
        session.enroll(issuer="Bench")
        users.append(session)
        if (index + 1) % 50 == 0 or index + 1 == count:
            print(f"  enrolled {index + 1}/{count} throwaway users", flush=True)
    return users


def phase_verify(users: list[Session], workers: int, total: int) -> tuple[list[float], int]:
    """S2S verification of the accept path: one request per user, so no request
    is a replay of another's step and every sample measures a real success.

    `policy_tenant_max_attempts` is a ceiling over the whole run, so a late
    phase can be throttled by the earlier ones. 429 is counted separately from
    errors: it is the limiter working, not a broken verification.
    """
    accepted: list[float] = []
    throttled = 0
    errors = 0

    def one(user: Session) -> tuple[float, int]:
        result = user.s2s_verify()
        return result.elapsed_ms, result.status

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for elapsed, status in pool.map(one, users):
            if status == 200:
                accepted.append(elapsed)
            elif status == 429:
                throttled += 1
            else:
                errors += 1

    if throttled:
        print(
            f"  note: {throttled} requests were throttled with 429 by the tenant "
            f"ceiling; latency below covers the {len(accepted)} accepted ones",
            flush=True,
        )
    return accepted or [0.0], errors


def phase_denied(users: list[Session], workers: int, total: int) -> tuple[list[float], int]:
    """Same path with a wrong code: measures the denial branch, which must cost
    about the same as acceptance (anti-enumeration ballast, T2).

    A flood of failures is exactly what the rate limiter exists for, so most of
    these requests come back 429 instead of 401. Both are refusals and both are
    the right answer, but they measure different things: 401 is the work the
    server does to deny (crypto + DB lookup), 429 is the cheap early exit. The
    samples are reported separately so the anti-enumeration cost is not hidden
    behind the throttle, and the throttle is not mistaken for slow denial.
    """
    denied: list[float] = []
    throttled: list[float] = []
    errors = 0

    def one(user: Session) -> tuple[float, int]:
        result = user.s2s_verify("000000")
        return result.elapsed_ms, result.status

    # A wrong code never consumes a step, so the pool is reused cyclically.
    tasks = [users[index % len(users)] for index in range(total)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for elapsed, status in pool.map(one, tasks):
            if status == 401:
                denied.append(elapsed)
            elif status == 429:
                throttled.append(elapsed)
            else:
                errors += 1

    if throttled:
        print(
            f"  note: {len(throttled)}/{total} were refused with 429 by the rate limiter; "
            f"reported below are the {len(denied)} real denials",
            flush=True,
        )
    if not denied:
        # Every request was throttled: the denial path was never measured.
        return throttled or [0.0], errors
    return denied, errors


def phase_forward_auth(users: list[Session], workers: int, total: int) -> tuple[list[float], int]:
    client = Client(users[0].client.base_url, service_key=users[0].client.service_key)
    tokens: list[str] = []
    for user in users[:workers]:
        result = user.mfa_verify()
        if result.status == 200:
            tokens.append(result.json["access_token"])
    if not tokens:
        return [0.0], 1

    samples: list[float] = []

    def one(token: str) -> tuple[float, int]:
        result = client.get(
            "/v1/authz/check", headers={"Authorization": f"Bearer {token}"}
        )
        return result.elapsed_ms, result.status

    tasks = [tokens[index % len(tokens)] for index in range(total)]
    errors = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for elapsed, status in pool.map(one, tasks):
            samples.append(elapsed)
            if status != 200:
                errors += 1
    return samples, errors


def main() -> int:
    if len(sys.argv) != 4:
        raise SystemExit(f"usage: {sys.argv[0]} <base_url> <service_key> <tenant_id>")
    base_url, service_key, tenant_id = sys.argv[1:4]

    report = []
    for index, (name, description, workers, total) in enumerate(PHASES):
        print(f"\n== {name}: {description} ({workers} workers, {total} requests)", flush=True)
        # A fresh pool per phase: every accepted verification consumes a step and
        # only ~3 steps are usable per factor, so reusing a user would measure
        # the replay path instead of the accept path.
        pool = total if name.startswith("verify") else min(workers + 5, 60)
        # Users are namespaced per phase so no two phases share a factor key.
        prefix = f"bench{index}"
        print(f"  enrolling {pool} throwaway users ...", flush=True)
        users = prepare_users(base_url, service_key, tenant_id, pool, prefix)

        started = time.perf_counter()
        if name == "forward_auth":
            samples, errors = phase_forward_auth(users, workers, total)
        elif name == "denied_wrong_code":
            samples, errors = phase_denied(users, workers, total)
        else:
            samples, errors = phase_verify(users, workers, total)
        wall = time.perf_counter() - started
        entry = summarize(name, samples, errors)
        entry["wall_s"] = round(wall, 2)
        # Throughput is over the requests actually issued, not over the samples
        # that survived the limiter: dividing by the sample count would report a
        # throughput the server never delivered.
        entry["throughput_rps"] = round(total / wall, 1) if wall else 0.0
        entry["mean_ms"] = round(statistics.fmean(samples), 2) if samples else 0.0
        report.append(entry)
        print(json.dumps(entry), flush=True)

    print("\n=== SUMMARY ===")
    print(f"{'phase':<26} {'reqs':>5} {'p50':>8} {'p95':>8} {'p99':>8} {'max':>8} {'rps':>8} {'err':>4}")
    for entry in report:
        print(
            f"{entry['phase']:<26} {entry['requests']:>5} {entry['p50_ms']:>8} "
            f"{entry['p95_ms']:>8} {entry['p99_ms']:>8} {entry['max_ms']:>8} "
            f"{entry['throughput_rps']:>8} {entry['errors']:>4}"
        )

    with open("bench-results.json", "w", encoding="utf-8") as handle:
        json.dump(
            {
                "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "base_url": base_url,
                "phases": report,
            },
            handle,
            indent=2,
        )
    print("\nwrote bench-results.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())