# BandAll task runner. `just check` mirrors the CI pipeline exactly: same
# commands, same flags, same order.
set shell := ["bash", "-uc"]

# List available recipes.
default:
    @just --list

# Full local gate: everything CI runs, in the same order.
check: fmt clippy test msrv coverage deny audit
    @echo "gate: local checks passed (sdks/docker jobs run in CI only)"

fmt:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

test:
    cargo test --workspace --locked

# Minimum supported Rust version must keep compiling.
msrv:
    cargo +1.85.0 check --workspace --all-targets --locked

# Core coverage (H1 gate: > 90%). See docs/VERIFICATION.md if llvm-cov is
# missing locally.
coverage:
    cargo llvm-cov --workspace --locked --lcov --output-path lcov.info

deny:
    cargo deny check

audit:
    cargo audit --deny warnings

# CI-only jobs, exposed locally for convenience.
sdks:
    cd sdks/ts && node --test test/vectors.test.ts
    cd sdks/python && python -m unittest discover -s tests

docker-build:
    docker build -f deploy/Dockerfile -t bandall:dev .

docker-up:
    docker compose -f deploy/compose/compose.yaml up --build -d

docker-down:
    docker compose -f deploy/compose/compose.yaml down -v

# Install the local tooling these recipes need.
install-tools:
    cargo install just cargo-deny cargo-audit --locked
    cargo install cargo-llvm-cov --locked