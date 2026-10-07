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
    # RUSTSEC-2023-0071 (Marvin Attack, RSA key recovery via timing) reaches
    # this graph only through `rsa` <- `sqlx-mysql`, an optional sqlx feature
    # that `crates/store` never enables, so `cargo tree` shows no `rsa` node in
    # the enabled feature graph and the code is never compiled. There is no
    # upstream fix. Revisit before BandAll ever enables a MySQL backend.
    #
    # Kept here rather than in an `audit.toml` because cargo-audit 0.22 has no
    # config file: it silently ignores one, so the ignore would look effective
    # and never apply.
    cargo audit --deny warnings --ignore RUSTSEC-2023-0071

# CI-only jobs, exposed locally for convenience.
sdks:
    #!/usr/bin/env bash
    set -euo pipefail
    # Python first: it has no toolchain requirement, so it must never be
    # skipped because of an unrelated Node limitation. `python3` is the name on
    # most systems; CI's setup-python puts `python` on PATH, `python3` covers
    # both.
    (cd sdks/python && python3 -m unittest discover -s tests)

    # The TypeScript test runs `node --test` on a `.ts` file, which needs Node's
    # native type stripping: default from Node 23.6 (CI pins 24). Older builds
    # and distro builds compiled without it fail with ERR_UNKNOWN_FILE_EXTENSION
    # / ERR_NO_TYPESCRIPT, which says nothing about the SDK. Detect that case
    # and skip instead of reporting a red gate for an environment gap; when the
    # Node is capable, a failure here is real and must fail the recipe.
    node_major=$(node --version | sed -E 's/^v([0-9]+)\..*/\1/')
    if [ "$node_major" -lt 24 ] || ! node -e 'process.features.typescript' 2>/dev/null; then
        echo "SKIP: sdks/ts (node $(node --version) has no native type stripping; CI pins 24)" >&2
    else
        (cd sdks/ts && node --test test/vectors.test.ts)
    fi

    # Go SDK: offline JWT + HMAC, same conformance vectors.
    (cd sdks/go && go test ./...)

    # C# SDK: offline JWT (Ed25519 via BouncyCastle) + HMAC, same vectors.
    if command -v dotnet >/dev/null 2>&1; then
        (cd sdks/csharp && dotnet test tests/BandAll.Tests/BandAll.Tests.csproj)
    else
        echo "SKIP: sdks/csharp (dotnet not installed)" >&2
    fi

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