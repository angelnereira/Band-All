# BandAll task runner. `just check` must match the CI pipeline exactly.
set shell := ["bash", "-uc"]

# List available recipes.
default:
    @just --list

# Run the full local gate: fmt + clippy + tests + deny + audit.
check: fmt clippy test deny audit

fmt:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
    cargo test --workspace

deny:
    cargo deny check

audit:
    cargo audit

# Install the local tooling this justfile needs.
install-tools:
    cargo install just cargo-deny cargo-audit --locked

# Build the production container image.
docker-build:
    docker build -f deploy/Dockerfile -t bandall:dev .

# Start the local dev stack (api + Postgres).
up:
    docker compose -f deploy/compose/compose.yaml up --build

down:
    docker compose -f deploy/compose/compose.yaml down
