# syntax=docker/dockerfile:1

# Builder: cargo-chef keeps dependency layers cached between builds.
FROM rust:1.98.1-bookworm AS chef
WORKDIR /app
RUN cargo install cargo-chef --locked

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked --bin bandall

# Runtime: debian slim pinned by digest with a dedicated non-root user.
# (ADR-0002: distroless cc-debian12:nonroot ships a 0-byte libgcc_s.so.1 on
# arm64, so it cannot run our binary here. Re-evaluate in H5 hardening.)
FROM debian:12-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS runtime
RUN useradd --uid 65532 --create-home --shell /usr/sbin/nologin nonroot \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/bandall /usr/local/bin/bandall
USER nonroot:nonroot
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD ["/usr/local/bin/bandall", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/bandall"]
