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

# Runtime: distroless, non-root, no shell. The healthcheck uses the binary itself.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime
COPY --from=builder /app/target/release/bandall /usr/local/bin/bandall
USER nonroot:nonroot
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD ["/usr/local/bin/bandall", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/bandall"]
