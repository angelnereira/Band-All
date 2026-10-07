# syntax=docker/dockerfile:1

# Builder: cargo-chef keeps dependency layers cached between builds.
# The Rust version mirrors `rust-toolchain.toml` (1.99.0).
FROM rust:1.99.0-bookworm AS chef
WORKDIR /app
RUN cargo install cargo-chef --locked

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked --bin bandall \
    # `/data` is where the runtime keeps its writable state (SQLite file,
    # signing keys). It must exist with user ownership in the image so that a
    # fresh named volume inherits it on first use.
    && mkdir -p /app/runtime-data

# Runtime: distroless cc, pinned by the digest of the multi-arch index.
#
# (ADR-0002 originally used debian:12-slim because distroless `cc` shipped a
# 0-byte libgcc_s.so.1 on arm64. Re-evaluated in H5 by pulling the current
# `cc-debian12:nonroot` index and extracting its layers: libgcc_s.so.1 is a
# real 133 KB ELF on arm64 and 125 KB on amd64, and the four libraries the
# release binary needs — libgcc_s, libm, libc, ld-linux — all ship in both
# architectures. ca-certificates and the `nonroot` user (uid 65532) come with
# the image, so no apt or useradd step is needed in the runtime stage.)
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime
COPY --from=builder /app/target/release/bandall /usr/local/bin/bandall
# The writable data directory, owned by the runtime user. Fresh named volumes
# inherit the ownership of this directory on first mount, otherwise a demo
# (= first boot) cannot create `keys` or the SQLite file.
COPY --from=builder --chown=nonroot:nonroot /app/runtime-data /data
USER nonroot:nonroot
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD ["/usr/local/bin/bandall", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/bandall"]
