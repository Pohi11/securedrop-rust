# syntax=docker/dockerfile:1.7
#
# SecureDrop API image.
#
#   docker build -f deploy/docker/Dockerfile -t securedrop-api .
#
# Stage layout:
#   planner  - computes a "recipe" of the dependency graph (cargo-chef)
#   builder  - builds dependencies from the recipe (cached layer), then the app
#   runtime  - distroless, non-root, contains only the binary

ARG RUST_IMAGE=lukemathwalker/cargo-chef:latest-rust-1-bookworm

FROM ${RUST_IMAGE} AS chef
WORKDIR /app

# --- 1. Planner: summarise Cargo.toml/Cargo.lock into recipe.json -------------------------
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# --- 2. Builder ---------------------------------------------------------------------------
FROM chef AS builder
# Dependencies only change when Cargo.toml/Cargo.lock change, so this layer (the slow part,
# ~400 crates including the AWS SDK) is reused across most source-code edits.
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json -p securedrop-api

COPY . .
# Compile-time-checked SQL is verified against the committed .sqlx/ data instead of a live DB.
ENV SQLX_OFFLINE=true
RUN cargo build --release --locked -p securedrop-api --bin securedrop-api

# --- 3. Runtime ---------------------------------------------------------------------------
# distroless/cc: glibc + libgcc + CA certificates, no shell, no package manager, no curl.
# Must match the builder's Debian release (bookworm = debian12) for glibc compatibility.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=builder /app/target/release/securedrop-api /usr/local/bin/securedrop-api

# The :nonroot variant runs as uid 65532. Combined with a read-only root filesystem in ECS,
# a compromised process can neither write binaries nor escalate via setuid tools (none exist).
USER nonroot:nonroot

ENV APP_ENV=production \
    BIND_ADDR=0.0.0.0:8080 \
    METRICS_ADDR=0.0.0.0:9100 \
    LOG_FORMAT=json

EXPOSE 8080 9100

# No shell or curl in the image, so the binary checks itself.
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/securedrop-api", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/securedrop-api"]
