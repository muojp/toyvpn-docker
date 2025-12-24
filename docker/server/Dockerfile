# Server Image - Rust version
FROM rust:1.83-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Rust project
COPY rust/Cargo.toml ./
COPY rust/src/ ./src/

# Build release binary
RUN cargo build --release

# Runtime image
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary from builder
COPY --from=builder /app/target/release/toyvpn-server .
COPY docker/server/server_entrypoint.sh .

RUN chmod +x server_entrypoint.sh toyvpn-server

# Set environment for logging
ENV RUST_LOG=info

ENTRYPOINT ["./server_entrypoint.sh"]
