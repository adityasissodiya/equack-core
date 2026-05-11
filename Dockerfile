FROM rust:1.85-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin equack_node

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/equack_node /usr/local/bin/
EXPOSE 9000
CMD ["equack_node"]
