# syntax=docker/dockerfile:1

FROM rust:1.89-bookworm AS builder
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY assets ./assets

RUN cargo build --release --locked

FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/deluge-torrent-mcp /usr/local/bin/deluge-torrent-mcp

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/deluge-torrent-mcp"]
CMD ["--transport", "http", "--http-bind", "0.0.0.0:8080"]
