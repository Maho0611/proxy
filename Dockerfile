FROM rust:1.85-bookworm AS zenproxy-builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY README.md ./README.md
COPY src ./src
COPY config.toml.example ./config.toml.example
RUN cargo build --release && strip target/release/zenproxy

FROM golang:1.24-bookworm AS singbox-builder
WORKDIR /src/sing-box-zenproxy
COPY sing-box-zenproxy/go.mod sing-box-zenproxy/go.sum ./
RUN go mod download
COPY sing-box-zenproxy ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -tags "with_clash_api with_utls with_quic" -o /out/sing-box ./cmd/sing-box

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=zenproxy-builder /app/target/release/zenproxy /app/zenproxy
COPY --from=zenproxy-builder /app/target/release/migrate_sqlite_to_postgres /app/migrate_sqlite_to_postgres
COPY --from=singbox-builder /out/sing-box /usr/local/bin/sing-box
COPY config.toml.example /app/config.toml
RUN mkdir -p /app/data \
    && chmod +x /app/zenproxy /app/migrate_sqlite_to_postgres /usr/local/bin/sing-box
EXPOSE 3000 1080
CMD ["./zenproxy"]
