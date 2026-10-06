FROM rust:alpine AS builder

WORKDIR /usr/src/app
RUN apk add --no-cache musl-dev sqlite-dev pkgconf
# Prepare a dummy main to cache dependencies
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
COPY schema.sql ./
RUN cargo build --release

FROM alpine:3.21

# Install sqlite for backups if needed, though the backup script could just run it
RUN apk add --no-cache sqlite
WORKDIR /app
COPY --from=builder /usr/src/app/target/release/verifier /app/verifier
COPY --from=builder /usr/src/app/target/release/emqx-device /app/emqx-device

# Create a nonroot user
RUN addgroup -S -g 65532 nonroot && adduser -S -u 65532 -G nonroot nonroot
RUN chown -R nonroot:nonroot /app
USER nonroot:nonroot

EXPOSE 8000
VOLUME /data

# Default CMD runs the server
CMD ["/app/verifier"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/verifier", "healthcheck"]
