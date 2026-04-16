FROM rust:1.90 as builder
RUN apt-get update && apt install -y cmake

WORKDIR /usr/src/matrix-lightning-tip-bot

# Build dependencies first, cached independently of src/.
# Uses a stub main.rs so cargo resolves + compiles all deps based on Cargo.toml+lock.
COPY Cargo.toml Cargo.lock ./
COPY diesel.toml .
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --locked
RUN rm -rf src target/release/matrix-lightning-tip-bot target/release/matrix-lightning-tip-bot.d \
    && find target/release/deps -name 'matrix_lightning_tip_bot*' -delete

# Now bring in the real sources and rebuild only our crate.
COPY src ./src
RUN cargo install --path . --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates  libssl-dev sqlite3 libsqlite3-dev && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/matrix-lightning-tip-bot /usr/local/bin/matrix-lightning-tip-bot
