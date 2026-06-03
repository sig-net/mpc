FROM redis:7.4.2 AS redis-bin

FROM node:20 AS eth-builder
WORKDIR /usr/src/app/contract-eth
COPY chain-signatures/contract-eth/package.json chain-signatures/contract-eth/package-lock.json ./
RUN npm install
COPY chain-signatures/contract-eth ./
RUN npx hardhat compile

FROM rust:latest AS node-builder
RUN rustc --version --verbose
WORKDIR /usr/src/app
ARG GIT_COMMIT_HASH
ENV GIT_COMMIT_HASH=$GIT_COMMIT_HASH
COPY chain-signatures/ ./chain-signatures
COPY integration-tests/ ./integration-tests
COPY Cargo.toml .
COPY Cargo.lock .
COPY --from=eth-builder /usr/src/app/contract-eth/artifacts chain-signatures/contract-eth/artifacts
RUN cargo build --release --package mpc-node --features helios

FROM debian:stable-slim AS runtime
RUN apt-get update && apt-get install --assume-yes libssl-dev ca-certificates curl

RUN update-ca-certificates

COPY --from=redis-bin /usr/local/bin/redis-server /usr/local/bin/redis-server
COPY --from=node-builder /usr/src/app/target/release/mpc-node /usr/local/bin/mpc-node
COPY chain-signatures/node/redis.conf /etc/redis/redis.conf

# Create a script to start both Redis and the Rust app
RUN echo "#!/bin/bash\nredis-server /etc/redis/redis.conf &\nexec env RUST_LOG=${RUST_LOG:-mpc_node=debug,helios=info} mpc-node start" > /start.sh \
    && chmod +x /start.sh

WORKDIR /usr/local/bin

# Start Redis and the Rust application
ENTRYPOINT [ "/start.sh" ]
