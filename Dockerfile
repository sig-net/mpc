FROM node:20 as eth-builder
WORKDIR /usr/src/app/contract-eth
COPY chain-signatures/contract-eth/package.json chain-signatures/contract-eth/package-lock.json ./
RUN npm install
COPY chain-signatures/contract-eth ./
RUN npx hardhat compile

FROM rust:latest as node-builder
RUN rustc --version --verbose
WORKDIR /usr/src/app
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends --assume-yes \
    protobuf-compiler libprotobuf-dev

# Create a dummy file to cache dependencies
RUN echo "fn main() {}" > dummy.rs
COPY chain-signatures/node/Cargo.toml Cargo.toml
RUN sed -i 's#src/main.rs#dummy.rs#' Cargo.toml
RUN sed -i 's#mpc-keys = { path = "../keys" }##' Cargo.toml
RUN sed -i 's#mpc-contract = { path = "../contract" }##' Cargo.toml
RUN sed -i 's#mpc-crypto = { path = "../mpc-crypto" }##' Cargo.toml
RUN sed -i 's#version.workspace = true##' Cargo.toml
RUN cargo build --release
# Now build the actual node
COPY chain-signatures/. .
COPY --from=eth-builder /usr/src/app/contract-eth/artifacts contract-eth/artifacts
RUN sed -i 's#target-dir = "../target"#target-dir = "target"#' .cargo/config.toml
RUN cargo build --release --package mpc-node

FROM debian:stable-slim as runtime
RUN apt-get update && apt-get install --assume-yes libssl-dev ca-certificates curl redis-server

RUN update-ca-certificates

COPY --from=node-builder /usr/src/app/target/release/mpc-node /usr/local/bin/mpc-node
COPY chain-signatures/node/redis.conf /etc/redis/redis.conf

# Create a script to start both Redis and the Rust app
RUN echo "#!/bin/bash\nchown redis:redis /data\nservice redis-server start &\nexec mpc-node start" > /start.sh \
    && chmod +x /start.sh

WORKDIR /usr/local/bin

# Start Redis and the Rust application
ENTRYPOINT [ "/start.sh" ]
