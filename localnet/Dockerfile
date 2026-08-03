# Bootstrap image for the local MPC cluster.
#
# Build from the repository root, because the Cargo workspace is the build context:
#
#   docker build -f localnet/Dockerfile -t mpc-localnet .
#
# `localnet/docker-compose.yaml` does this for you with `context: ..`.
#
# The MPC node image is the repository's root Dockerfile, untouched. This one carries only
# the bootstrap binary and the two compiled artifacts it installs on the two chains.

# The contract has to be built with rustc 1.81. Newer versions emit wasm features that the
# nearcore build inside the sandbox image rejects, with an unhelpful deserialisation error.
# `build-contract.sh` pins the same version for the same reason.
FROM rust:1.81-bookworm AS contract-builder
WORKDIR /usr/src/app
RUN rustup target add wasm32-unknown-unknown
COPY Cargo.toml Cargo.lock ./
COPY chain-signatures/ ./chain-signatures
COPY integration-tests/ ./integration-tests
COPY localnet/ ./localnet
RUN cargo build --release --target wasm32-unknown-unknown --package mpc-contract

# Tracks the root Dockerfile's node-builder, which also builds this workspace on rust:latest.
FROM rust:latest AS bootstrap-builder
WORKDIR /usr/src/app
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends --assume-yes \
    protobuf-compiler libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY chain-signatures/ ./chain-signatures
COPY integration-tests/ ./integration-tests
COPY localnet/ ./localnet
RUN cargo build --release --package mpc-localnet

FROM debian:stable-slim AS runtime
RUN apt-get update \
    && apt-get install --no-install-recommends --assume-yes ca-certificates curl libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

COPY --from=bootstrap-builder /usr/src/app/target/release/mpc-localnet /usr/local/bin/mpc-localnet
COPY --from=contract-builder \
    /usr/src/app/target/wasm32-unknown-unknown/release/mpc_contract.wasm \
    /artifacts/mpc_contract.wasm
# Prebuilt from sig-net/solana-signet-program 0.4.0. Its declare_id! pins it to the address
# in localnet/bootstrap/src/solana.rs.
COPY chain-signatures/contract-sol/artifacts/chain_signatures.so /artifacts/chain_signatures.so

WORKDIR /localnet
ENTRYPOINT ["mpc-localnet"]
CMD ["bootstrap"]
