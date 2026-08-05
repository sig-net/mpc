# A whole MPC network in one image: Redis, a NEAR sandbox, the bootstrap and three MPC nodes.
#
# Build from the repository root, because the Cargo workspace is the build context:
#
#   docker build -f localnet/Dockerfile -t sig-net/mpc-localnet .
#
# `localnet/docker-compose.yaml` does this for you with `context: ..`.
#
# Solana is deliberately not in here. It is the one dependency a consumer is likely to
# already run, so it is reached over the network and configured with LOCALNET_SOLANA_RPC.

# The contract has to be built with rustc 1.81. Newer versions emit wasm features that the
# nearcore build in the sandbox stage rejects, with an unhelpful deserialisation error.
# `build-contract.sh` pins the same version for the same reason.
FROM rust:1.81-bookworm AS contract-builder
WORKDIR /usr/src/app
RUN rustup target add wasm32-unknown-unknown
COPY Cargo.toml Cargo.lock ./
COPY chain-signatures/ ./chain-signatures
COPY integration-tests/ ./integration-tests
COPY localnet/ ./localnet
RUN cargo build --release --target wasm32-unknown-unknown --package mpc-contract

# Both binaries come out of one cargo invocation. They share a workspace and most of their
# dependency graph, so building them separately compiles that graph twice.
#
# The repository root Dockerfile runs hardhat to produce the ChainSignatures ABI that
# `chain-signatures/node/src/rpc.rs` pulls in with include_str!. That artifact is committed
# and is not excluded by .dockerignore, so it arrives with the source and this stage needs
# neither node nor npm.
FROM rust:latest AS binaries
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
RUN cargo build --release --package mpc-node --package mpc-localnet

# NEAR's own `ghcr.io/near/sandbox` is not usable here. Its `latest` tag is amd64-only, and
# on an Apple Silicon host that means emulation: plain qemu-user hangs neard at 0% CPU, and
# Rosetta is on its way out of macOS. Its `latest-aarch64` tag is native but was built in
# 2023 against nearcore 1.35.0, which is too old for the near-workspaces version this
# repository uses. It fails with a missing `genesis_hash` field.
#
# NEAR does publish Linux-aarch64 sandbox binaries, from nearcore 2.6.5 onwards. They are
# simply newer than the 2.3.1 that near-sandbox-utils 0.12.0 defaults to, which is why the
# tooling reports arm64 as unsupported. Downloading one directly gives a native image on
# both architectures without compiling nearcore.
FROM debian:stable-slim AS near-sandbox
# First version with Linux-aarch64 builds, and the closest such version to the 2.3.1 that
# near-workspaces 0.15.0 was written against. Newer versions up to 2.13.2 also publish
# arm64 binaries if this ever needs moving.
ARG NEAR_SANDBOX_VERSION=2.6.5
RUN apt-get update \
    && apt-get install --no-install-recommends --assume-yes ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
# The architecture comes from `uname -m` rather than BuildKit's TARGETARCH, so this builds
# under the classic builder too, and because its output already matches the names NEAR
# publishes under.
RUN set -eu; \
    arch="$(uname -m)"; \
    case "${arch}" in \
      aarch64) platform=Linux-aarch64 ;; \
      x86_64)  platform=Linux-x86_64 ;; \
      *) echo "no near-sandbox build published for ${arch}" >&2; exit 1 ;; \
    esac; \
    curl --fail --silent --show-error --location \
      "https://s3-us-west-1.amazonaws.com/build.nearprotocol.com/nearcore/${platform}/${NEAR_SANDBOX_VERSION}/near-sandbox.tar.gz" \
      | tar xz -C /tmp; \
    mv "/tmp/${platform}/near-sandbox" /usr/local/bin/near-sandbox; \
    chmod +x /usr/local/bin/near-sandbox; \
    rm -rf "/tmp/${platform}"

# Initialising at build time makes genesis part of the image rather than something generated
# per container, so restarting keeps the same chain.
#
# --test-seed makes the root account's key a function of the seed instead of random, so the
# bootstrap can derive it rather than having it passed in. --chain-id keeps that stable too,
# since init otherwise invents a random one. --fast shortens block production, which is what
# you want locally and nowhere else.
ARG NEAR_ROOT_ACCOUNT=test.near
RUN near-sandbox --home /near-home init \
    --chain-id localnet \
    --account-id "${NEAR_ROOT_ACCOUNT}" \
    --test-seed "${NEAR_ROOT_ACCOUNT}" \
    --fast

FROM redis:7.4.2 AS redis-bin

FROM debian:stable-slim AS runtime
# procps is here for whoever has to look inside a running container. Five processes share
# this one, so `ps` and `pgrep` are the difference between diagnosing a dead node and
# guessing. `kill` is a bash builtin, but procps supplies the standalone binary that
# `docker exec <container> kill <pid>` needs.
RUN apt-get update \
    && apt-get install --no-install-recommends --assume-yes \
    ca-certificates curl libssl3 procps \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

COPY --from=redis-bin /usr/local/bin/redis-server /usr/local/bin/redis-server
COPY --from=near-sandbox /usr/local/bin/near-sandbox /usr/local/bin/near-sandbox
COPY --from=near-sandbox /near-home /near-home
COPY --from=binaries /usr/src/app/target/release/mpc-node /usr/local/bin/mpc-node
COPY --from=binaries /usr/src/app/target/release/mpc-localnet /usr/local/bin/mpc-localnet
COPY --from=contract-builder \
    /usr/src/app/target/wasm32-unknown-unknown/release/mpc_contract.wasm \
    /artifacts/mpc_contract.wasm

COPY chain-signatures/node/redis.conf /etc/redis/redis.conf
# Prebuilt from sig-net/solana-signet-program 0.4.0. Its declare_id! pins it to the address
# in localnet/bootstrap/src/solana.rs.
COPY chain-signatures/contract-sol/artifacts/chain_signatures.so /artifacts/chain_signatures.so
# The dealt triples and presignatures the bootstrap preloads into Redis, from the same file
# the committed key shares come from.
COPY integration-tests/src/mpc_fixture/3_nodes.json /artifacts/mpc_fixture.json

COPY localnet/nodes/ /localnet/nodes/
# Baked in rather than mounted, so the image is the whole cluster. The nodes only rewrite a
# share during key generation or resharing, neither of which happens here, but the container
# layer is writable so a stray write is harmless instead of fatal.
COPY localnet/keyshares/mpc0.test.near.json /data/keyshare-mpc0.test.near
COPY localnet/keyshares/mpc1.test.near.json /data/keyshare-mpc1.test.near
COPY localnet/keyshares/mpc2.test.near.json /data/keyshare-mpc2.test.near
COPY localnet/keyshares/ /localnet/keyshares/

COPY localnet/entrypoint.sh /usr/local/bin/localnet-entrypoint
RUN chmod +x /usr/local/bin/localnet-entrypoint

ENV LOCALNET_NODES_DIR=/localnet/nodes \
    LOCALNET_KEYSHARES_DIR=/localnet/keyshares \
    LOCALNET_CONTRACT_WASM=/artifacts/mpc_contract.wasm \
    LOCALNET_PROGRAM_SO=/artifacts/chain_signatures.so \
    LOCALNET_FIXTURE=/artifacts/mpc_fixture.json \
    LOCALNET_NEAR_RPC=http://127.0.0.1:3030 \
    LOCALNET_REDIS_URL=redis://127.0.0.1:6379

# 3000 to 3002 are the MPC nodes, 3030 is the NEAR RPC, 6379 is Redis. Redis and NEAR are
# published for inspection; nothing outside needs them.
EXPOSE 3000 3001 3002 3030 6379

# `running` is not the same as ready: a request submitted the moment the nodes report it goes
# unanswered for roughly another 25 seconds. This reports the state the nodes report, so
# treat healthy as "the cluster exists", not as "it will answer you".
HEALTHCHECK --interval=5s --timeout=5s --start-period=30s --retries=60 \
    CMD for p in 3000 3001 3002; do \
          curl --fail --silent "http://127.0.0.1:$p/state" | grep -q '"running"' || exit 1; \
        done

ENTRYPOINT ["/usr/local/bin/localnet-entrypoint"]
