FROM redis:7.4.2 AS redis-bin

FROM node:20 AS eth-builder
WORKDIR /usr/src/app/contract-eth
COPY chain-signatures/contract-eth/package.json chain-signatures/contract-eth/package-lock.json ./
RUN npm install
COPY chain-signatures/contract-eth ./
RUN npx hardhat compile

# What the Midnight publisher proves with: the singleton's packaged keys and IR, the
# KZG parameters its circuits and the DUST spend need, and the DUST spend's keys. The
# node fetches a missing file at runtime, so baking them in keeps proving offline.
FROM debian:bookworm-slim AS midnight-artifacts
RUN apt-get update && apt-get install --assume-yes --no-install-recommends ca-certificates curl
WORKDIR /tmp/midnight
RUN curl -fsSL --retry 4 -o contract.tgz \
      https://registry.npmjs.org/@sig-net/midnight-contract/-/midnight-contract-0.25.0.tgz \
    && echo "c965f4033897dd09d7fc8eaf4b1a0913e7992401f8b5c206aa9a9f9f177fb928  contract.tgz" | sha256sum -c \
    && tar -xzf contract.tgz \
    && mkdir -p /out/signet-contract /out/zk-params/dust/9 \
    && cp -R package/dist/managed/keys package/dist/managed/zkir /out/signet-contract/ \
    && for file in bls_midnight_2p13 bls_midnight_2p16 dust/9/spend.prover dust/9/spend.verifier dust/9/spend.bzkir; do \
         curl -fsSL --retry 4 -o "/out/zk-params/$file" "https://srs.midnight.network/$file"; \
       done \
    && cd /out/zk-params \
    && printf '%s\n' \
      "d3324910969c4cc54143b8045b649e5c3a4bd5fb7b8f85fe1b770f640ce1c803  bls_midnight_2p13" \
      "09c877216d6589b370263e18af40a030a901b41a7a7c37ef58c9901db41f05c6  bls_midnight_2p16" \
      "996602da7ca386284e656c78ea03e55bffdba29475e6a67965c50de05e13efc2  dust/9/spend.prover" \
      "3f1569ebcab0655c5c145b28947c74edc4e3f5c6b276e4404b661cf0905b49d3  dust/9/spend.verifier" \
      "904181287e75b0fb596ba5fcc116c882ee5d28e3115304c93ebd913722ce5841  dust/9/spend.bzkir" \
      | sha256sum -c

FROM rust:1.93-bookworm AS node-builder
RUN rustc --version --verbose
WORKDIR /usr/src/app
ARG GIT_COMMIT_HASH
ENV GIT_COMMIT_HASH=$GIT_COMMIT_HASH
ARG BUILD_TIMESTAMP
ENV BUILD_TIMESTAMP=$BUILD_TIMESTAMP
COPY chain-signatures/ ./chain-signatures
COPY integration-tests/ ./integration-tests
COPY signet-primitives/ ./signet-primitives
COPY signet-crypto/ ./signet-crypto
COPY Cargo.toml .
COPY Cargo.lock .
COPY --from=eth-builder /usr/src/app/contract-eth/artifacts chain-signatures/contract-eth/artifacts
RUN cargo build --release --package mpc-node

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install --assume-yes libssl-dev ca-certificates curl

RUN update-ca-certificates

COPY --from=redis-bin /usr/local/bin/redis-server /usr/local/bin/redis-server
COPY --from=node-builder /usr/src/app/target/release/mpc-node /usr/local/bin/mpc-node
COPY chain-signatures/node/redis.conf /etc/redis/redis.conf
# The paths PublisherConfig defaults to.
COPY --from=midnight-artifacts /out/signet-contract /usr/local/share/midnight/signet-contract
COPY --from=midnight-artifacts /out/zk-params /usr/local/share/midnight/zk-params

# Create a script to start both Redis and the Rust app
RUN echo "#!/bin/bash\nredis-server /etc/redis/redis.conf &\nexec env RUST_LOG=${RUST_LOG:-mpc=debug} mpc-node start" > /start.sh \
    && chmod +x /start.sh

WORKDIR /usr/local/bin

# Start Redis and the Rust application
ENTRYPOINT [ "/start.sh" ]
