FROM redis:7.4.2 AS redis-bin

FROM node:20 AS eth-builder
WORKDIR /usr/src/app/contract-eth
COPY chain-signatures/contract-eth/package.json chain-signatures/contract-eth/package-lock.json ./
RUN npm ci
COPY chain-signatures/contract-eth ./
RUN npx hardhat compile

# What the Midnight publisher proves with: the responder's packaged keys and IR, the
# KZG parameters its circuits and the DUST spend need, and the DUST spend's keys. The
# node fetches a missing file at runtime, so baking them in keeps proving offline.
FROM debian:bookworm-slim AS midnight-artifacts
RUN apt-get update && apt-get install --assume-yes --no-install-recommends ca-certificates curl
WORKDIR /tmp/midnight
RUN curl -fsSL --retry 4 -o responder.tgz \
      https://registry.npmjs.org/@sig-net/midnight-responder/-/midnight-responder-0.26.0-rc.7.tgz \
    && echo "5ad53684e1a77978e2ca71a4776f3d3ad6281a6c9a19dc2bd16e8940bf9b3cb7  responder.tgz" | sha256sum -c \
    && tar -xzf responder.tgz \
    && mkdir -p /out/signet-responder/keys /out/signet-responder/zkir /out/zk-params/dust/10 \
    && for circuit in respond respondBidirectional; do \
         cp "package/dist/managed/keys/$circuit.prover" "package/dist/managed/keys/$circuit.verifier" /out/signet-responder/keys/ \
         && cp "package/dist/managed/zkir/$circuit.bzkir" /out/signet-responder/zkir/; \
       done \
    && for file in bls_midnight_2p10 bls_midnight_2p11 bls_midnight_2p13 dust/10/spend.prover dust/10/spend.verifier dust/10/spend.bzkir; do \
         curl -fsSL --retry 4 -o "/out/zk-params/$file" "https://srs.midnight.network/$file"; \
       done \
    && cd /out/zk-params \
    && printf '%s\n' \
      "46b2290933cbed4c378889e4ba971f1a92888331ffb09466acd4ff61a1e2cb42  bls_midnight_2p10" \
      "9901589d7956ff58be0d85569b2f455b77b58c3758026ffb5bbe4807000b96d1  bls_midnight_2p11" \
      "d3324910969c4cc54143b8045b649e5c3a4bd5fb7b8f85fe1b770f640ce1c803  bls_midnight_2p13" \
      "3dff9f54add761350ad02621a425d67fe3d656c8145fef8ef147870489ffdc81  dust/10/spend.prover" \
      "d15a1295780549f534287a39c938005e1faa3232be21861573bd0cdb148949cb  dust/10/spend.verifier" \
      "d211cacb22391b9db60f945787d98c16d344cbb4790246132117084c080399c1  dust/10/spend.bzkir" \
      | sha256sum -c

FROM rust:1.95-bookworm AS node-builder
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
RUN cargo build --release --locked --package mpc-node

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install --assume-yes libssl-dev ca-certificates curl

RUN update-ca-certificates

COPY --from=redis-bin /usr/local/bin/redis-server /usr/local/bin/redis-server
COPY --from=node-builder /usr/src/app/target/release/mpc-node /usr/local/bin/mpc-node
COPY chain-signatures/node/redis.conf /etc/redis/redis.conf
# The paths PublisherConfig defaults to.
COPY --from=midnight-artifacts /out/signet-responder /usr/local/share/midnight/signet-responder
COPY --from=midnight-artifacts /out/zk-params /usr/local/share/midnight/zk-params

# Create a script to start both Redis and the Rust app
RUN echo "#!/bin/bash\nredis-server /etc/redis/redis.conf &\nexec env RUST_LOG=${RUST_LOG:-mpc=debug} mpc-node start" > /start.sh \
    && chmod +x /start.sh

WORKDIR /usr/local/bin

# Start Redis and the Rust application
ENTRYPOINT [ "/start.sh" ]
