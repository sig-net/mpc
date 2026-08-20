FROM redis:7.4.2 AS redis-bin

FROM node:20 AS eth-builder
WORKDIR /usr/src/app/contract-eth
COPY chain-signatures/contract-eth/package.json chain-signatures/contract-eth/package-lock.json ./
RUN npm install
COPY chain-signatures/contract-eth ./
RUN npx hardhat compile

FROM node:22-bookworm-slim AS midnight-publisher-builder
WORKDIR /usr/src/app/midnight-publisher
COPY chain-signatures/midnight-publisher-ts/package.json chain-signatures/midnight-publisher-ts/package-lock.json ./
RUN npm ci
COPY chain-signatures/midnight-publisher-ts/tsconfig.json chain-signatures/midnight-publisher-ts/tsconfig.build.json ./
COPY chain-signatures/midnight-publisher-ts/src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-bookworm-slim AS midnight-publisher-runtime
COPY --from=midnight-publisher-builder /usr/src/app/midnight-publisher /opt/midnight-publisher
RUN chmod +x /opt/midnight-publisher/dist/main.js \
    && ln -s /opt/midnight-publisher/dist/main.js /usr/local/bin/midnight-publisher \
    && test -s /opt/midnight-publisher/node_modules/@sig-net/midnight-contract/dist/managed/keys/respond.prover \
    && test -s /opt/midnight-publisher/node_modules/@sig-net/midnight-contract/dist/managed/keys/respondBidirectional.prover \
    && test -s /opt/midnight-publisher/node_modules/@sig-net/midnight-contract/dist/managed/zkir/respond.bzkir \
    && test -s /opt/midnight-publisher/node_modules/@sig-net/midnight-contract/dist/managed/zkir/respondBidirectional.bzkir \
    && test "$(printf '{"id":0,"op":"ready","protocolVersion":1}\n' | env -i \
      PATH=/usr/local/bin:/usr/bin:/bin \
      MIDNIGHT_PUB_NETWORK_ID=undeployed \
      MIDNIGHT_PUB_NODE_URL=ws://127.0.0.1:9944 \
      MIDNIGHT_PUB_PROOF_SERVER_URL=http://127.0.0.1:6300 \
      MIDNIGHT_PUB_INDEXER_URL=http://127.0.0.1:8088/api/v3/graphql \
      MIDNIGHT_PUB_INDEXER_WS_URL=ws://127.0.0.1:8088/api/v3/graphql/ws \
      MIDNIGHT_PUB_FUNDING_SEED=abababababababababababababababababababababababababababababababab \
      midnight-publisher 2>/dev/null)" = \
      '{"id":0,"ok":true,"ready":true,"protocolVersion":1,"submitTimeoutMs":360000,"recipeTtlMs":300000}'

FROM rust:1.93-bookworm AS node-builder
RUN rustc --version --verbose
WORKDIR /usr/src/app
ARG GIT_COMMIT_HASH
ENV GIT_COMMIT_HASH=$GIT_COMMIT_HASH
COPY chain-signatures/ ./chain-signatures
COPY integration-tests/ ./integration-tests
COPY signet-primitives/ ./signet-primitives
COPY signet-crypto/ ./signet-crypto
COPY Cargo.toml .
COPY Cargo.lock .
COPY --from=eth-builder /usr/src/app/contract-eth/artifacts chain-signatures/contract-eth/artifacts
RUN cargo build --release --package mpc-node --features helios

FROM midnight-publisher-runtime AS runtime
RUN apt-get update && apt-get install --assume-yes libssl-dev ca-certificates curl

RUN update-ca-certificates

COPY --from=redis-bin /usr/local/bin/redis-server /usr/local/bin/redis-server
COPY --from=node-builder /usr/src/app/target/release/mpc-node /usr/local/bin/mpc-node
COPY chain-signatures/node/redis.conf /etc/redis/redis.conf

# Create a script to start both Redis and the Rust app
RUN echo "#!/bin/bash\nredis-server /etc/redis/redis.conf &\nexec env RUST_LOG=${RUST_LOG:-mpc=debug,helios=info} mpc-node start" > /start.sh \
    && chmod +x /start.sh

WORKDIR /usr/local/bin

# Start Redis and the Rust application
ENTRYPOINT [ "/start.sh" ]
