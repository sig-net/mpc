FROM rust:latest as builder
WORKDIR /usr/src/app
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends --assume-yes \
    protobuf-compiler libprotobuf-dev
COPY . .
RUN if [ -f ./target/docker-cache.tgz ]; then \
        tar -xzC / -f ./target/docker-cache.tgz \
        && rm -rf ./target/docker-cache.tgz; \
    fi
RUN CARGO_INCREMENTAL=0 cargo build --release --package mpc-recovery

FROM scratch as export-artifacts
COPY --from=builder /usr/src/app/target /usr/src/app/target
COPY --from=builder /usr/local/cargo/bin /usr/local/cargo/bin
COPY --from=builder /usr/local/cargo/gi[t] /usr/local/cargo/git
COPY --from=builder /usr/local/cargo/.crates.tom[l] /usr/local/cargo/.crates.toml
COPY --from=builder /usr/local/cargo/.crates2.jso[n] /usr/local/cargo/.crates2.json
COPY --from=builder /usr/local/cargo/registry/cache /usr/local/cargo/registry/cache
COPY --from=builder /usr/local/cargo/registry/index /usr/local/cargo/registry/index

FROM debian:buster-slim as runtime
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends --assume-yes \
    libssl-dev ca-certificates
RUN update-ca-certificates
COPY --from=builder /usr/src/app/target/release/mpc-recovery /usr/local/bin/mpc-recovery
WORKDIR /usr/local/bin

ENTRYPOINT [ "mpc-recovery" ]
