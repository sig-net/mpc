#!/bin/sh

set -eu

# Keep benchmark builds reproducible and representative of the target machine.
export CARGO_INCREMENTAL=0
export CARGO_NET_OFFLINE=${CARGO_NET_OFFLINE:-false}
export CARGO_PROFILE_RELEASE_DEBUG=0
export CARGO_PROFILE_BENCH_DEBUG=0
export MPC_TEST_BUILD_DISABLED=1
export RUSTFLAGS="${RUSTFLAGS:-} -C target-cpu=native"

cd chain-signatures/
cargo build --locked -p mpc-contract --release --features "bench" --target wasm32-unknown-unknown
cargo build --locked -p mpc-node --release --features "bench"

cd ../integration-tests
cargo bench --locked
