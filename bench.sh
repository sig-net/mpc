#!/bin/sh

cd chain-signatures/
cargo build -p mpc-contract --release --features "bench" --target wasm32-unknown-unknown
cargo build -p mpc-node --release --features "bench"

cd ../integration-tests
cargo bench
