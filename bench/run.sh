#!/bin/sh

cargo +1.81.0 build -p mpc-contract --release --target wasm32-unknown-unknown --features "bench"
cargo build -p mpc-node --release --features "bench"

cd bench/
cargo bench
