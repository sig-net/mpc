#!/bin/sh

RUSTFLAGS="-C target-cpu=mvp" cargo +1.86.0 build -p mpc-contract --release --target wasm32-unknown-unknown $@

# Optimize and strip incompatible WASM features using npx wasm-opt
npx wasm-opt -Oz --strip-debug --strip-dwarf --strip-producers --disable-reference-types --disable-multivalue target/wasm32-unknown-unknown/release/mpc_contract.wasm -o target/wasm32-unknown-unknown/release/mpc_contract.wasm
