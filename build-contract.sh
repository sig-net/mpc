#!/bin/sh
# Build the NEAR contract wasm and copy it where integration tests load it from.
set -e

# Apple default clang lacks WASM support
if [ -z "$CC" ] && [ -x "/opt/homebrew/opt/llvm/bin/clang" ]; then
    export CC="/opt/homebrew/opt/llvm/bin/clang"
fi

cargo +1.93.0 near build non-reproducible-wasm \
    --manifest-path chain-signatures/contract/Cargo.toml \
    --no-abi --env 'RUSTFLAGS=--cfg near -C link-arg=--allow-undefined' \
    "$@"

mkdir -p target/wasm32-unknown-unknown/release
cp target/near/mpc_contract/mpc_contract.wasm target/wasm32-unknown-unknown/release/mpc_contract.wasm
