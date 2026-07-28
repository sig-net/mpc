#!/bin/sh

cargo +1.93.0 near build non-reproducible-wasm \
    --manifest-path chain-signatures/contract/Cargo.toml \
    --no-abi --env 'RUSTFLAGS=-C link-arg=--allow-undefined' \
    $@
