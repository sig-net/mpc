#!/bin/sh

cargo +1.86.0 build -p mpc-contract --release --target wasm32-unknown-unknown $@
