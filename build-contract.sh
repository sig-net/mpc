#!/bin/sh

cargo +1.93.0 build -p mpc-contract --release --target wasm32-unknown-unknown $@
