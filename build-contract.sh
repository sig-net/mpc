#!/bin/sh

cargo build -p mpc-contract --release --target wasm32-unknown-unknown $@
