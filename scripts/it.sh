#!/usr/bin/env bash

set -euo pipefail

./build-contract.sh
cargo build-node

if command -v cargo-nextest >/dev/null 2>&1; then
  if [[ $# -eq 0 ]]; then
    cargo nextest run -p integration-tests
  else
    cargo test -p integration-tests "$1" -- --test-threads 1 --nocapture
  fi
else
  if [[ $# -eq 0 ]]; then
    cargo test -p integration-tests --jobs 1 -- --test-threads 1
  else
    cargo test -p integration-tests "$1" -- --test-threads 1 --nocapture
  fi
fi
