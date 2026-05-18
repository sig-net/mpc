#!/usr/bin/env bash

set -euo pipefail

if [[ $# -eq 0 ]]; then
  cargo test --workspace --exclude integration-tests -- --show-output
  exit 0
fi

case "$1" in
  contract)
    cargo test -p mpc-contract -- --show-output
    ;;
  *)
    echo "unknown unit test target: $1" >&2
    exit 1
    ;;
esac
