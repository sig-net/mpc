#!/usr/bin/env bash

set -euo pipefail

if [[ $# -eq 0 ]]; then
  python3 ./scripts/env_manager.py sign
  exit 0
fi

case "$1" in
  multi)
    if [[ $# -ne 2 ]]; then
      echo "usage: just sign multi <count>" >&2
      exit 1
    fi
    python3 ./scripts/env_manager.py sign multi "$2"
    ;;
  bidirectional)
    python3 ./scripts/env_manager.py sign bidirectional
    ;;
  *)
    if [[ $# -ne 1 ]]; then
      echo "usage: just sign [tx_hash]" >&2
      exit 1
    fi
    python3 ./scripts/env_manager.py sign "$1"
    ;;
esac
