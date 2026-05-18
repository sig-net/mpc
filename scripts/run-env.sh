#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: just run <nodes> [threshold]" >&2
  echo "example: just run 8n" >&2
  echo "example: just run 5n 4t" >&2
  exit 1
fi

nodes_arg="$1"
threshold_arg="${2:-}"

if [[ ! "$nodes_arg" =~ ^([0-9]+)n$ ]]; then
  echo "expected node count like 8n or 1n, got: $nodes_arg" >&2
  exit 1
fi

nodes="${BASH_REMATCH[1]}"

if [[ -n "$threshold_arg" ]]; then
  if [[ ! "$threshold_arg" =~ ^([0-9]+)t$ ]]; then
    echo "expected threshold like 4t, got: $threshold_arg" >&2
    exit 1
  fi
  threshold="${BASH_REMATCH[1]}"
else
  threshold=$(( nodes / 2 + 1 ))
fi

python3 ./scripts/env_manager.py start "${nodes}n" "${threshold}t"
