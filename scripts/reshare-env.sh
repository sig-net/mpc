#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: just reshare join|kick [account_id]" >&2
  exit 1
fi

action="$1"

case "$action" in
  join)
    python3 ./scripts/env_manager.py reshare join
    ;;
  kick)
    if [[ $# -eq 2 ]]; then
      python3 ./scripts/env_manager.py reshare kick "$2"
    else
      python3 ./scripts/env_manager.py reshare kick
    fi
    ;;
  *)
    echo "unknown reshare action: $action" >&2
    exit 1
    ;;
esac
