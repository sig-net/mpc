#!/usr/bin/env bash
# Builds signet/midnight-node-toolkit:2.0.0-rc.3-compact033 — the stock toolkit
# image plus a compact-0.33 toolkit-js variant (see Dockerfile).
#
# The compactc-resolver.js in this directory is the upstream /toolkit-js/dist file
# with exactly two changes:
#   1. SUPPORTED_COMPACTC_VERSIONS gains '0.33'
#   2. the module-resolution hook additionally intercepts
#      @midnight-ntwrk/platform-js, @midnightntwrk/ledger-v9 and
#      @midnightntwrk/onchain-runtime-v4 (new packages in the 2.5.5-rc line)
set -euo pipefail
cd "$(dirname "$0")"

TAG="signet/midnight-node-toolkit:2.0.0-rc.3-compact033"

if docker image inspect "$TAG" >/dev/null 2>&1; then
  echo "$TAG already present"
  exit 0
fi

docker build -t "$TAG" .
echo "built $TAG"
