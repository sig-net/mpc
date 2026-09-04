#!/bin/bash

# Test script for running production binary compatibility tests.
# Requires compatibility binaries generated via scripts/build-compat-binaries.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
VERSIONS_FILE="$REPO_ROOT/scripts/prod-compat-versions.json"
COMPAT_ROOT="$REPO_ROOT/target/compat"

get_version() {
  local channel="$1"
  jq -r --arg channel "$channel" \
    'if has($channel) then .[$channel] else error("Unknown compatibility channel \($channel).") end' "$VERSIONS_FILE"
}

binary_path_for() {
    local channel="$1"
    local version="$(get_version "$channel")"
    echo "$COMPAT_ROOT/$channel/$version/release/mpc-node"
}

check_binary() {
    local channel="$1"
    local binary_path
    binary_path="$(binary_path_for "$channel")"
    if [[ -f "$binary_path" ]]; then
        echo "✓ Found $channel binary: $binary_path"
        return 0
    fi
    echo "⚠️  Missing $channel binary at $binary_path"
    echo "   Run ./scripts/build-compat-binaries.sh to build it from tags"
    return 1
}

echo "🔧 Building current code..."
cargo build-node

echo ""
echo "📦 Checking for production binaries..."

if ! check_binary testnet; then
    RUN_TESTNET=false
else
    RUN_TESTNET=true
fi

if ! check_binary mainnet; then
    RUN_MAINNET=false
else
    RUN_MAINNET=true
fi

echo ""
echo "🧪 Running production compatibility tests..."
echo ""

if [ "$RUN_TESTNET" = true ]; then
    echo "▶ Running testnet binary compatibility test..."
    cargo test -p integration-tests test_testnet_compatibility -- --ignored --nocapture
fi

if [ "$RUN_MAINNET" = true ]; then
    echo ""
    echo "▶ Running mainnet binary compatibility test..."
    cargo test -p integration-tests test_mainnet_compatibility -- --ignored --nocapture
fi

echo ""
echo "✅ All compatibility tests completed!"
