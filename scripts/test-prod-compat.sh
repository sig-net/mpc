#!/bin/bash

# Runs the release compatibility test: current code next to the latest release
# binary built by scripts/build-compat-binaries.sh.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
BINARY_PATH="$REPO_ROOT/target/compat/latest/release/mpc-node"

echo "🔧 Building current code..."
./setup.sh

echo ""
if [[ ! -f "$BINARY_PATH" ]]; then
    echo "⚠️  Missing latest release binary at $BINARY_PATH"
    echo "   Run ./scripts/build-compat-binaries.sh to build it from the tag"
    exit 1
fi
echo "✓ Found latest release binary: $(readlink "$REPO_ROOT/target/compat/latest")"

echo ""
echo "🧪 Running release compatibility test..."
cargo test -p integration-tests test_latest_release_compatibility -- --ignored --nocapture
