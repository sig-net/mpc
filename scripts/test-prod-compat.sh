#!/bin/bash

# Runs the release compatibility test: current code next to the latest release
# binary built by scripts/build-compat-binaries.sh. Run via `just test-compat`,
# which builds the contract and the current node first.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
BINARY_PATH="$REPO_ROOT/target/compat/latest/release/mpc-node"

if [[ ! -f "$BINARY_PATH" ]]; then
    echo "⚠️  Missing latest release binary at $BINARY_PATH"
    echo "   Run \`just build compat\` to build it from the tag"
    exit 1
fi
echo "✓ Found latest release binary: $(readlink "$REPO_ROOT/target/compat/latest")"

echo "🧪 Running release compatibility test..."
cargo test -p integration-tests test_latest_release_compatibility -- --ignored --nocapture
