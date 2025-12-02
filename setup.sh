#!/bin/sh

# expects this script to be at the root of the project:
export ROOT_DIR=$(dirname -- "$0")
# Use CARGO_TARGET_DIR if it is set, or the default ./target location otherwise
export TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT_DIR/target}

CARGO_CMD_ARGS="$@"
CARGO_BUILD_INDENT="            "

# Only run the prebuild (contract + node) when cargo is running integration-tests.
# Other crates (e.g. component-tests) skip it automatically.
if [ "${CARGO_PKG_NAME}" = "integration-tests" ]; then
    echo "${CARGO_BUILD_INDENT} running MPC build script"
else
    echo "${CARGO_BUILD_INDENT} skipping MPC prebuild (CARGO_PKG_NAME=${CARGO_PKG_NAME})"
fi

# Default feature set for building local binaries used by tests.
NODE_FEATURES="test-feature,debug-page"
CONTRACT_FEATURES=""

# Add additional features if we're benchmarking.
if echo "$CARGO_CMD_ARGS" | grep -q "bench"; then
    CONTRACT_FEATURES="--features bench"
    NODE_FEATURES="${NODE_FEATURES},bench"
fi

NODE_FEATURE_ARGS="--features ${NODE_FEATURES}"

set -
set -e
if [ "${CARGO_PKG_NAME}" = "integration-tests" ]; then
    if [ -n "$CONTRACT_FEATURES" ]; then
        . $ROOT_DIR/build-contract.sh $CONTRACT_FEATURES
    else
        . $ROOT_DIR/build-contract.sh
    fi

    cargo build -p mpc-node --release $NODE_FEATURE_ARGS
fi

exec $CARGO_CMD_ARGS
