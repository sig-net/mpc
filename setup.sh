#!/bin/sh

# expects this script to be at the root of the project:
export ROOT_DIR=$(dirname -- "$0")
# Use CARGO_TARGET_DIR if it is set, or the default ./target location otherwise
export TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT_DIR/target}

# Only run the prebuild for integration tests unless explicitly forced.
# Set MPC_SETUP_SKIP=1 to skip running setup.sh
# Set MPC_SETUP_ALWAYS=1 to run setup.sh regardless of package
if [ "${MPC_SETUP_SKIP:-}" = "1" ]; then
    exec -- "$@"
fi
if [ "${MPC_SETUP_ALWAYS:-}" != "1" ] && [ "${CARGO_PKG_NAME:-}" != "integration-tests" ]; then
    exec -- "$@"
fi

# Special case for cargo nextest, which needs to be able to list tests without building
for arg in "$@"; do
    case "$arg" in
        --list) exec -- "$@" ;;
    esac
done

CARGO_CMD_ARGS="$@"
CARGO_BUILD_INDENT="            "
echo "${CARGO_BUILD_INDENT} running MPC build script"

# Default feature set for building local binaries used by tests.
NODE_FEATURES="test-feature,debug-page"
CONTRACT_FEATURES=""

# Add additional features if we're benchmarking.
if echo "$CARGO_CMD_ARGS" | grep -q "bench"; then
    CONTRACT_FEATURES="--features bench"
    NODE_FEATURES="${NODE_FEATURES},bench"
fi

NODE_FEATURE_ARGS="--features ${NODE_FEATURES}"

set --
set -e
if [ -n "$CONTRACT_FEATURES" ]; then
    . $ROOT_DIR/build-contract.sh $CONTRACT_FEATURES
else
    . $ROOT_DIR/build-contract.sh
fi

cargo build -p mpc-store --release

# On macOS, the host build produces a .dylib which cannot be loaded by the Linux Redis container.
# We build a Linux .so using Docker to satisfy the integration test requirements.
if [ "$(uname)" = "Darwin" ]; then
    echo "${CARGO_BUILD_INDENT} detected macOS, building Linux Redis module using Docker..."
    docker build -t mpc-store-builder -f - "$ROOT_DIR" <<EOF
FROM rust:latest
RUN apt-get update && apt-get install -y clang llvm libclang-dev
WORKDIR /usr/src/app
COPY chain-signatures/ ./chain-signatures
COPY integration-tests/ ./integration-tests
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release --package mpc-store
EOF
    mkdir -p "$TARGET_DIR/release"
    docker run --rm mpc-store-builder cat /usr/src/app/target/release/libmpc_store.so > "$TARGET_DIR/release/libmpc_store.so"
    chmod +x "$TARGET_DIR/release/libmpc_store.so"
fi

cargo build -p mpc-node --release $NODE_FEATURE_ARGS

exec $CARGO_CMD_ARGS
