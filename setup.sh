#!/bin/sh

# expects this script to be at the root of the project:
export ROOT_DIR=$(dirname -- "$0")
# Use CARGO_TARGET_DIR if it is set, or the default ./target location otherwise
export TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT_DIR/target}

CARGO_CMD_ARGS="$@"
CARGO_BUILD_INDENT="            "
echo "${CARGO_BUILD_INDENT} running MPC build script"

# add additional features if we're benchmarking:
if echo $CARGO_CMD_ARGS | grep -q "bench"; then
    FEATURES="--features bench"
fi

set --
set -e
. $ROOT_DIR/build-contract.sh $FEATURES
cargo build -p mpc-node --release $FEATURES

exec $CARGO_CMD_ARGS
