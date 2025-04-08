#!/bin/sh

# expects this script to be at the root of the project:
export ROOT_DIR=$(dirname -- "$0")
export TARGET_DIR=$ROOT_DIR/target

CARGO_CMD_ARGS="$@"
CARGO_BUILD_INDENT="            "

if echo $CARGO_PKG_NAME | grep -q "integration-tests"; then
    echo "${CARGO_BUILD_INDENT} running MPC build script"
    # add additional features if we're benchmarking:
    if echo $CARGO_CMD_ARGS | grep -q "bench"; then
        FEATURES="--features bench"
    fi

    set --
    set -e
    . $ROOT_DIR/build-contract.sh $FEATURES
    cargo build -p mpc-node --release $FEATURES
fi

exec $CARGO_CMD_ARGS
