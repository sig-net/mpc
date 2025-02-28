#!/bin/sh

# expects this script to be at the root of the project:
export ROOT_DIR=$(dirname -- "$0")
export TARGET_DIR=$ROOT_DIR/target

echo "running cargo build script"

# add additional features if we're benchmarking:
if echo "$@" | grep -q "bench"; then
    FEATURES="--features bench"
fi

set -e
cd $ROOT_DIR
./build-contract.sh $FEATURES
cargo build -p mpc-node $FEATURES

exec "$@"
