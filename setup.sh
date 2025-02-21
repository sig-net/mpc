#!/bin/sh

# expects this script to be at the root of the project:
export ROOT_DIR=$(dirname -- "$0")
export TARGET_DIR=$ROOT_DIR/target

echo "running integration test build script"
. $ROOT_DIR/build-contract.sh
cargo build-node

exec "$@"
