#!/bin/bash
# Image entrypoint: start the bundled Redis, then the node.
# RUST_LOG from the environment is honoured; mpc=debug is the default.
set -euo pipefail

redis-server /etc/redis/redis.conf &

export RUST_LOG="${RUST_LOG:-mpc=debug}"
exec mpc-node "${@:-start}"
