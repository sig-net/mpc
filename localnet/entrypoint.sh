#!/usr/bin/env bash
#
# Bring up a whole MPC network inside one container: Redis, a NEAR sandbox, the one-shot
# bootstrap, and three MPC nodes.
#
# The Solana chain stays outside. It is the one dependency a consumer is likely to already
# have, or to want to share with the rest of their stack, so it is reached over the network
# at LOCALNET_SOLANA_RPC.
#
# Any process dying takes the container down. A cluster missing a node is a cluster that
# reports itself healthy and then times out every signature, which is far more expensive to
# debug than a container that simply exits.
set -euo pipefail

NODE_COUNT="${LOCALNET_NODE_COUNT:-3}"
BASE_PORT="${LOCALNET_BASE_PORT:-3000}"
NEAR_RPC_PORT="${LOCALNET_NEAR_RPC_PORT:-3030}"
REDIS_PORT="${LOCALNET_REDIS_PORT:-6379}"

# Where the parts live inside the image.
NODES_DIR="${LOCALNET_NODES_DIR:-/localnet/nodes}"
NEAR_HOME="${LOCALNET_NEAR_HOME:-/near-home}"

pids=()

log() { printf '%s entrypoint: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

shutdown() {
    trap - TERM INT EXIT
    log "shutting down"
    for pid in "${pids[@]:-}"; do
        [ -n "${pid}" ] && kill "${pid}" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}
trap shutdown TERM INT EXIT

wait_for_http() {
    local url="$1" what="$2" deadline=$(( SECONDS + ${3:-120} ))
    until curl --fail --silent --output /dev/null "${url}"; do
        if (( SECONDS >= deadline )); then
            log "gave up waiting for ${what} at ${url}"
            return 1
        fi
        sleep 1
    done
    log "${what} is up"
}

log "starting redis on ${REDIS_PORT}"
redis-server /etc/redis/redis.conf --port "${REDIS_PORT}" --daemonize no &
pids+=("$!")

log "starting the near sandbox on ${NEAR_RPC_PORT}"
near-sandbox --home "${NEAR_HOME}" run --rpc-addr "0.0.0.0:${NEAR_RPC_PORT}" &
pids+=("$!")

wait_for_http "http://127.0.0.1:${NEAR_RPC_PORT}/status" "the near sandbox" 180

# The bootstrap waits for Solana itself and checks for the effect of every step before
# performing it, so a restart against chains that are already prepared is a no-op.
log "bootstrapping both chains"
mpc-localnet bootstrap

for (( i = 0; i < NODE_COUNT; i++ )); do
    port=$(( BASE_PORT + i ))
    log "starting mpc node ${i} on ${port}"
    (
        set -a
        # shellcheck disable=SC1090,SC1091
        . "${NODES_DIR}/common.env"
        # shellcheck disable=SC1090
        . "${NODES_DIR}/node${i}.env"
        set +a
        # Endpoint settings come from the container's environment so that a consumer can
        # repoint them without rebuilding the image. Applying them after the env files makes
        # them win.
        export MPC_NEAR_RPC="http://127.0.0.1:${NEAR_RPC_PORT}"
        export MPC_REDIS_URL="redis://127.0.0.1:${REDIS_PORT}"
        export MPC_SOL_RPC_HTTP_URL="${LOCALNET_SOLANA_RPC:-http://surfpool:8899}"
        export MPC_SOL_RPC_WS_URL="${LOCALNET_SOLANA_WS:-ws://surfpool:8900}"
        export RUST_LOG="${RUST_LOG:-mpc_node=info,mpc_node::indexer_sol=debug}"
        exec mpc-node start
    ) &
    pids+=("$!")
done

log "all ${NODE_COUNT} nodes started, supervising"

# Return as soon as any child exits, whatever it was, so a dead node is not mistaken for a
# healthy cluster.
wait -n
status=$?
log "a supervised process exited with ${status}, taking the container down"
exit "${status:-1}"
