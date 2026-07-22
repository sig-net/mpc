#!/usr/bin/env bash
# Test stub for the publisher's JSON-RPC `curl` calls (GET /state fetch path).
# Records each request body to $FAKE_RPC_LOG and returns a canned response
# keyed by the JSON-RPC method. Env inputs:
#   FAKE_RPC_LOG       file to append each request body to (required)
#   FAKE_RPC_HEAD      finalized-head hash, bare hex no 0x (required)
#   FAKE_RPC_NUMBER    header.number, hex quantity e.g. 0x2a (required)
#   FAKE_RPC_STATE_MN  path to a .mn blob returned by midnight_contractState
set -euo pipefail

# The request body is the argument immediately after "-d".
body=""
prev=""
for arg in "$@"; do
  [ "$prev" = "-d" ] && body="$arg"
  prev="$arg"
done

echo "$body" >> "${FAKE_RPC_LOG:?}"

case "$body" in
  *chain_getFinalizedHead*)
    printf '{"jsonrpc":"2.0","id":1,"result":"0x%s"}\n' "${FAKE_RPC_HEAD:?}"
    ;;
  *chain_getHeader*)
    printf '{"jsonrpc":"2.0","id":1,"result":{"number":"%s","parentHash":"0x00"}}\n' "${FAKE_RPC_NUMBER:?}"
    ;;
  *midnight_contractState*)
    hex=$(od -An -v -tx1 "${FAKE_RPC_STATE_MN:?}" | tr -d ' \n')
    printf '{"jsonrpc":"2.0","id":1,"result":"%s"}\n' "$hex"
    ;;
  *)
    printf '{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"fake-rpc: unknown method"}}\n'
    ;;
esac
