# mpc-chain-tron

Tron integration for the MPC chain-signatures stack. Tron is a
**destination chain** for bidirectional signing (see
`doc/bidirectional-calls.md`): requests originate on the source chain,
nodes assemble and sign `TriggerSmartContract` transactions, a relayer
broadcasts them, and `TronWatcher` confirms execution by polling
solidified receipts. There is no Tron source indexer and no Tron
contract — the crate is the RPC client plus that execution watcher.
The transaction format — protobuf messages, canonical parsing, signing
derivations, address forms — lives in [`mpc-tron-wire`](../tron-wire).

Core pieces:

- `TronHttp` — wallet and solidity routers, with retry and TronGrid
  API-key support:

| method | endpoint | notes |
|---|---|---|
| `get_now_block` | `/wallet/getnowblock` | head block for ref-block fields |
| `get_now_block_solidity` | `/walletsolidity/getnowblock` | solidified head; the expiry check |
| `broadcast_transaction` | `/wallet/broadcasthex` | `Accepted` / `AlreadyKnown` (`DUP_TRANSACTION_ERROR`) / `Rejected`; congestion errors retry |
| `get_account_balance` | `/wallet/getaccount` | sun; `{}` for accounts the chain has never seen reads as 0 |
| `get_transaction_info_solidity` | `/walletsolidity/gettransactioninfobyid` | `Ok(None)` = not solidified yet |

- `TronWatcher` — polls solidified receipts by txID and resolves
  `Executing` entries whose validity window closed as unexecutable,
  keyed off the backlog so a duplicate flat txID that displaced a watch
  still resolves. The head and receipt reads hit separately routed
  solidity instances, so the attestation requires the head past the
  window by a read-skew margin (3 slots). Implements `ChainIndexer`
  purely as the supervision vehicle (no block scanning, no catchup).

## Configuration

`TronConfig` fields, populated from the node's `--tron-*` flags or their
environment variables:

| field | env var | required? | notes |
|---|---|---|---|
| `endpoint` | `MPC_TRON_ENDPOINT` | to watch execution | wallet/solidity base URL; without it the node admits and signs Tron targets but nothing confirms execution or expiry |
| `api_key` | `MPC_TRON_API_KEY` | no | `TRON-PRO-API-KEY` when the provider is TronGrid; requires the endpoint |
| `poll_interval` | `MPC_TRON_POLL_INTERVAL_MS` | no | milliseconds between receipt polls, default `15000` |

`request_timeout` (10s) and the HTTP `retry` backoff are fixed defaults.

## Live gate

`tests/live_gate.rs` exercises the full path — assembly, signing,
broadcast, settlement, execution watching — against a real network
(default Nile). The same sequence runs in CI against the recorded
responses in `tests/fixtures/nile/`, served verbatim except the receipt
`id` (the recording's txid belongs to the recording's key).

```sh
TRON_ENDPOINT=https://api.nileex.io \
TRON_PRIVATE_KEY=$(openssl rand -hex 32) \
cargo test -p mpc-chain-tron --test live_gate -- --ignored --nocapture
```

A key with no TRX stops after printing its address — fund it at the
[Nile faucet](https://nileex.io/join/getJoinPage) and re-run.

| env | required | notes |
|---|---|---|
| `TRON_ENDPOINT` | yes | wallet/solidity base URL |
| `TRON_PRIVATE_KEY` | yes | 32-byte hex; pays the fees, no token balance expected |
| `TRON_CONTRACT` | no | call target (base58 or hex); default Nile USDT |
| `TRON_TOKEN_ARTIFACT` | no | artifact to deploy via `deploycontract` and target (TRE leg) |
| `TRON_API_KEY` | no | `TRON-PRO-API-KEY` for TronGrid rate limits |
| `TRON_POLL_SECS`, `TRON_DEADLINE_SECS` | no | settle poll (3) and deadline (180) |

Probes: a USDT `transfer` must settle with a txID-matching receipt
(`SUCCESS` asserts the `Transfer` log; a token-less key reverts — both
classify); re-broadcasting the identical bytes must DUP-reject; a call
to a codeless address must come back `CONTRACT_VALIDATE_ERROR`.

### TRE (CI)

`just test-tron-tre` runs the same gate against [TRE](https://hub.docker.com/r/tronbox/tre),
the dockerized single-node java-tron dev chain: pinned `2.0.0`,
deterministic key `0x00…01`, `GateToken` deployed from
`tests/fixtures/tre/` via the node's `deploycontract` API. Rejection
classifications match Nile byte-for-byte and solidification is instant;
`tests/fixtures/nile/` pins the wire shapes, the TRE run covers
mempool admission, signature checks, and execution.

## Tests

Unit tests live with the code. `mpc-tron-wire`'s `tests/golden.rs`
replays recorded mainnet USDT transfers; this crate's
`tests/live_gate.rs` replays the recorded Nile responses above.
