# mpc-chain-tron

Tron integration for the MPC chain-signatures stack. Tron is a
**destination chain** for bidirectional signing (see
`doc/bidirectional-calls.md`): requests originate on the source chain,
nodes assemble and sign `TriggerSmartContract` transactions, and a
relayer broadcasts them. There is no Tron indexer and no Tron contract —
this crate is the RPC client: broadcast and settlement polling. The
transaction format itself — protobuf messages, canonical parsing,
signing derivations, address forms — lives in [`mpc-tron-wire`](../tron-wire),
pinned against recorded mainnet fixtures: `RawTransaction::parse`
(admission-shaped validation), `sign_and_hash(r, s, v)` with the 65-byte
`[r ‖ s ‖ v]` signature, `txID = sha256(raw_data)` (the signature is
outside the preimage), `NowBlock::reference_fields` (`ref_block_bytes`
is the block height's low two bytes big-endian, `ref_block_hash` is the
block ID's bytes 8..16).

Core pieces:

- `TronHttp` — wallet and solidity routers, with retry and TronGrid
  API-key support:

| method | endpoint | notes |
|---|---|---|
| `get_now_block` | `/wallet/getnowblock` | head block for ref-block fields |
| `broadcast_transaction` | `/wallet/broadcasthex` | `Accepted` / `AlreadyKnown` (`DUP_TRANSACTION_ERROR`) / `Rejected`; congestion errors retry |
| `get_account_balance` | `/wallet/getaccount` | sun; `{}` for accounts the chain has never seen reads as 0 |
| `get_transaction_info_solidity` | `/walletsolidity/gettransactioninfobyid` | `Ok(None)` = not solidified yet |

## Live gate

`tests/live_gate.rs` exercises the full path — assembly, signing,
broadcast, settlement — against a real network (default Nile via
TronGrid). The same sequence runs in CI against the recorded responses
in `tests/fixtures/nile/`, served verbatim except for the receipt `id`
(the recording's txid belongs to the recording's key).

```sh
TRON_ENDPOINT=https://nile.trongrid.io \
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
classifications match Nile byte-for-byte and solidification is instant.
`tests/fixtures/nile/` pins the wire shapes; the TRE run covers the
rest: mempool admission, signature checks, execution.

## Tests

Unit tests live with the code. `mpc-tron-wire`'s `tests/golden.rs` replays
recorded mainnet USDT transfers; this crate's `tests/live_gate.rs` replays
the recorded Nile responses above (the client's receipt unit test embeds
the same recording).
