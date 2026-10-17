# mpc-chain-tron

Tron integration for the MPC chain-signatures stack. Tron is a
**destination chain** for bidirectional signing (see
`doc/bidirectional_calls.md`): requests originate on the source chain,
nodes assemble and sign `TriggerSmartContract` transactions, and a
relayer broadcasts them. There is no Tron indexer and no Tron contract —
this crate is the transaction format: protobuf parsing, signing, and
broadcast.

Core pieces:

- `pb::*` — hand-declared protobuf messages (`Contract`, `RawTransaction`,
  `Transaction`, `TriggerSmartContract`), pinned against recorded mainnet
  fixtures.
- `RawTransaction::parse` — admission-shaped validation: one contract,
  type pinned `TriggerSmartContract`, ref-block fields present,
  `expiration > 0`. `sign_and_hash(r, s, v)` appends the 65-byte
  `[r ‖ s ‖ v]` signature and returns the signed transaction with its
  txID; `txID = sha256(raw_data)` — the signature is outside the preimage.
- `NowBlock::reference_fields` — `ref_block_bytes` is the block height's
  low two bytes big-endian, `ref_block_hash` is the block ID's bytes
  8..16. Pinned against recorded mainnet fixtures.
- `TronHttp` — wallet and solidity routers, with retry and TronGrid
  API-key support:

| method | endpoint | notes |
|---|---|---|
| `get_now_block` | `/wallet/getnowblock` | head block for ref-block fields |
| `broadcast_transaction` | `/wallet/broadcasthex` | `Accepted` / `AlreadyKnown` (`DUP_TRANSACTION_ERROR`) / `Rejected`; congestion errors retry |
| `get_account_balance` | `/wallet/getaccount` | sun; `{}` for accounts the chain has never seen reads as 0 |
| `get_transaction_info_solidity` | `/walletsolidity/gettransactioninfobyid` | `Ok(None)` = not solidified yet |

## Live gate

`tests/live_gate.rs` verifies the transaction path — parsing, signing,
broadcast, and receipt settlement — against a real network, currently
[Nile](https://nileex.io) keyless via `https://nile.trongrid.io`.
A mock-backed sequence of the same code runs in CI; the live run is
opt-in:

```sh
TRON_ENDPOINT=https://nile.trongrid.io \
TRON_PRIVATE_KEY=$(openssl rand -hex 32) \
cargo test -p mpc-chain-tron --test live_gate -- --ignored --nocapture
```

A key with no TRX stops the run after printing its address — fund it at
the [Nile faucet](https://nileex.io/join/getJoinPage) and re-run.

| env | required | notes |
|---|---|---|
| `TRON_ENDPOINT` | yes | wallet/solidity base URL |
| `TRON_PRIVATE_KEY` | yes | 32-byte hex; TRX only, it pays the fees — no token balance is expected |
| `TRON_CONTRACT` | no | call target; default Nile USDT (`TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf`, verified on-chain via `name()`) |
| `TRON_API_KEY` | no | `TRON-PRO-API-KEY` header, for TronGrid rate limits |
| `TRON_POLL_SECS` | no | settle poll interval, default 3 |
| `TRON_DEADLINE_SECS` | no | solidification deadline, default 180 |

The gate is a single-key relayer simulation — the ECDSA part is real
(k256 over the sha256 prehash), and the transaction assembly goes through
the same `parse`/`sign_and_hash` path the nodes use. Three probes:

1. **acceptance** — assemble a USDT `transfer`, broadcast, settle on the
   solidity router; asserts the txID equals `sha256(raw_data)` computed
   before signing and the receipt id equals it after execution. The
   execution itself classifies either way: `SUCCESS` asserts the
   `Transfer` log, while a key holding TRX but no tokens reverts on the
   balance check — both are valid settled receipts.
2. **duplicate** — re-broadcasting the identical signed bytes must be
   rejected as `DUP_TRANSACTION_ERROR`: replay protection keyed by txID,
   which never covers the signature.
3. **codeless** — a call to an address with no code must be rejected as
   `CONTRACT_VALIDATE_ERROR`, the classification recorded on both Nile and
   mainnet.

Facts pinned on Nile: solidification ~60 s after broadcast (2/3 of
the 27 SRs at 3 s blocks), `REVERT` receipts carry
`resMessage "REVERT opcode executed"` with zero fee, and all four
endpoints above behave identically on `api.trongrid.io`.

## Tests

- Unit tests live with the code; `tests/golden.rs` replays recorded
  mainnet USDT transfers (`tests/fixtures/`): proto round-trip is
  byte-identical, ref-block derivation, assembly, signing, and txID all
  reproduce the recorded transactions.
