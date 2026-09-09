# mpc-chain-solana

Solana integration for the MPC chain-signatures stack. Provides the
[`SolanaIndexer`] that drives catchup over historical Solana slots, emits MPC
signing request/response events, and surfaces them through the
[`mpc-chain-integration-core`](../chain-integration-core) `ChainIndexer`
trait.

The indexer runs in two phases:

- **Catchup** — pure HTTP RPC: paged `getSignaturesForAddress` (newest-first
  walk-back) → deduplicated slot set → batched `getBlock` (50/chunk, 5
  concurrent) → `process_block` per slot.
- **Live** — interval polling of the finalized slot with the same catchup
  machinery.

## Configuration

`SolConfig` fields, typically populated by the node from environment
variables:

| field            | env var                  | required? | notes |
|------------------|--------------------------|-----------|-------|
| `account_sk`     | `MPC_SOL_ACCOUNT_SK`     | yes       | payer keypair (base58) for respond transactions |
| `rpc_http_url`   | `MPC_SOL_RPC_HTTP_URL`   | yes       | JSON-RPC endpoint (Helius, Alchemy, …) |
| `program_address`| `MPC_SOL_PROGRAM_ADDRESS`| yes       | signet program id (base58) |
| `indexer.poll_interval` | `MPC_SOL_POLL_INTERVAL_MS` | no | default `1000`; finalized slots advance ~every 400ms |
| `indexer.slot_stall_timeout` | — | no | default 60s; anchor-stall watchdog |

## Benchmarking catchup

The `bench` feature instruments the catchup path with global RPC counters and
timing. The report is emitted under the `mpc_chain_solana::bench` tracing
target via `bench::report_metrics`.

```sh
RPC_URL=https://solana-devnet.g.alchemy.com/v2/<KEY> \
PROGRAM_ADDRESS=CMGYAEsqXw5z52R8fmMZwPYQARHPEkGbefJA2FmeHLMh \
START=375977077 END=377504390 \
RUST_LOG=mpc_chain_solana::bench=info \
cargo run -p mpc-chain-solana --example bench_catchup --features bench
```

There is no caching proxy layer (eRPC is EVM-only): runs go straight against
the live endpoint, so wall-clock figures are a reference snapshot (endpoint
tier, latency, and load dependent), not a guarantee.

Only slots with program activity are fetched and processed.

### Report fields

| field | meaning |
|---|---|
| `slots_per_sec` / `rpc_per_sec` | throughput over the catchup wall time |
| `sig_fetch_ms` | paged `getSignaturesForAddress` walk-back (newest → start) |
| `batch_fetch_ms` | batched `getBlock` POSTs (50/chunk, 5 concurrent) |
| `refetch_ms` | single-slot `getBlock` retries for slots missing from a batch |
| `process_ms` | per-slot parse + event emission |
| `walk_back` | pages fetched, signatures scanned vs. active slots — the ratio quantifies walk-back waste (pages past the range, or many sigs per slot) |
| `rpc_breakdown` | per-method logical requests vs. HTTP round-trips (batch sub-requests share one POST); counts attempted, not successful |

### Reference numbers

Devnet catchup over the program's full active history
(`START=375977077 END=377504390`, ~1.5M slots, Alchemy devnet):

| metric | value |
|---|---|
| catchup wall time | 2.5 s |
| slots processed | 22 |
| `sig_fetch_ms` | 1003 |
| `batch_fetch_ms` | 1470 |
| `process_ms` | 17 |
| walk-back | 1 page (250-sig cap), 250 sigs → 22 slots (11.4x) |
| total RPC | 24 logical / 3 HTTP |

Notes:

- Alchemy caps `getSignaturesForAddress` pages at **250** despite our
  1000-signature request, so larger histories page more than
  `CATCHUP_PAGE_SIZE` implies.
- The dominant cost for this shape is the batched `getBlock` POST
  (`full` transaction details, `jsonParsed`), not per-slot processing.

### Environment variables

| var | required? | description |
|---|---|---|
| `RPC_URL` | yes | Solana JSON-RPC endpoint |
| `PROGRAM_ADDRESS` | yes | signet program id (base58) |
| `END` | yes | exclusive end of the range (the anchor slot); must be finalized |
| `START` | yes | inclusive start of the range |
| `RUST_LOG` | no | tracing filter — `mpc_chain_solana::bench=info` for just the report |

## Features

| feature | description |
|---|---|
| `bench` | the `bench` module + RPC/timing counters in the catchup path; required by `examples/bench_catchup.rs` |
