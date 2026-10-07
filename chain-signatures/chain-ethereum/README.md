# mpc-chain-ethereum

Ethereum integration for the MPC chain-signatures stack. Provides the
`EthereumIndexer` that drives catchup over historical Ethereum blocks,
emits MPC signing request/response events, and surfaces them through the
[`mpc-chain-integration-core`](../chain-integration-core) `ChainIndexer`
trait.

A single client is supported:

- **Direct RPC**: `rpc::RpcEthereumClient` — talks to a standard JSON-RPC
  endpoint (`eth_*`, `debug_*`).

In the full node, this crate is driven by [`mpc-node`](../node) via the
`ChainIndexer` trait (`EthereumIndexer::run`). Catchup and the live tail are
one cursor-driven path: historical blocks stream out of
`EthereumClient::catchup_batch_stream` and are processed strictly in order via
`process_catchup_item` — all wired up on the operator's behalf, with config
plumbed through from the node's config, not constructed by hand.

## Configuration

`EthConfig` fields, typically populated from environment variables:

| field                     | env var             | required? | notes |
|---------------------------|---------------------|-----------|-------|
| `execution_rpc_http_url`  | `RPC_URL`           | yes       | execution-layer JSON-RPC endpoint (Alchemy, Infura, OnFinality, …) |
| `contract_address`        | `CONTRACT_ADDRESS`  | yes       | MPC contract address, with or without the `0x` prefix |
| `network`                 | `NETWORK`           | no        | default `sepolia` |
| `refresh_finalized_interval` | —                | no        | milliseconds between finalized-head watcher polls (production) |
| `optimistic_requests`     | `OPTIMISTIC`        | no        | default off (production waits for finality via the finalized-head watcher); set `1` for the demo/soft-tip path |

### Catchup fetch tuning

`rpc.catchup` (`CatchupFetchConfig`) shapes historical block fetching:

| field | default | notes |
|---|---|---|
| `block_batch_size` | 32 | blocks per `eth_getBlockByNumber` JSON-RPC batch |
| `fetch_concurrency` | 4 | batch fetches kept in flight at once |

Batches are fetched concurrently but yielded strictly in block order.

## Benchmarking catchup

The `bench` feature instruments the direct-RPC catchup path with global RPC
counters and timing. The report is emitted under the `mpc_chain_ethereum::bench`
tracing target via `bench::report_metrics`.

### eRPC cache (recommended)

Run against a cached RPC so results are reproducible and don't rate-limit. The
`bench/` directory has a docker-compose bringing up <https://erpc.cloud> (eRPC) + Redis fronting
four public Sepolia endpoints. First run populates the cache; subsequent runs
over the same `[START, END)` range read from Redis.

```sh
docker compose -f bench/docker-compose.bench.yml up -d

RPC_URL=http://localhost:4000/sepolia/evm/11155111 \
CONTRACT_ADDRESS=0x69C6b28Fdc74618817fa380De29a653060e14009 \
START=11214938 END=11215038 \
RUST_LOG=mpc_chain_ethereum::bench=info \
cargo run --example bench_catchup --features bench

docker compose -f bench/docker-compose.bench.yml down -v   # clear cache
```

Alternatively point `RPC_URL` directly at a public Sepolia endpoint (slower,
noisier):

```sh
RPC_URL=https://eth-sepolia.api.onfinality.io/public \
CONTRACT_ADDRESS=0x69C6b28Fdc74618817fa380De29a653060e14009 \
START=11214938 END=11215038 \
RUST_LOG=mpc_chain_ethereum::bench=info \
cargo run --example bench_catchup --features bench
```

### Reference numbers

Current catchup baseline for a 100-block catchup over an already-finalized
range (`START=11214938 END=11215038`, `OPTIMISTIC=0`, default
`REFRESH_FINALIZED_INTERVAL`).

#### Provider cost

> NOTE: Using Alchemy CU scheme, but per-request method weights are similar across providers, so these are a reasonable cost estimates in general

| method | calls | compute CU | throughput CU |
|---|---|---|---|
| `eth_getBlockByNumber(Finalized)` | 1 | 20 | 20 |
| `eth_getBlockByNumber(batch)` | 100 | 2000 | 2000 |
| `eth_getLogs(batch)` | 9 | 540 | 540 |
| **total (100 blocks)** | **110** | **2560** | **2560** |

#### Speed (reference snapshot)

100-block Alchemy catchup with default settings (concurrent batch fetching,
`fetch_concurrency: 4`):

| metric | value |
|---|---|
| catchup wall time | 0.54 s |
| blocks/s | 186 |
| `batch_fetch_ms` (wall) | 535 |
| `fetch_work_ms` (summed) | 1955 |
| `fetch_parallelism` | 3.7 |
| `process_ms` | 1 |

> NOTE: Wall-clock figures are a reference snapshot (endpoint tier, latency, and
> load dependent), not a guarantee.

### Watchers benchmark

`examples/bench_watchers.rs` drives `EthereumIndexer` over a fixed historical
block range with a simulated load of pending cross-chain execution watchers.
This exercises the nonce-gated polling logic to ensure receipt requests don't
rate-limit the RPC. Dummy watchers (with `nonce = u64::MAX`, i.e. never
executable) are injected into a `MockStateManager` before catchup starts.

```sh
RPC_URL=http://localhost:4000/sepolia/evm/11155111 \
CONTRACT_ADDRESS=0x69C6b28Fdc74618817fa380De29a653060e14009 \
START=11214938 END=11215038 WATCHERS=1000 \
RUST_LOG=mpc_chain_ethereum::bench=info \
cargo run --example bench_watchers --features bench
```

### Environment variables

| var              | required? | description |
|------------------|-----------|-------------|
| `RPC_URL`        | yes       | execution-layer RPC endpoint (eRPC URL or direct) |
| `CONTRACT_ADDRESS` | yes     | contract to watch (with/without `0x`) |
| `END`            | yes       | exclusive end of the range |
| `START`          | no        | inclusive start; if omitted only `END-1` is processed |
| `NETWORK`        | no        | default `sepolia` |
| `OPTIMISTIC`     | no        | `0` (default, production) waits for finality via the watcher; `1` enables the demo/soft-tip path |
| `WATCHERS`       | no        | `bench_watchers` only — number of pending dummy watchers to simulate (default `50`) |
| `RUST_LOG`       | no        | tracing filter — `mpc_chain_ethereum::bench=info` for just the report |

## Features

| feature   | what it enables |
|-----------|-----------------|
| `bench`   | the `bench` module + RPC/timing counters in the RPC client; required by `examples/bench_catchup.rs` and `examples/bench_watchers.rs` |
