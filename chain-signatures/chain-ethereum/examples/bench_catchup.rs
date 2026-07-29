//! Standalone catchup benchmark for the Ethereum indexer.
//!
//! Drives `EthereumIndexer` over a fixed historical block range against a real
//! RPC endpoint and emits the `Catchup Benchmark Report` (RPC breakdown +
//! `batch_fetch_ns` / `per_block_process_ns` / `rpc_per_sec` / `blocks_per_sec`).
//!
//! # Configuration (env vars only)
//!
//! - `RPC_URL` (required) — execution-layer RPC endpoint, e.g. an Alchemy URL.
//! - `CONTRACT_ADDRESS` (required) — contract address to watch, with or
//!   without the `0x` prefix.
//! - `END` (required) — exclusive end of the catchup range (the anchor
//!   height).
//! - `START` (optional) — inclusive start of the range. If omitted, only
//!   the single block `END - 1` is processed.
//! - `NETWORK` (optional, default `sepolia`).
//! - `OPTIMISTIC` (optional, default `0`) — production (non-optimistic) path by
//!   default; the finalized-head watcher drives finality. Set to `1` for the
//!   demo/soft-tip path (no finality wait).
//! - `REFRESH_FINALIZED_INTERVAL` (optional, default `10000` ms) — cadence of
//!   the finalized-head watcher in OPTIMISTIC=0 mode.
//!
//! # Usage
//!
//! ```sh
//! RPC_URL=https://eth-sepolia.g.alchemy.com/v2/<KEY> \
//! CONTRACT_ADDRESS=<hex> START=5000000 END=5000100 \
//! cargo run --example bench_catchup --features bench
//! ```
//!
//! Filter logs with `RUST_LOG=mpc_chain_ethereum::bench=info` to see just the
//! final report; otherwise the full `tracing` log is emitted

#[path = "helpers/mod.rs"]
mod helpers;
use helpers::{init_tracing, make_config, parse_start_end, run_catchup};
use mpc_chain_integration_core::{MockStateManager, StateManager};
use mpc_primitives::Chain;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let config = make_config()?;
    let (start, end) = parse_start_end()?;

    let state = MockStateManager::new();
    state.set_processed_block(Chain::Ethereum, start - 1).await;

    run_catchup(config, state, end, "bench_catchup").await?;
    Ok(())
}
