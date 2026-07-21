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
//! - `OPTIMISTIC` (optional, default `1`) — set to `0` to disable
//!   optimistic requests and exercise the per-block `wait_for_finalized_block`
//!   poll path (mostly useful for measuring finality polling overhead).
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

use anyhow::anyhow;
use futures_util::StreamExt;
use mpc_chain_ethereum::{EthConfig, EthereumStream};
use mpc_chain_integration_core::{
    ChainIndexer, ChainStream, MockStateManager, NoopChainTelemetry, StateManager,
};
use mpc_primitives::Chain;

/// Helper to read an environment variable and return an error if it's not set.
fn opt_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).map_err(|_| anyhow!("{name} is required"))
}

/// Helper to read an environment variable and parse it as a `u64`.
fn env_u64(name: &str) -> anyhow::Result<u64> {
    let raw = opt_env(name)?;
    raw.parse().map_err(|e| anyhow!("invalid {name}: {e}"))
}

/// Helper to read an environment variable and parse it as a `bool`.
fn env_bool(name: &str, default: bool) -> anyhow::Result<bool> {
    match std::env::var(name) {
        Ok(v) => match v.as_str() {
            "1" | "true" | "yes" => Ok(true),
            "0" | "false" | "no" => Ok(false),
            other => Err(anyhow!("invalid {name}: {other:?}, expected 0/1")),
        },
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err(anyhow!("invalid {name}: not valid UTF-8")),
    }
}

fn make_config() -> anyhow::Result<EthConfig> {
    Ok(EthConfig {
        account_sk: String::new(),
        consensus_rpc_http_url: String::new(),
        execution_rpc_http_url: opt_env("RPC_URL")?,
        contract_address: opt_env("CONTRACT_ADDRESS")?
            .trim_start_matches("0x")
            .to_string(),
        network: std::env::var("NETWORK").unwrap_or_else(|_| "sepolia".to_string()),
        helios_data_path: "/tmp/helios-bench".to_string(),
        refresh_finalized_interval: 1,
        optimistic_requests: env_bool("OPTIMISTIC", true)?,
        light_client: false,
        rpc: Default::default(),
        gas: Default::default(),
        publisher: Default::default(),
        indexer: Default::default(),
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Enable tracing logs
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let config = make_config()?;
    let end = env_u64("END")?;

    // `catchup_range(end)` derives `current_block = processed_block + 1` and
    // clamps to `clamp_oldest_supported(current_block, end)`. To process
    // `[start, end)` we set `processed_block = start - 1`. If `START` is
    // unset we still set `processed_block = end - 1` so the (empty) range
    // `[end, end)` is processed — useful as a "live-anchor" smoke test only;
    // supply both `START` and `END` for a real historical range.
    let start = match std::env::var("START") {
        Ok(s) => {
            let s: u64 = s.parse().map_err(|e| anyhow!("invalid START: {e}"))?;
            if s == 0 {
                return Err(anyhow!("START must be >= 1"));
            }
            if s >= end {
                return Err(anyhow!("START must be < END"));
            }
            s
        }
        Err(std::env::VarError::NotPresent) => end,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(anyhow!("invalid START: not valid UTF-8"));
        }
    };

    let state = MockStateManager::new();
    state.set_processed_block(Chain::Ethereum, start - 1).await;

    // Build the stream. `EthereumStream` creates the bounded event channel
    // internally
    let mut stream = EthereumStream::new(config, state, NoopChainTelemetry).await?;
    let mut indexer = stream.start().await?;

    tracing::info!("bench_catchup: starting catchup over [{start}..{end})");

    // Drain emitted events in parallel so process_catchup never blocks on a
    // full channel.
    let drain = tokio::spawn(async move {
        loop {
            match stream.next_event().await {
                Some(ev) => tracing::debug!(?ev, "bench_catchup drained event"),
                None => {
                    tracing::warn!("bench_catchup: event channel closed during catchup");
                    return;
                }
            }
        }
    });

    let blocks_stream = indexer.catchup_range(end).await;
    let mut blocks = std::pin::pin!(blocks_stream);
    let mut count: u64 = 0;
    while let Some(block) = blocks.next().await {
        indexer.process_catchup(&block).await?;
        count += 1;
    }

    // Fires the final `report_metrics("catchup_completed")` log under `bench`.
    indexer.notify_catchup_completed().await?;

    drain.abort();
    let _ = drain.await;

    tracing::info!("bench_catchup: processed {count} blocks; final report above");
    Ok(())
}
