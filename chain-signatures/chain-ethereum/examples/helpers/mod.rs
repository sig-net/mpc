//! Shared helpers for the Ethereum benchmark examples.

use anyhow::anyhow;
use futures_util::StreamExt;
use mpc_chain_ethereum::{EthConfig, EthereumIndexer};
use mpc_chain_integration_core::{
    utils::{retry::SharedBackoff, stream::chain_event_channel},
    MockStateManager, NoopChainTelemetry,
};
use tokio_util::sync::CancellationToken;

/// Read a required environment variable, erroring if it's not set.
pub fn opt_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).map_err(|_| anyhow!("{name} is required"))
}

/// Read an environment variable and parse it as a `u64`, falling back to
/// `default` if unset. Pass `None` to make the variable required.
pub fn env_u64(name: &str, default: Option<u64>) -> anyhow::Result<u64> {
    match std::env::var(name) {
        Ok(v) => v.parse().map_err(|e| anyhow!("invalid {name}: {e}")),
        Err(std::env::VarError::NotPresent) => default.ok_or_else(|| anyhow!("{name} is required")),
        Err(std::env::VarError::NotUnicode(_)) => Err(anyhow!("invalid {name}: not valid UTF-8")),
    }
}

/// Read an environment variable and parse it as a `bool` (`0/1/true/false/yes/no`).
pub fn env_bool(name: &str, default: bool) -> anyhow::Result<bool> {
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

/// Build an [`EthConfig`] from the standard set of benchmark env vars
/// (`RPC_URL`, `CONTRACT_ADDRESS`, `NETWORK`, `OPTIMISTIC`,
/// `REFRESH_FINALIZED_INTERVAL`).
pub fn make_config() -> anyhow::Result<EthConfig> {
    Ok(EthConfig {
        // The bench only indexes; the signer is never used.
        account_sk: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .parse()
            .unwrap(),
        consensus_rpc_http_url: String::new(),
        execution_rpc_http_url: opt_env("RPC_URL")?
            .parse()
            .map_err(|e| anyhow!("invalid RPC_URL: {e}"))?,
        contract_address: opt_env("CONTRACT_ADDRESS")?
            .parse()
            .map_err(|e| anyhow!("invalid CONTRACT_ADDRESS: {e}"))?,
        network: std::env::var("NETWORK").unwrap_or_else(|_| "sepolia".to_string()),
        helios_data_path: "/tmp/helios-bench".to_string(),
        // Production finality-watch cadence; The watcher drives finality in OPTIMISTIC=0 mode.
        refresh_finalized_interval: env_u64("REFRESH_FINALIZED_INTERVAL", Some(10_000))?,
        // Default to the production (non-optimistic) path;
        optimistic_requests: env_bool("OPTIMISTIC", false)?,
        light_client: false,
        rpc: Default::default(),
        gas: Default::default(),
        publisher: Default::default(),
        indexer: Default::default(),
    })
}

/// Initialize the `tracing` subscriber the same way in every bench binary.
pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .init();
}

/// Spin up an [`EthereumStream`]/[`ChainIndexer`] pair, spawn a background
/// task that drains emitted events (so `process_catchup` never blocks on a
/// full channel), then drive `catchup_range(end)` -> `process_catchup` to
/// completion, firing `notify_catchup_completed` (and the resulting
/// `Catchup Benchmark Report`) at the end.
///
/// Returns the number of blocks processed.
pub async fn run_catchup(
    config: EthConfig,
    state: MockStateManager,
    end: u64,
    label: &'static str,
) -> anyhow::Result<u64> {
    let indexer =
        EthereumIndexer::new(config, state, NoopChainTelemetry, SharedBackoff::new()).await?;
    let (events_tx, mut events_rx) = chain_event_channel();

    // Maintain the finalized head the same way `run()` does, so OPTIMISTIC=0
    // (the default) exercises the production finality-watch path.
    let cancel = CancellationToken::new();
    let _watcher = indexer.spawn_finalized_head_watcher(cancel.clone());

    tracing::info!("{label}: starting catchup ending at {end}");

    let drain = tokio::spawn(async move {
        while let Some(ev) = events_rx.recv().await {
            tracing::debug!(?ev, "bench_catchup drained event");
        }
    });

    let blocks_stream = indexer.catchup_blocks(end).await;
    let mut blocks = std::pin::pin!(blocks_stream);
    let mut count: u64 = 0;
    while let Some(block) = blocks.next().await {
        indexer.process_catchup_item(&events_tx, &block).await?;
        count += 1;
    }

    cancel.cancel();

    // Fires the final `report_metrics("catchup_completed")` log under `bench`.
    #[cfg(feature = "bench")]
    mpc_chain_ethereum::bench::report_metrics("catchup_completed");

    drain.abort();
    let _ = drain.await;

    tracing::info!("{label}: processed {count} blocks; final report above");
    Ok(count)
}

/// Parse the standard `START`/`END` pair into `(start, processed_block)`.
///
/// `processed_block = start - 1` so that `catchup_range(end)` covers
/// `[start, end)`. If `START` is unset, `start` defaults to `end` (an
/// empty/"live-anchor" range — mainly useful as a smoke test).
#[allow(dead_code)] // `bench_watchers` doesn't use this, but `bench_catchup` does.
pub fn parse_start_end() -> anyhow::Result<(u64, u64)> {
    let end = env_u64("END", None)?;
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
    Ok((start, end))
}
