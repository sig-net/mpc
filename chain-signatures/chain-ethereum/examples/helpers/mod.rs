//! Shared helpers for the Ethereum benchmark examples.

use anyhow::anyhow;
use futures_util::StreamExt;
use mpc_chain_ethereum::{EthConfig, EthereumStream};
use mpc_chain_integration_core::{ChainIndexer, ChainStream, MockStateManager, NoopChainTelemetry};

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
/// (`RPC_URL`, `CONTRACT_ADDRESS`, `NETWORK`, `OPTIMISTIC`).
pub fn make_config() -> anyhow::Result<EthConfig> {
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
    let mut stream = EthereumStream::new(config, state, NoopChainTelemetry).await?;
    let mut indexer = stream.start().await?;

    tracing::info!("{label}: starting catchup ending at {end}");

    let drain = tokio::spawn(async move {
        loop {
            match stream.next_event().await {
                Some(ev) => tracing::debug!(?ev, "{label} drained event"),
                None => {
                    tracing::warn!("{label}: event channel closed during catchup");
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

    indexer.notify_catchup_completed().await?;

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
