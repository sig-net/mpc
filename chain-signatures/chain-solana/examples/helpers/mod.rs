//! Shared helpers for the Solana benchmark examples.

use anyhow::anyhow;
use mpc_chain_integration_core::{
    utils::stream::chain_event_channel, MockStateManager, NoopChainTelemetry,
};
use mpc_chain_solana::{SolConfig, SolanaIndexer};

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

/// Build a [`SolConfig`] from the standard set of benchmark env vars
/// (`RPC_URL`, `PROGRAM_ADDRESS`).
pub fn make_config() -> anyhow::Result<SolConfig> {
    let rpc_http_url = opt_env("RPC_URL")?;
    Ok(SolConfig {
        // The bench only indexes; the signer is never used.
        account_sk: String::new(),
        rpc_http_url,
        program_address: opt_env("PROGRAM_ADDRESS")?,
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

/// Parse the standard `START`/`END` pair. Both are required: the catchup
/// covers `[START, END)`, i.e. slots with program activity from `START`
/// through the anchor `END - 1`. Only slots with program activity are
/// processed — a 10k-slot range with a sparse program may touch very few.
pub fn parse_start_end() -> anyhow::Result<(u64, u64)> {
    let end = env_u64("END", None)?;
    let start = env_u64("START", None)?;
    if start >= end {
        return Err(anyhow!("START must be < END"));
    }
    Ok((start, end))
}

/// Spin up a [`SolanaIndexer`], spawn a background task that drains emitted
/// events (so emission never blocks on a full channel), then drive the
/// production drain path — `drain_range(end, start)` — to completion,
/// firing the final `Catchup Benchmark Report` at the end.
pub async fn run_catchup(
    config: SolConfig,
    start: u64,
    end: u64,
    label: &'static str,
) -> anyhow::Result<()> {
    let indexer = SolanaIndexer::new(config, MockStateManager::new(), NoopChainTelemetry)?;
    let (events_tx, mut events_rx) = chain_event_channel();

    tracing::info!(start, end, "{label}: starting catchup");

    let drain = tokio::spawn(async move {
        while let Some(ev) = events_rx.recv().await {
            tracing::debug!(?ev, "{label} drained event");
        }
    });

    // Production drain path; never cancelled, returns on its own at the
    // anchor.
    let cancel = tokio_util::sync::CancellationToken::new();
    indexer.drain_range(&events_tx, end, start, &cancel).await?;

    // Fires the final `report_metrics("catchup_completed")` log under `bench`.
    #[cfg(feature = "bench")]
    mpc_chain_solana::bench::report_metrics("catchup_completed");

    drain.abort();
    let _ = drain.await;

    tracing::info!("{label}: catchup complete; final report above");
    Ok(())
}
