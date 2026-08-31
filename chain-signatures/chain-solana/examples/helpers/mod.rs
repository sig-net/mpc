//! Shared helpers for the Solana benchmark examples.

use anyhow::anyhow;
use futures_util::StreamExt;
use mpc_chain_integration_core::{
    utils::stream::chain_event_channel, MockStateManager, NoopChainTelemetry,
};
use mpc_chain_solana::{SolConfig, SolanaCatchupBlock, SolanaIndexer};

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
/// (`RPC_URL`, `WS_URL`, `PROGRAM_ADDRESS`).
pub fn make_config() -> anyhow::Result<SolConfig> {
    let rpc_http_url = opt_env("RPC_URL")?;
    let rpc_ws_url = match std::env::var("WS_URL") {
        Ok(ws) => ws,
        Err(_) => {
            // Deriving the WS URL is only correct for providers that expose
            // the websocket endpoint on the same host at `/` (e.g. Helius).
            // Set WS_URL explicitly for anything else.
            let parsed =
                reqwest::Url::parse(&rpc_http_url).map_err(|e| anyhow!("invalid RPC_URL: {e}"))?;
            let scheme = match parsed.scheme() {
                "https" => "wss",
                "http" => "ws",
                other => return Err(anyhow!("unsupported RPC_URL scheme: {other}")),
            };
            let mut ws = parsed;
            ws.set_scheme(scheme)
                .map_err(|_| anyhow!("failed to derive WS_URL from RPC_URL"))?;
            ws.set_path("/");
            ws.set_query(None);
            ws.into()
        }
    };
    Ok(SolConfig {
        // The bench only indexes; the signer is never used.
        account_sk: String::new(),
        rpc_http_url,
        rpc_ws_url,
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
/// events (so processing never blocks on a full channel), then drive
/// `catchup_blocks(end, start)` → `process_catchup_item` to completion,
/// firing the final `Catchup Benchmark Report` at the end.
///
/// Returns the number of slots processed (only slots with program activity;
/// skipped slots produce no blocks).
pub async fn run_catchup(
    config: SolConfig,
    start: u64,
    end: u64,
    label: &'static str,
) -> anyhow::Result<u64> {
    let indexer = SolanaIndexer::new(config, MockStateManager::new(), NoopChainTelemetry)?;
    let (events_tx, mut events_rx) = chain_event_channel();

    tracing::info!(start, end, "{label}: starting catchup");

    let drain = tokio::spawn(async move {
        while let Some(ev) = events_rx.recv().await {
            tracing::debug!(?ev, "{label} drained event");
        }
    });

    let blocks_stream = indexer.catchup_blocks(end, start).await?;
    let mut blocks = std::pin::pin!(blocks_stream);
    let mut count: u64 = 0;
    while let Some(item) = blocks.next().await {
        let (slot, block) = item?;
        if matches!(block, SolanaCatchupBlock::Missing) {
            tracing::debug!(slot, "{label}: slot missing from batch, refetching");
        }
        indexer
            .process_catchup_item(&events_tx, slot, &block)
            .await?;
        count += 1;
    }

    // Fires the final `report_metrics("catchup_completed")` log under `bench`.
    #[cfg(feature = "bench")]
    mpc_chain_solana::bench::report_metrics("catchup_completed");

    drain.abort();
    let _ = drain.await;

    tracing::info!(count, "{label}: processed slots; final report above");
    Ok(count)
}
