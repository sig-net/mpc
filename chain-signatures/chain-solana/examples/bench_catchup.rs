//! Standalone catchup benchmark for the Solana indexer.
//!
//! Drives `SolanaIndexer` over a fixed historical slot range against a real
//! RPC endpoint and emits the `Catchup Benchmark Report` (RPC breakdown +
//! `sig_fetch_ms` / `batch_fetch_ms` / `process_ms` / `rpc_per_sec` /
//! `slots_per_sec` + the signature walk-back overhead ratio).
//!
//! # Configuration (env vars only)
//!
//! - `RPC_URL` (required) — Solana JSON-RPC endpoint, e.g. a Helius or
//!   Alchemy devnet/mainnet URL.
//! - `PROGRAM_ADDRESS` (required) — signet program id (base58).
//! - `START` (required) — inclusive start of the catchup range.
//! - `END` (required) — exclusive end of the catchup range (the anchor
//!   slot). Must be finalized.
//! - `WS_URL` (optional) — derived from `RPC_URL` by default; only correct
//!   for providers that expose websockets on the same host at `/`.
//!
//! Note: only slots with program activity are fetched and processed. Pick a
//! range where the program is active (check with a block explorer), or the
//! bench will spend all its time in the signature walk-back.
//!
//! # Usage
//!
//! ```sh
//! RPC_URL=https://devnet.helius-rpc.com/?api-key=<KEY> \
//! PROGRAM_ADDRESS=<base58> START=410000000 END=410010000 \
//! RUST_LOG=mpc_chain_solana::bench=info \
//! cargo run -p mpc-chain-solana --example bench_catchup --features bench
//! ```
//!
//! Filter logs with `RUST_LOG=mpc_chain_solana::bench=info` to see just the
//! report; `RUST_LOG=mpc_chain_solana=info` also shows pagination progress.

#[path = "helpers/mod.rs"]
mod helpers;
use helpers::{init_tracing, make_config, parse_start_end, run_catchup};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let config = make_config()?;
    let (start, end) = parse_start_end()?;

    run_catchup(config, start, end, "bench_catchup").await?;
    Ok(())
}
