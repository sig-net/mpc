//! Standalone watcher benchmark for the Ethereum indexer.
//!
//! Drives `EthereumIndexer` over a fixed historical block range with a simulated
//! load of pending cross-chain execution watchers. This exercises the nonce-gated
//! polling logic to ensure we do not rate-limit the RPC with receipt requests.
//!
//! # Configuration (env vars only)
//!
//! - `RPC_URL` (required) — execution-layer RPC endpoint, e.g. an Alchemy URL.
//! - `CONTRACT_ADDRESS` (required) — contract address to watch.
//! - `END` (required) — exclusive end of the catchup range.
//! - `START` (optional) — inclusive start of the range.
//! - `WATCHERS` (optional, default `50`) — number of pending dummy watchers to simulate.
//! - `NETWORK` (optional, default `sepolia`).
//!
//! # Usage
//!
//! ```sh
//! RPC_URL=http://localhost:4000/sepolia/evm/11155111 \
//! CONTRACT_ADDRESS=0x69C6b28Fdc74618817fa380De29a653060e14009 \
//! START=11214938 END=11215038 WATCHERS=100 \
//! RUST_LOG=mpc_chain_ethereum::bench=info \
//! cargo run --example bench_watchers --features bench
//! ```

#[path = "helpers/mod.rs"]
mod helpers;
use anyhow::anyhow;
use helpers::{env_u64, init_tracing, make_config, run_catchup};
use mpc_chain_integration_core::{MockStateManager, StateManager};
use mpc_primitives::{BidirectionalTx, BidirectionalTxId, Chain, SignId, LATEST_MPC_KEY_VERSION};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let config = make_config()?;
    let end = env_u64("END", None)?;
    let start = env_u64("START", Some(end))?;

    if start == 0 || start >= end {
        return Err(anyhow!("START must be >= 1 and < END"));
    }

    let watchers_count = env_u64("WATCHERS", Some(1000))?;

    let state = MockStateManager::new();
    state.set_processed_block(Chain::Ethereum, start - 1).await;

    let dummy_address = alloy::primitives::address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
    for i in 0..watchers_count {
        let mut hash = [0u8; 32];
        hash[24..].copy_from_slice(&i.to_be_bytes());

        let tx = BidirectionalTx {
            id: BidirectionalTxId(hash),
            sender: [0u8; 32],
            serialized_transaction: vec![],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "eip155:11155111".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0,
            path: "m/44'/60'/0'/0/0".to_string(),
            algo: "secp256k1".to_string(),
            dest: Chain::Ethereum.to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: vec![],
            request_id: hash,
            from_address: **dummy_address,
            nonce: u64::MAX,
        };

        state
            .watch_execution(Chain::Ethereum, SignId::new(hash), tx)
            .await;
    }
    tracing::info!("bench_watchers: injected {watchers_count} dummy watchers");

    run_catchup(config, state, end, "bench_watchers").await?;
    Ok(())
}
