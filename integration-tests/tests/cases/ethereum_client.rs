use anyhow::{Context, Result};
use ethers::types::{Address, U256};
use integration_tests::containers::EthereumSandbox;
use integration_tests::eth;
use mpc_node::backlog::Backlog;
use mpc_node::indexer_client::{ChainClient, ChainEvent};
use mpc_node::indexer_eth::{EthConfig, EthereumIndexerClient};
use mpc_node::mesh::MeshState;
use mpc_node::node_client::NodeClient;
use mpc_node::protocol::Chain;
use mpc_node::rpc::ContractStateWatcher;
use mpc_node::storage::app_data_storage::AppDataStorage;
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use near_workspaces::{Account, Contract, Worker};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::{sleep, timeout};

// Integration tests for EthereumIndexerClient
//
// These tests validate the client's ability to:
// - Parse sign and respond events from the Ethereum blockchain
// - Handle catchup when the client starts behind
// - Emit proper checkpoints
// - Detect execution confirmations for bidirectional flows
// - Process events only after finality
//
// NOTE: These tests only spin up Anvil (Ethereum sandbox) and deploy the contract.
// No full MPC cluster is created. We test the client in isolation.

/// Helper to create minimal test dependencies for EthereumIndexerClient
fn create_test_dependencies() -> (Backlog, watch::Receiver<MeshState>, NodeClient) {
    let backlog = Backlog::new();
    let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());
    let node_client = NodeClient::new(&Default::default());
    (backlog, mesh_rx, node_client)
}

/// Helper to setup NEAR sandbox and contract watcher (minimal version)
async fn setup_near_sandbox(
) -> Result<(Worker<near_workspaces::network::Sandbox>, Account, Contract)> {
    let worker = near_workspaces::sandbox().await?;
    let account = worker.dev_create_account().await?;

    // Deploy a minimal contract for contract watcher
    let wasm_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("chain-signatures/res/mpc_test_contract.wasm");
    let wasm = std::fs::read(&wasm_path)
        .with_context(|| format!("Failed to read WASM file at {:?}", wasm_path))?;
    let contract = account.deploy(&wasm).await?.result;

    // Initialize contract
    let _ = contract
        .call("init")
        .args_json(serde_json::json!({
            "threshold": 2,
            "candidates": serde_json::json!({})
        }))
        .max_gas()
        .transact()
        .await?;

    Ok((worker, account, contract))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that EthereumIndexerClient can parse basic Sign events
    ///
    /// This test:
    /// 1. Spins up Anvil and deploys ChainSignatures contract
    /// 2. Creates an EthereumIndexerClient with test configuration
    /// 3. Submits a Sign request directly to the contract
    /// 4. Verifies client.next_event() returns ChainEvent::SignRequest with correct data
    #[tokio::test]
    #[ignore = "needs ethereum sandbox setup"]
    async fn test_ethereum_client_parse_sign_event() -> Result<()> {
        // TODO: Implement with:
        // 1. Start Anvil (anvil --port 8545)
        // 2. Deploy ChainSignatures contract
        // 3. Create EthereumIndexerClient with minimal dependencies
        // 4. Submit sign request via ethers contract call
        // 5. Verify client emits ChainEvent::SignRequest
        Ok(())
    }

    /// Test that EthereumIndexerClient emits checkpoint events regularly
    #[tokio::test]
    #[ignore = "needs ethereum sandbox setup"]
    async fn test_ethereum_client_emits_checkpoints() -> Result<()> {
        // TODO: Same setup, just wait for checkpoint events as blocks are mined
        Ok(())
    }

    /// Test that EthereumIndexerClient can linearly catch up when starting behind
    #[tokio::test]
    #[ignore = "needs ethereum sandbox setup"]
    async fn test_ethereum_client_catchup_linear() -> Result<()> {
        // TODO:
        // 1. Submit 3 sign requests to contract
        // 2. Wait for finality
        // 3. Create client (should catch up from block 0)
        // 4. Verify client receives all 3 requests
        // 5. Verify checkpoints are monotonically increasing
        Ok(())
    }

    /// Test that EthereumIndexerClient only processes events after finality
    #[tokio::test]
    #[ignore = "needs ethereum sandbox setup"]
    async fn test_ethereum_client_finality_requirement() -> Result<()> {
        // TODO:
        // 1. Submit sign request
        // 2. Record submission block number
        // 3. Wait for client to emit SignRequest
        // 4. Verify request was processed at or after submission block + finality confirmations
        Ok(())
    }

    /// Test that EthereumIndexerClient detects execution confirmations for bidirectional flows
    #[tokio::test]
    #[ignore = "needs ethereum sandbox setup"]
    async fn test_ethereum_client_execution_confirmation() -> Result<()> {
        // TODO:
        // 1. Manually add an execution watcher to the backlog
        // 2. Submit a transaction that matches the watcher
        // 3. Verify client emits ChainEvent::ExecutionConfirmed
        Ok(())
    }

    /// Test that EthereumIndexerClient handles multiple concurrent sign requests
    #[tokio::test]
    #[ignore = "needs ethereum sandbox setup"]
    async fn test_ethereum_client_concurrent_events() -> Result<()> {
        // TODO: Submit 3 concurrent requests, verify client sees all
        Ok(())
    }

    /// Test that checkpoint persistence works across Ethereum client restarts
    #[tokio::test]
    #[ignore = "needs ethereum sandbox setup"]
    async fn test_ethereum_client_checkpoint_persistence() -> Result<()> {
        // TODO:
        // 1. Create client, process events, observe checkpoint in backlog
        // 2. Drop client
        // 3. Create new client with same backlog
        // 4. Verify new client resumes from last checkpoint
        Ok(())
    }
}
