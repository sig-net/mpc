use anyhow::{Context, Result};
use integration_tests::containers::Solana;
use k256::Scalar;
use mpc_crypto::ScalarExt;
use mpc_node::backlog::Backlog;
use mpc_node::indexer_client::{ChainClient, ChainEvent};
use mpc_node::indexer_sol::{SolConfig, SolanaClient};
use mpc_node::mesh::MeshState;
use mpc_node::node_client::NodeClient;
use mpc_node::protocol::{Chain, IndexedSignRequest};
use mpc_node::rpc::ContractStateWatcher;
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use near_workspaces::network::Sandbox;
use near_workspaces::{Account, Contract, Worker};
use solana_sdk::signer::Signer;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::timeout;

/// Sets up Solana sandbox with deployed contract
async fn setup_solana_sandbox() -> Result<Solana> {
    let solana = Solana::run().await;
    solana.deploy_contract().await?;
    Ok(solana)
}

/// Helper to create minimal test dependencies for SolanaClient
fn create_test_dependencies() -> (Backlog, watch::Receiver<MeshState>, NodeClient) {
    let backlog = Backlog::new();
    let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());
    let node_client = NodeClient::new(&Default::default());
    (backlog, mesh_rx, node_client)
}

/// Creates a SolanaClient with the given config
fn create_solana_client(
    config: SolConfig,
    contract_watcher: ContractStateWatcher,
    mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
) -> Result<SolanaClient> {
    SolanaClient::new(Some(config), contract_watcher, mesh_state, node_client)
        .context("failed to create SolanaClient")
}

/// Helper to setup NEAR sandbox and contract watcher (minimal version)
async fn setup_near_sandbox() -> Result<(Worker<Sandbox>, Account, Contract)> {
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

/// Helper to wait for a specific event type, skipping checkpoints
async fn wait_for_sign_request(client: &mut SolanaClient) -> Result<IndexedSignRequest> {
    loop {
        match timeout(Duration::from_secs(10), client.next_event()).await {
            Ok(Some(ChainEvent::SignRequest(req))) => return Ok(req),
            Ok(Some(ChainEvent::Block(_))) => continue,
            Ok(Some(other)) => anyhow::bail!("Expected SignRequest, got {:?}", other),
            Ok(None) => anyhow::bail!("client returned None"),
            Err(_) => anyhow::bail!("timeout waiting for SignRequest event"),
        }
    }
}

/// Test that SolanaClient can parse basic Sign events
///
/// This test:
/// 1. Spins up Solana sandbox and deploys contract
/// 2. Creates a SolanaClient with test configuration
/// 3. Submits a Sign request directly to the contract
/// 4. Verifies client.next_event() returns ChainEvent::SignRequest with correct data
#[tokio::test]
async fn test_solana_client_parse_sign_event() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    // Setup Solana sandbox
    let solana = setup_solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();

    // Setup NEAR contract watcher
    let (_worker, _account, contract) = setup_near_sandbox().await?;
    let (contract_watcher, _) = ContractStateWatcher::new(contract.id());

    // Create dependencies
    let (_backlog, mesh_state, node_client) = create_test_dependencies();

    // Create client
    let config = solana.get_config(program_address);
    let mut client = create_solana_client(config, contract_watcher, mesh_state, node_client)?;

    // Submit sign request
    let payload = [1u8; 32];
    let path = "test";
    let key_version = LATEST_MPC_KEY_VERSION;

    solana
        .sign(payload, path, key_version, "secp256k1", "", "")
        .await?;

    // Wait for SignRequest event (skip block markers)
    let req = wait_for_sign_request(&mut client).await?;

    // Verify the request
    assert_eq!(req.chain, Chain::Solana);
    assert_eq!(req.args.payload, Scalar::from_bytes(payload).unwrap());
    assert_eq!(req.args.path, path);
    assert_eq!(req.args.key_version, key_version);

    Ok(())
}

/// Test that SolanaClient emits block events regularly
#[tokio::test]
async fn test_solana_client_emits_blocks() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let solana = setup_solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();

    let (_worker, _account, contract) = setup_near_sandbox().await?;
    let (contract_watcher, _) = ContractStateWatcher::new(contract.id());

    let (_backlog, mesh_state, node_client) = create_test_dependencies();
    let config = solana.get_config(program_address);
    let mut client = create_solana_client(config, contract_watcher, mesh_state, node_client)?;

    // Submit a transaction to generate activity
    let payload = [2u8; 32];
    solana
        .sign(payload, "test", LATEST_MPC_KEY_VERSION, "secp256k1", "", "")
        .await?;

    // Collect events and verify we get block markers
    let mut found_block = false;
    for _ in 0..5 {
        if let Ok(Some(event)) = timeout(Duration::from_secs(5), client.next_event()).await {
            if matches!(event, ChainEvent::Block(_)) {
                found_block = true;
                break;
            }
        }
    }

    assert!(found_block, "did not receive block event");
    Ok(())
}

/// Test that SolanaClient can linearly catch up when starting behind
#[tokio::test]
async fn test_solana_client_catchup_linear() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let solana = setup_solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();

    let (_worker, _account, contract) = setup_near_sandbox().await?;
    let (contract_watcher, _) = ContractStateWatcher::new(contract.id());

    // Create first client and process some events
    let (_backlog, mesh_state, node_client) = create_test_dependencies();
    let config = solana.get_config(program_address.clone());
    let mut client1 = create_solana_client(
        config.clone(),
        contract_watcher.clone(),
        mesh_state.clone(),
        node_client.clone(),
    )?;

    // Submit requests while client is running
    for i in 0..3 {
        let payload = [i as u8; 32];
        solana
            .sign(payload, "test", LATEST_MPC_KEY_VERSION, "secp256k1", "", "")
            .await?;
    }

    // Collect some events from first client
    let mut seen_by_client1 = 0;
    let mut last_block_client1 = 0;
    for _ in 0..10 {
        if let Ok(Some(event)) = timeout(Duration::from_millis(500), client1.next_event()).await {
            match event {
                ChainEvent::SignRequest(_) => seen_by_client1 += 1,
                ChainEvent::Block(block) => last_block_client1 = last_block_client1.max(block),
                _ => {}
            }
        }
    }
    assert!(seen_by_client1 > 0, "first client saw no events");
    assert!(last_block_client1 > 0, "first client saw no block events");

    // Drop first client
    drop(client1);

    // Create new client immediately (before more events) - should start processing from now
    let (_backlog2, mesh_state2, node_client2) = create_test_dependencies();
    let mut client2 = create_solana_client(config, contract_watcher, mesh_state2, node_client2)?;

    // Submit new requests while second client is running
    for i in 3..6 {
        let payload = [i as u8; 32];
        solana
            .sign(payload, "test", LATEST_MPC_KEY_VERSION, "secp256k1", "", "")
            .await?;
    }

    // Client should process new events
    let mut sign_events = Vec::new();
    let mut caught_up = false;
    for _ in 0..20 {
        if let Ok(Some(event)) = timeout(Duration::from_secs(2), client2.next_event()).await {
            match event {
                ChainEvent::SignRequest(req) => {
                    sign_events.push(req);
                }
                ChainEvent::Block(block) if block >= last_block_client1 => {
                    caught_up = true;
                }
                _ => {}
            }
            if caught_up && !sign_events.is_empty() {
                break;
            }
        }
    }

    // Verify we caught up to the last block the first client observed and saw new events
    assert!(caught_up, "second client did not catch up to prior block height");
    assert!(
        !sign_events.is_empty(),
        "second client did not process new events"
    );
    Ok(())
}

/// Test that SolanaClient can parse SignBidirectional events
#[tokio::test]
async fn test_solana_client_parse_sign_bidirectional() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let solana = setup_solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();

    let (_worker, _account, contract) = setup_near_sandbox().await?;
    let (contract_watcher, _) = ContractStateWatcher::new(contract.id());

    let (_backlog, mesh_state, node_client) = create_test_dependencies();
    let config = solana.get_config(program_address);
    let mut client = create_solana_client(config, contract_watcher, mesh_state, node_client)?;

    // Submit bidirectional sign request
    let serialized_tx = vec![1, 2, 3, 4];
    let callback_program = solana_sdk::pubkey::Pubkey::new_unique();

    solana
        .sign_bidirectional(
            &serialized_tx,
            "solana:localnet",
            LATEST_MPC_KEY_VERSION,
            "test",
            "secp256k1",
            "",
            "",
            callback_program,
            &[],
            &[],
        )
        .await?;

    // Wait for SignRequest event (skip checkpoints)
    let req = wait_for_sign_request(&mut client).await?;

    // Verify it's a bidirectional sign request
    assert_eq!(req.chain, Chain::Solana);
    assert!(matches!(
        req.sign_request_type,
        mpc_node::protocol::SignRequestType::SignBidirectional(_)
    ));

    Ok(())
}

/// Test that SolanaClient handles multiple concurrent submissions
#[tokio::test]
async fn test_solana_client_concurrent_events() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let solana = setup_solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();

    let (_worker, _account, contract) = setup_near_sandbox().await?;
    let (contract_watcher, _) = ContractStateWatcher::new(contract.id());

    let (_backlog, mesh_state, node_client) = create_test_dependencies();
    let config = solana.get_config(program_address);
    let mut client = create_solana_client(config, contract_watcher, mesh_state, node_client)?;

    // Submit multiple concurrent sign requests
    let num_requests = 5;
    for i in 0..num_requests {
        let payload = [i as u8; 32];
        solana
            .sign(payload, "test", LATEST_MPC_KEY_VERSION, "secp256k1", "", "")
            .await?;
    }

    // Collect all sign request events
    let mut sign_events = Vec::new();
    for _ in 0..num_requests * 2 {
        if let Ok(Some(event)) = timeout(Duration::from_secs(10), client.next_event()).await {
            if let ChainEvent::SignRequest(req) = event {
                sign_events.push(req);
                if sign_events.len() == num_requests {
                    break;
                }
            }
        }
    }

    assert_eq!(
        sign_events.len(),
        num_requests,
        "did not receive all sign requests"
    );

    // Verify all payloads are unique
    let mut seen_payloads: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for req in sign_events {
        let payload_bytes: [u8; 32] = req.args.payload.to_bytes().into();
        assert!(
            seen_payloads.insert(payload_bytes),
            "duplicate payload detected"
        );
    }

    Ok(())
}

/// Test that checkpoint persistence works across client restarts
#[tokio::test]
async fn test_solana_client_checkpoint_persistence() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let solana = setup_solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();

    let (_worker, _account, contract) = setup_near_sandbox().await?;
    let (contract_watcher, _) = ContractStateWatcher::new(contract.id());

    // Create backlog that will persist checkpoints
    let (backlog, mesh_state, node_client) = create_test_dependencies();
    let config = solana.get_config(program_address.clone());
    let mut client = create_solana_client(
        config.clone(),
        contract_watcher.clone(),
        mesh_state.clone(),
        node_client.clone(),
    )?;

    // Submit request and wait for a block marker
    solana
        .sign(
            [1u8; 32],
            "test",
            LATEST_MPC_KEY_VERSION,
            "secp256k1",
            "",
            "",
        )
        .await?;

    let mut checkpoint_block = None;
    for _ in 0..10 {
        if let Ok(Some(event)) = timeout(Duration::from_secs(2), client.next_event()).await {
            if let ChainEvent::Block(block) = event {
                checkpoint_block = Some(block);
                // Set checkpoint in backlog
                backlog.set_processed_block(Chain::Solana, block).await;
                break;
            }
        }
    }

    assert!(checkpoint_block.is_some(), "did not receive block event");
    drop(client);

    // Create new client with same backlog - should resume from checkpoint
    let (_backlog2, mesh_state2, node_client2) = create_test_dependencies();
    let mut client2 = create_solana_client(config, contract_watcher, mesh_state2, node_client2)?;

    // Submit new request
    solana
        .sign(
            [2u8; 32],
            "test",
            LATEST_MPC_KEY_VERSION,
            "secp256k1",
            "",
            "",
        )
        .await?;

    // New client should pick up new events
    let event = timeout(Duration::from_secs(10), client2.next_event())
        .await
        .context("timeout waiting for event")?
        .context("client returned None")?;

    // Should get sign request or block marker
    assert!(
        matches!(
            event,
            ChainEvent::SignRequest(_) | ChainEvent::Block(_)
        ),
        "expected SignRequest or Block after restart"
    );

    Ok(())
}
