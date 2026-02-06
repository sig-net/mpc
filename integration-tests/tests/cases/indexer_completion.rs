use anyhow::{anyhow, Context, Result};
use ethers::types::{BlockNumber, U256};
use integration_tests::{cluster, eth};
use mpc_node::backlog::Backlog;
use mpc_node::indexer_eth::{EthConfig, EthereumIndexer};
use mpc_node::mesh::MeshState;
use mpc_node::node_client::NodeClient;
use mpc_node::protocol::Sign;
use mpc_node::storage::app_data_storage::AppDataStorage;
use mpc_primitives::SignId;
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use near_sdk::AccountId;
use std::str::FromStr;
use std::sync::Arc;
use test_log::test;
use tokio::sync::{mpsc, watch};
use tokio::time::{timeout, Duration};

/// Test that the Ethereum indexer correctly observes SignatureResponded events
/// and sends Sign::Completion messages.
///
/// This test validates that the indexer can process completion events from the contract,
/// which is critical for preventing tasks from piling up when signatures complete.
///
/// **NOTE**: This test requires a properly configured Ethereum sandbox (Anvil).
/// If you see "ethereum sandbox rpc did not become ready" errors, ensure:
/// - Anvil is installed: `curl -L https://foundry.paradigm.xyz | bash && foundryup`
/// - Docker is running (for docker-test feature)
/// - No other process is using port 8545
///
/// Run with: `cargo test -p integration-tests test_indexer_observes_completion_events`
#[test(tokio::test)]
async fn test_indexer_observes_completion_events() -> Result<()> {
    // Setup: Use cluster infrastructure to properly set up Ethereum sandbox
    // We don't need to wait for MPC nodes, just the Ethereum sandbox
    let cluster = cluster::spawn()
        .disable_prestockpile()
        .ethereum()
        .await?;
    
    // Give the Ethereum sandbox a moment to fully stabilize
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Extract Ethereum context
    let ctx = cluster.nodes.ctx();
    let eth_ctx = ctx
        .ethereum
        .as_ref()
        .context("ethereum sandbox not initialized")?;
    
    let endpoint = eth_ctx.sandbox.external_http_endpoint.clone();
    let secret_key = eth_ctx.sandbox.secret_key.clone();
    let chain_id = eth_ctx.sandbox.chain_id;
    let contract_address = eth_ctx.contract_address;

    let (client, requester) = eth::client(&endpoint, &secret_key, chain_id)?;

    let contract = eth::ChainSignaturesContract::new(contract_address, client.clone());

    tracing::info!(?contract_address, "using deployed chain signatures contract");

    // Use a deposit value for the sign request
    let signature_deposit = U256::from(1_u64);

    // Step 1: Send a sign request to the contract
    let payload = [42u8; 32];
    let path = "test-indexer";
    let algo = "secp256k1";
    let dest = "solana:TestDestination";
    let params = "{}";

    let request = eth::SignRequest {
        payload,
        path: path.to_string(),
        key_version: LATEST_MPC_KEY_VERSION,
        algo: algo.to_string(),
        dest: dest.to_string(),
        params: params.to_string(),
    };

    let call = contract.sign(request.clone()).value(signature_deposit);
    let pending = call.send().await?;
    let sign_receipt = pending.await?.context("sign transaction failed")?;
    let sign_block_number = sign_receipt
        .block_number
        .context("missing block number in sign receipt")?;

    let request_id = eth::compute_request_id(
        requester,
        payload,
        path,
        LATEST_MPC_KEY_VERSION,
        U256::from(chain_id),
        algo,
        dest,
        params,
    );

    let sign_id = SignId::new(request_id.into());

    tracing::info!(
        ?sign_id,
        ?sign_block_number,
        "sent sign request to contract"
    );

    // Step 2: Manually send a fake signature response
    // In a real scenario, the MPC nodes would generate this signature.
    // For this test, we just need to trigger the SignatureResponded event.

    let fake_signature = eth::chain_signatures_contract::Signature {
        big_r: eth::chain_signatures_contract::AffinePoint {
            x: U256::from(1),
            y: U256::from(2),
        },
        s: U256::from(3).into(),
        recovery_id: 0,
    };

    let fake_response = eth::chain_signatures_contract::Response {
        request_id: request_id.into(),
        signature: fake_signature,
    };

    let respond_call = contract.respond(vec![fake_response]);
    let respond_pending = respond_call.send().await?;
    let respond_receipt = respond_pending
        .await?
        .context("respond transaction failed")?;
    let respond_block_number = respond_receipt
        .block_number
        .context("missing block number in respond receipt")?;

    tracing::info!(
        ?respond_block_number,
        "sent fake signature response to contract"
    );

    // Step 3: Verify the SignatureResponded event was emitted
    let from_block = BlockNumber::Number(respond_block_number);
    let events = contract
        .event::<eth::SignatureRespondedFilter>()
        .from_block(from_block)
        .query()
        .await?;

    let matching_event = events
        .iter()
        .find(|event| event.request_id == request_id[..] && event.responder == requester)
        .context("SignatureResponded event not found in contract logs")?;

    tracing::info!(
        ?matching_event.request_id,
        ?matching_event.responder,
        "verified SignatureResponded event was emitted"
    );

    // Step 4: Set up the indexer to observe the completion event
    // Use the cluster's Redis instance
    let redis_pool = cluster.nodes.ctx().redis.pool();
    let (sign_tx, mut sign_rx) = mpsc::channel::<Sign>(100);

    // Create a minimal backlog for the indexer
    let backlog = Backlog::new();

    // Create minimal dependencies for the indexer
    let account_id = AccountId::from_str("test-indexer.near")?;
    let (contract_watcher, _contract_state_tx) =
        mpc_node::rpc::ContractStateWatcher::new(&account_id);

    let (mesh_state_tx, mesh_state_rx) = watch::channel(MeshState::default());

    let message_options = mpc_node::node_client::Options {
        timeout: 10_000,
        ..Default::default()
    };
    let node_client = NodeClient::new(&message_options);

    let kv_store = mpc_node::storage::app_data_storage::init(&redis_pool, &account_id);

    // Get Redis address for storage options  
    let redis_address = cluster.nodes.ctx().redis.internal_address.clone();

    // Configure the indexer
    let eth_config = EthConfig {
        account_sk: secret_key.clone(),
        consensus_rpc_http_url: endpoint.clone(),
        execution_rpc_http_url: endpoint.clone(),
        contract_address: format!("{:x}", contract_address),
        network: "sepolia".to_string(),
        helios_data_path: format!("/tmp/helios-test-{}", contract_address),
        refresh_finalized_interval: 100, // Fast refresh for testing
        total_timeout: 300,
        optimistic_requests: true, // Use optimistic mode to avoid waiting for finality
        light_client: false,       // Use direct RPC for simplicity
    };

    tracing::info!(?eth_config, "configured ethereum indexer");

    // Create and run the indexer
    let indexer = EthereumIndexer::new(
        Some(eth_config),
        sign_tx,
        kv_store,
        backlog.clone(),
        contract_watcher,
        mesh_state_rx,
        node_client,
    )
    .await
    .context("failed to create ethereum indexer")?;

    // Run the indexer in the background
    tokio::spawn(async move {
        indexer.run().await;
    });

    // Step 5: Wait for the indexer to send both the Sign::Request and Sign::Completion
    let mut received_request = false;
    let mut received_completion = false;

    let result = timeout(Duration::from_secs(30), async {
        while let Some(sign_message) = sign_rx.recv().await {
            match sign_message {
                Sign::Completion(received_sign_id) => {
                    if received_sign_id == sign_id {
                        tracing::info!(
                            ?received_sign_id,
                            "✓ received Sign::Completion from indexer"
                        );
                        received_completion = true;
                        if received_request {
                            return Ok::<_, anyhow::Error>(());
                        }
                    } else {
                        tracing::warn!(
                            ?received_sign_id,
                            ?sign_id,
                            "received completion for different sign_id"
                        );
                    }
                }
                Sign::Request(indexed_request) => {
                    if indexed_request.id == sign_id {
                        tracing::info!(
                            sign_id = ?indexed_request.id,
                            "✓ received Sign::Request from indexer"
                        );
                        received_request = true;
                        if received_completion {
                            return Ok::<_, anyhow::Error>(());
                        }
                    } else {
                        tracing::info!(
                            sign_id = ?indexed_request.id,
                            "received Sign::Request for different sign_id"
                        );
                    }
                }
            }
        }
        Err(anyhow!("indexer channel closed without sending expected messages"))
    })
    .await
    .context("timeout waiting for indexer to process events")??;

    if !received_request {
        return Err(anyhow!("did not receive Sign::Request from indexer"));
    }
    if !received_completion {
        return Err(anyhow!("did not receive Sign::Completion from indexer"));
    }

    tracing::info!("✓ test passed: indexer successfully observed both request and completion events");

    Ok(())
}
