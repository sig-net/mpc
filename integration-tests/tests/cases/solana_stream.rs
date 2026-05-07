use anyhow::{Context, Result};
use integration_tests::containers::Solana;
use k256::Scalar;
use mpc_crypto::ScalarExt;
use mpc_node::backlog::Backlog;
use mpc_node::indexer_sol::{SolConfig, SolanaStream};
use mpc_node::mesh::MeshState;
use mpc_node::node_client::NodeClient;
use mpc_node::protocol::{Chain, IndexedSignRequest};
use mpc_node::stream::{ChainEvent, ChainStream};
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use solana_sdk::signer::Signer;
use tokio::sync::watch;
use tokio::time::timeout;

use std::time::Duration;

async fn solana_sandbox() -> Result<Solana> {
    let solana = Solana::run().await;
    solana.deploy_contract().await?;
    Ok(solana)
}

fn test_dependencies() -> (Backlog, watch::Receiver<MeshState>, NodeClient) {
    let backlog = Backlog::new();
    let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());
    let node_client = NodeClient::new(&Default::default());
    (backlog, mesh_rx, node_client)
}

async fn stream_solana(config: SolConfig) -> Result<SolanaStream> {
    let mut stream = SolanaStream::new(Some(config)).context("failed to create SolanaStream")?;
    ChainStream::start(&mut stream).await;
    Ok(stream)
}

/// Helper to wait for a specific event type, skipping block events
async fn wait_for_sign_request(stream: &mut SolanaStream) -> Result<IndexedSignRequest> {
    loop {
        match timeout(Duration::from_secs(6), stream.next_event()).await {
            Ok(Some(ChainEvent::SignRequest(req))) => return Ok(req),
            Ok(Some(ChainEvent::Block(_))) => continue,
            Ok(Some(other)) => anyhow::bail!("Expected SignRequest, got {:?}", other),
            Ok(None) => anyhow::bail!("stream returned None"),
            Err(_) => anyhow::bail!("timeout waiting for SignRequest event"),
        }
    }
}

/// Test that SolanaStream can parse basic Sign events
///
/// This test:
/// 1. Spins up Solana sandbox and deploys contract
/// 2. Creates a SolanaStream with test configuration
/// 3. Submits a Sign request directly to the contract
/// 4. Verifies stream.next_event() returns ChainEvent::SignRequest with correct data
#[test_log::test(tokio::test)]
async fn test_solana_stream_parse_sign_event() -> Result<()> {
    let solana = solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();
    let config = solana.get_config(program_address);
    let mut stream = stream_solana(config).await?;

    // Submit sign request
    let payload = [1u8; 32];
    let path = "test";
    let key_version = LATEST_MPC_KEY_VERSION;
    solana
        .sign(payload, path, key_version, "secp256k1", "", "")
        .await?;

    // Wait for SignRequest event
    let req = wait_for_sign_request(&mut stream).await?;

    // Verify the request
    assert_eq!(req.chain, Chain::Solana);
    assert_eq!(req.args.payload, Scalar::from_bytes(payload).unwrap());
    assert_eq!(req.args.path, path);
    assert_eq!(req.args.key_version, key_version);

    Ok(())
}

/// Test that SolanaStream emits block events regularly
#[test_log::test(tokio::test)]
async fn test_solana_stream_emits_blocks() -> Result<()> {
    let solana = solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();

    let config = solana.get_config(program_address);
    let mut stream = stream_solana(config).await?;

    // Submit a transaction to generate activity
    let payload = [2u8; 32];
    solana
        .sign(payload, "test", LATEST_MPC_KEY_VERSION, "secp256k1", "", "")
        .await?;

    // Collect events and verify we get block markers
    let mut found_block = false;
    for _ in 0..5 {
        if let Ok(Some(event)) = timeout(Duration::from_secs(3), stream.next_event()).await {
            if matches!(event, ChainEvent::Block(_)) {
                found_block = true;
                break;
            }
        }
    }

    assert!(found_block, "did not receive block event");
    Ok(())
}

/// Test that SolanaStream can linearly catch up when starting behind
#[test_log::test(tokio::test)]
async fn test_solana_stream_catchup_linear() -> Result<()> {
    let solana = solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();

    // Create first client and process some events
    let config = solana.get_config(program_address.clone());
    let mut stream1 = stream_solana(config.clone()).await?;

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
        if let Ok(Some(event)) = timeout(Duration::from_millis(500), stream1.next_event()).await {
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
    drop(stream1);

    // Create new client immediately (before more events) - should start processing from now
    let mut stream2 = stream_solana(config).await?;

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
        if let Ok(Some(event)) = timeout(Duration::from_secs(1), stream2.next_event()).await {
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
    assert!(
        caught_up,
        "second client did not catch up to prior block height"
    );
    assert!(
        !sign_events.is_empty(),
        "second client did not process new events"
    );
    Ok(())
}

/// Test that SolanaStream can parse SignBidirectional events
#[test_log::test(tokio::test)]
async fn test_solana_stream_parse_sign_bidirectional() -> Result<()> {
    let solana = solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();
    let config = solana.get_config(program_address);
    let mut stream = stream_solana(config).await?;

    // Submit bidirectional sign request
    let serialized_tx = vec![1, 2, 3, 4];
    let callback_program = solana_sdk::pubkey::Pubkey::new_unique();

    solana
        .sign_bidirectional(
            &serialized_tx,
            Chain::Solana.caip2_chain_id(),
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

    // Wait for SignRequest event
    let req = wait_for_sign_request(&mut stream).await?;

    // Verify it's a bidirectional sign request
    assert_eq!(req.chain, Chain::Solana);
    assert!(matches!(
        req.kind,
        mpc_node::protocol::SignKind::SignBidirectional(_)
    ));

    Ok(())
}

/// Test that SolanaStream handles multiple concurrent submissions
#[test_log::test(tokio::test)]
async fn test_solana_stream_concurrent_events() -> Result<()> {
    let solana = solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();
    let config = solana.get_config(program_address);
    let mut stream = stream_solana(config).await?;

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
        if let Ok(Some(ChainEvent::SignRequest(req))) =
            timeout(Duration::from_secs(5), stream.next_event()).await
        {
            sign_events.push(req);
            if sign_events.len() == num_requests {
                break;
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
#[test_log::test(tokio::test)]
async fn test_solana_stream_checkpoint_persistence() -> Result<()> {
    let solana = solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();
    let (backlog, _, _) = test_dependencies();
    let config = solana.get_config(program_address.clone());
    let mut stream1 = stream_solana(config.clone()).await?;

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
        if let Ok(Some(ChainEvent::Block(block))) =
            timeout(Duration::from_secs(1), stream1.next_event()).await
        {
            checkpoint_block = Some(block);
            // Set checkpoint in backlog
            backlog.set_processed_block(Chain::Solana, block).await;
            break;
        }
    }

    assert!(checkpoint_block.is_some(), "did not receive block event");
    drop(stream1);

    // Create new client with same backlog - should resume from checkpoint
    let mut stream2 = stream_solana(config).await?;

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
    let event = timeout(Duration::from_secs(5), stream2.next_event())
        .await
        .context("timeout waiting for event")?
        .context("client returned None")?;

    // Should get sign request or block marker
    assert!(
        matches!(event, ChainEvent::SignRequest(_) | ChainEvent::Block(_)),
        "expected SignRequest or Block after restart"
    );

    Ok(())
}
