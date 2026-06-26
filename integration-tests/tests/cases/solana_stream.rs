use anyhow::{Context, Result};
use cait_sith::protocol::Participant;
use integration_tests::containers::Solana;
use k256::{AffinePoint, Scalar};
use mpc_crypto::ScalarExt;
use mpc_indexer_core::{ChainStream, ChainTelemetry, NoopChainTelemetry, StateManager};
use mpc_node::backlog::Backlog;
use mpc_node::indexer_sol::{SolConfig, SolanaStream};
use mpc_node::mesh::connection::NodeStatus;
use mpc_node::mesh::MeshState;
use mpc_node::node_client::NodeClient;
use mpc_node::protocol::contract::primitives::{ParticipantInfo, Participants};
use mpc_node::protocol::{Chain, IndexedSignRequest, Sign};
use mpc_node::rpc::{ContractStateWatcher, RpcAction, RpcChannel};
use mpc_node::sign_bidirectional::{PublishState, SignStatus};
use mpc_node::storage::checkpoint_storage::CheckpointStorage;
use mpc_node::stream::{run_stream, ChainPipeline, ChainStreaming};
use mpc_primitives::{
    ChainEvent, CheckpointDigest, SignArgs, SignId, Signature, LATEST_MPC_KEY_VERSION,
};
use near_primitives::types::AccountId;
use solana_sdk::signer::Signer;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::time::timeout;
use tokio::time::Instant;

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

async fn stream_solana(
    config: SolConfig,
) -> Result<(
    SolanaStream<impl StateManager, impl ChainTelemetry>,
    watch::Sender<CheckpointDigest>,
)> {
    let (backlog, _, _) = test_dependencies();
    stream_solana_with_backlog(config, backlog).await
}

async fn stream_solana_with_backlog(
    config: SolConfig,
    backlog: Backlog,
) -> Result<(
    SolanaStream<impl StateManager, impl ChainTelemetry>,
    watch::Sender<CheckpointDigest>,
)> {
    let mut stream = SolanaStream::new(Some(config), backlog.clone(), NoopChainTelemetry)
        .context("failed to create SolanaStream")?;
    let indexer = ChainStream::start(&mut stream).await?;
    let (cp_tx, cp_rx) = watch::channel(CheckpointDigest::default());
    let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());
    let node_client = NodeClient::new(&Default::default());
    // Start from Recovery so that handle_recovery() calls livestream(), which
    // spawns the live event subscription and initializes the live_rx channel.
    // Starting in Live would skip this initialization and produce no events.
    let (sign_tx, _sign_rx) = mpsc::channel(1);
    let (pipeline, mut state_rx) = ChainPipeline::new(
        indexer,
        cp_rx,
        backlog,
        sign_tx,
        mesh_rx,
        node_client,
        0,
        "test.near".parse().unwrap(),
    );
    tokio::spawn(pipeline.run());

    // Wait until the pipeline is live so the WS subscription and anchor are established
    // before callers begin submitting transactions.
    timeout(Duration::from_secs(30), async {
        loop {
            if *state_rx.borrow() == ChainStreaming::Live {
                return Ok(());
            }
            if state_rx.changed().await.is_err() {
                anyhow::bail!("pipeline shut down before reaching Live state");
            }
        }
    })
    .await
    .context("timed out waiting for pipeline to reach Live state")??;

    Ok((stream, cp_tx))
}

/// Helper to wait for a specific event type, skipping block events
async fn wait_for_sign_request<S: StateManager, T: ChainTelemetry>(
    stream: &mut SolanaStream<S, T>,
) -> Result<IndexedSignRequest> {
    loop {
        match timeout(Duration::from_secs(6), stream.next_event()).await {
            Ok(Some(ChainEvent::SignRequest { request, .. })) => return Ok(request),
            Ok(Some(ChainEvent::Block(_))) => continue,
            Ok(Some(ChainEvent::CatchupCompleted)) => {
                tracing::info!("received CatchupCompleted event while waiting for SignRequest");
                continue;
            }
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
    let (mut stream, _cp_tx) = stream_solana(config).await?;

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
    let (mut stream, _cp_tx) = stream_solana(config).await?;

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
    let (mut stream1, _cp_tx) = stream_solana(config.clone()).await?;

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
                ChainEvent::SignRequest { .. } => seen_by_client1 += 1,
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
    let (mut stream2, _cp_tx2) = stream_solana(config).await?;

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
                ChainEvent::SignRequest { request, .. } => {
                    sign_events.push(request);
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
    let (mut stream, _cp_tx) = stream_solana(config).await?;

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
        mpc_primitives::SignKind::SignBidirectional(_)
    ));

    Ok(())
}

/// Test that SolanaStream handles multiple concurrent submissions
#[test_log::test(tokio::test)]
async fn test_solana_stream_concurrent_events() -> Result<()> {
    let solana = solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();
    let config = solana.get_config(program_address);
    let (mut stream, _cp_tx) = stream_solana(config).await?;

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

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while sign_events.len() < num_requests {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        if let Ok(Some(ChainEvent::SignRequest { request, .. })) =
            timeout(remaining, stream.next_event()).await
        {
            sign_events.push(request);
        }
    }

    assert_eq!(
        sign_events.len(),
        num_requests,
        "did not receive all sign requests {sign_events:?}"
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
    let (mut stream1, _cp_tx) = stream_solana_with_backlog(config.clone(), backlog.clone()).await?;
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

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut checkpoint_block = None;
    while Instant::now() < deadline {
        match timeout(Duration::from_secs(1), stream1.next_event()).await {
            Ok(Some(ChainEvent::Block(block))) => {
                tracing::info!(block, "received block event");
                checkpoint_block = Some(block);
                backlog.set_processed_block(Chain::Solana, block).await;
                break;
            }
            Ok(Some(event)) => {
                tracing::info!(?event, "received non-block event");
                continue;
            }
            Err(_) => continue,
            Ok(None) => break,
        }
    }

    assert!(
        checkpoint_block.is_some(),
        "did not receive block event within time"
    );
    drop(stream1);

    // Create new client with same backlog - should resume from checkpoint
    let (mut stream2, _cp_tx2) = stream_solana_with_backlog(config, backlog.clone()).await?;

    // Verify the backlog was persisted
    let persisted_block = backlog.get_processed_block(Chain::Solana).await;
    assert_eq!(
        persisted_block, checkpoint_block,
        "backlog did not persist the checkpoint block"
    );

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
    timeout(Duration::from_secs(5), async {
        loop {
            match stream2.next_event().await {
                Some(ChainEvent::SignRequest { request, .. }) => break Ok(request),
                Some(other) => {
                    tracing::info!(?other, "received non-sign/block event");
                    continue;
                }
                None => anyhow::bail!("stream returned None"),
            }
        }
    })
    .await
    .context("timeout waiting for event")?
    .context("client returned None")?;

    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_solana_stream_republishes_pending_publish_after_checkpoint_recovery() -> Result<()> {
    let solana = solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();
    let config = solana.get_config(program_address);

    let storage = CheckpointStorage::in_memory();
    let seeded_backlog = Backlog::persisted(storage.clone());
    let sign_id = SignId::new([77u8; 32]);
    let signature = Signature::new(AffinePoint::GENERATOR, Scalar::ONE, 0);
    let checkpoint_slot = solana.rpc_client.get_slot().await?;

    seeded_backlog
        .insert(IndexedSignRequest::sign(
            sign_id,
            SignArgs {
                entropy: [9u8; 32],
                epsilon: Scalar::from(1u64),
                payload: Scalar::from(2u64),
                path: "test".to_string(),
                key_version: LATEST_MPC_KEY_VERSION,
            },
            Chain::Solana,
            0,
        ))
        .await;
    seeded_backlog
        .set_status(
            Chain::Solana,
            &sign_id,
            SignStatus::PendingPublish {
                publish: PublishState {
                    signature,
                    participants: vec![Participant::from(0u32)],
                    is_proposer: true,
                },
            },
        )
        .await;
    seeded_backlog
        .set_processed_block(Chain::Solana, checkpoint_slot)
        .await;
    let checkpoint = seeded_backlog
        .checkpoint(Chain::Solana)
        .await
        .expect("checkpoint creation should succeed");
    seeded_backlog
        .on_consensus_confirmed(Chain::Solana, &checkpoint)
        .await;

    let recovered_backlog = Backlog::persisted(storage);
    let stream = SolanaStream::new(Some(config), recovered_backlog.clone(), NoopChainTelemetry)
        .context("failed to create SolanaStream")?;

    let (sign_tx, mut sign_rx) = mpsc::channel::<Sign>(4);
    let (rpc_tx, mut rpc_rx) = mpsc::channel::<RpcAction>(4);
    let rpc = RpcChannel { tx: rpc_tx };

    let account_id: AccountId = "test.near".parse().unwrap();
    let (contract_watcher, _contract_tx) = ContractStateWatcher::with_running(
        &account_id,
        AffinePoint::GENERATOR,
        1,
        Participants::default(),
    );

    let mut mesh_state = MeshState::default();
    mesh_state.update(
        Participant::from(0u32),
        NodeStatus::Active,
        ParticipantInfo::new(0),
    );
    let (_mesh_tx, mesh_rx) = watch::channel(mesh_state);
    let node_client = NodeClient::new(&Default::default());

    let (_cp_tx, checkpoints_rx) = watch::channel(CheckpointDigest::default());
    let run_handle = tokio::spawn(async move {
        run_stream(
            stream,
            sign_tx,
            rpc,
            recovered_backlog,
            NoopChainTelemetry,
            contract_watcher,
            mesh_rx,
            node_client,
            checkpoints_rx,
        )
        .await;
    });

    solana
        .sign(
            [3u8; 32],
            "recovery-anchor",
            LATEST_MPC_KEY_VERSION,
            "secp256k1",
            "",
            "",
        )
        .await?;

    let action = timeout(Duration::from_secs(15), rpc_rx.recv())
        .await
        .context("timeout waiting for recovered publish action")?
        .context("rpc channel closed before publish action")?;

    while let Ok(Some(message)) = timeout(Duration::from_millis(50), sign_rx.recv()).await {
        if let Sign::Request(req) = &message {
            if req.id == sign_id {
                anyhow::bail!("recovered publish request was incorrectly requeued for signing");
            }
        }
    }

    match action {
        RpcAction::Publish(action) => {
            assert_eq!(action.indexed.id, sign_id);
            assert_eq!(action.indexed.chain, Chain::Solana);
            assert_eq!(action.signature, signature);
            assert_eq!(action.participants, vec![Participant::from(0u32)]);
        }
    }

    run_handle.abort();
    Ok(())
}
