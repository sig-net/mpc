use anyhow::{Context, Result};
use cait_sith::protocol::Participant;
use integration_tests::containers::Solana;
use k256::{AffinePoint, Scalar};
use mpc_chain_integration_core::{
    utils::test::ChainIndexerStream, ChainPublisher, NoopChainTelemetry, NoopPublisherTelemetry,
    PublishAction, StateManager,
};
use mpc_chain_solana::{SolConfig, SolanaClient, SolanaIndexer};
use mpc_crypto::ScalarExt;
use mpc_node::backlog::Backlog;
use mpc_node::mesh::connection::NodeStatus;
use mpc_node::mesh::MeshState;
use mpc_node::node_client::NodeClient;
use mpc_node::protocol::contract::primitives::{ParticipantInfo, Participants};
use mpc_node::rpc::{ContractStateWatcher, RpcAction, RpcChannel};
use mpc_node::sign_bidirectional::{PublishState, SignStatus};
use mpc_node::storage::checkpoint_storage::CheckpointStorage;
use mpc_node::stream::{supervisor::run_supervised, StreamContext};
use mpc_primitives::{
    Chain, ChainEvent, IndexedSignRequest, SignArgs, SignCommand, SignId, Signature,
    LATEST_MPC_KEY_VERSION,
};
use near_primitives::types::AccountId;
use solana_sdk::signer::Signer;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::time::timeout;
use tokio::time::Instant;

use std::time::Duration;

/// Timeout for waiting for a finalized event (SignRequest or Block)
const FINALIZED_EVENT_TIMEOUT: Duration = Duration::from_secs(45);

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

async fn run_solana_indexer(config: SolConfig) -> Result<ChainIndexerStream> {
    let (backlog, _, _) = test_dependencies();
    run_solana_indexer_with_backlog(config, backlog).await
}

async fn run_solana_indexer_with_backlog(
    config: SolConfig,
    backlog: Backlog,
) -> Result<ChainIndexerStream> {
    let indexer = SolanaIndexer::new(config, backlog, NoopChainTelemetry)
        .context("failed to create SolanaIndexer")?;
    ChainIndexerStream::start(indexer, Duration::from_secs(30)).await
}

/// Helper to wait for a specific event type, skipping block events
async fn wait_for_sign_request(
    indexer: &mut ChainIndexerStream,
) -> Result<Arc<IndexedSignRequest>> {
    loop {
        match timeout(FINALIZED_EVENT_TIMEOUT, indexer.next_event()).await {
            Ok(Some(ChainEvent::SignRequest { request, .. })) => return Ok(request),
            Ok(Some(ChainEvent::Block(_))) => continue,
            Ok(Some(ChainEvent::CatchupCompleted)) => {
                tracing::info!("received CatchupCompleted event while waiting for SignRequest");
                continue;
            }
            Ok(Some(other)) => anyhow::bail!("Expected SignRequest, got {:?}", other),
            Ok(None) => anyhow::bail!("indexer returned None"),
            Err(_) => anyhow::bail!("timeout waiting for SignRequest event"),
        }
    }
}

/// Wait for a SignCommand::Request to arrive on the sign channel
async fn next_sign_command(
    sign_rx: &mut mpsc::Receiver<SignCommand>,
) -> Result<Arc<IndexedSignRequest>> {
    loop {
        match timeout(FINALIZED_EVENT_TIMEOUT, sign_rx.recv()).await {
            Ok(Some(SignCommand::Request(request))) => return Ok(request),
            Ok(Some(other)) => {
                tracing::debug!(?other, "ignoring non-request sign command")
            }
            Ok(None) => anyhow::bail!("sign command channel closed"),
            Err(_) => anyhow::bail!("timeout waiting for SignCommand::Request"),
        }
    }
}

/// Spawn a supervised Solana indexer over `backlog` (test wiring for
/// `run_supervised`).
/// Returns its abort handle and sign command receiver.
async fn spawn_supervised_stream(
    config: SolConfig,
    backlog: Backlog,
) -> Result<(tokio::task::JoinHandle<()>, mpsc::Receiver<SignCommand>)> {
    let indexer = SolanaIndexer::new(config, backlog.clone(), NoopChainTelemetry)
        .context("failed to create SolanaIndexer")?;

    let (sign_tx, sign_rx) = mpsc::channel::<SignCommand>(16);
    let (rpc_tx, _rpc_rx) = mpsc::channel::<RpcAction>(16);
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
    let (_cp_tx, checkpoints_rx) = watch::channel(None);

    // We need to forget the tx handles because they are not used after this point
    // and we don't want them to be dropped and close the channels.
    // The indexer will use the channels internally.
    std::mem::forget((_mesh_tx, _cp_tx));

    let run_handle = tokio::spawn(async move {
        run_supervised(
            indexer,
            StreamContext::new(
                backlog,
                sign_tx,
                rpc,
                contract_watcher,
                mesh_rx,
                node_client,
                checkpoints_rx,
            ),
            NoopChainTelemetry,
        )
        .await;
    });

    Ok((run_handle, sign_rx))
}

/// Test that the Solana indexer can parse basic Sign events
///
/// This test:
/// 1. Spins up Solana sandbox and deploys contract
/// 2. Creates a SolanaIndexer with test configuration
/// 3. Submits a Sign request directly to the contract
/// 4. Verifies the indexer emits ChainEvent::SignRequest with correct data
#[test_log::test(tokio::test)]
async fn test_solana_stream_parse_sign_event() -> Result<()> {
    let solana = solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();
    let config = solana.get_config(program_address);
    let mut indexer = run_solana_indexer(config).await?;

    // Submit sign request
    let payload = [1u8; 32];
    let path = "test";
    let key_version = LATEST_MPC_KEY_VERSION;
    solana
        .sign(payload, path, key_version, "secp256k1", "", "")
        .await?;

    // Wait for SignRequest event
    let req = wait_for_sign_request(&mut indexer).await?;

    // Verify the request
    assert_eq!(req.chain, Chain::Solana);
    assert_eq!(req.args.payload, Scalar::from_bytes(payload).unwrap());
    assert_eq!(req.args.path, path);
    assert_eq!(req.args.key_version, key_version);

    Ok(())
}

/// Test that the Solana indexer emits block events regularly
#[test_log::test(tokio::test)]
async fn test_solana_stream_emits_blocks() -> Result<()> {
    let solana = solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();

    let config = solana.get_config(program_address);
    let mut indexer = run_solana_indexer(config).await?;

    // Submit a transaction to generate activity
    let payload = [2u8; 32];
    solana
        .sign(payload, "test", LATEST_MPC_KEY_VERSION, "secp256k1", "", "")
        .await?;

    // Collect events and verify we get block markers
    // Collect events until a block marker arrives; heartbeats only start
    // flowing once the finalized anchor leaves 0 (fresh-validator warmup), so
    // budget for the finality lag.
    let mut found_block = false;
    let deadline = Instant::now() + FINALIZED_EVENT_TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(Some(event)) = timeout(Duration::from_secs(1), indexer.next_event()).await {
            if matches!(event, ChainEvent::Block(_)) {
                found_block = true;
                break;
            }
        }
    }

    assert!(found_block, "did not receive block event");
    Ok(())
}

/// Test that the Solana indexer can linearly catch up when starting behind
#[test_log::test(tokio::test)]
async fn test_solana_stream_catchup_linear() -> Result<()> {
    let solana = solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();

    // Create first client and process some events
    let config = solana.get_config(program_address.clone());
    let mut indexer1 = run_solana_indexer(config.clone()).await?;

    // Submit requests while client is running
    for i in 0..3 {
        let payload = [i as u8; 32];
        solana
            .sign(payload, "test", LATEST_MPC_KEY_VERSION, "secp256k1", "", "")
            .await?;
    }

    // Collect events from the first client until it has seen both requests
    // (they surface only after finalization; dense Block markers stream
    // meanwhile).
    let mut seen_by_client1 = 0;
    let mut last_block_client1 = 0;
    let mut prev_block: Option<u64> = None;
    let deadline = Instant::now() + FINALIZED_EVENT_TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(Some(event)) = timeout(Duration::from_secs(1), indexer1.next_event()).await {
            match event {
                ChainEvent::SignRequest { .. } => {
                    seen_by_client1 += 1;
                    if seen_by_client1 >= 2 {
                        break;
                    }
                }
                ChainEvent::Block(block) => {
                    if let Some(prev) = prev_block {
                        assert_eq!(
                            block,
                            prev + 1,
                            "Block sequence must be gapless over a live run"
                        );
                    }
                    prev_block = Some(block);
                    last_block_client1 = last_block_client1.max(block);
                }
                _ => {}
            }
        }
    }
    assert!(seen_by_client1 > 0, "first client saw no events");
    assert!(last_block_client1 > 0, "first client saw no block events");

    // Drop first client
    drop(indexer1);

    // Create new client immediately (before more events) - should start processing from now
    let mut indexer2 = run_solana_indexer(config).await?;

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
    let deadline = Instant::now() + FINALIZED_EVENT_TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(Some(event)) = timeout(Duration::from_secs(1), indexer2.next_event()).await {
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

/// Test that the Solana indexer can parse SignBidirectional events
#[test_log::test(tokio::test)]
async fn test_solana_stream_parse_sign_bidirectional() -> Result<()> {
    let solana = solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();
    let config = solana.get_config(program_address);
    let mut indexer = run_solana_indexer(config).await?;

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
    let req = wait_for_sign_request(&mut indexer).await?;

    // Verify it's a bidirectional sign request
    assert_eq!(req.chain, Chain::Solana);
    assert!(matches!(
        req.kind,
        mpc_primitives::SignKind::SignBidirectional(_)
    ));

    Ok(())
}

/// Test that the Solana indexer handles multiple concurrent submissions
#[test_log::test(tokio::test)]
async fn test_solana_stream_concurrent_events() -> Result<()> {
    let solana = solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();
    let config = solana.get_config(program_address);
    let mut indexer = run_solana_indexer(config).await?;

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

    let deadline = tokio::time::Instant::now() + FINALIZED_EVENT_TIMEOUT;
    while sign_events.len() < num_requests {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        if let Ok(Some(ChainEvent::SignRequest { request, .. })) =
            timeout(remaining, indexer.next_event()).await
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
    let mut indexer1 = run_solana_indexer_with_backlog(config.clone(), backlog.clone()).await?;
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

    let deadline = Instant::now() + FINALIZED_EVENT_TIMEOUT;
    let mut checkpoint_block = None;
    while Instant::now() < deadline {
        match timeout(Duration::from_secs(1), indexer1.next_event()).await {
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
    drop(indexer1);

    // Create new client with same backlog - should resume from checkpoint
    let mut indexer2 = run_solana_indexer_with_backlog(config, backlog.clone()).await?;

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
    timeout(FINALIZED_EVENT_TIMEOUT, async {
        loop {
            match indexer2.next_event().await {
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
        .insert(Arc::new(IndexedSignRequest::sign(
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
        )))
        .await;
    seeded_backlog
        .publish(
            Chain::Solana,
            &sign_id,
            Arc::new(PublishState {
                signature,
                participants: vec![Participant::from(0u32)],
                is_proposer: true,
            }),
        )
        .await
        .unwrap();
    seeded_backlog
        .set_processed_block(Chain::Solana, checkpoint_slot)
        .await;
    let checkpoint = seeded_backlog
        .checkpoint(Chain::Solana)
        .await
        .expect("checkpoint creation should succeed");
    assert!(matches!(
        seeded_backlog
            .confirm_consensus(Chain::Solana, checkpoint.digest())
            .await,
        Ok(true)
    ));

    let recovered_backlog = Backlog::persisted(storage);
    let indexer = SolanaIndexer::new(config, recovered_backlog.clone(), NoopChainTelemetry)
        .context("failed to create SolanaIndexer")?;

    let (sign_tx, mut sign_rx) = mpsc::channel::<SignCommand>(4);
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

    let (_cp_tx, checkpoints_rx) = watch::channel(None);
    let run_handle = tokio::spawn(async move {
        run_supervised(
            indexer,
            StreamContext::new(
                recovered_backlog.clone(),
                sign_tx.clone(),
                rpc.clone(),
                contract_watcher.clone(),
                mesh_rx.clone(),
                node_client.clone(),
                checkpoints_rx.clone(),
            ),
            NoopChainTelemetry,
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

    let action = timeout(FINALIZED_EVENT_TIMEOUT, rpc_rx.recv())
        .await
        .context("timeout waiting for recovered publish action")?
        .context("rpc channel closed before publish action")?;

    while let Ok(Some(message)) = timeout(Duration::from_millis(50), sign_rx.recv()).await {
        if let SignCommand::Request(req) = &message {
            if req.id == sign_id {
                anyhow::bail!("recovered publish request was incorrectly requeued for signing");
            }
        }
    }

    match action {
        RpcAction::Publish(action) => {
            assert_eq!(action.request.id, sign_id);
            assert_eq!(action.request.chain, Chain::Solana);
            assert_eq!(action.signature, signature);
            assert_eq!(action.participants, vec![Participant::from(0u32)]);
        }
        RpcAction::VoteCheckpoint { checkpoint, .. } => {
            panic!("unexpected checkpoint vote: {checkpoint:?}");
        }
        RpcAction::AbortCheckpoints(chain) => {
            panic!("unexpected chain abort: {chain:?}");
        }
    }

    run_handle.abort();
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_solana_respond_round_trip() -> Result<()> {
    let solana = solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();
    let config = solana.get_config(program_address);
    let mut indexer = run_solana_indexer(config.clone()).await?;

    let payload = [7u8; 32];

    // Submit a sign request to the Solana contract
    solana
        .sign(
            payload,
            "respond-round-trip",
            LATEST_MPC_KEY_VERSION,
            "secp256k1",
            "",
            "",
        )
        .await?;
    let request = wait_for_sign_request(&mut indexer).await?;

    let publisher = SolanaClient::from_config(&config, Arc::new(NoopPublisherTelemetry));

    // Publish a signature for the request
    publisher
        .publish_signature(&PublishAction {
            request: request.clone(),
            signature: Signature::new(AffinePoint::GENERATOR, Scalar::ONE, 0),
            participants: vec![Participant::from(0u32)],
            timestamp: std::time::Instant::now(),
        })
        .await
        .context("failed to publish signature")?;

    // Wait for the indexer to emit a Respond event for the request
    let event = indexer
        .wait_for(
            |event| matches!(event, ChainEvent::Respond(_)),
            FINALIZED_EVENT_TIMEOUT,
        )
        .await
        .context("indexer never emitted the on-chain respond event")?;

    let ChainEvent::Respond(responded) = event else {
        panic!("expected Respond event, got {event:?}");
    };
    assert_eq!(responded.request_id, request.id.request_id);
    assert_eq!(responded.chain, Chain::Solana);
    assert_eq!(responded.signature.big_r, AffinePoint::GENERATOR);
    assert_eq!(responded.signature.s, Scalar::ONE);
    assert_eq!(responded.signature.recovery_id, 0);

    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_solana_stream_failed_tx_skipped() -> Result<()> {
    let solana = solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();
    let config = solana.get_config(program_address);
    let mut indexer = run_solana_indexer(config).await?;

    let failed_payload = [8u8; 32];
    let failed_slot = solana
        .sign_failed_tx(failed_payload, "failed-tx", LATEST_MPC_KEY_VERSION)
        .await?;

    // Wait for the failed transaction's slot to be emitted as a Block event, and verify that no SignRequest events from the failed transaction leak into the stream.
    loop {
        match timeout(FINALIZED_EVENT_TIMEOUT, indexer.next_event()).await {
            Ok(Some(ChainEvent::SignRequest { .. })) => {
                anyhow::bail!("sign CPI event from the failed tx leaked into the stream")
            }
            Ok(Some(ChainEvent::Block(slot))) if slot >= failed_slot => break,
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("indexer stream closed"),
            Err(_) => anyhow::bail!("failed tx slot never surfaced as a Block event"),
        }
    }

    let valid_payload = [9u8; 32];
    solana
        .sign(
            valid_payload,
            "failed-tx-survival",
            LATEST_MPC_KEY_VERSION,
            "secp256k1",
            "",
            "",
        )
        .await?;
    let request = wait_for_sign_request(&mut indexer).await?;
    assert_eq!(
        request.args.payload,
        Scalar::from_bytes(valid_payload).unwrap(),
        "stream must keep parsing sign requests after a failed tx"
    );

    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_solana_stream_resumes_gap_free_after_outage() -> Result<()> {
    let mut solana = solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();
    let config = solana.get_config(program_address);

    let backlog = Backlog::new();
    let (run_handle, mut sign_rx) = spawn_supervised_stream(config, backlog.clone()).await?;

    let payload_a = [0xA1; 32];

    // Snapshot the processed block before submitting request A
    let processed_before = backlog.get_processed_block(Chain::Solana).await;
    solana
        .sign(
            payload_a,
            "restart-before-outage",
            LATEST_MPC_KEY_VERSION,
            "secp256k1",
            "",
            "",
        )
        .await?;
    let request_a = next_sign_command(&mut sign_rx).await?;
    assert_eq!(
        request_a.args.payload,
        Scalar::from_bytes(payload_a).unwrap()
    );

    // Wait for the processed block to advance past the snapshot
    let deadline = Instant::now() + FINALIZED_EVENT_TIMEOUT;
    loop {
        let processed = backlog.get_processed_block(Chain::Solana).await;
        if processed.is_some_and(|slot| processed_before.is_none_or(|prev| slot > prev)) {
            break;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "processed block never advanced past A"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Kill the validator and submit a request while it's down
    solana
        .process
        .kill()
        .context("failed to kill solana-test-validator")?;
    let payload_b = [0xB2; 32];
    let down = solana
        .sign(
            payload_b,
            "restart-during-outage",
            LATEST_MPC_KEY_VERSION,
            "secp256k1",
            "",
            "",
        )
        .await;
    assert!(down.is_err(), "sign must fail while the validator is down");

    // Restart the validator and submit a request after it's back up
    solana.restart().await.context("validator restart failed")?;

    let payload_c = [0xC3; 32];
    solana
        .sign(
            payload_c,
            "restart-after-outage",
            LATEST_MPC_KEY_VERSION,
            "secp256k1",
            "",
            "",
        )
        .await?;

    let mut seen = vec![request_a.id];
    let request_c_id;

    // Wait for the post-restart request to appear on the sign channel, and record its id
    loop {
        let request = next_sign_command(&mut sign_rx).await?;
        seen.push(request.id);
        if request.args.payload == Scalar::from_bytes(payload_c).unwrap() {
            request_c_id = request.id;
            break;
        }
    }

    // Drain any remaining requests from the sign channel for a few seconds, to ensure that no other requests are emitted.
    let drain_until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < drain_until {
        match timeout(drain_until - Instant::now(), sign_rx.recv()).await {
            Ok(Some(SignCommand::Request(request))) => seen.push(request.id),
            Ok(_) | Err(_) => break,
        }
    }

    let distinct: HashSet<_> = seen.iter().collect();
    assert_eq!(
        distinct,
        HashSet::from([&request_a.id, &request_c_id]),
        "gap-free resume: exactly the submitted requests appear"
    );
    assert_eq!(
        seen.iter().filter(|id| **id == request_c_id).count(),
        1,
        "the post-restart request must be indexed exactly once"
    );
    run_handle.abort();
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_solana_stream_backfills_requests_missed_during_downtime() -> Result<()> {
    let solana = solana_sandbox().await?;
    let program_address = solana.program_keypair.pubkey().to_string();
    let config = solana.get_config(program_address);

    let backlog = Backlog::new();
    let (run1, mut sign_rx1) = spawn_supervised_stream(config.clone(), backlog.clone()).await?;

    let payload_a = [0xA1; 32];

    // Snapshot the processed block before submitting request A
    let processed_before = backlog.get_processed_block(Chain::Solana).await;
    solana
        .sign(
            payload_a,
            "downtime-before",
            LATEST_MPC_KEY_VERSION,
            "secp256k1",
            "",
            "",
        )
        .await?;

    // Wait for the first request to appear on the sign channel, and verify its payload
    let request_a = next_sign_command(&mut sign_rx1).await?;
    assert_eq!(
        request_a.args.payload,
        Scalar::from_bytes(payload_a).unwrap()
    );

    // Wait for the processed block to advance past the snapshot,
    // ensuring that the indexer has processed request A
    let deadline = Instant::now() + FINALIZED_EVENT_TIMEOUT;
    loop {
        let processed = backlog.get_processed_block(Chain::Solana).await;
        if processed.is_some_and(|slot| processed_before.is_none_or(|prev| slot > prev)) {
            break;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "processed block never advanced past A"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Kill the first run, simulate downtime, and submit a request while it's down
    run1.abort();
    let _ = run1.await;
    let payload_b = [0xB2; 32];
    solana
        .sign(
            payload_b,
            "downtime-during",
            LATEST_MPC_KEY_VERSION,
            "secp256k1",
            "",
            "",
        )
        .await?;

    // Wait for the Solana chain to produce a new slot after the downtime request
    let slot_after_b = solana.rpc_client.get_slot().await?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while solana.rpc_client.get_slot().await? <= slot_after_b {
        anyhow::ensure!(Instant::now() < deadline, "chain stopped producing slots");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Restart the indexer: same backlog, so catchup resumes from its watermark.
    let (run2, mut sign_rx2) = spawn_supervised_stream(config, backlog.clone()).await?;

    // Submit a request after the restart, which should be processed live.
    let payload_c = [0xC3; 32];
    solana
        .sign(
            payload_c,
            "downtime-after",
            LATEST_MPC_KEY_VERSION,
            "secp256k1",
            "",
            "",
        )
        .await?;

    // Collect all requests from the sign channel until we see the post-restart request
    let mut payloads = Vec::new();
    loop {
        let request = next_sign_command(&mut sign_rx2).await?;
        payloads.push(<[u8; 32]>::from(request.args.payload.to_bytes()));
        if request.args.payload == Scalar::from_bytes(payload_c).unwrap() {
            break;
        }
    }

    // Drain any remaining requests from the sign channel
    let drain_until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < drain_until {
        match timeout(drain_until - Instant::now(), sign_rx2.recv()).await {
            Ok(Some(SignCommand::Request(request))) => {
                payloads.push(<[u8; 32]>::from(request.args.payload.to_bytes()))
            }
            Ok(_) | Err(_) => break,
        }
    }

    assert_eq!(
        payloads.iter().collect::<HashSet<_>>(),
        HashSet::from([&payload_a, &payload_b, &payload_c]),
        "backfill: the pre-downtime, missed-during-downtime and post-restart requests all appear"
    );
    for (payload, label) in [
        (payload_a, "pre-downtime"),
        (payload_b, "backfilled"),
        (payload_c, "post-restart"),
    ] {
        assert_eq!(
            payloads.iter().filter(|p| **p == payload).count(),
            1,
            "{label} request must be indexed exactly once"
        );
    }
    run2.abort();
    Ok(())
}
