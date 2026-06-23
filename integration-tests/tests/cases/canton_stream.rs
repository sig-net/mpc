use anyhow::{Context as _, Result};
use integration_tests::canton::{
    test_evm_type2_anvil_cases, test_sign_request_event, CantonSandbox,
};
use mpc_node::backlog::Backlog;
use mpc_node::indexer_canton::contracts::{CantonSignature, EcdsaSigData};
use mpc_node::indexer_canton::{der_encode_signature, CantonStream};
use mpc_node::mesh::MeshState;
use mpc_node::node_client::NodeClient;
use mpc_node::protocol::{Chain, IndexedSignRequest};
use mpc_node::sign_bidirectional::{hash_rlp_data, SignBidirectionalEventExt};
use mpc_node::stream::{ChainPipeline, ChainStream, ChainStreaming};
use mpc_primitives::{
    ChainEvent, ChainTelemetry, CheckpointDigest, NoopChainTelemetry, ScalarExt, SignKind,
    Signature, StateManager, LATEST_MPC_KEY_VERSION,
};
use serde_json::json;
use serial_test::serial;
use std::collections::HashSet;
use std::time::Duration;
use test_log::test;
use tokio::time::timeout;

/// Create a CantonStream from the sandbox config with an externally-provided Backlog.
/// Accepts Backlog as parameter (needed for checkpoint tests).
async fn stream_canton(
    sandbox: &CantonSandbox,
    backlog: Backlog,
) -> Result<CantonStream<impl StateManager, impl ChainTelemetry>> {
    let config = sandbox.get_config();
    let mut stream = CantonStream::new(Some(config), backlog.clone(), NoopChainTelemetry)
        .context("failed to create CantonStream")?;
    let indexer = ChainStream::start(&mut stream).await?;
    let (_cp_tx, cp_rx) = tokio::sync::watch::channel(CheckpointDigest::default());
    let (_mesh_tx, mesh_rx) = tokio::sync::watch::channel(MeshState::default());
    let node_client = NodeClient::new(&Default::default());
    let (pipeline, mut state_rx) = ChainPipeline::new(
        indexer,
        cp_rx,
        backlog,
        mesh_rx,
        node_client,
        0,
        "test.near".parse().unwrap(),
    );
    tokio::spawn(pipeline.run());

    // Wait until the pipeline is live so the subscription and anchor are established
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
    Ok(stream)
}

/// Poll stream for a SignRequest event with timeout.
async fn wait_for_sign_request(
    stream: &mut CantonStream<impl StateManager, impl ChainTelemetry>,
    timeout_secs: u64,
) -> Result<IndexedSignRequest> {
    timeout(Duration::from_secs(timeout_secs), async {
        loop {
            match stream.next_event().await {
                Some(ChainEvent::SignRequest { request, .. }) => return Ok(request),
                Some(ChainEvent::Block(_)) => continue,
                Some(_) => continue,
                None => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    })
    .await
    .context("timeout waiting for SignRequest")?
}

#[ignore] // requires dpm
#[serial]
#[test(tokio::test)]
async fn test_canton_stream_parse_sign_event() -> Result<()> {
    let sandbox = CantonSandbox::run().await?;
    let backlog = Backlog::new();
    let mut stream = stream_canton(&sandbox, backlog).await?;

    let expected_case = test_evm_type2_anvil_cases()[0].clone();
    let expected_event = test_sign_request_event(&sandbox, &expected_case);
    sandbox.submit_sign_request(None).await?;

    let event = wait_for_sign_request(&mut stream, 30).await?;

    assert_eq!(event.chain, Chain::Canton);
    assert_eq!(event.args.key_version, LATEST_MPC_KEY_VERSION);
    assert_eq!(event.args.path, sandbox.requester_party);
    assert_ne!(
        event.id.request_id, [0u8; 32],
        "request_id should not be zero"
    );

    // Verify bidirectional inner fields survive the indexer pipeline.
    let SignKind::SignBidirectional(ref bidir) = event.kind else {
        panic!("expected SignBidirectional, got {:?}", event.kind);
    };

    let expected_hash = hash_rlp_data(&bidir.serialized_transaction);
    let expected_payload = <k256::Scalar as ScalarExt>::from_bytes(expected_hash)
        .expect("test tx hash must be a valid scalar");
    assert_eq!(
        event.args.payload, expected_payload,
        "payload should match keccak256 of normalized serialized_transaction"
    );
    assert_eq!(bidir.caip2_id, expected_event.caip2_id);
    assert_eq!(bidir.dest, expected_event.dest);
    assert_eq!(bidir.key_version, expected_event.key_version);
    assert_eq!(bidir.path, expected_event.path);
    assert_eq!(
        bidir.output_deserialization_schema,
        expected_event.output_deserialization_schema.as_bytes()
    );
    assert_eq!(
        bidir.respond_serialization_schema,
        expected_event.respond_serialization_schema.as_bytes()
    );
    Ok(())
}

#[ignore]
#[serial]
#[test(tokio::test)]
async fn test_canton_stream_emits_blocks() -> Result<()> {
    let sandbox = CantonSandbox::run().await?;
    let backlog = Backlog::new();
    let mut stream = stream_canton(&sandbox, backlog).await?;

    sandbox.submit_sign_request(None).await?;

    let mut saw_block = false;
    for _ in 0..10 {
        match timeout(Duration::from_secs(5), stream.next_event()).await {
            Ok(Some(ChainEvent::Block(_))) => {
                saw_block = true;
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => {
                anyhow::bail!("stream returned None unexpectedly");
            }
            Err(_) => break, // timeout
        }
    }
    assert!(
        saw_block,
        "expected at least one Block event from Canton stream"
    );
    Ok(())
}

#[ignore]
#[serial]
#[test(tokio::test)]
async fn test_canton_stream_concurrent_events() -> Result<()> {
    let sandbox = CantonSandbox::run().await?;
    let backlog = Backlog::new();
    let mut stream = stream_canton(&sandbox, backlog).await?;

    // Distinct EVM nonces produce distinct request_ids, which is what this
    // test exercises — the Canton stream must deliver each as a separate event.
    for nonce in 0..3 {
        sandbox.submit_sign_request(Some(nonce)).await?;
    }

    // Collect SignRequest events until we have all 3, verifying content on each
    let mut received_ids = HashSet::new();
    for _ in 0..20 {
        match timeout(Duration::from_secs(5), stream.next_event()).await {
            Ok(Some(ChainEvent::SignRequest { request, .. })) => {
                assert_eq!(request.chain, Chain::Canton);
                assert_eq!(request.args.path, sandbox.requester_party);
                received_ids.insert(request.id.request_id);
                if received_ids.len() >= 3 {
                    break;
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("stream closed"),
            Err(_) => break,
        }
    }

    assert_eq!(received_ids.len(), 3, "expected 3 distinct sign requests");
    Ok(())
}

#[ignore]
#[serial]
#[test(tokio::test)]
async fn test_canton_stream_catchup_linear() -> Result<()> {
    let sandbox = CantonSandbox::run().await?;

    // Phase 1: stream1 sees events
    let backlog1 = Backlog::new();
    let mut stream1 = stream_canton(&sandbox, backlog1).await?;

    sandbox.submit_sign_request(None).await?;

    let mut seen_by_stream1 = 0;
    let mut last_block_stream1: u64 = 0;
    for _ in 0..10 {
        match timeout(Duration::from_millis(500), stream1.next_event()).await {
            Ok(Some(ChainEvent::SignRequest { .. })) => seen_by_stream1 += 1,
            Ok(Some(ChainEvent::Block(b))) => {
                if b > last_block_stream1 {
                    last_block_stream1 = b;
                }
            }
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    assert!(seen_by_stream1 > 0, "stream1 saw no events");
    assert!(last_block_stream1 > 0, "stream1 saw no blocks");

    // Drop stream1
    drop(stream1);

    // Phase 2: stream2 should catch up and see new events
    let backlog2 = Backlog::new();
    let mut stream2 = stream_canton(&sandbox, backlog2).await?;

    sandbox.submit_sign_request(None).await?;

    let mut caught_up = false;
    let mut seen_sign_events = false;
    for _ in 0..20 {
        match timeout(Duration::from_secs(1), stream2.next_event()).await {
            Ok(Some(ChainEvent::Block(b))) if b >= last_block_stream1 => caught_up = true,
            Ok(Some(ChainEvent::SignRequest { .. })) => seen_sign_events = true,
            Ok(Some(_)) => {}
            _ => break,
        }
        if caught_up && seen_sign_events {
            break;
        }
    }
    assert!(
        caught_up,
        "stream2 did not catch up to stream1's block height"
    );
    assert!(seen_sign_events, "stream2 saw no SignRequest events");
    Ok(())
}

#[ignore]
#[serial]
#[test(tokio::test)]
async fn test_canton_stream_checkpoint_persistence() -> Result<()> {
    // Use interval=1 so every block produces a checkpoint. Canton generates
    // few blocks (only on ledger activity), so a larger interval risks timing out.
    const INTERVAL: u64 = 1;

    let sandbox = CantonSandbox::run().await?;
    let backlog = Backlog::new();
    let mut stream = stream_canton(&sandbox, backlog.clone()).await?;

    sandbox.submit_sign_request(None).await?;

    // Phase 1: process events, insert sign requests into backlog, wait for a
    // checkpoint that contains a pending request.
    let checkpoint = tokio::time::timeout(Duration::from_secs(30), async {
        let mut saw_sign_request = false;
        loop {
            let Some(event) = stream.next_event().await else {
                break None;
            };
            match event {
                ChainEvent::SignRequest { request, .. } => {
                    saw_sign_request = true;
                    backlog.insert(request).await;
                }
                ChainEvent::Block(height) => {
                    if let Some(persisted_checkpoint) = backlog
                        .set_processed_block_interval(Chain::Canton, height, INTERVAL)
                        .await
                    {
                        if saw_sign_request && !persisted_checkpoint.pending_requests.is_empty() {
                            break Some(persisted_checkpoint);
                        }
                    }
                }
                _ => {}
            }
        }
    })
    .await
    .expect("timed out waiting for checkpoint")
    .expect("stream ended without checkpoint");

    assert_eq!(
        checkpoint.pending_requests.len(),
        1,
        "expected one pending request in checkpoint"
    );
    let checkpoint_height = checkpoint.block_height;
    let phase1_request_id = checkpoint.pending_requests[0].sign_id.request_id;
    drop(stream);

    // Verify the backlog actually persisted the block height
    assert_eq!(
        backlog.get_processed_block(Chain::Canton).await,
        Some(checkpoint_height),
        "backlog should retain checkpoint height after stream1 is dropped"
    );

    // Phase 2: new stream with same backlog should resume from checkpoint.
    // Key invariant: stream2 must start from the checkpointed offset, not
    // replay from 0. Phase 2 uses a distinct EVM nonce so its request_id
    // differs from phase 1, letting us prove no replay occurred. We verify:
    // (a) the first Block event is >= checkpoint_height
    // (b) exactly 1 SignRequest arrives (the new one, not a replay of phase 1)
    let mut stream2 = stream_canton(&sandbox, backlog.clone()).await?;

    sandbox.submit_sign_request(Some(1)).await?;

    let mut sign_request_ids = Vec::new();
    let mut first_block: Option<u64> = None;
    let mut saw_new_checkpoint = false;
    for _ in 0..20 {
        match timeout(Duration::from_secs(5), stream2.next_event()).await {
            Ok(Some(ChainEvent::SignRequest { request, .. })) => {
                sign_request_ids.push(request.id.request_id);
                backlog.insert(request).await;
                if saw_new_checkpoint {
                    break;
                }
            }
            Ok(Some(ChainEvent::Block(height))) => {
                if first_block.is_none() {
                    first_block = Some(height);
                }
                if backlog
                    .set_processed_block_interval(Chain::Canton, height, INTERVAL)
                    .await
                    .is_some()
                {
                    saw_new_checkpoint = true;
                    if !sign_request_ids.is_empty() {
                        break;
                    }
                }
            }
            Ok(Some(_)) => continue,
            _ => break,
        }
    }

    // stream2 must have started at or past the checkpoint, not from 0
    let first_block = first_block.expect("stream2 did not emit any Block events");
    assert!(
        first_block >= checkpoint_height,
        "stream2 started at offset {first_block}, expected >= {checkpoint_height} (checkpoint was not used)"
    );

    // Exactly one sign request: the Phase 2 submission, not a replay of Phase 1
    assert_eq!(
        sign_request_ids.len(),
        1,
        "expected exactly 1 sign request in phase 2, got {} — checkpoint may not have prevented replay",
        sign_request_ids.len()
    );
    assert_ne!(
        sign_request_ids[0], phase1_request_id,
        "stream2 replayed the phase 1 request instead of skipping it"
    );

    assert!(
        saw_new_checkpoint,
        "stream2 did not produce a new checkpoint"
    );
    Ok(())
}

#[ignore]
#[serial]
#[test(tokio::test)]
async fn test_canton_stream_sign_and_respond_flow() -> Result<()> {
    let sandbox = CantonSandbox::run().await?;
    let backlog = Backlog::new();
    let mut stream = stream_canton(&sandbox, backlog).await?;

    sandbox.submit_sign_request(None).await?;
    let sign_event = wait_for_sign_request(&mut stream, 30).await?;
    assert_eq!(sign_event.chain, Chain::Canton);
    let request_id = hex::encode(sign_event.id.request_id);
    let sign_event_cid = match &sign_event.kind {
        SignKind::SignBidirectional(event) if event.chain == Chain::Canton => {
            let chain_ctx_bytes = event
                .chain_ctx
                .as_deref()
                .expect("missing chain_ctx on Canton sign request");
            let ctx: mpc_node::indexer_canton::CantonChainCtx =
                borsh::from_slice(chain_ctx_bytes).expect("failed to deserialize CantonChainCtx");
            ctx.sign_event_contract_id.clone()
        }
        _ => panic!("expected Canton SignBidirectional event"),
    };

    // Build a valid on-curve signature using the secp256k1 generator point,
    // then DER-encode it — this mirrors how the real MPC respond path works.
    let expected_big_r = k256::ProjectivePoint::GENERATOR.to_affine();
    let expected_s = k256::Scalar::from(11u64);
    let expected_recovery_id: u8 = 0;

    let mpc_sig = Signature::new(expected_big_r, expected_s, expected_recovery_id);
    let der_bytes = der_encode_signature(&mpc_sig)?;
    let der_hex = hex::encode(&der_bytes);
    let canton_signature = serde_json::to_value(CantonSignature::EcdsaSig(EcdsaSigData {
        der: der_hex,
        recovery_id: expected_recovery_id,
    }))?;

    sandbox
        .sig_network_runtime_client
        .exercise_choice(
            &[&sandbox.party_id],
            &sandbox.signer_template_id,
            &sandbox.signer_cid,
            "Respond",
            json!({
                "signEventCid": &sign_event_cid,
                "requestId": &request_id,
                "signature": canton_signature,
            }),
            &[],
        )
        .await?;

    let mut saw_respond = false;
    for _ in 0..10 {
        match timeout(Duration::from_secs(5), stream.next_event()).await {
            Ok(Some(ChainEvent::Respond(ev))) => {
                assert_eq!(ev.chain, mpc_primitives::Chain::Canton);
                assert_eq!(hex::encode(ev.request_id), request_id);
                assert_eq!(ev.signature.big_r, expected_big_r);
                assert_eq!(ev.signature.s, expected_s);
                assert_eq!(ev.signature.recovery_id, expected_recovery_id);
                saw_respond = true;
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("stream closed"),
            Err(_) => break,
        }
    }
    assert!(saw_respond, "expected Respond event from Canton stream");
    Ok(())
}

/// Verify bidirectional inner fields are fully parsed from the Canton ledger event.
/// Mirrors Solana's test_solana_stream_parse_sign_bidirectional — Canton always
/// submits SignBidirectional, but we assert the structured inner fields here.
#[ignore] // requires dpm
#[serial]
#[test(tokio::test)]
async fn test_canton_stream_parse_sign_bidirectional_fields() -> Result<()> {
    let sandbox = CantonSandbox::run().await?;
    let backlog = Backlog::new();
    let mut stream = stream_canton(&sandbox, backlog).await?;

    let expected_case = test_evm_type2_anvil_cases()[0].clone();
    let expected_event = test_sign_request_event(&sandbox, &expected_case);
    sandbox.submit_sign_request(None).await?;

    let req = wait_for_sign_request(&mut stream, 30).await?;
    assert_eq!(req.chain, Chain::Canton);

    let SignKind::SignBidirectional(ref bidir) = req.kind else {
        panic!("expected SignBidirectional, got {:?}", req.kind);
    };

    assert_eq!(bidir.caip2_id, expected_event.caip2_id);
    assert_eq!(bidir.dest, expected_event.dest);
    assert_eq!(bidir.path, expected_event.path);
    assert_eq!(bidir.key_version, expected_event.key_version);
    let expected_sender = hex::decode(&expected_event.sender)?;
    assert_eq!(
        bidir.sender,
        <[u8; 32]>::try_from(expected_sender.as_slice())?
    );
    assert_eq!(bidir.chain, Chain::Canton, "expected Canton chain");
    assert_eq!(
        bidir.target_chain()?,
        Chain::Ethereum,
        "caip2_id should parse to Chain::Ethereum"
    );
    assert_eq!(
        bidir.output_deserialization_schema,
        expected_event.output_deserialization_schema.as_bytes()
    );
    assert_eq!(
        bidir.respond_serialization_schema,
        expected_event.respond_serialization_schema.as_bytes()
    );
    assert!(
        !bidir.serialized_transaction.is_empty(),
        "RLP-encoded tx should not be empty"
    );
    Ok(())
}
