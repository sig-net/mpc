//! Midnight stream-tier tests: indexer + ChainPipeline, no MPC cluster.
//!
//! Prereqs (see integration-tests/src/midnight.rs header): docker with the
//! pinned l9 images, a full-ZK compiled signet-signer, and release builds in
//! chain-signatures/midnight-publisher/target/release/. `sign`/`respond`
//! prove in-container; test_midnight_stream_parse_sign_bidirectional proves
//! sign_bidirectional natively (~24 GiB RSS — needs a ≥32 GiB host).
//! Run: cargo test -p integration-tests --test lib -- midnight_stream --ignored --test-threads 1

use anyhow::{Context as _, Result};
use integration_tests::midnight::{
    MidnightBiParams, MidnightSandbox, GOLDEN_COMMITMENT_HEX, GOLDEN_SIGN_PAYLOAD_0,
    GOLDEN_SIGN_PAYLOAD_1, GOLDEN_SIGN_REQUEST_ID_0,
};
use mpc_chain_integration_core::{ChainStream, ChainTelemetry, NoopChainTelemetry, StateManager};
use mpc_chain_midnight::MidnightStream;
use mpc_node::backlog::Backlog;
use mpc_node::mesh::MeshState;
use mpc_node::node_client::NodeClient;
use mpc_node::protocol::{Chain, IndexedSignRequest};
use mpc_node::sign_bidirectional::SignBidirectionalEventExt;
use mpc_node::stream::{ChainPipeline, ChainStreaming};
use mpc_primitives::{ChainEvent, CheckpointDigest, ScalarExt, SignKind, LATEST_MPC_KEY_VERSION};
use serial_test::serial;
use std::time::Duration;
use test_log::test;
use tokio::sync::watch;
use tokio::time::timeout;

async fn stream_midnight(
    sandbox: &MidnightSandbox,
    backlog: Backlog,
) -> Result<(
    MidnightStream<impl StateManager, impl ChainTelemetry>,
    watch::Sender<Option<CheckpointDigest>>,
)> {
    let config = sandbox.get_config();
    let mut stream = MidnightStream::new(config, backlog.clone(), NoopChainTelemetry)
        .context("failed to create MidnightStream")?;
    let indexer = ChainStream::start(&mut stream).await?;
    let (cp_tx, cp_rx) = watch::channel(None);
    let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());
    let node_client = NodeClient::new(&Default::default());
    let (sign_tx, _sign_rx) = tokio::sync::mpsc::channel(1);
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

    timeout(Duration::from_secs(60), async {
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
    .context("timed out waiting for pipeline Live state")??;
    Ok((stream, cp_tx))
}

async fn wait_for_sign_request(
    stream: &mut MidnightStream<impl StateManager, impl ChainTelemetry>,
    timeout_secs: u64,
) -> Result<IndexedSignRequest> {
    timeout(Duration::from_secs(timeout_secs), async {
        loop {
            match stream.next_event().await {
                Some(ChainEvent::SignRequest { request, .. }) => return Ok(request),
                Some(_) => continue,
                None => anyhow::bail!("stream closed"),
            }
        }
    })
    .await
    .context("timeout waiting for SignRequest")?
}

#[ignore] // requires docker + l9 stack prereqs
#[serial]
#[test(tokio::test)]
async fn test_midnight_stream_parse_sign_event() -> Result<()> {
    let sandbox = MidnightSandbox::run_standalone().await?;
    let backlog = Backlog::new();
    let (mut stream, _cp_tx) = stream_midnight(&sandbox, backlog).await?;

    // Fresh chain → signetNonce 0 → the golden sign case reproduces exactly.
    sandbox.submit_sign(GOLDEN_SIGN_PAYLOAD_0, 1).await?;
    let request = wait_for_sign_request(&mut stream, 120).await?;

    assert_eq!(request.chain, Chain::Midnight);
    assert_eq!(request.kind, SignKind::Sign);
    assert_eq!(hex::encode(request.id.request_id), GOLDEN_SIGN_REQUEST_ID_0);
    assert_eq!(request.args.path, GOLDEN_COMMITMENT_HEX);
    assert_eq!(request.args.key_version, LATEST_MPC_KEY_VERSION);
    // entropy = keccak256(rid); payload = the submitted scalar.
    let rid = request.id.request_id;
    assert_eq!(request.args.entropy, alloy::primitives::keccak256(rid).0);
    let expected_payload = <k256::Scalar as ScalarExt>::from_bytes(
        integration_tests::utils::hex32(GOLDEN_SIGN_PAYLOAD_0),
    )
    .unwrap();
    assert_eq!(request.args.payload, expected_payload);
    // epsilon binds this deployment's contract address.
    let expected_epsilon = mpc_crypto::kdf::derive_epsilon_midnight(
        LATEST_MPC_KEY_VERSION,
        &sandbox.contract_address,
        GOLDEN_COMMITMENT_HEX,
    );
    assert_eq!(request.args.epsilon, expected_epsilon);
    Ok(())
}

#[ignore] // requires ≥32 GiB host (native sign_bidirectional prove)
#[serial]
#[test(tokio::test)]
async fn test_midnight_stream_parse_sign_bidirectional() -> Result<()> {
    let sandbox = MidnightSandbox::run_standalone().await?;
    let backlog = Backlog::new();
    let (mut stream, _cp_tx) = stream_midnight(&sandbox, backlog).await?;

    let params = MidnightBiParams {
        evm_to: "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".into(),
        evm_chain_id: 31_337,
        evm_nonce: 0,
        evm_gas_limit: 100_000,
        evm_max_fee: 100_000_000_000,
        evm_priority_fee: 1_000_000_000,
        evm_value: 0,
        func_sig: "transfer(address,uint256)".into(),
        args: vec![
            format!("{:0>64}", "2222222222222222222222222222222222222222"),
            format!("{:0>64x}", 0x16e360u64),
        ],
        arg_count: 2,
        caip2: Chain::Ethereum.caip2_chain_id().into(),
        key_version: 1,
        dest: "ethereum".into(),
        params: String::new(),
        output_schema: r#"["bool"]"#.into(),
        respond_schema: r#"["bool"]"#.into(),
    };
    sandbox.submit_sign_bidirectional(&params).await?;

    let request = wait_for_sign_request(&mut stream, 600).await?;
    assert_eq!(request.chain, Chain::Midnight);
    let SignKind::SignBidirectional(ref bidir) = request.kind else {
        panic!("expected SignBidirectional, got {:?}", request.kind);
    };
    assert_eq!(bidir.caip2_id, Chain::Ethereum.caip2_chain_id());
    assert_eq!(bidir.target_chain()?, Chain::Ethereum);
    assert_eq!(bidir.chain, Chain::Midnight);
    assert_eq!(bidir.deposit, 1);
    assert_eq!(bidir.path, GOLDEN_COMMITMENT_HEX);
    assert_eq!(hex::encode(bidir.sender), sandbox.contract_address);
    assert_eq!(bidir.dest, "ethereum");
    assert_eq!(bidir.output_deserialization_schema, br#"["bool"]"#.to_vec());
    assert_eq!(bidir.respond_serialization_schema, br#"["bool"]"#.to_vec());
    assert!(!bidir.serialized_transaction.is_empty());
    assert!(bidir.chain_ctx.is_none());
    let expected_payload = <k256::Scalar as ScalarExt>::from_bytes(
        alloy::primitives::keccak256(&bidir.serialized_transaction).0,
    )
    .unwrap();
    assert_eq!(request.args.payload, expected_payload);
    Ok(())
}

#[ignore]
#[serial]
#[test(tokio::test)]
async fn test_midnight_stream_blocks_and_checkpoint_resume() -> Result<()> {
    // Event ids are sparse: interval 1 so every boundary checkpoints.
    const INTERVAL: u64 = 1;
    let sandbox = MidnightSandbox::run_standalone().await?;
    let backlog = Backlog::new();
    let (mut stream, _cp_tx) = stream_midnight(&sandbox, backlog.clone()).await?;

    sandbox.submit_sign(GOLDEN_SIGN_PAYLOAD_0, 1).await?;

    // Phase 1: request lands in the backlog, then a Block boundary checkpoints it.
    let checkpoint = timeout(Duration::from_secs(120), async {
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
                    if let Some(cp) = backlog
                        .set_processed_block_interval(Chain::Midnight, height, INTERVAL)
                        .await
                    {
                        if saw_sign_request && !cp.pending_requests.is_empty() {
                            break Some(cp);
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

    let phase1_rid = checkpoint.pending_requests[0].sign_id.request_id;
    let checkpoint_height = checkpoint.block_height;
    drop(stream);
    assert_eq!(
        backlog.get_processed_block(Chain::Midnight).await,
        Some(checkpoint_height)
    );

    // Phase 2: same backlog, new stream — must resume, not replay phase 1.
    let (mut stream2, _cp_tx2) = stream_midnight(&sandbox, backlog.clone()).await?;
    sandbox.submit_sign(GOLDEN_SIGN_PAYLOAD_1, 1).await?;

    let mut rids = Vec::new();
    for _ in 0..40 {
        match timeout(Duration::from_secs(10), stream2.next_event()).await {
            Ok(Some(ChainEvent::SignRequest { request, .. })) => {
                rids.push(request.id.request_id);
                break;
            }
            Ok(Some(_)) => continue,
            _ => break,
        }
    }
    assert_eq!(rids.len(), 1, "expected exactly the phase-2 request");
    assert_ne!(
        rids[0], phase1_rid,
        "phase-1 request replayed past its checkpoint"
    );
    Ok(())
}

#[ignore]
#[serial]
#[test(tokio::test)]
async fn test_midnight_stream_sign_and_respond_flow() -> Result<()> {
    let sandbox = MidnightSandbox::run_standalone().await?;
    let backlog = Backlog::new();
    let (mut stream, _cp_tx) = stream_midnight(&sandbox, backlog).await?;

    sandbox.submit_sign(GOLDEN_SIGN_PAYLOAD_0, 1).await?;
    let request = wait_for_sign_request(&mut stream, 120).await?;
    let rid_hex = hex::encode(request.id.request_id);
    assert_eq!(rid_hex, GOLDEN_SIGN_REQUEST_ID_0);

    // Manual respond with an on-curve signature (generator point, s = 9) —
    // exactly the golden respond inputs, which answer this very request.
    let expected_big_r = k256::ProjectivePoint::GENERATOR.to_affine();
    sandbox
        .submit_respond(
            &rid_hex,
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            &format!("{:0>64x}", 9u64),
            0,
        )
        .await?;

    let saw = timeout(Duration::from_secs(300), async {
        loop {
            match stream.next_event().await {
                Some(ChainEvent::Respond(ev)) => return Some(ev),
                Some(_) => continue,
                None => return None,
            }
        }
    })
    .await
    .context("timeout waiting for Respond event")?
    .context("stream closed")?;

    assert_eq!(saw.chain, mpc_primitives::Chain::Midnight);
    assert_eq!(hex::encode(saw.request_id), rid_hex);
    assert_eq!(saw.signature.big_r, expected_big_r);
    assert_eq!(saw.signature.s, k256::Scalar::from(9u64));
    assert_eq!(saw.signature.recovery_id, 0);
    Ok(())
}
