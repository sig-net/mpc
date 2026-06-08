use alloy::network::{Ethereum, TransactionBuilder};
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::request::TransactionRequest;
use anyhow::{Context, Result};
use cait_sith::protocol::Participant;
use integration_tests::cluster::spawner::ClusterSpawner;
use integration_tests::containers::EthereumSandbox;
use integration_tests::eth::{self, ChainSignatures, SignRequest};
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use k256::{AffinePoint, Scalar};
use mpc_node::backlog::Backlog;
use mpc_node::indexer_eth::{EthConfig, EthereumStream};
use mpc_node::mesh::{connection::NodeStatus, MeshState};
use mpc_node::node_client::NodeClient;
use mpc_node::protocol::{Chain, IndexedSignRequest, ParticipantInfo, Sign, SignKind};
use mpc_node::rpc::{ContractStateWatcher, RpcChannel};
use mpc_node::sign_bidirectional::{PublishState, SignStatus};
use mpc_node::storage::checkpoint_storage::CheckpointStorage;
use mpc_node::stream::ops::SignBidirectionalEvent as NodeSignBidirectionalEvent;
use mpc_node::stream::ops::SignatureRespondedEvent;
use mpc_node::stream::{catchup_then_livestream, run_stream, ChainEvent, ChainStream};
use mpc_node::util::current_unix_timestamp;
use mpc_primitives::{SignArgs, SignId, LATEST_MPC_KEY_VERSION};
use near_primitives::types::AccountId;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

fn signature_deposit() -> U256 {
    U256::from(1u64)
}

fn test_rpc_channel(buffer: usize) -> (RpcChannel, mpsc::Receiver<mpc_node::rpc::RpcAction>) {
    let (tx, rx) = mpsc::channel(buffer);
    (RpcChannel { tx }, rx)
}

// Integration tests for EthereumStream
//
// These tests spin up Anvil, deploy the ChainSignatures contract, and exercise the
// Ethereum indexer stream in isolation (no MPC cluster required).

struct EthereumTestEnvironment {
    _spawner: ClusterSpawner,
    sandbox: EthereumSandbox,
    signer: eth::SandboxMiddleware,
    wallet: Address,
    contract_address: Address,
    _block_pumper: tokio::task::JoinHandle<()>,
}

fn random_secret_key() -> String {
    loop {
        let secret_key = format!("0x{}", hex::encode(rand::random::<[u8; 32]>()));
        if eth::client("http://127.0.0.1:8545", &secret_key, 31337).is_ok() {
            return secret_key;
        }
    }
}

fn transfer_tx(to: Address, value: U256) -> TransactionRequest {
    <TransactionRequest as TransactionBuilder<Ethereum>>::with_value(
        <TransactionRequest as TransactionBuilder<Ethereum>>::with_to(
            TransactionRequest::default(),
            to,
        ),
        value,
    )
}

impl EthereumTestEnvironment {
    async fn new() -> Result<Self> {
        let spawner = ClusterSpawner::default()
            .network("eth-client-tests")
            .init_network()
            .await?;
        let sandbox = EthereumSandbox::run(&spawner).await?;

        let (signer, wallet) = eth::client(
            &sandbox.external_http_endpoint,
            &sandbox.secret_key,
            sandbox.chain_id,
        )?;

        // Spawn a background task to continuously produce blocks on Anvil.
        //
        // Important: this must NOT call our ChainSignatures contract, and it must
        // avoid nonce contention with the main `signer` used by tests.
        //
        // We therefore:
        // 1) Generate a fresh, independent funded account.
        // 2) Fund it once from the sandbox deployer wallet.
        // 3) Use it to send a simple empty ETH transfer once per second.
        let pumper_secret_key = random_secret_key();
        let (pumper_client, pumper_address) = eth::client(
            &sandbox.external_http_endpoint,
            &pumper_secret_key,
            sandbox.chain_id,
        )?;

        // Fund the pumper account with a small amount of ETH for gas.
        // (0.001 ETH is plenty for these tests.)
        let fund_tx = transfer_tx(pumper_address, U256::from(1_000_000_000_000_000u64));
        let pending_fund = signer.send_transaction(fund_tx).await?;
        let _ = pending_fund
            .get_receipt()
            .await
            .context("failed to mine block pumper funding transaction")?;

        let block_pumper = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                interval.tick().await;
                let tx = transfer_tx(wallet, U256::ZERO);

                match pumper_client.send_transaction(tx).await {
                    Ok(pending) => {
                        // Await mining so each tick reliably corresponds to a mined block.
                        // If it takes too long, just continue; the next iteration will try again.
                        let _ = tokio::time::timeout(Duration::from_secs(5), pending.get_receipt())
                            .await;
                    }
                    Err(err) => {
                        tracing::debug!(?err, "block pumper failed to send tx");
                        // Brief backoff in case the node is restarting.
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                }
            }
        });

        let contract_address =
            eth::deploy_chain_signatures(signer.clone(), wallet, wallet, signature_deposit())
                .await?;

        Ok(Self {
            _spawner: spawner,
            sandbox,
            signer,
            wallet,
            contract_address,
            _block_pumper: block_pumper,
        })
    }

    fn config(&self, optimistic_requests: bool) -> EthConfig {
        EthConfig {
            account_sk: self.sandbox.secret_key.clone(),
            consensus_rpc_http_url: self.sandbox.external_http_endpoint.clone(),
            execution_rpc_http_url: self.sandbox.external_http_endpoint.clone(),
            contract_address: format!("{:x}", self.contract_address),
            network: "sepolia".to_string(),
            helios_data_path: "/tmp/helios".to_string(),
            refresh_finalized_interval: 500,
            optimistic_requests,
            light_client: false,
        }
    }

    fn backlog(&self) -> Backlog {
        Backlog::new()
    }

    fn contract(&self) -> ChainSignatures::ChainSignaturesInstance<eth::SandboxMiddleware> {
        ChainSignatures::new(self.contract_address, self.signer.clone())
    }
}

async fn submit_sign_request(
    ctx: &EthereumTestEnvironment,
    payload: [u8; 32],
    path: &str,
) -> Result<B256> {
    let contract = ctx.contract();
    let sign_request = SignRequest {
        payload: payload.into(),
        path: path.to_string(),
        keyVersion: LATEST_MPC_KEY_VERSION,
        algo: "secp256k1".to_string(),
        dest: "".to_string(),
        params: "".to_string(),
    };

    let call = contract.sign(sign_request).value(signature_deposit());
    let pending_tx = call.send().await?;
    let receipt = pending_tx
        .get_receipt()
        .await
        .context("failed to mine sign transaction")?;
    Ok(receipt.transaction_hash)
}

async fn submit_sign_request_with_block(
    ctx: &EthereumTestEnvironment,
    payload: [u8; 32],
    path: &str,
) -> Result<(B256, u64)> {
    let contract = ctx.contract();
    let sign_request = SignRequest {
        payload: payload.into(),
        path: path.to_string(),
        keyVersion: LATEST_MPC_KEY_VERSION,
        algo: "secp256k1".to_string(),
        dest: "".to_string(),
        params: "".to_string(),
    };

    let call = contract.sign(sign_request).value(signature_deposit());
    let pending_tx = call.send().await?;
    let receipt = pending_tx
        .get_receipt()
        .await
        .context("failed to mine sign transaction")?;

    Ok((
        receipt.transaction_hash,
        receipt
            .block_number
            .context("sign transaction missing block number")?,
    ))
}

async fn submit_eth_transfer(ctx: &EthereumTestEnvironment) -> Result<B256> {
    let pending_tx = ctx
        .signer
        .send_transaction(transfer_tx(ctx.wallet, U256::ZERO))
        .await?;
    let receipt = pending_tx
        .get_receipt()
        .await
        .context("failed to mine eth transfer transaction")?;
    Ok(receipt.transaction_hash)
}

async fn submit_eth_transfer_with_block(ctx: &EthereumTestEnvironment) -> Result<(B256, u64)> {
    let pending_tx = ctx
        .signer
        .send_transaction(transfer_tx(ctx.wallet, U256::ZERO))
        .await?;
    let receipt = pending_tx
        .get_receipt()
        .await
        .context("failed to mine eth transfer transaction")?;

    Ok((
        receipt.transaction_hash,
        receipt
            .block_number
            .context("eth transfer transaction missing block number")?,
    ))
}

async fn submit_respond_for_request_id<P>(
    contract: ChainSignatures::ChainSignaturesInstance<P>,
    request_id: [u8; 32],
    signature: mpc_primitives::Signature,
) -> Result<B256>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    let enc = signature.big_r.to_encoded_point(false);
    let x = enc.x().expect("big_r must have x coordinate");
    let y = enc.y().expect("big_r must have y coordinate");
    let s = U256::from_be_bytes(signature.s.to_bytes().into());

    let response = ChainSignatures::Response {
        requestId: request_id.into(),
        signature: ChainSignatures::Signature {
            bigR: ChainSignatures::AffinePoint {
                x: U256::from_be_slice(x),
                y: U256::from_be_slice(y),
            },
            s,
            recoveryId: signature.recovery_id,
        },
    };

    let respond_call = contract.respond(vec![response]);
    let pending_tx = respond_call.send().await?;
    let receipt = pending_tx
        .get_receipt()
        .await
        .context("respond transaction execution failed")?;
    Ok(receipt.transaction_hash)
}

async fn next_sign_message_within(
    rx: &mut mpsc::Receiver<Sign>,
    duration: Duration,
) -> Result<Sign> {
    timeout(duration, rx.recv())
        .await
        .context("timed out waiting for sign message")?
        .context("sign channel closed unexpectedly")
}

fn test_sign_args(seed: u8) -> SignArgs {
    SignArgs {
        entropy: [seed; 32],
        epsilon: k256::Scalar::from(1u64),
        payload: k256::Scalar::from((seed as u64) + 1),
        path: format!("test-path-{seed}"),
        key_version: LATEST_MPC_KEY_VERSION,
    }
}

use mpc_node::kdf::valid_signature;

fn test_bidirectional_event() -> NodeSignBidirectionalEvent {
    let mut rlp_s = rlp::RlpStream::new_list(9);
    rlp_s.append(&0u64);
    rlp_s.append(&0u64);
    rlp_s.append(&0u64);
    rlp_s.append(&Vec::<u8>::new());
    rlp_s.append(&0u64);
    rlp_s.append(&Vec::<u8>::new());
    rlp_s.append(&1u64);
    rlp_s.append(&0u64);
    rlp_s.append(&0u64);

    NodeSignBidirectionalEvent::Solana(signet_program::SignBidirectionalEvent {
        sender: solana_sdk::pubkey::Pubkey::new_unique(),
        serialized_transaction: rlp_s.out().to_vec(),
        dest: Chain::Ethereum.to_string(),
        caip2_id: "eip155:31337".to_string(),
        key_version: LATEST_MPC_KEY_VERSION,
        deposit: 1,
        path: "bidirectional-test-path".to_string(),
        algo: "secp256k1".to_string(),
        params: "{}".to_string(),
        program_id: solana_sdk::pubkey::Pubkey::new_unique(),
        output_deserialization_schema: vec![],
        respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
    })
}

struct StartedEthereumStream {
    stream: EthereumStream,
    _indexer_task: tokio::task::JoinHandle<()>,
}

impl std::ops::Deref for StartedEthereumStream {
    type Target = EthereumStream;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl std::ops::DerefMut for StartedEthereumStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

async fn next_event_within(
    client: &mut StartedEthereumStream,
    duration: Duration,
) -> Result<ChainEvent> {
    timeout(duration, async {
        loop {
            if let Some(event) = client.next_event().await {
                return event;
            }
        }
    })
    .await
    .context("timed out waiting for chain event")
}

/// Helper for starting the ethereum stream, especially in cases where we do not want
/// to call into run_stream where we want to directly call `next_event` on each test.
async fn stream_ethereum(
    ctx: &EthereumTestEnvironment,
    backlog: Backlog,
) -> Result<StartedEthereumStream> {
    let mut stream = EthereumStream::new(Some(ctx.config(true)), backlog).await?;
    let indexer = stream.start().await?;
    let indexer_task = tokio::spawn(catchup_then_livestream(indexer));

    Ok(StartedEthereumStream {
        stream,
        _indexer_task: indexer_task,
    })
}

#[test_log::test(tokio::test)]
async fn test_ethereum_stream_resume_starts_after_checkpoint_height() -> Result<()> {
    let ctx = EthereumTestEnvironment::new().await?;
    let storage = CheckpointStorage::in_memory();
    let seeded_backlog = Backlog::persisted(storage.clone());

    let replayed_payload = [0x31; 32];
    let (_, processed_height) =
        submit_sign_request_with_block(&ctx, replayed_payload, "resume-processed-path").await?;

    seeded_backlog
        .set_processed_block(Chain::Ethereum, processed_height)
        .await;
    seeded_backlog.checkpoint(Chain::Ethereum).await;

    let mut expected_payload = [0x32; 32];
    loop {
        let (_, block_height) =
            submit_sign_request_with_block(&ctx, expected_payload, "resume-new-path").await?;
        if block_height > processed_height {
            break;
        }

        expected_payload[0] = expected_payload[0].saturating_add(1);
    }

    let backlog = Backlog::persisted(storage);
    let stream = EthereumStream::new(Some(ctx.config(true)), backlog.clone()).await?;
    let (sign_tx, mut sign_rx) = mpsc::channel(16);
    let (contract_watcher, _contract_tx) = ContractStateWatcher::with_running(
        &"test.near".parse::<AccountId>().unwrap(),
        k256::ProjectivePoint::GENERATOR.to_affine(),
        1,
        Default::default(),
    );

    let mut mesh_state = MeshState::default();
    let mut info = ParticipantInfo::new(0);
    info.url = "http://127.0.0.1:1".to_string();
    mesh_state.update(Participant::from(0u32), NodeStatus::Active, info);
    let (_mesh_tx, mesh_rx) = watch::channel(mesh_state);
    let (rpc, _rpc_rx) = test_rpc_channel(16);

    let run_handle = tokio::spawn(run_stream(
        stream,
        sign_tx,
        rpc,
        backlog,
        contract_watcher,
        mesh_rx,
        NodeClient::new(&Default::default()),
    ));

    let mut saw_replayed_payload = false;
    let mut saw_expected_payload = false;
    for _ in 0..12 {
        match next_sign_message_within(&mut sign_rx, Duration::from_secs(10)).await? {
            Sign::Request(req) => {
                let payload: [u8; 32] = req.args.payload.to_bytes().into();
                if payload == replayed_payload {
                    saw_replayed_payload = true;
                }
                if payload == expected_payload {
                    saw_expected_payload = true;
                    break;
                }
            }
            _ => continue,
        }
    }

    run_handle.abort();

    assert!(
        !saw_replayed_payload,
        "stream replayed the stored processed block"
    );
    assert!(
        saw_expected_payload,
        "stream did not catch up the next block"
    );
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_ethereum_stream_linear_catchup_from_checkpoint() -> Result<()> {
    let ctx = EthereumTestEnvironment::new().await?;

    let responder_secret_key = random_secret_key();
    let (responder_signer, responder_address) = eth::client(
        &ctx.sandbox.external_http_endpoint,
        &responder_secret_key,
        ctx.sandbox.chain_id,
    )?;
    let fund_tx = transfer_tx(responder_address, U256::from(1_000_000_000_000_000u64));
    let pending_fund = ctx.signer.send_transaction(fund_tx).await?;
    let _ = pending_fund
        .get_receipt()
        .await
        .context("failed to mine responder funding transaction")?;

    let checkpoint_height = ctx.signer.get_block_number().await?;
    let checkpoint_nonce = ctx.signer.get_transaction_count(ctx.wallet).await?;

    let storage = CheckpointStorage::in_memory();
    let seeded_backlog = Backlog::persisted(storage.clone());

    let resolved_sign_id = SignId::new([0x11; 32]);
    let requeued_sign_id = SignId::new([0x22; 32]);
    seeded_backlog
        .insert(mpc_node::protocol::IndexedSignRequest::sign(
            resolved_sign_id,
            test_sign_args(0x11),
            Chain::Ethereum,
            current_unix_timestamp(),
        ))
        .await;
    seeded_backlog
        .insert(mpc_node::protocol::IndexedSignRequest::sign(
            requeued_sign_id,
            test_sign_args(0x22),
            Chain::Ethereum,
            current_unix_timestamp(),
        ))
        .await;
    seeded_backlog
        .set_processed_block(Chain::Ethereum, checkpoint_height)
        .await;
    seeded_backlog.checkpoint(Chain::Ethereum).await;

    let backlog = Backlog::persisted(storage.clone());

    let execution_sign_id = SignId::new([0x33; 32]);
    backlog
        .insert(mpc_node::protocol::IndexedSignRequest::sign_bidirectional(
            execution_sign_id,
            test_sign_args(0x33),
            Chain::Solana,
            current_unix_timestamp(),
            test_bidirectional_event(),
        ))
        .await;

    let execution_tx = mpc_node::sign_bidirectional::BidirectionalTx {
        id: mpc_node::sign_bidirectional::BidirectionalTxId(B256::from([0x44; 32])),
        sender: [0u8; 32],
        serialized_transaction: vec![],
        source_chain: Chain::Solana,
        target_chain: Chain::Ethereum,
        caip2_id: "eip155:31337".to_string(),
        key_version: LATEST_MPC_KEY_VERSION,
        deposit: 1,
        path: "bidirectional-test-path".to_string(),
        algo: "secp256k1".to_string(),
        dest: Chain::Ethereum.to_string(),
        params: "{}".to_string(),
        output_deserialization_schema: vec![],
        respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
        request_id: execution_sign_id.request_id,
        from_address: ctx.wallet,
        nonce: checkpoint_nonce,
    };
    backlog
        .set_status(
            execution_tx.source_chain,
            &execution_sign_id,
            SignStatus::PendingPublish {
                publish: PublishState {
                    signature: mpc_primitives::Signature::new(
                        AffinePoint::GENERATOR,
                        Scalar::ONE,
                        0,
                    ),
                    participants: vec![Participant::from(0u32), Participant::from(1u32)],
                    is_proposer: true,
                },
            },
        )
        .await;
    backlog
        .advance(Chain::Solana, execution_sign_id, execution_tx)
        .await
        .context("failed to seed execution watcher")?;

    let responder_contract = ChainSignatures::new(ctx.contract_address, responder_signer.clone());

    let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
    let root_pk = root_sk.public_key().to_projective().to_affine();

    let resolved_args = test_sign_args(0x11);
    let resolved_sig = valid_signature(&root_sk, &resolved_args);

    submit_respond_for_request_id(
        responder_contract,
        resolved_sign_id.request_id,
        resolved_sig,
    )
    .await?;
    submit_eth_transfer(&ctx).await?;
    let catchup_payload = [0x55; 32];
    submit_sign_request(&ctx, catchup_payload, "catchup-linear-path").await?;

    let stream = EthereumStream::new(Some(ctx.config(true)), backlog.clone()).await?;
    let (sign_tx, mut sign_rx) = mpsc::channel(16);
    let (contract_watcher, _contract_tx) = ContractStateWatcher::with_running(
        &"test.near".parse::<AccountId>().unwrap(),
        root_pk,
        1,
        Default::default(),
    );

    let mut mesh_state = MeshState::default();
    let mut info = ParticipantInfo::new(0);
    info.url = "http://127.0.0.1:1".to_string();
    mesh_state.update(Participant::from(0u32), NodeStatus::Active, info);
    let (_mesh_tx, mesh_rx) = watch::channel(mesh_state);
    let (rpc, _rpc_rx) = test_rpc_channel(16);

    let run_handle = tokio::spawn(run_stream(
        stream,
        sign_tx,
        rpc,
        backlog.clone(),
        contract_watcher,
        mesh_rx,
        NodeClient::new(&Default::default()),
    ));

    let mut saw_execution_follow_up = false;
    let mut saw_catchup_request = false;
    let mut saw_requeued_request = false;

    for _ in 0..8 {
        match next_sign_message_within(&mut sign_rx, Duration::from_secs(20)).await? {
            Sign::Completion(sign_id) => {
                assert_ne!(
                    sign_id, resolved_sign_id,
                    "pre-catchup resolved request should not emit a completion"
                );
            }
            Sign::Request(req) if req.id == execution_sign_id => {
                assert!(matches!(req.kind, SignKind::RespondBidirectional(_)));
                assert_eq!(req.chain, Chain::Solana);
                saw_execution_follow_up = true;
            }
            Sign::Request(req) if req.id == requeued_sign_id => {
                saw_requeued_request = true;
            }
            Sign::Request(req) if req.chain == Chain::Ethereum => {
                assert_eq!(req.args.payload.to_bytes(), catchup_payload.into());
                saw_catchup_request = true;
            }
            _ => {}
        }

        if saw_execution_follow_up && saw_catchup_request && saw_requeued_request {
            break;
        }
    }

    assert!(
        saw_execution_follow_up,
        "expected execution follow-up request after catchup"
    );
    assert!(
        saw_catchup_request,
        "expected caught-up ethereum sign request to be emitted"
    );
    assert!(
        saw_requeued_request,
        "expected surviving recovered request to be requeued after catchup"
    );

    run_handle.abort();
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_ethereum_stream_parse_sign_event() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    let ctx = EthereumTestEnvironment::new().await?;
    let backlog = ctx.backlog();
    let mut stream = stream_ethereum(&ctx, backlog).await?;

    let payload = k256::Scalar::from(1u64).to_bytes().into();
    let path = "m/44'/60'/0'/0/0";
    submit_sign_request(&ctx, payload, path).await?;

    let req = loop {
        match next_event_within(&mut stream, Duration::from_secs(10)).await? {
            ChainEvent::SignRequest(req) => break req,
            _ => continue,
        }
    };

    assert_eq!(req.chain, Chain::Ethereum);
    assert_eq!(req.args.path, path);
    assert_eq!(req.args.payload.to_bytes(), payload.into());
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_ethereum_stream_emits_blocks() -> Result<()> {
    let ctx = EthereumTestEnvironment::new().await?;
    let backlog = ctx.backlog();
    let mut stream = stream_ethereum(&ctx, backlog).await?;

    submit_sign_request(&ctx, [2u8; 32], "test-path").await?;

    let mut saw_block = false;
    for _ in 0..5 {
        match next_event_within(&mut stream, Duration::from_secs(10)).await? {
            ChainEvent::Block(_) => {
                saw_block = true;
                break;
            }
            _ => continue,
        }
    }

    assert!(saw_block, "expected block event");
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_ethereum_stream_execution_confirmation() -> Result<()> {
    let ctx = EthereumTestEnvironment::new().await?;
    let backlog = ctx.backlog();

    // Register an execution watcher with an intentionally stale nonce to trigger the staleness path.
    let tx = mpc_node::sign_bidirectional::BidirectionalTx {
        id: mpc_node::sign_bidirectional::BidirectionalTxId(B256::from([9u8; 32])),
        sender: [0u8; 32],
        serialized_transaction: vec![],
        source_chain: Chain::Solana,
        target_chain: Chain::Ethereum,
        caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
        key_version: LATEST_MPC_KEY_VERSION,
        deposit: 0,
        path: "m/44'/60'/0'/0/0".to_string(),
        algo: "secp256k1".to_string(),
        dest: "".to_string(),
        params: "".to_string(),
        output_deserialization_schema: vec![],
        respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
        request_id: [7u8; 32],
        from_address: ctx.wallet,
        nonce: 0,
    };
    let sign_id = SignId::new([7u8; 32]);
    backlog.watch_execution(Chain::Ethereum, sign_id, tx).await;

    let mut stream = stream_ethereum(&ctx, backlog.clone()).await?;

    // Send a transaction from the watched address to bump nonce and trigger the staleness check.
    submit_sign_request(&ctx, [4u8; 32], "execution-path").await?;

    let mut saw_execution = false;
    for _ in 0..8 {
        match next_event_within(&mut stream, Duration::from_secs(10)).await? {
            ChainEvent::ExecutionConfirmed { sign_id: ev_id, .. } if ev_id == sign_id => {
                saw_execution = true;
                break;
            }
            _ => continue,
        }
    }

    assert!(saw_execution, "did not observe ExecutionConfirmed event");
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_ethereum_stream_backfills_late_execution_watcher_after_catchup() -> Result<()> {
    let ctx = EthereumTestEnvironment::new().await?;
    let backlog = ctx.backlog();

    let dummy_sign_id = SignId::new([0x66; 32]);
    backlog
        .insert(IndexedSignRequest::sign(
            dummy_sign_id,
            test_sign_args(0x66),
            Chain::Ethereum,
            current_unix_timestamp(),
        ))
        .await;

    let stream = EthereumStream::new(Some(ctx.config(true)), backlog.clone()).await?;
    let (sign_tx, mut sign_rx) = mpsc::channel(16);
    let (contract_watcher, _contract_tx) = ContractStateWatcher::with_running(
        &"test.near".parse::<AccountId>().unwrap(),
        k256::ProjectivePoint::GENERATOR.to_affine(),
        1,
        Default::default(),
    );

    let mut mesh_state = MeshState::default();
    let mut info = ParticipantInfo::new(0);
    info.url = "http://127.0.0.1:1".to_string();
    mesh_state.update(Participant::from(0u32), NodeStatus::Active, info);
    let (_mesh_tx, mesh_rx) = watch::channel(mesh_state);
    let (rpc, _rpc_rx) = test_rpc_channel(16);

    let run_handle = tokio::spawn(run_stream(
        stream,
        sign_tx,
        rpc,
        backlog.clone(),
        contract_watcher,
        mesh_rx,
        NodeClient::new(&Default::default()),
    ));

    let mut saw_catchup_flush = false;
    for _ in 0..20 {
        match next_sign_message_within(&mut sign_rx, Duration::from_secs(10)).await? {
            Sign::Request(req) if req.id == dummy_sign_id => {
                saw_catchup_flush = true;
                break;
            }
            _ => continue,
        }
    }
    assert!(
        saw_catchup_flush,
        "ethereum stream did not flush the pre-seeded request after catchup"
    );

    let (tx_hash, tx_block) = submit_eth_transfer_with_block(&ctx).await?;

    timeout(Duration::from_secs(20), async {
        loop {
            let processed_block = backlog.processed_block(Chain::Ethereum).await.unwrap_or(0);
            if processed_block >= tx_block {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("ethereum stream did not advance past the mined execution block")?;

    // Register the execution watcher only after catchup has completed and the
    // transaction is already in the past relative to the stream.
    let sign_id = SignId::new([0x88; 32]);
    let tx_id = mpc_node::sign_bidirectional::BidirectionalTxId(tx_hash);
    let tx = mpc_node::sign_bidirectional::BidirectionalTx {
        id: tx_id,
        sender: [0u8; 32],
        serialized_transaction: vec![],
        source_chain: Chain::Solana,
        target_chain: Chain::Ethereum,
        caip2_id: "eip155:31337".to_string(),
        key_version: LATEST_MPC_KEY_VERSION,
        deposit: 0,
        path: "m/44'/60'/0'/0/1".to_string(),
        algo: "secp256k1".to_string(),
        dest: Chain::Ethereum.to_string(),
        params: "{}".to_string(),
        output_deserialization_schema: vec![],
        respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
        request_id: sign_id.request_id,
        from_address: ctx.wallet,
        nonce: 0,
    };
    backlog
        .insert(IndexedSignRequest::sign_bidirectional(
            sign_id,
            test_sign_args(0x88),
            Chain::Solana,
            current_unix_timestamp(),
            test_bidirectional_event(),
        ))
        .await;
    backlog
        .set_status(
            tx.source_chain,
            &sign_id,
            SignStatus::PendingPublish {
                publish: PublishState {
                    signature: mpc_primitives::Signature::new(
                        AffinePoint::GENERATOR,
                        Scalar::ONE,
                        0,
                    ),
                    participants: vec![Participant::from(0u32), Participant::from(1u32)],
                    is_proposer: true,
                },
            },
        )
        .await;
    backlog
        .advance(Chain::Solana, sign_id, tx)
        .await
        .context("failed to seed late execution watcher")?;

    let msg = next_sign_message_within(&mut sign_rx, Duration::from_secs(20)).await?;
    match msg {
        Sign::Request(req) => {
            assert_eq!(req.id, sign_id);
            assert_eq!(req.chain, Chain::Solana);
            match req.kind {
                SignKind::RespondBidirectional(res) => {
                    assert_eq!(res.tx_id, tx_id);
                    assert!(
                        !res.output.starts_with(&[0xde, 0xad, 0xbe, 0xef]),
                        "late watcher backfill should preserve the successful execution path"
                    );
                }
                other => panic!("expected RespondBidirectional request, got {other:?}"),
            }
        }
        other => panic!("expected Sign::Request from late watcher backfill, got {other:?}"),
    }

    let watchers = backlog.execution_watchers(Chain::Ethereum).await;
    assert!(
        watchers.is_empty(),
        "late watcher should be cleared after backfill"
    );

    let no_extra_message = timeout(Duration::from_millis(1500), sign_rx.recv()).await;
    assert!(
        no_extra_message.is_err(),
        "late watcher backfill emitted an unexpected duplicate follow-up"
    );

    run_handle.abort();
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_ethereum_stream_concurrent_events() -> Result<()> {
    let ctx = EthereumTestEnvironment::new().await?;
    let backlog = ctx.backlog();
    let mut stream = stream_ethereum(&ctx, backlog).await?;

    let payloads: Vec<[u8; 32]> = (0u8..5)
        .map(|i| {
            let mut p = [0u8; 32];
            p[0] = i;
            p
        })
        .collect();

    for payload in &payloads {
        submit_sign_request(&ctx, *payload, "concurrent-path").await?;
    }

    let mut received: Vec<[u8; 32]> = Vec::new();
    while received.len() < payloads.len() {
        if let ChainEvent::SignRequest(req) =
            next_event_within(&mut stream, Duration::from_secs(10)).await?
        {
            let bytes: [u8; 32] = req.args.payload.to_bytes().into();
            received.push(bytes);
        }
    }

    for payload in &payloads {
        assert!(received.contains(payload));
    }
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_ethereum_stream_checkpointing() -> Result<()> {
    const INTERVAL: u64 = 4;

    let ctx = EthereumTestEnvironment::new().await?;
    let backlog = ctx.backlog();

    let mut stream = stream_ethereum(&ctx, backlog.clone()).await?;
    submit_sign_request(&ctx, [5u8; 32], "some-path").await?;

    let checkpoint = tokio::time::timeout(Duration::from_secs(20), async move {
        let mut saw_sign_request = false;
        loop {
            let Some(event) = stream.next_event().await else {
                break None;
            };
            match event {
                ChainEvent::SignRequest(req) => {
                    saw_sign_request = true;

                    // The production indexer loop inserts sign requests into the backlog.
                    // These integration tests consume `ChainEvent`s directly, so replicate
                    // that behavior here so checkpoints capture pending requests.
                    if matches!(req.kind, SignKind::RespondBidirectional(_)) {
                        continue;
                    }
                    backlog.insert(req.clone()).await;
                }
                ChainEvent::Block(height) => {
                    tracing::info!(height, "observed block event");
                    if let Some(checkpoint) = backlog
                        .set_processed_block_interval(Chain::Ethereum, height, INTERVAL)
                        .await
                    {
                        // With block events now emitted even for empty blocks, it's possible to
                        // hit a checkpoint boundary before any requests have been indexed.
                        // Keep going until we've observed at least one sign request and the
                        // checkpoint captures it.
                        if saw_sign_request && !checkpoint.pending_requests.is_empty() {
                            break Some(checkpoint);
                        }
                    }
                }
                _ => {}
            }
        }
    })
    .await
    .expect("timed out waiting for block event and checkpoint")
    .expect("stream was canceled");
    assert_eq!(
        checkpoint.pending_requests.len(),
        1,
        "expected to have one pending request"
    );

    // Start a fresh client with the same storage; it should resume and observe new events.
    let backlog = ctx.backlog();
    let mut stream = stream_ethereum(&ctx, backlog.clone()).await?;
    submit_sign_request(&ctx, [6u8; 32], "checkpoint-path").await?;

    let mut saw_new_event = false;
    let mut saw_new_checkpoint = false;
    for _ in 0..12 {
        match next_event_within(&mut stream, Duration::from_secs(10)).await? {
            ChainEvent::SignRequest(req) => {
                saw_new_event = true;

                if matches!(req.kind, SignKind::RespondBidirectional(_)) {
                    continue;
                }
                backlog.insert(req.clone()).await;

                if saw_new_checkpoint {
                    break;
                }
            }
            ChainEvent::Block(height) => {
                if backlog
                    .set_processed_block_interval(Chain::Ethereum, height, INTERVAL)
                    .await
                    .is_some()
                {
                    saw_new_checkpoint = true;
                    if saw_new_event {
                        break;
                    }
                }
            }
            _ => continue,
        }
    }

    assert!(saw_new_event, "new stream did not observe new event");
    assert!(
        saw_new_checkpoint,
        "new stream did not observe new checkpoint"
    );
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_ethereum_stream_sign_and_respond_flow() -> Result<()> {
    let ctx = EthereumTestEnvironment::new().await?;
    let backlog = ctx.backlog();
    let mut stream = stream_ethereum(&ctx, backlog).await?;
    let _ = tracing_subscriber::fmt::try_init();

    // Submit a sign request and capture its id from the emitted event.
    let payload = [9u8; 32];
    let path = "m/44'/60'/0'/0/42";
    submit_sign_request(&ctx, payload, path).await?;

    let sign_req = loop {
        match next_event_within(&mut stream, Duration::from_secs(30)).await? {
            ChainEvent::SignRequest(req) => break req,
            _ => continue,
        }
    };

    // Prepare a valid on-curve signature payload and respond via the contract.
    let expected_big_r = k256::ProjectivePoint::GENERATOR.to_affine();
    let expected_s = k256::Scalar::from(11u64);
    let expected_recovery_id: u8 = 1;

    let enc = k256::ProjectivePoint::GENERATOR.to_encoded_point(false);
    let x = enc.x().expect("generator must have x coordinate");
    let y = enc.y().expect("generator must have y coordinate");

    let big_r = ChainSignatures::AffinePoint {
        x: U256::from_be_slice(x),
        y: U256::from_be_slice(y),
    };
    let expected_s_bytes = expected_s.to_bytes();
    let s = U256::from_be_bytes(expected_s_bytes.into());
    let signature = ChainSignatures::Signature {
        bigR: big_r,
        s,
        recoveryId: expected_recovery_id,
    };

    let response = ChainSignatures::Response {
        requestId: sign_req.id.request_id.into(),
        signature,
    };

    let contract = ctx.contract();
    let respond_call = contract.respond(vec![response]);
    let pending_tx = respond_call.send().await?;
    let receipt = pending_tx
        .get_receipt()
        .await
        .context("respond transaction execution failed")?;

    // Sanity-check that the contract emitted the SignatureResponded log we're expecting.
    let logs = receipt.logs().to_vec();
    assert!(!logs.is_empty(), "respond transaction produced no logs");
    let sig_topic = alloy::primitives::keccak256(
        "SignatureResponded(bytes32,address,((uint256,uint256),uint256,uint8))",
    );
    assert_eq!(
        logs[0].topic0(),
        Some(&sig_topic),
        "unexpected event emitted"
    );

    // Verify the indexer emits the Respond event with matching data.
    let mut saw_respond = false;
    for _ in 0..8 {
        match next_event_within(&mut stream, Duration::from_secs(10)).await? {
            ChainEvent::Respond(SignatureRespondedEvent::Ethereum(ev)) => {
                assert_eq!(ev.request_id, sign_req.id.request_id);
                assert_eq!(ev.signature.big_r, expected_big_r);
                assert_eq!(ev.signature.s, expected_s);
                assert_eq!(ev.signature.recovery_id, expected_recovery_id);
                saw_respond = true;
                break;
            }
            _ => continue,
        }
    }

    assert!(saw_respond, "did not receive SignatureResponded event");
    Ok(())
}
