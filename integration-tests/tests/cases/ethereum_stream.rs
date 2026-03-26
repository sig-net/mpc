use alloy::primitives::{Address as AlloyAddress, B256};
use anyhow::{Context, Result};
use ethers::middleware::{Middleware, SignerMiddleware};
use ethers::providers::{Http, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::BlockNumber;
use ethers::types::TransactionRequest;
use ethers::types::{Address, H256, U256};
use integration_tests::cluster::spawner::ClusterSpawner;
use integration_tests::containers::{EthereumSandbox, KurtosisEthereum};
use integration_tests::eth::{
    self, chain_signatures_contract, ChainSignaturesContract, EthereumTarget, SignRequest,
};
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use mpc_node::backlog::{Backlog, BacklogTransaction, SignTx};
use mpc_node::indexer_eth::{EthConfig, EthereumStream};
use mpc_node::protocol::Chain;
use mpc_node::stream::ops::SignatureRespondedEvent;
use mpc_node::stream::{ChainEvent, ChainStream};
use mpc_primitives::{SignId, LATEST_MPC_KEY_VERSION};
use rand::thread_rng;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

fn signature_deposit() -> U256 {
    U256::from(1u64)
}

// Integration tests for EthereumStream
//
// These tests spin up Anvil, deploy the ChainSignatures contract, and exercise the
// Ethereum indexer stream in isolation (no MPC cluster required).

enum EthereumTestBackend {
    Sandbox {
        _spawner: ClusterSpawner,
        _sandbox: EthereumSandbox,
        _block_pumper: tokio::task::JoinHandle<()>,
    },
    Kurtosis {
        _kurtosis: KurtosisEthereum,
    },
}

struct EthereumTestEnvironment {
    _backend: EthereumTestBackend,
    signer: Arc<eth::SandboxMiddleware>,
    wallet: Address,
    contract_address: Address,
    account_sk: String,
    consensus_rpc_http_url: String,
    execution_rpc_http_url: String,
    network: String,
    helios_data_path: String,
    refresh_finalized_interval: u64,
}

impl EthereumTestEnvironment {
    async fn new(target: EthereumTarget) -> Result<Self> {
        match target {
            EthereumTarget::Sandbox => Self::new_sandbox().await,
            EthereumTarget::Kurtosis => Self::new_kurtosis().await,
        }
    }

    async fn sandbox() -> Result<Self> {
        Self::new(EthereumTarget::Sandbox).await
    }

    async fn kurtosis() -> Result<Self> {
        Self::new(EthereumTarget::Kurtosis).await
    }

    async fn new_sandbox() -> Result<Self> {
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
        let pumper_wallet = LocalWallet::new(&mut thread_rng()).with_chain_id(sandbox.chain_id);
        let pumper_address = pumper_wallet.address();
        let pumper_provider = Provider::<Http>::try_from(sandbox.external_http_endpoint.as_str())?;
        let pumper_client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>> =
            Arc::new(SignerMiddleware::new(pumper_provider, pumper_wallet));

        // Fund the pumper account with a small amount of ETH for gas.
        // (0.001 ETH is plenty for these tests.)
        let fund_tx = TransactionRequest::new()
            .to(pumper_address)
            .value(U256::from(1_000_000_000_000_000u64));
        let pending_fund = signer.send_transaction(fund_tx, None).await?;
        let _ = pending_fund
            .await
            .context("failed to mine block pumper funding transaction")?
            .context("block pumper funding transaction dropped from mempool")?;

        let block_pumper = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                interval.tick().await;
                let tx = TransactionRequest::new().to(wallet).value(U256::zero());

                match pumper_client.send_transaction(tx, None).await {
                    Ok(pending) => {
                        // Await mining so each tick reliably corresponds to a mined block.
                        // If it takes too long, just continue; the next iteration will try again.
                        let _ = tokio::time::timeout(Duration::from_secs(5), pending).await;
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
            eth::deploy_chain_signatures(signer.clone(), wallet, signature_deposit()).await?;
        let account_sk = sandbox.secret_key.clone();
        let consensus_rpc_http_url = sandbox.external_http_endpoint.clone();
        let execution_rpc_http_url = sandbox.external_http_endpoint.clone();

        Ok(Self {
            _backend: EthereumTestBackend::Sandbox {
                _spawner: spawner,
                _sandbox: sandbox,
                _block_pumper: block_pumper,
            },
            signer,
            wallet,
            contract_address,
            account_sk,
            consensus_rpc_http_url,
            execution_rpc_http_url,
            network: "sepolia".to_string(),
            helios_data_path: "/tmp/helios".to_string(),
            refresh_finalized_interval: 500,
        })
    }

    async fn new_kurtosis() -> Result<Self> {
        let spawner = ClusterSpawner::default();
        let kurtosis = KurtosisEthereum::run(&spawner).await?;
        let account_sk = kurtosis.secret_key.clone();
        let consensus_rpc_http_url = kurtosis.external_consensus_http_endpoint.clone();
        let execution_rpc_http_url = kurtosis.external_http_endpoint.clone();
        let network = kurtosis.network.clone();
        let helios_data_path = kurtosis.helios_data_path.clone();
        let refresh_finalized_interval = kurtosis.refresh_finalized_interval;
        let provider = Provider::<Http>::try_from(kurtosis.external_http_endpoint.as_str())?;
        let chain_id = provider.get_chainid().await?.as_u64();
        let (signer, wallet) = eth::client(
            &kurtosis.external_http_endpoint,
            &kurtosis.secret_key,
            chain_id,
        )?;
        let contract_address =
            eth::deploy_chain_signatures(signer.clone(), wallet, signature_deposit()).await?;

        Ok(Self {
            _backend: EthereumTestBackend::Kurtosis {
                _kurtosis: kurtosis,
            },
            signer,
            wallet,
            contract_address,
            account_sk,
            consensus_rpc_http_url,
            execution_rpc_http_url,
            network,
            helios_data_path,
            refresh_finalized_interval,
        })
    }

    fn config(&self, optimistic_requests: bool) -> EthConfig {
        EthConfig {
            account_sk: self.account_sk.clone(),
            consensus_rpc_http_url: self.consensus_rpc_http_url.clone(),
            execution_rpc_http_url: self.execution_rpc_http_url.clone(),
            contract_address: format!("{:x}", self.contract_address),
            network: self.network.clone(),
            helios_data_path: self.helios_data_path.clone(),
            refresh_finalized_interval: self.refresh_finalized_interval,
            optimistic_requests,
            light_client: false,
        }
    }

    fn backlog(&self) -> Backlog {
        Backlog::new()
    }

    fn contract(&self) -> ChainSignaturesContract<Arc<eth::SandboxMiddleware>> {
        ChainSignaturesContract::new(self.contract_address, self.signer.clone().into())
    }
}

async fn submit_sign_request(
    ctx: &EthereumTestEnvironment,
    payload: [u8; 32],
    path: &str,
) -> Result<(H256, u64)> {
    let contract = ctx.contract();
    let sign_request = SignRequest {
        payload,
        path: path.to_string(),
        key_version: LATEST_MPC_KEY_VERSION,
        algo: "secp256k1".to_string(),
        dest: "".to_string(),
        params: "".to_string(),
    };

    let call = contract.sign(sign_request).value(signature_deposit());
    let pending_tx = call.send().await?;
    let receipt = pending_tx
        .await
        .context("failed to mine sign transaction")?
        .context("sign transaction dropped from mempool")?;
    let block_number = receipt
        .block_number
        .context("sign transaction missing block number")?
        .as_u64();
    tracing::info!(
        contract = ?ctx.contract_address,
        block_number,
        tx_hash = ?receipt.transaction_hash,
        "sign transaction mined"
    );
    Ok((receipt.transaction_hash, block_number))
}

async fn next_event_within(client: &mut EthereumStream, duration: Duration) -> Result<ChainEvent> {
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

fn sample_response(
    request_id: [u8; 32],
) -> (
    chain_signatures_contract::Response,
    k256::AffinePoint,
    k256::Scalar,
    u8,
) {
    let expected_big_r = k256::ProjectivePoint::GENERATOR.to_affine();
    let expected_s = k256::Scalar::from(11u64);
    let expected_recovery_id: u8 = 1;

    let enc = k256::ProjectivePoint::GENERATOR.to_encoded_point(false);
    let x = enc.x().expect("generator must have x coordinate");
    let y = enc.y().expect("generator must have y coordinate");

    let big_r = chain_signatures_contract::AffinePoint {
        x: U256::from_big_endian(x),
        y: U256::from_big_endian(y),
    };
    let expected_s_bytes = expected_s.to_bytes();
    let s = U256::from_big_endian(expected_s_bytes.as_slice());
    let signature = chain_signatures_contract::Signature {
        big_r,
        s,
        recovery_id: expected_recovery_id,
    };

    (
        chain_signatures_contract::Response {
            request_id,
            signature,
        },
        expected_big_r,
        expected_s,
        expected_recovery_id,
    )
}

async fn submit_signature_response(
    ctx: &EthereumTestEnvironment,
    response: chain_signatures_contract::Response,
) -> Result<u64> {
    let contract = ctx.contract();
    let respond_call = contract.respond(vec![response]);
    let pending_tx = respond_call.send().await?;
    let receipt = pending_tx
        .await
        .context("respond transaction execution failed")?
        .ok_or_else(|| anyhow::anyhow!("respond transaction dropped from mempool"))?;
    let response_block = receipt
        .block_number
        .context("respond transaction missing block number")?
        .as_u64();
    tracing::info!(
        contract = ?ctx.contract_address,
        response_block,
        tx_hash = ?receipt.transaction_hash,
        logs = receipt.logs.len(),
        "respond transaction mined"
    );

    let logs = receipt.logs.clone();
    assert!(!logs.is_empty(), "respond transaction produced no logs");
    let sig_topic = H256::from(ethers::utils::keccak256(
        "SignatureResponded(bytes32,address,((uint256,uint256),uint256,uint8))",
    ));
    assert_eq!(logs[0].topics[0], sig_topic, "unexpected event emitted");

    Ok(response_block)
}

async fn wait_for_finalized_block_at_least(
    ctx: &EthereumTestEnvironment,
    target_block: u64,
    timeout_duration: Duration,
) -> Result<()> {
    let started = tokio::time::Instant::now();

    loop {
        if let Some(block) = ctx
            .signer
            .provider()
            .get_block(BlockNumber::Finalized)
            .await?
        {
            if block
                .number
                .is_some_and(|number| number.as_u64() >= target_block)
            {
                return Ok(());
            }
        }

        if started.elapsed() >= timeout_duration {
            anyhow::bail!(
                "timed out waiting for finalized block >= {target_block} on Kurtosis Ethereum"
            );
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn assert_signature_responded(
    stream: &mut EthereumStream,
    request_id: [u8; 32],
    expected_big_r: k256::AffinePoint,
    expected_s: k256::Scalar,
    expected_recovery_id: u8,
    attempts: usize,
    timeout_per_attempt: Duration,
) -> Result<()> {
    let started = tokio::time::Instant::now();
    let total_timeout = timeout_per_attempt.saturating_mul(attempts as u32);

    loop {
        let elapsed = started.elapsed();
        if elapsed >= total_timeout {
            break;
        }

        let remaining = total_timeout.saturating_sub(elapsed);
        let next_timeout = remaining.min(timeout_per_attempt);

        match next_event_within(stream, next_timeout).await? {
            ChainEvent::Respond(SignatureRespondedEvent::Ethereum(ev)) => {
                tracing::info!(request_id = ?ev.request_id, "observed SignatureResponded event");
                assert_eq!(ev.request_id, request_id);
                assert_eq!(ev.signature.big_r, expected_big_r);
                assert_eq!(ev.signature.s, expected_s);
                assert_eq!(ev.signature.recovery_id, expected_recovery_id);
                return Ok(());
            }
            other => {
                tracing::info!(
                    ?other,
                    "observed non-respond chain event while waiting for SignatureResponded"
                );
                continue;
            }
        }
    }

    anyhow::bail!("did not receive SignatureResponded event")
}

#[test_log::test(tokio::test)]
async fn test_ethereum_stream_parse_sign_event() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    let ctx = EthereumTestEnvironment::sandbox().await?;
    let backlog = ctx.backlog();
    let mut stream = EthereumStream::new(Some(ctx.config(true)), backlog).await?;

    let payload = k256::Scalar::from(1u64).to_bytes().into();
    let path = "m/44'/60'/0'/0/0";
    let _ = submit_sign_request(&ctx, payload, path).await?;

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
    let ctx = EthereumTestEnvironment::sandbox().await?;
    let backlog = ctx.backlog();
    let mut stream = EthereumStream::new(Some(ctx.config(true)), backlog).await?;

    let _ = submit_sign_request(&ctx, [2u8; 32], "test-path").await?;

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
    let ctx = EthereumTestEnvironment::sandbox().await?;
    let backlog = ctx.backlog();

    // Register an execution watcher with an intentionally stale nonce to trigger the staleness path.
    let tx = mpc_node::sign_bidirectional::BidirectionalTx {
        id: mpc_node::sign_bidirectional::BidirectionalTxId(B256::from([9u8; 32])),
        sender: [0u8; 32],
        serialized_transaction: vec![],
        source_chain: Chain::Solana,
        target_chain: Chain::Ethereum,
        caip2_id: "eip155:31337".to_string(),
        key_version: LATEST_MPC_KEY_VERSION,
        deposit: 0,
        path: "m/44'/60'/0'/0/0".to_string(),
        algo: "secp256k1".to_string(),
        dest: "".to_string(),
        params: "".to_string(),
        output_deserialization_schema: vec![],
        respond_serialization_schema: vec![],
        request_id: [7u8; 32],
        from_address: AlloyAddress::from_slice(ctx.wallet.as_bytes()),
        nonce: 0,
        status: mpc_node::sign_bidirectional::PendingRequestStatus::PendingExecution,
    };
    let sign_id = SignId::new([7u8; 32]);
    backlog.watch_execution(Chain::Ethereum, sign_id, tx).await;

    let mut stream = EthereumStream::new(Some(ctx.config(true)), backlog.clone()).await?;

    // Send a transaction from the watched address to bump nonce and trigger the staleness check.
    let _ = submit_sign_request(&ctx, [4u8; 32], "execution-path").await?;

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
async fn test_ethereum_stream_concurrent_events() -> Result<()> {
    let ctx = EthereumTestEnvironment::sandbox().await?;
    let backlog = ctx.backlog();
    let mut stream = EthereumStream::new(Some(ctx.config(true)), backlog).await?;

    let payloads: Vec<[u8; 32]> = (0u8..5)
        .map(|i| {
            let mut p = [0u8; 32];
            p[0] = i;
            p
        })
        .collect();

    for payload in &payloads {
        let _ = submit_sign_request(&ctx, *payload, "concurrent-path").await?;
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

    let ctx = EthereumTestEnvironment::sandbox().await?;
    let backlog = ctx.backlog();

    let mut stream = EthereumStream::new(Some(ctx.config(true)), backlog.clone()).await?;
    let _ = submit_sign_request(&ctx, [5u8; 32], "some-path").await?;

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
                    backlog
                        .insert(
                            req.chain,
                            req.id,
                            BacklogTransaction::Sign(SignTx {
                                request_id: req.id.request_id,
                                source_chain: req.chain,
                                status: mpc_node::sign_bidirectional::PendingRequestStatus::AwaitingResponse,
                                args: req.args.clone(),
                                unix_timestamp_indexed: req.unix_timestamp_indexed,
                            }),
                            req.sign_request_type.clone(),
                        )
                        .await;
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
    let mut stream = EthereumStream::new(Some(ctx.config(true)), backlog.clone()).await?;
    let _ = submit_sign_request(&ctx, [6u8; 32], "checkpoint-path").await?;

    let mut saw_new_event = false;
    let mut saw_new_checkpoint = false;
    for _ in 0..12 {
        match next_event_within(&mut stream, Duration::from_secs(10)).await? {
            ChainEvent::SignRequest(req) => {
                saw_new_event = true;

                backlog
                    .insert(
                        req.chain,
                        req.id,
                        BacklogTransaction::Sign(SignTx {
                            request_id: req.id.request_id,
                            source_chain: req.chain,
                            status: mpc_node::sign_bidirectional::PendingRequestStatus::AwaitingResponse,
                            args: req.args.clone(),
                            unix_timestamp_indexed: req.unix_timestamp_indexed,
                        }),
                        req.sign_request_type.clone(),
                    )
                    .await;

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
    let ctx = EthereumTestEnvironment::sandbox().await?;
    let backlog = ctx.backlog();
    let mut stream = EthereumStream::new(Some(ctx.config(true)), backlog).await?;
    let _ = tracing_subscriber::fmt::try_init();

    // Submit a sign request and capture its id from the emitted event.
    let payload = [9u8; 32];
    let path = "m/44'/60'/0'/0/42";
    let _ = submit_sign_request(&ctx, payload, path).await?;

    let sign_req = loop {
        match next_event_within(&mut stream, Duration::from_secs(30)).await? {
            ChainEvent::SignRequest(req) => break req,
            _ => continue,
        }
    };

    let (response, expected_big_r, expected_s, expected_recovery_id) =
        sample_response(sign_req.id.request_id);
    let _ = submit_signature_response(&ctx, response).await?;
    assert_signature_responded(
        &mut stream,
        sign_req.id.request_id,
        expected_big_r,
        expected_s,
        expected_recovery_id,
        8,
        Duration::from_secs(10),
    )
    .await?;

    Ok(())
}

#[test_log::test(tokio::test)]
#[ignore = "requires Kurtosis Ethereum endpoints via KURTOSIS_ETH_* env vars"]
async fn test_ethereum_stream_finality_on_kurtosis() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    let ctx = EthereumTestEnvironment::kurtosis().await?;
    let backlog = ctx.backlog();
    let mut stream = EthereumStream::new(Some(ctx.config(false)), backlog).await?;

    let payload = [0xabu8; 32];
    let path = "m/44'/60'/0'/0/31337";
    let (_, sign_block) = submit_sign_request(&ctx, payload, path).await?;
    wait_for_finalized_block_at_least(&ctx, sign_block, Duration::from_secs(180)).await?;

    let sign_req = loop {
        match next_event_within(&mut stream, Duration::from_secs(30)).await? {
            ChainEvent::SignRequest(req) => break req,
            _ => continue,
        }
    };

    assert_eq!(sign_req.chain, Chain::Ethereum);
    assert_eq!(sign_req.args.path, path);

    let (response, expected_big_r, expected_s, expected_recovery_id) =
        sample_response(sign_req.id.request_id);
    let response_block = submit_signature_response(&ctx, response).await?;
    wait_for_finalized_block_at_least(&ctx, response_block, Duration::from_secs(180)).await?;
    assert_signature_responded(
        &mut stream,
        sign_req.id.request_id,
        expected_big_r,
        expected_s,
        expected_recovery_id,
        12,
        Duration::from_secs(20),
    )
    .await?;

    Ok(())
}
