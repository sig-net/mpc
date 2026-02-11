use alloy::primitives::{Address as AlloyAddress, B256};
use anyhow::{Context, Result};
use ethers::types::{Address, H256, U256};
use integration_tests::cluster::spawner::ClusterSpawner;
use integration_tests::containers::{EthereumSandbox, Redis};
use integration_tests::eth::{self, ChainSignaturesContract, SignRequest};
use mpc_node::backlog::Backlog;
use mpc_node::indexer_client::{ChainClient, ChainEvent};
use mpc_node::indexer_eth::{EthConfig, EthereumIndexerClient};
use mpc_node::protocol::Chain;
use mpc_node::storage::app_data_storage::AppDataStorage;
use mpc_primitives::{SignId, LATEST_MPC_KEY_VERSION};
use near_account_id::AccountId;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

fn signature_deposit() -> U256 {
    U256::from(1u64)
}

// Integration tests for EthereumIndexerClient
//
// These tests spin up Anvil, deploy the ChainSignatures contract, and exercise the
// Ethereum indexer client in isolation (no MPC cluster required).

struct EthTestCtx {
    _spawner: ClusterSpawner,
    redis: Redis,
    sandbox: EthereumSandbox,
    signer: Arc<eth::SandboxMiddleware>,
    wallet: Address,
    contract_address: Address,
    chain_id: u64,
}

impl EthTestCtx {
    async fn new() -> Result<Self> {
        let spawner = ClusterSpawner::default()
            .network("eth-client-tests")
            .init_network()
            .await?;
        let redis = Redis::run(&spawner).await;
        let sandbox = EthereumSandbox::run(&spawner).await?;
        let chain_id = sandbox.chain_id;

        let (signer, wallet) = eth::client(
            &sandbox.external_http_endpoint,
            &sandbox.secret_key,
            sandbox.chain_id,
        )?;

        let contract_address =
            eth::deploy_chain_signatures(signer.clone(), wallet, signature_deposit()).await?;

        Ok(Self {
            _spawner: spawner,
            redis,
            sandbox,
            signer,
            wallet,
            contract_address,
            chain_id,
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
            total_timeout: 120,
            optimistic_requests,
            light_client: false,
        }
    }

    fn app_data_storage(&self) -> AppDataStorage {
        let pool = self.redis.pool();
        let account_id: AccountId = "eth-client.test.near".parse().unwrap();
        mpc_node::storage::app_data_storage::init(&pool, &account_id)
    }

    fn backlog(&self) -> Backlog {
        Backlog::new()
    }

    fn contract(&self) -> ChainSignaturesContract<Arc<eth::SandboxMiddleware>> {
        ChainSignaturesContract::new(self.contract_address, self.signer.clone().into())
    }
}

async fn submit_sign_request(ctx: &EthTestCtx, payload: [u8; 32], path: &str) -> Result<H256> {
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
    Ok(receipt.transaction_hash)
}

async fn next_event_within(
    client: &mut EthereumIndexerClient,
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

#[tokio::test]
async fn test_ethereum_client_parse_sign_event() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    let ctx = EthTestCtx::new().await?;
    let app_data_storage = ctx.app_data_storage();
    let backlog = ctx.backlog();
    let mut client =
        EthereumIndexerClient::new(Some(ctx.config(true)), app_data_storage, backlog).await?;

    let payload = k256::Scalar::from(1u64).to_bytes().into();
    let path = "m/44'/60'/0'/0/0";
    submit_sign_request(&ctx, payload, path).await?;

    let req = loop {
        match next_event_within(&mut client, Duration::from_secs(30)).await? {
            ChainEvent::SignRequest(req) => break req,
            _ => continue,
        }
    };

    assert_eq!(req.chain, Chain::Ethereum);
    assert_eq!(req.args.path, path);
    assert_eq!(req.args.payload.to_bytes(), payload.into());
    Ok(())
}

#[tokio::test]
async fn test_ethereum_client_emits_checkpoints() -> Result<()> {
    let ctx = EthTestCtx::new().await?;
    let app_data_storage = ctx.app_data_storage();
    let backlog = ctx.backlog();
    let mut client =
        EthereumIndexerClient::new(Some(ctx.config(true)), app_data_storage, backlog).await?;

    submit_sign_request(&ctx, [2u8; 32], "test-path").await?;

    let mut saw_checkpoint = false;
    for _ in 0..5 {
        match next_event_within(&mut client, Duration::from_secs(20)).await? {
            ChainEvent::Checkpoint(_) => {
                saw_checkpoint = true;
                break;
            }
            _ => continue,
        }
    }

    assert!(saw_checkpoint, "expected checkpoint event");
    Ok(())
}

#[tokio::test]
async fn test_ethereum_client_catchup_linear() -> Result<()> {
    let ctx = EthTestCtx::new().await?;

    // Produce events before the client starts
    let payloads = [[10u8; 32], [11u8; 32], [12u8; 32]];
    for payload in &payloads {
        submit_sign_request(&ctx, *payload, "catchup-path").await?;
    }

    let app_data_storage = ctx.app_data_storage();
    app_data_storage.set_last_processed_block_eth(0).await?;
    let backlog = ctx.backlog();
    let mut client =
        EthereumIndexerClient::new(Some(ctx.config(true)), app_data_storage, backlog).await?;

    let mut seen = Vec::new();
    let deadline = Duration::from_secs(60);
    let start = std::time::Instant::now();
    while seen.len() < payloads.len() && start.elapsed() < deadline {
        if let ChainEvent::SignRequest(req) =
            next_event_within(&mut client, Duration::from_secs(10)).await?
        {
            seen.push(req.args.payload.to_bytes());
        }
    }

    assert!(seen.len() >= payloads.len(), "missing caught up events");
    Ok(())
}

#[tokio::test]
async fn test_ethereum_client_finality_requirement() -> Result<()> {
    let ctx = EthTestCtx::new().await?;
    let app_data_storage = ctx.app_data_storage();
    let backlog = ctx.backlog();

    // set optimistic requests to false to trigger finality.
    let optimistic_requests = false;
    let mut client = EthereumIndexerClient::new(
        Some(ctx.config(optimistic_requests)),
        app_data_storage,
        backlog,
    )
    .await?;

    submit_sign_request(&ctx, [3u8; 32], "finality-path").await?;

    let mut saw_sign = false;
    for _ in 0..5 {
        match next_event_within(&mut client, Duration::from_secs(30)).await? {
            ChainEvent::SignRequest(_) => {
                saw_sign = true;
                break;
            }
            _ => continue,
        }
    }

    assert!(saw_sign, "sign event not emitted after finality");
    Ok(())
}

#[tokio::test]
async fn test_ethereum_client_execution_confirmation() -> Result<()> {
    let ctx = EthTestCtx::new().await?;
    let app_data_storage = ctx.app_data_storage();
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
    backlog
        .watch_execution(Chain::Ethereum, sign_id.clone(), tx)
        .await;

    let mut client =
        EthereumIndexerClient::new(Some(ctx.config(true)), app_data_storage, backlog.clone())
            .await?;

    // Send a transaction from the watched address to bump nonce and trigger the staleness check.
    submit_sign_request(&ctx, [4u8; 32], "execution-path").await?;

    let mut saw_execution = false;
    for _ in 0..10 {
        match next_event_within(&mut client, Duration::from_secs(30)).await? {
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

#[tokio::test]
async fn test_ethereum_client_concurrent_events() -> Result<()> {
    let ctx = EthTestCtx::new().await?;
    let app_data_storage = ctx.app_data_storage();
    let backlog = ctx.backlog();
    let mut client =
        EthereumIndexerClient::new(Some(ctx.config(true)), app_data_storage, backlog).await?;

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
            next_event_within(&mut client, Duration::from_secs(30)).await?
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

#[tokio::test]
async fn test_ethereum_client_checkpoint_persistence() -> Result<()> {
    let ctx = EthTestCtx::new().await?;
    let app_data_storage = ctx.app_data_storage();
    let backlog = ctx.backlog();

    let mut client = EthereumIndexerClient::new(
        Some(ctx.config(true)),
        app_data_storage.clone(),
        backlog.clone(),
    )
    .await?;

    submit_sign_request(&ctx, [5u8; 32], "checkpoint-path").await?;

    // Capture the first checkpoint height and persist it manually.
    let checkpoint_height = loop {
        match next_event_within(&mut client, Duration::from_secs(30)).await? {
            ChainEvent::Checkpoint(height) => break height,
            _ => continue,
        }
    };
    app_data_storage
        .set_last_processed_block_eth(checkpoint_height)
        .await?;

    drop(client);

    // Start a fresh client with the same storage; it should resume and observe new events.
    let mut client =
        EthereumIndexerClient::new(Some(ctx.config(true)), app_data_storage, backlog).await?;

    submit_sign_request(&ctx, [6u8; 32], "checkpoint-path-new").await?;

    let mut saw_new_event = false;
    for _ in 0..5 {
        match next_event_within(&mut client, Duration::from_secs(30)).await? {
            ChainEvent::SignRequest(_) | ChainEvent::Checkpoint(_) => {
                saw_new_event = true;
                break;
            }
            _ => continue,
        }
    }

    assert!(
        saw_new_event,
        "new client did not resume from stored checkpoint"
    );
    Ok(())
}
