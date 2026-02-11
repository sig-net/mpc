use alloy::primitives::{Address as AlloyAddress, B256};
use anyhow::{Context, Result};
use ethers::types::{Address, H256, U256};
use integration_tests::cluster::spawner::ClusterSpawner;
use integration_tests::containers::{EthereumSandbox, Redis};
use integration_tests::eth::{
    self, chain_signatures_contract, ChainSignaturesContract, SignRequest,
};
use mpc_node::backlog::Backlog;
use mpc_node::indexer_client::{ChainClient, ChainEvent};
use mpc_node::indexer_common::SignatureRespondedEvent;
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

struct EthereumTestEnvironment {
    _spawner: ClusterSpawner,
    redis: Redis,
    sandbox: EthereumSandbox,
    signer: Arc<eth::SandboxMiddleware>,
    wallet: Address,
    contract_address: Address,
}

impl EthereumTestEnvironment {
    async fn new() -> Result<Self> {
        let spawner = ClusterSpawner::default()
            .network("eth-client-tests")
            .init_network()
            .await?;
        let redis = Redis::run(&spawner).await;
        let sandbox = EthereumSandbox::run(&spawner).await?;

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

async fn submit_sign_request(
    ctx: &EthereumTestEnvironment,
    payload: [u8; 32],
    path: &str,
) -> Result<H256> {
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
    let ctx = EthereumTestEnvironment::new().await?;
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
async fn test_ethereum_client_emits_blocks() -> Result<()> {
    let ctx = EthereumTestEnvironment::new().await?;
    let app_data_storage = ctx.app_data_storage();
    let backlog = ctx.backlog();
    let mut client =
        EthereumIndexerClient::new(Some(ctx.config(true)), app_data_storage, backlog).await?;

    submit_sign_request(&ctx, [2u8; 32], "test-path").await?;

    let mut saw_block = false;
    for _ in 0..5 {
        match next_event_within(&mut client, Duration::from_secs(20)).await? {
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

#[tokio::test]
async fn test_ethereum_client_execution_confirmation() -> Result<()> {
    let ctx = EthereumTestEnvironment::new().await?;
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
    let ctx = EthereumTestEnvironment::new().await?;
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
async fn test_ethereum_client_block_persistence() -> Result<()> {
    let ctx = EthereumTestEnvironment::new().await?;
    let app_data_storage = ctx.app_data_storage();
    let backlog = ctx.backlog();

    let mut client = EthereumIndexerClient::new(
        Some(ctx.config(true)),
        app_data_storage.clone(),
        backlog.clone(),
    )
    .await?;

    submit_sign_request(&ctx, [5u8; 32], "checkpoint-path").await?;

    // Capture the first block height marker and persist it manually.
    let checkpoint_height = loop {
        match next_event_within(&mut client, Duration::from_secs(30)).await? {
            ChainEvent::Block(height) => break height,
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
            ChainEvent::SignRequest(_) | ChainEvent::Block(_) => {
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

#[tokio::test]
async fn test_ethereum_client_sign_and_respond_flow() -> Result<()> {
    let ctx = EthereumTestEnvironment::new().await?;
    let app_data_storage = ctx.app_data_storage();
    let backlog = ctx.backlog();
    let mut client =
        EthereumIndexerClient::new(Some(ctx.config(true)), app_data_storage, backlog).await?;
    let _ = tracing_subscriber::fmt::try_init();

    // Submit a sign request and capture its id from the emitted event.
    let payload = [9u8; 32];
    let path = "m/44'/60'/0'/0/42";
    submit_sign_request(&ctx, payload, path).await?;

    let sign_req = loop {
        match next_event_within(&mut client, Duration::from_secs(30)).await? {
            ChainEvent::SignRequest(req) => break req,
            _ => continue,
        }
    };

    // Prepare a dummy signature and respond via the contract. The contract does not
    // validate signature contents, so we can use placeholder values that map onto the
    // indexer's expected v/r/s parsing.
    let v: u8 = 27;
    let r = [7u8; 32];
    let s = [11u8; 32];
    let signature = chain_signatures_contract::Signature {
        big_r: chain_signatures_contract::AffinePoint {
            x: U256::from_big_endian(&r),
            y: U256::zero(),
        },
        s: U256::from_big_endian(&s),
        recovery_id: v,
    };

    let response = chain_signatures_contract::Response {
        request_id: sign_req.id.request_id,
        signature,
    };

    let contract = ctx.contract();
    let respond_call = contract.respond(vec![response]);
    let pending_tx = respond_call.send().await?;
    let receipt = pending_tx
        .await
        .context("respond transaction execution failed")?
        .ok_or_else(|| anyhow::anyhow!("respond transaction dropped from mempool"))?;

    // Sanity-check that the contract emitted the SignatureResponded log we're expecting.
    let logs = receipt.logs.clone();
    assert!(!logs.is_empty(), "respond transaction produced no logs");
    let sig_topic = H256::from(ethers::utils::keccak256(
        "SignatureResponded(bytes32,address,((uint256,uint256),uint256,uint8))",
    ));
    assert_eq!(logs[0].topics[0], sig_topic, "unexpected event emitted");

    // Verify the indexer emits the Respond event with matching data.
    let mut saw_respond = false;
    for _ in 0..10 {
        match next_event_within(&mut client, Duration::from_secs(30)).await? {
            ChainEvent::Respond(SignatureRespondedEvent::Ethereum(ev)) => {
                assert_eq!(ev.request_id, sign_req.id.request_id);
                assert_eq!(ev.v, v);
                assert_eq!(ev.r, r);
                assert_eq!(ev.s, s);
                saw_respond = true;
                break;
            }
            _ => continue,
        }
    }

    assert!(saw_respond, "did not receive SignatureResponded event");
    Ok(())
}
