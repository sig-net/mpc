use alloy::primitives::{Address as AlloyAddress, B256};
use anyhow::{Context, Result};
use ethers::middleware::{Middleware, SignerMiddleware};
use ethers::providers::{Http, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::TransactionRequest;
use ethers::types::{Address, U256};
use integration_tests::cluster::spawner::ClusterSpawner;
use integration_tests::containers::{EthereumSandbox, Solana};
use integration_tests::eth::{self, chain_signatures_contract, ChainSignaturesContract, SignRequest};
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use mpc_node::backlog::Backlog;
use mpc_node::indexer_eth::{EthConfig, EthereumStream};
use mpc_node::indexer_sol::{SolConfig, SolanaStream};
use mpc_node::protocol::Chain;
use mpc_node::stream::{ChainEvent, ChainStream};
use mpc_primitives::{SignId, LATEST_MPC_KEY_VERSION};
use rand::thread_rng;
use solana_sdk::signer::Signer as _;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

#[derive(Clone, Copy, Debug)]
enum StreamKind {
    Solana,
    Ethereum,
}

impl StreamKind {
    fn all() -> [Self; 2] {
        [Self::Solana, Self::Ethereum]
    }

    fn chain(self) -> Chain {
        match self {
            Self::Solana => Chain::Solana,
            Self::Ethereum => Chain::Ethereum,
        }
    }
}

enum AnyEnv {
    Solana(Solana),
    Ethereum(EthereumTestEnvironment),
}

enum AnyStream {
    Solana(SolanaStream),
    Ethereum(EthereumStream),
}

impl AnyStream {
    async fn next_event(&mut self) -> Option<ChainEvent> {
        match self {
            AnyStream::Solana(stream) => stream.next_event().await,
            AnyStream::Ethereum(stream) => stream.next_event().await,
        }
    }
}

fn signature_deposit() -> U256 {
    U256::from(1u64)
}

struct EthereumTestEnvironment {
    _spawner: ClusterSpawner,
    sandbox: EthereumSandbox,
    signer: Arc<eth::SandboxMiddleware>,
    wallet: Address,
    contract_address: Address,
    _block_pumper: tokio::task::JoinHandle<()>,
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

        let pumper_wallet = LocalWallet::new(&mut thread_rng()).with_chain_id(sandbox.chain_id);
        let pumper_address = pumper_wallet.address();
        let pumper_provider = Provider::<Http>::try_from(sandbox.external_http_endpoint.as_str())?;
        let pumper_client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>> =
            Arc::new(SignerMiddleware::new(pumper_provider, pumper_wallet));

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
                        let _ = tokio::time::timeout(Duration::from_secs(5), pending).await;
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                }
            }
        });

        let contract_address =
            eth::deploy_chain_signatures(signer.clone(), wallet, signature_deposit()).await?;

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
            total_timeout: 120,
            optimistic_requests,
            light_client: false,
        }
    }

    fn contract(&self) -> ChainSignaturesContract<Arc<eth::SandboxMiddleware>> {
        ChainSignaturesContract::new(self.contract_address, self.signer.clone().into())
    }
}

async fn setup_env(kind: StreamKind) -> Result<AnyEnv> {
    match kind {
        StreamKind::Solana => {
            let solana = Solana::run().await;
            solana.deploy_contract().await?;
            Ok(AnyEnv::Solana(solana))
        }
        StreamKind::Ethereum => Ok(AnyEnv::Ethereum(EthereumTestEnvironment::new().await?)),
    }
}

async fn spawn_stream(
    kind: StreamKind,
    env: &AnyEnv,
    backlog: Backlog,
    optimistic_requests: bool,
) -> Result<AnyStream> {
    match (kind, env) {
        (StreamKind::Solana, AnyEnv::Solana(solana)) => {
            let program_address = solana.program_keypair.pubkey().to_string();
            let config: SolConfig = solana.get_config(program_address);
            let stream = SolanaStream::new(Some(config)).context("failed to create SolanaStream")?;
            Ok(AnyStream::Solana(stream))
        }
        (StreamKind::Ethereum, AnyEnv::Ethereum(ctx)) => {
            let stream = EthereumStream::new(Some(ctx.config(optimistic_requests)), backlog).await?;
            Ok(AnyStream::Ethereum(stream))
        }
        _ => anyhow::bail!("invalid env for stream kind"),
    }
}

async fn submit_sign(env: &AnyEnv, payload: [u8; 32], path: &str) -> Result<()> {
    match env {
        AnyEnv::Solana(solana) => {
            solana
                .sign(payload, path, LATEST_MPC_KEY_VERSION, "secp256k1", "", "")
                .await?;
            Ok(())
        }
        AnyEnv::Ethereum(ctx) => {
            let request = SignRequest {
                payload,
                path: path.to_string(),
                key_version: LATEST_MPC_KEY_VERSION,
                algo: "secp256k1".to_string(),
                dest: "".to_string(),
                params: "".to_string(),
            };
            let contract = ctx.contract();
            let call = contract.sign(request).value(signature_deposit());
            let pending = call.send().await?;
            let _ = pending
                .await
                .context("failed to mine sign transaction")?
                .context("sign transaction dropped from mempool")?;
            Ok(())
        }
    }
}

async fn submit_sign_bidirectional(env: &AnyEnv) -> Result<()> {
    match env {
        AnyEnv::Solana(solana) => {
            let serialized_tx = vec![1, 2, 3, 4];
            let callback_program = solana_sdk::pubkey::Pubkey::new_unique();
            solana
                .sign_bidirectional(
                    &serialized_tx,
                    "solana:localnet",
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
            Ok(())
        }
        AnyEnv::Ethereum(_) => anyhow::bail!("ethereum sign bidirectional unsupported"),
    }
}

fn dummy_eth_signature() -> chain_signatures_contract::Signature {
    let enc = k256::ProjectivePoint::GENERATOR.to_encoded_point(false);
    let x = enc.x().expect("generator must have x coordinate");
    let y = enc.y().expect("generator must have y coordinate");

    let big_r = chain_signatures_contract::AffinePoint {
        x: U256::from_big_endian(x),
        y: U256::from_big_endian(y),
    };
    let s = U256::from_big_endian(k256::Scalar::from(11u64).to_bytes().as_slice());

    chain_signatures_contract::Signature {
        big_r,
        s,
        recovery_id: 1,
    }
}

fn dummy_sol_signature() -> signet_program::Signature {
    let enc = k256::ProjectivePoint::GENERATOR.to_encoded_point(false);
    let x = enc.x().expect("generator must have x coordinate");
    let y = enc.y().expect("generator must have y coordinate");

    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(x);
    let mut y_bytes = [0u8; 32];
    y_bytes.copy_from_slice(y);

    signet_program::Signature {
        big_r: signet_program::AffinePoint {
            x: x_bytes,
            y: y_bytes,
        },
        s: k256::Scalar::from(11u64).to_bytes().into(),
        recovery_id: 1,
    }
}

async fn submit_respond(env: &AnyEnv, request_id: [u8; 32]) -> Result<()> {
    match env {
        AnyEnv::Solana(solana) => {
            solana.respond(vec![request_id], vec![dummy_sol_signature()]).await?;
            Ok(())
        }
        AnyEnv::Ethereum(ctx) => {
            let response = chain_signatures_contract::Response {
                request_id,
                signature: dummy_eth_signature(),
            };

            let contract = ctx.contract();
            let respond_call = contract.respond(vec![response]);
            let pending_tx = respond_call.send().await?;
            let _ = pending_tx
                .await
                .context("respond transaction execution failed")?
                .ok_or_else(|| anyhow::anyhow!("respond transaction dropped from mempool"))?;
            Ok(())
        }
    }
}

async fn submit_respond_bidirectional(env: &AnyEnv, request_id: [u8; 32]) -> Result<()> {
    match env {
        AnyEnv::Solana(solana) => {
            let sig = cait_sith::FullSignature::<k256::Secp256k1> {
                big_r: k256::ProjectivePoint::GENERATOR.to_affine(),
                s: k256::Scalar::from(11u64),
            };
            solana
                .respond_bidirectional(request_id, vec![0xde, 0xad, 0xbe, 0xef], &sig, 1)
                .await?;
            Ok(())
        }
        AnyEnv::Ethereum(_) => anyhow::bail!("ethereum respond bidirectional unsupported"),
    }
}

async fn next_event_within(stream: &mut AnyStream, duration: Duration) -> Result<ChainEvent> {
    timeout(duration, async {
        loop {
            if let Some(event) = stream.next_event().await {
                return event;
            }
        }
    })
    .await
    .context("timed out waiting for chain event")
}

#[test_log::test(tokio::test)]
async fn test_stream_common_parse_sign() -> Result<()> {
    for kind in StreamKind::all() {
        let env = setup_env(kind).await?;
        let backlog = Backlog::new();
        let mut stream = spawn_stream(kind, &env, backlog, true).await?;

        submit_sign(&env, [1u8; 32], "test").await?;

        let req = loop {
            match next_event_within(&mut stream, Duration::from_secs(20)).await? {
                ChainEvent::SignRequest(req) => break req,
                _ => continue,
            }
        };

        assert_eq!(req.chain, kind.chain());
    }

    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_stream_common_parse_sign_bidirectional() -> Result<()> {
    for kind in StreamKind::all() {
        let env = setup_env(kind).await?;
        let backlog = Backlog::new();
        let mut stream = spawn_stream(kind, &env, backlog, true).await?;

        if submit_sign_bidirectional(&env).await.is_err() {
            continue;
        }

        let req = loop {
            match next_event_within(&mut stream, Duration::from_secs(20)).await? {
                ChainEvent::SignRequest(req) => break req,
                _ => continue,
            }
        };

        assert!(matches!(
            req.sign_request_type,
            mpc_node::protocol::SignRequestType::SignBidirectional(_)
        ));
    }

    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_stream_common_parse_respond() -> Result<()> {
    for kind in StreamKind::all() {
        let env = setup_env(kind).await?;
        let backlog = Backlog::new();
        let mut stream = spawn_stream(kind, &env, backlog, true).await?;

        submit_sign(&env, [3u8; 32], "respond-path").await?;

        let sign_req = loop {
            match next_event_within(&mut stream, Duration::from_secs(20)).await? {
                ChainEvent::SignRequest(req) => break req,
                _ => continue,
            }
        };

        submit_respond(&env, sign_req.id.request_id).await?;

        let mut found = false;
        for _ in 0..20 {
            match next_event_within(&mut stream, Duration::from_secs(10)).await? {
                ChainEvent::Respond(ev) if ev.request_id() == sign_req.id.request_id => {
                    found = true;
                    break;
                }
                _ => continue,
            }
        }

        assert!(found, "did not observe respond event for {kind:?}");
    }

    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_stream_common_parse_respond_bidirectional() -> Result<()> {
    for kind in StreamKind::all() {
        let env = setup_env(kind).await?;
        let backlog = Backlog::new();
        let mut stream = spawn_stream(kind, &env, backlog, true).await?;

        if submit_sign_bidirectional(&env).await.is_err() {
            continue;
        }

        let sign_req = loop {
            match next_event_within(&mut stream, Duration::from_secs(20)).await? {
                ChainEvent::SignRequest(req) => break req,
                _ => continue,
            }
        };

        if submit_respond_bidirectional(&env, sign_req.id.request_id)
            .await
            .is_err()
        {
            continue;
        }

        let mut found = false;
        for _ in 0..20 {
            match next_event_within(&mut stream, Duration::from_secs(10)).await? {
                ChainEvent::RespondBidirectional(ev) if ev.request_id() == sign_req.id.request_id => {
                    found = true;
                    break;
                }
                _ => continue,
            }
        }

        assert!(found, "did not observe respond bidirectional event for {kind:?}");
    }

    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_stream_common_blocks_and_checkpoints() -> Result<()> {
    for kind in StreamKind::all() {
        let env = setup_env(kind).await?;
        let backlog = Backlog::new();
        let mut stream = spawn_stream(kind, &env, backlog.clone(), true).await?;

        submit_sign(&env, [9u8; 32], "block-path").await?;

        let mut found_checkpoint = false;
        for _ in 0..20 {
            match next_event_within(&mut stream, Duration::from_secs(10)).await? {
                ChainEvent::Block(block) => {
                    if backlog
                        .set_processed_block_interval(kind.chain(), block, 1)
                        .await
                        .is_some()
                    {
                        found_checkpoint = true;
                        break;
                    }
                }
                _ => continue,
            }
        }

        assert!(found_checkpoint, "did not observe checkpoint block for {kind:?}");
    }

    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_stream_common_linear_catchup() -> Result<()> {
    for kind in StreamKind::all() {
        if matches!(kind, StreamKind::Solana) {
            continue;
        }

        let env = setup_env(kind).await?;
        let backlog = Backlog::new();

        let mut stream1 = spawn_stream(kind, &env, backlog.clone(), true).await?;

        submit_sign(&env, [11u8; 32], "catchup-1").await?;
        submit_sign(&env, [12u8; 32], "catchup-2").await?;

        let mut checkpoint_block = 0;
        for _ in 0..20 {
            match next_event_within(&mut stream1, Duration::from_secs(10)).await? {
                ChainEvent::Block(block) => {
                    checkpoint_block = checkpoint_block.max(block);
                    backlog.set_processed_block(kind.chain(), checkpoint_block).await;
                }
                ChainEvent::SignRequest(_) => {}
                _ => {}
            }
            if checkpoint_block > 0 {
                break;
            }
        }
        assert!(checkpoint_block > 0, "no checkpoint block observed");

        drop(stream1);

        submit_sign(&env, [13u8; 32], "catchup-3").await?;

        let mut stream2 = spawn_stream(kind, &env, backlog.clone(), true).await?;
        let mut saw_new = false;
        for _ in 0..20 {
            match next_event_within(&mut stream2, Duration::from_secs(10)).await? {
                ChainEvent::SignRequest(_) => {
                    saw_new = true;
                    break;
                }
                _ => continue,
            }
        }

        assert!(saw_new, "stream did not process new events after restart");
    }

    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_stream_common_execution_confirmation_detection() -> Result<()> {
    let kind = StreamKind::Ethereum;
    let env = setup_env(kind).await?;
    let AnyEnv::Ethereum(ctx) = &env else {
        anyhow::bail!("expected ethereum env")
    };

    let backlog = Backlog::new();

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

    let mut stream = spawn_stream(kind, &env, backlog.clone(), true).await?;

    submit_sign(&env, [4u8; 32], "execution-path").await?;

    let mut saw_execution = false;
    for _ in 0..12 {
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
async fn test_stream_common_concurrent_submissions() -> Result<()> {
    for kind in StreamKind::all() {
        let env = setup_env(kind).await?;
        let backlog = Backlog::new();
        let mut stream = spawn_stream(kind, &env, backlog, true).await?;

        let payloads: Vec<[u8; 32]> = (0u8..5)
            .map(|i| {
                let mut p = [0u8; 32];
                p[0] = i;
                p
            })
            .collect();

        for payload in &payloads {
            submit_sign(&env, *payload, "concurrent-path").await?;
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
    }

    Ok(())
}

#[test_log::test(tokio::test)]
#[ignore = "placeholder: finality-based processing will be enabled in sandbox later"]
async fn test_stream_common_finality_placeholder() -> Result<()> {
    Ok(())
}
