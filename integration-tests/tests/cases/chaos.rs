use anyhow::{anyhow, Context as _, Result};
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Middleware, Provider};
use ethers::signers::{coins_bip39::English, LocalWallet, MnemonicBuilder, Signer};
use ethers::types::{Address, H256, U256};
use futures::future::try_join_all;
use integration_tests::cluster::Cluster;
use integration_tests::{cluster, eth};
use mpc_primitives::{Chain, Checkpoint, LATEST_MPC_KEY_VERSION};
use near_workspaces::AccountId;
use rand::thread_rng;
use test_log::test;
use tokio::time::{sleep, Duration, Instant};

const ETH_MNEMONIC: &str = "test test test test test test test test test test test junk";
const ETH_ALGO: &str = "secp256k1";
const ETH_DESTINATION: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const ETH_PARAMS: &str = "{}";
const ETH_DEPOSIT_WEI: u64 = 1;

const BURST_REQUEST_COUNT: usize = 3;
const BURST_TIMEOUT: Duration = Duration::from_secs(240);
const FULL_CLUSTER_RESTART_TIMEOUT: Duration = Duration::from_secs(180);
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(90);
const NO_RESPONSE_WINDOW: Duration = Duration::from_secs(8);

static ETHEREUM_SANDBOX_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

#[derive(Clone, Debug)]
struct SubmittedEthRequest {
    request_id: H256,
    receipt_block: u64,
}

#[test(tokio::test)]
async fn test_ethereum_chaos_concurrent_burst_sign_requests_complete_within_budget() -> Result<()> {
    let _sandbox_guard = ETHEREUM_SANDBOX_LOCK.lock().await;
    configure_checkpoint_env();

    let cluster = cluster::spawn().ethereum().await?;
    cluster.wait().signable_many(BURST_REQUEST_COUNT).await?;

    let eth_ctx = cluster
        .nodes
        .ctx()
        .ethereum
        .as_ref()
        .context("ethereum sandbox not initialized")?;
    let endpoint = eth_ctx.sandbox.external_http_endpoint.clone();
    let chain_id = eth_ctx.sandbox.chain_id;
    let contract_address = eth_ctx.contract_address;

    let request_contracts = (0..BURST_REQUEST_COUNT)
        .map(|idx| build_contract_for_signer(&endpoint, chain_id, contract_address, idx as u32))
        .collect::<Result<Vec<_>>>()?;

    let (watch_client, _) =
        eth::client(&endpoint, &eth_ctx.sandbox.secret_key, eth_ctx.sandbox.chain_id)?;

    let started_at = Instant::now();
    let submissions = try_join_all(request_contracts.into_iter().enumerate().map(
        |(idx, (contract, requester))| async move {
            submit_eth_sign_request(&contract, requester, chain_id, idx + 1, "chaos/burst").await
        },
    ))
    .await?;

    let request_ids: Vec<_> = submissions.iter().map(|submission| submission.request_id).collect();

    let active_account = cluster.account_id(1).clone();
    wait_for_checkpoint_predicate(
        &cluster,
        &active_account,
        1,
        BURST_TIMEOUT,
        |checkpoint| checkpoint_contains_any_request(checkpoint, &request_ids),
    )
    .await?;

    let checkpoint_interval = Chain::Ethereum
        .checkpoint_interval()
        .context("ethereum checkpoint interval should be configured")?;
    let active_checkpoint_before_cleanup = current_checkpoint_or_empty(&cluster, &active_account).await?;

    produce_empty_eth_blocks(&watch_client, checkpoint_interval).await?;

    let min_cleanup_height = next_checkpoint_height(
        active_checkpoint_before_cleanup.block_height,
        checkpoint_interval,
    );

    let active_checkpoint = wait_for_checkpoint_predicate(
        &cluster,
        &active_account,
        min_cleanup_height,
        BURST_TIMEOUT,
        |checkpoint| checkpoint_contains_no_requests(checkpoint, &request_ids),
    )
    .await?;

    assert!(
        started_at.elapsed() <= BURST_TIMEOUT,
        "burst requests exceeded {:?}",
        BURST_TIMEOUT
    );

    let _ = active_checkpoint;

    Ok(())
}

#[test(tokio::test)]
async fn test_ethereum_chaos_restart_during_pending_requests_recovers_checkpoint() -> Result<()> {
    let _sandbox_guard = ETHEREUM_SANDBOX_LOCK.lock().await;
    configure_checkpoint_env();

    let mut cluster = cluster::spawn().ethereum().await?;
    cluster.wait().signable_many(BURST_REQUEST_COUNT).await?;

    let eth_ctx = cluster
        .nodes
        .ctx()
        .ethereum
        .as_ref()
        .context("ethereum sandbox not initialized")?;
    let endpoint = eth_ctx.sandbox.external_http_endpoint.clone();
    let chain_id = eth_ctx.sandbox.chain_id;
    let contract_address = eth_ctx.contract_address;

    let request_contracts = (0..BURST_REQUEST_COUNT)
        .map(|idx| build_contract_for_signer(&endpoint, chain_id, contract_address, idx as u32))
        .collect::<Result<Vec<_>>>()?;

    let (watch_client, _) =
        eth::client(&endpoint, &eth_ctx.sandbox.secret_key, eth_ctx.sandbox.chain_id)?;

    let submissions = try_join_all(request_contracts.into_iter().enumerate().map(
        |(idx, (contract, requester))| async move {
            submit_eth_sign_request(&contract, requester, chain_id, idx + 40, "chaos/restart")
                .await
        },
    ))
    .await?;
    let request_ids: Vec<_> = submissions.iter().map(|submission| submission.request_id).collect();

    let restarted_account = cluster.account_id(0).clone();
    let restarted_config = cluster.kill_node(&restarted_account).await;

    cluster.restart_node(restarted_config).await?;
    cluster.wait().nodes_running().await?;

    let active_account = cluster.account_id(1).clone();
    let checkpoint_interval = Chain::Ethereum
        .checkpoint_interval()
        .context("ethereum checkpoint interval should be configured")?;
    let active_checkpoint_before_cleanup = current_checkpoint_or_empty(&cluster, &active_account).await?;

    produce_empty_eth_blocks(&watch_client, checkpoint_interval).await?;

    let min_cleanup_height = next_checkpoint_height(
        active_checkpoint_before_cleanup.block_height,
        checkpoint_interval,
    );

    let active_checkpoint = wait_for_checkpoint_predicate(
        &cluster,
        &active_account,
        min_cleanup_height,
        RECOVERY_TIMEOUT,
        |checkpoint| checkpoint_contains_no_requests(checkpoint, &request_ids),
    )
    .await?;

    let restarted_checkpoint = wait_for_checkpoint_predicate(
        &cluster,
        &restarted_account,
        active_checkpoint.block_height,
        RECOVERY_TIMEOUT,
        |checkpoint| checkpoint_contains_no_requests(checkpoint, &request_ids),
    )
    .await?;

    assert_eq!(
        active_checkpoint, restarted_checkpoint,
        "restarted node should recover the same ethereum checkpoint as an active peer"
    );

    Ok(())
}

#[test(tokio::test)]
async fn test_ethereum_chaos_pending_request_waits_for_quorum_then_completes_after_rejoin() -> Result<()> {
    let _sandbox_guard = ETHEREUM_SANDBOX_LOCK.lock().await;
    configure_checkpoint_env();

    let mut cluster = cluster::spawn().disable_prestockpile().ethereum().await?;
    cluster.wait().signable().await?;

    let survivor_account = cluster.account_id(0).clone();
    let recovered_account = cluster.account_id(1).clone();
    let recovered_config = cluster.kill_node(&recovered_account).await;
    let other_offline_account = cluster.account_id(1).clone();
    let _other_offline_config = cluster.kill_node(&other_offline_account).await;

    cluster.wait().nodes_running().await?;

    let eth_ctx = cluster
        .nodes
        .ctx()
        .ethereum
        .as_ref()
        .context("ethereum sandbox not initialized")?;
    let endpoint = eth_ctx.sandbox.external_http_endpoint.clone();
    let chain_id = eth_ctx.sandbox.chain_id;
    let contract_address = eth_ctx.contract_address;

    let (submit_contract, requester) =
        build_contract_for_signer(&endpoint, chain_id, contract_address, 7)?;
    let (watch_client, _) =
        eth::client(&endpoint, &eth_ctx.sandbox.secret_key, eth_ctx.sandbox.chain_id)?;
    let _watch_contract = eth::ChainSignaturesContract::new(contract_address, watch_client.clone());

    let submission = submit_eth_sign_request(
        &submit_contract,
        requester,
        chain_id,
        99,
        "chaos/quorum",
    )
    .await?;

    tokio::time::sleep(NO_RESPONSE_WINDOW).await;

    cluster.restart_node(recovered_config).await?;
    cluster.wait().nodes_running().await?;

    let checkpoint_interval = Chain::Ethereum
        .checkpoint_interval()
        .context("ethereum checkpoint interval should be configured")?;
    let survivor_checkpoint_before_cleanup = current_checkpoint_or_empty(&cluster, &survivor_account).await?;

    produce_empty_eth_blocks(&watch_client, checkpoint_interval).await?;

    let min_cleanup_height = next_checkpoint_height(
        survivor_checkpoint_before_cleanup.block_height,
        checkpoint_interval,
    );

    let survivor_checkpoint = wait_for_checkpoint_predicate(
        &cluster,
        &survivor_account,
        min_cleanup_height,
        RECOVERY_TIMEOUT,
        |checkpoint| !checkpoint_contains_request(checkpoint, &submission.request_id),
    )
    .await?;

    let recovered_checkpoint = wait_for_checkpoint_predicate(
        &cluster,
        &recovered_account,
        survivor_checkpoint.block_height,
        RECOVERY_TIMEOUT,
        |checkpoint| !checkpoint_contains_request(checkpoint, &submission.request_id),
    )
    .await?;

    assert_eq!(
        survivor_checkpoint, recovered_checkpoint,
        "restored quorum should converge on the same ethereum checkpoint"
    );

    Ok(())
}

#[test(tokio::test)]
async fn test_ethereum_chaos_full_cluster_restart_recovers_pending_request_checkpoint() -> Result<()> {
    let _sandbox_guard = ETHEREUM_SANDBOX_LOCK.lock().await;
    configure_checkpoint_env();

    let mut cluster = cluster::spawn().ethereum().await?;
    cluster.wait().signable().await?;

    let eth_ctx = cluster
        .nodes
        .ctx()
        .ethereum
        .as_ref()
        .context("ethereum sandbox not initialized")?;
    let endpoint = eth_ctx.sandbox.external_http_endpoint.clone();
    let chain_id = eth_ctx.sandbox.chain_id;
    let contract_address = eth_ctx.contract_address;

    let (submit_contract, requester) =
        build_contract_for_signer(&endpoint, chain_id, contract_address, 7)?;
    let (watch_client, _) =
        eth::client(&endpoint, &eth_ctx.sandbox.secret_key, eth_ctx.sandbox.chain_id)?;

    let submission = submit_eth_sign_request(
        &submit_contract,
        requester,
        chain_id,
        133,
        "chaos/full-restart",
    )
    .await?;

    let active_account = cluster.account_id(0).clone();
    wait_for_checkpoint_predicate(
        &cluster,
        &active_account,
        submission.receipt_block,
        FULL_CLUSTER_RESTART_TIMEOUT,
        |checkpoint| checkpoint_contains_request(checkpoint, &submission.request_id),
    )
    .await?;

    let node_ids = cluster
        .account_ids()
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    assert!(node_ids.len() >= 2, "chaos suite expects at least two nodes");

    let mut killed = Vec::with_capacity(node_ids.len());
    for account_id in &node_ids {
        let config = cluster.kill_node(account_id).await;
        killed.push((account_id.clone(), config));
    }

    for (_, config) in killed {
        cluster.restart_node(config).await?;
    }

    cluster.wait().nodes_running().await?;

    let restarted_account = node_ids[0].clone();
    wait_for_checkpoint_predicate(
        &cluster,
        &restarted_account,
        submission.receipt_block,
        FULL_CLUSTER_RESTART_TIMEOUT,
        |checkpoint| checkpoint_contains_request(checkpoint, &submission.request_id),
    )
    .await?;

    let checkpoint_interval = Chain::Ethereum
        .checkpoint_interval()
        .context("ethereum checkpoint interval should be configured")?;
    let restarted_checkpoint_before_cleanup =
        current_checkpoint_or_empty(&cluster, &restarted_account).await?;

    produce_empty_eth_blocks(&watch_client, checkpoint_interval).await?;

    let min_cleanup_height = next_checkpoint_height(
        restarted_checkpoint_before_cleanup.block_height,
        checkpoint_interval,
    );

    let restarted_checkpoint = wait_for_checkpoint_predicate(
        &cluster,
        &restarted_account,
        min_cleanup_height,
        FULL_CLUSTER_RESTART_TIMEOUT,
        |checkpoint| checkpoint_contains_no_requests(checkpoint, &[submission.request_id]),
    )
    .await?;

    let peer_account = node_ids[1].clone();
    let peer_checkpoint = wait_for_checkpoint_predicate(
        &cluster,
        &peer_account,
        restarted_checkpoint.block_height,
        FULL_CLUSTER_RESTART_TIMEOUT,
        |checkpoint| checkpoint_contains_no_requests(checkpoint, &[submission.request_id]),
    )
    .await?;

    assert_eq!(
        restarted_checkpoint, peer_checkpoint,
        "fully restarted cluster should converge on the same ethereum checkpoint"
    );

    Ok(())
}

fn configure_checkpoint_env() {
    for (name, value) in Chain::checkpoint_env_vars() {
        std::env::set_var(name, value);
    }
}

fn next_checkpoint_height(block_height: u64, interval: u64) -> u64 {
    ((block_height / interval) + 1) * interval
}

fn checkpoint_contains_request(checkpoint: &Checkpoint, request_id: &H256) -> bool {
    checkpoint
        .pending_requests
        .iter()
        .any(|pending| pending.sign_id.request_id == *request_id.as_bytes())
}

fn checkpoint_contains_any_request(checkpoint: &Checkpoint, request_ids: &[H256]) -> bool {
    request_ids
        .iter()
        .any(|request_id| checkpoint_contains_request(checkpoint, request_id))
}

fn checkpoint_contains_no_requests(checkpoint: &Checkpoint, request_ids: &[H256]) -> bool {
    request_ids
        .iter()
        .all(|request_id| !checkpoint_contains_request(checkpoint, request_id))
}

fn node_index(cluster: &Cluster, account_id: &AccountId) -> Result<usize> {
    cluster
        .account_ids()
        .into_iter()
        .position(|current| current == account_id)
        .with_context(|| format!("node {account_id} is not part of the cluster"))
}

async fn current_checkpoint_or_empty(cluster: &Cluster, account_id: &AccountId) -> Result<Checkpoint> {
    let node_idx = node_index(cluster, account_id)?;
    let checkpoints = cluster.fetch_checkpoints(node_idx).await?;
    Ok(checkpoints
        .get(&Chain::Ethereum)
        .cloned()
        .unwrap_or_else(|| Checkpoint::empty(Chain::Ethereum)))
}

async fn wait_for_checkpoint_predicate<F>(
    cluster: &Cluster,
    account_id: &AccountId,
    min_block_height: u64,
    timeout: Duration,
    mut predicate: F,
) -> Result<Checkpoint>
where
    F: FnMut(&Checkpoint) -> bool,
{
    tokio::time::timeout(timeout, async {
        loop {
            let checkpoint = current_checkpoint_or_empty(cluster, account_id).await?;
            if checkpoint.block_height >= min_block_height && predicate(&checkpoint) {
                return Ok(checkpoint);
            }

            sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .map_err(|_| {
        anyhow!(
            "timed out waiting for ethereum checkpoint on node {account_id} (min_height={min_block_height})"
        )
    })?
}

fn build_contract_for_signer(
    endpoint: &str,
    chain_id: u64,
    contract_address: Address,
    signer_index: u32,
) -> Result<(eth::ChainSignaturesContract<eth::SandboxMiddleware>, Address)> {
    let wallet: LocalWallet = MnemonicBuilder::<English>::default()
        .phrase(ETH_MNEMONIC)
        .index(signer_index)?
        .build()?
        .with_chain_id(chain_id);
    let requester = wallet.address();
    let provider = Provider::<Http>::try_from(endpoint)?;
    let client = std::sync::Arc::new(SignerMiddleware::new(provider, wallet));
    Ok((
        eth::ChainSignaturesContract::new(contract_address, client),
        requester,
    ))
}

async fn submit_eth_sign_request(
    contract: &eth::ChainSignaturesContract<eth::SandboxMiddleware>,
    requester: Address,
    chain_id: u64,
    seed: usize,
    path_prefix: &str,
) -> Result<SubmittedEthRequest> {
    let payload = [seed as u8; 32];
    let path = format!("{path_prefix}/{seed}");

    let request = eth::SignRequest {
        payload,
        path: path.clone(),
        key_version: LATEST_MPC_KEY_VERSION,
        algo: ETH_ALGO.to_string(),
        dest: ETH_DESTINATION.to_string(),
        params: ETH_PARAMS.to_string(),
    };

    let call = contract.sign(request).value(U256::from(ETH_DEPOSIT_WEI));
    let pending = call.send().await?;
    let receipt = pending.await?.context("sign transaction failed")?;
    let receipt_block = receipt
        .block_number
        .context("missing block number in sign receipt")?
        .as_u64();

    let request_id = eth::compute_request_id(
        requester,
        payload,
        &path,
        LATEST_MPC_KEY_VERSION,
        U256::from(chain_id),
        ETH_ALGO,
        ETH_DESTINATION,
        ETH_PARAMS,
    );

    Ok(SubmittedEthRequest {
        request_id,
        receipt_block,
    })
}

async fn produce_empty_eth_blocks(
    client: &std::sync::Arc<eth::SandboxMiddleware>,
    block_count: u64,
) -> Result<()> {
    for _ in 0..block_count {
        let _: serde_json::Value = client.provider().request("evm_mine", ()).await?;
    }

    Ok(())
}