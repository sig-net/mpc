use anyhow::{anyhow, Context, Result};

use integration_tests::cluster::Cluster;
use integration_tests::{actions, cluster, eth};
use k256::ecdsa::VerifyingKey;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, EncodedPoint, FieldBytes, PublicKey as K256PublicKey};
use mpc_crypto::derive_key;
use mpc_crypto::kdf::derive_epsilon_eth;
use mpc_primitives::{Chain, Checkpoint, LATEST_MPC_KEY_VERSION};
use test_log::test;
use tokio::time::Duration;

#[test(tokio::test)]
async fn test_signature_ethereum() -> Result<()> {
    let cluster = cluster::spawn().disable_prestockpile().ethereum().await?;
    cluster.wait().signable().await?;

    let ctx = cluster.nodes.ctx();
    let eth_ctx = ctx
        .ethereum
        .as_ref()
        .context("ethereum sandbox not initialized")?;
    let endpoint = eth_ctx.sandbox.external_http_endpoint.clone();
    let secret_key = eth_ctx.sandbox.secret_key.clone();
    let chain_id = eth_ctx.sandbox.chain_id;
    let contract_address = eth_ctx.contract_address;

    let client = eth::client(&endpoint, &secret_key, chain_id)?;
    let requester = client.address;

    let payload = [7u8; 32];
    let path = "test";
    let algo = "secp256k1";
    let dest = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
    let params = "{}";

    let request = eth::SignRequest {
        payload,
        path: path.to_string(),
        key_version: LATEST_MPC_KEY_VERSION,
        algo: algo.to_string(),
        dest: dest.to_string(),
        params: params.to_string(),
    };

    // Send sign request via raw transaction
    let tx_hash = eth::send_sign_request(&client, contract_address, request.clone(), 1).await?;
    let receipt = client.wait_for_receipt(&tx_hash, Duration::from_secs(10)).await?;
    // Parse block number from receipt (hex string)
    let block_hex = receipt.get("blockNumber").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("missing block number"))?;
    let from_block = u64::from_str_radix(block_hex.trim_start_matches("0x"), 16)?;

    let expected_request_id = eth::compute_request_id(
        requester,
        payload,
        path,
        LATEST_MPC_KEY_VERSION,
        chain_id,
        algo,
        dest,
        params,
    );

    // Poll logs for the expected request_id
    let mut matching_log = None;
    for _ in 0..30 {
        let topics = vec![None, Some(format!("0x{}", hex::encode(expected_request_id)))];
        let logs = client.get_logs(from_block, from_block + 20, Some(contract_address), topics).await?;
        if let Some(log) = logs.into_iter().find(|l| {
            // check topic[1] equals request id
            if let Some(topics) = l.get("topics").and_then(|t| t.as_array()) {
                if topics.len() > 1 {
                    return topics[1].as_str().map(|s| s == format!("0x{}", hex::encode(expected_request_id))).unwrap_or(false);
                }
            }
            false
        }) {
            matching_log = Some(log);
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let log = matching_log.ok_or_else(|| anyhow!("did not observe signature response on ethereum"))?;

    // Parse event data to extract signature
    let data_hex = log.get("data").and_then(|d| d.as_str()).ok_or_else(|| anyhow!("missing data in log"))?;
    let data_bytes = hex::decode(data_hex.trim_start_matches("0x"))?;
    if data_bytes.len() < 160 {
        anyhow::bail!("unexpected event data length: {}", data_bytes.len());
    }
    // responder is first 32 bytes (right-aligned address)
    let responder_bytes = &data_bytes[0..32];
    let responder_addr = {
        let addr_slice = &responder_bytes[12..32];
        let mut arr = [0u8; 20];
        arr.copy_from_slice(addr_slice);
        arr
    };

    // signature components
    let big_r_x = &data_bytes[32..64];
    let big_r_y = &data_bytes[64..96];
    let s_bytes = &data_bytes[96..128];
    let recovery_id_byte = data_bytes[128];

    // Build signature bytes: r is the x-coordinate reduced to scalar; here we use big_r_x directly
    let mut signature_bytes = [0u8; 64];
    signature_bytes[..32].copy_from_slice(big_r_x);
    signature_bytes[32..].copy_from_slice(s_bytes);
    let recovery_id = recovery_id_byte as i32;

    let recovered_address = actions::recover_eth_address(&payload, &signature_bytes, recovery_id as u8);

    let network_public_key = cluster.root_public_key().await?;
    let mut network_pk = vec![0x04];
    network_pk.extend_from_slice(&network_public_key.as_bytes()[1..]);
    let encoded_network_pk = EncodedPoint::from_bytes(&network_pk).context("invalid network public key encoding")?;
    let network_affine = AffinePoint::from_encoded_point(&encoded_network_pk)
        .into_option()
        .ok_or_else(|| anyhow!("invalid network public key"))?;

    let sender_hex = format!("0x{}", hex::encode(requester));
    let epsilon = derive_epsilon_eth(LATEST_MPC_KEY_VERSION, &sender_hex, path);
    let user_affine = derive_key(network_affine, epsilon);
    let user_public_key = K256PublicKey::from_affine(user_affine)
        .map_err(|_| anyhow!("invalid derived public key"))?;
    let verifying_key = VerifyingKey::from(&user_public_key);
    let verifying_bytes = verifying_key.to_encoded_point(false);
    let verifying_pub = secp256k1::PublicKey::from_slice(verifying_bytes.as_bytes()).unwrap();
    let expected_address = actions::public_key_to_address(&verifying_pub);

    anyhow::ensure!(
        recovered_address == expected_address,
        "signature recovered address mismatch: expected {expected_address:?}, got {recovered_address:?}"
    );

    Ok(())
}

/// Test that checkpoints are properly cleaned up after responses are observed
#[test(tokio::test)]
async fn test_proper_indexer_checkpoint() -> Result<()> {
    let cluster = cluster::spawn().disable_prestockpile().ethereum().await?;
    cluster.wait().signable().await?;

    let ctx = cluster.nodes.ctx();
    let eth_ctx = ctx
        .ethereum
        .as_ref()
        .context("ethereum sandbox not initialized")?;
    let endpoint = eth_ctx.sandbox.external_http_endpoint.clone();
    let secret_key = eth_ctx.sandbox.secret_key.clone();
    let chain_id = eth_ctx.sandbox.chain_id;
    let contract_address = eth_ctx.contract_address;

    let client = eth::client(&endpoint, &secret_key, chain_id)?;
    let requester = client.address;

    // Get initial checkpoint state
    let node_idx = 0;
    let initial_checkpoint = cluster.nodes.fetch_checkpoints(node_idx).await?;

    tracing::info!(
        ?initial_checkpoint,
        "initial checkpoint state before request"
    );

    // Submit a signature request
    let payload = [42u8; 32];
    let path = "test";
    let algo = "secp256k1";
    let dest = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
    let params = "{}";

    let request = eth::SignRequest {
        payload,
        path: path.to_string(),
        key_version: LATEST_MPC_KEY_VERSION,
        algo: algo.to_string(),
        dest: dest.to_string(),
        params: params.to_string(),
    };

    let tx_hash = eth::send_sign_request(&client, contract_address, request.clone(), 1).await?;
    let receipt = client.wait_for_receipt(&tx_hash, Duration::from_secs(10)).await?;
    let block_hex = receipt.get("blockNumber").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("missing block number"))?;
    let from_block = u64::from_str_radix(block_hex.trim_start_matches("0x"), 16)?;

    let expected_request_id = eth::compute_request_id(
        requester,
        payload,
        path,
        LATEST_MPC_KEY_VERSION,
        chain_id,
        algo,
        dest,
        params,
    );

    tracing::info!(?expected_request_id, "submitted signature request");

    // Wait a bit for the request to be indexed and added to backlog
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Check checkpoint - request should be in the pending transactions
    let checkpoints = cluster.fetch_checkpoints(node_idx).await?;
    tracing::info!(?checkpoints, "checkpoint after request submitted");

    let checkpoint = checkpoints
        .get(&Chain::Ethereum)
        .expect("checkpoint not found for eth");
    tracing::info!(
        pending_count = checkpoint.pending_requests.len(),
        "pending transactions in checkpoint"
    );

    // Poll logs for the expected request id
    let mut matching_log = None;
    for _ in 0..30 {
        let topics = vec![None, Some(format!("0x{}", hex::encode(expected_request_id)))];
        let logs = client.get_logs(from_block, from_block + 20, Some(contract_address), topics).await?;
        if let Some(log) = logs.into_iter().find(|l| {
            if let Some(topics) = l.get("topics").and_then(|t| t.as_array()) {
                if topics.len() > 1 {
                    return topics[1].as_str().map(|s| s == format!("0x{}", hex::encode(expected_request_id))).unwrap_or(false);
                }
            }
            false
        }) {
            matching_log = Some(log);
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let _log = matching_log.ok_or_else(|| anyhow!("did not observe signature response on ethereum"))?;

    tracing::info!("signature response observed on-chain");

    // Wait for indexer to process the response event and remove from backlog
    // The indexer polls every few seconds, so we give it time
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Check checkpoint again - request should be removed
    let checkpoints = cluster.fetch_checkpoints(node_idx).await?;
    tracing::info!(?checkpoints, "checkpoint after response observed");

    let checkpoint = checkpoints
        .get(&Chain::Ethereum)
        .expect("checkpoint not found for eth");
    tracing::info!(
        pending_count = checkpoint.pending_requests.len(),
        "pending transactions count after response"
    );

    let expected_request_bytes = expected_request_id;
    let request_still_present = checkpoint
        .pending_requests
        .iter()
        .any(|tx| tx.sign_id.request_id == expected_request_bytes);

    assert!(
        !request_still_present,
        "request should be removed from checkpoint after response is observed"
    );

    tracing::info!("request successfully removed from checkpoint after response");

    Ok(())
}

/// Test that a node can recover from a checkpoint after being offline
#[test(tokio::test)]
async fn test_checkpoint_recovery_after_offline() -> anyhow::Result<()> {
    let mut cluster = cluster::spawn().disable_prestockpile().ethereum().await?;
    cluster.wait().signable().await?;

    let ctx = cluster.nodes.ctx();
    let eth_ctx = ctx
        .ethereum
        .as_ref()
        .context("ethereum sandbox not initialized")?;
    let eth_client = eth::client(
        &eth_ctx.sandbox.external_http_endpoint,
        &eth_ctx.sandbox.secret_key,
        eth_ctx.sandbox.chain_id,
    )?;
    let requester = eth_client.address;
    let eth_contract = eth_ctx.contract_address; // use raw contract address

    // Produce a few sign requests up front so nodes create initial checkpoints
    for i in 0..5 {
        submit_eth_sign_request(&eth_client, eth_contract, i).await?;
    }

    let active_idx = 1usize;
    let initial_checkpoint = wait_node_checkpoint(
        &cluster,
        active_idx,
        Chain::Ethereum,
        1,
        Duration::from_secs(10),
    )
    .await?;

    let target_account = cluster.account_id(0).clone();
    let offline_idx = 0usize;

    tracing::info!(%target_account, ?initial_checkpoint, "taking node offline for checkpoint recovery test");
    let offline_config = cluster.kill_node(&target_account).await;

    // Keep the node offline while the remaining nodes continue operating and sign requests
    // are being processed alongside new checkpoints being created.
    let offline_duration = Duration::from_secs(10);
    let mut elapsed = Duration::default();
    let mut seed = 100usize;
    while elapsed < offline_duration {
        submit_eth_sign_request(&eth_client, eth_contract, seed).await?;
        seed += 1;
        tokio::time::sleep(Duration::from_secs(2)).await;
        elapsed += Duration::from_secs(2);
    }

    // Wait for active node to create a new checkpoint beyond the initial one
    let node_active_checkpoint = wait_node_checkpoint(
        &cluster,
        active_idx,
        Chain::Ethereum,
        initial_checkpoint.block_height + 1,
        Duration::from_secs(10),
    )
    .await?;

    tracing::info!(
        block_height = node_active_checkpoint.block_height,
        "active node created new checkpoint while peer is offline"
    );

    tracing::info!("bringing offline node back online");
    cluster.restart_node(offline_config).await?;
    cluster.wait().signable().await?;

    // Verify the restarted node recovers to the same checkpoint via node consensus
    let node_recovered_checkpoint = wait_node_checkpoint(
        &cluster,
        offline_idx,
        Chain::Ethereum,
        node_active_checkpoint.block_height,
        Duration::from_secs(10),
    )
    .await?;

    tracing::info!(
        ?node_active_checkpoint,
        ?node_recovered_checkpoint,
        "offline node has restarted and checkpoint recovery complete",
    );

    assert_eq!(
        node_active_checkpoint, node_recovered_checkpoint,
        "restarted node should recover to same checkpoint as active node via consensus"
    );

    let active_checkpoint_after_restart = wait_node_checkpoint(
        &cluster,
        active_idx,
        Chain::Ethereum,
        node_active_checkpoint.block_height,
        Duration::from_secs(10),
    )
    .await?;

    assert_eq!(
        node_active_checkpoint, active_checkpoint_after_restart,
        "active node checkpoint should remain aligned after peer recovery"
    );

    Ok(())
}

async fn submit_eth_sign_request(
    client: &eth::EthClient,
    contract: alloy::primitives::Address,
    seed: usize,
) -> anyhow::Result<()> {
    let payload = [seed as u8; 32];
    let request = eth::SignRequest {
        payload,
        path: format!("offline_test_{seed}"),
        key_version: LATEST_MPC_KEY_VERSION,
        algo: "secp256k1".to_string(),
        dest: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".to_string(),
        params: "{}".to_string(),
    };

    let tx_hash = eth::send_sign_request(client, contract, request, 1).await?;
    client
        .wait_for_receipt(&tx_hash, Duration::from_secs(10))
        .await?
        .to_owned();

    Ok(())
}

async fn wait_node_checkpoint(
    nodes: &Cluster,
    node_idx: usize,
    chain: Chain,
    min_block_height: u64,
    timeout: Duration,
) -> anyhow::Result<Checkpoint> {
    tokio::time::timeout(timeout, async {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;

            let checkpoints = nodes.fetch_checkpoints(node_idx).await?;
            if let Some(checkpoint) = checkpoints.get(&chain) {
                if checkpoint.block_height >= min_block_height {
                    return Ok(checkpoint.clone());
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!("timed out waiting for node {node_idx} checkpoint >= {min_block_height}")
    })
}
