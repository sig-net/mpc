use alloy::primitives::U256;
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
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

    let (client, requester) = eth::client(&endpoint, &secret_key, chain_id)?;
    let contract = eth::ChainSignatures::new(contract_address, client.clone());

    let payload = [7u8; 32];
    let path = "test";
    let algo = "secp256k1";
    let dest = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
    let params = "{}";

    let request = eth::SignRequest {
        payload: payload.into(),
        path: path.to_string(),
        keyVersion: LATEST_MPC_KEY_VERSION,
        algo: algo.to_string(),
        dest: dest.to_string(),
        params: params.to_string(),
    };

    let pending = contract
        .sign(request)
        .to(contract_address)
        .value(U256::from(1_u64))
        .send()
        .await?;
    let receipt = pending.get_receipt().await?;
    let from_block = receipt
        .block_number
        .context("missing block number in receipt")?;

    let expected_request_id = eth::compute_request_id(
        requester,
        payload,
        path,
        LATEST_MPC_KEY_VERSION,
        U256::from(chain_id),
        algo,
        dest,
        params,
    );

    let signature_responded_topic = alloy::primitives::keccak256(
        "SignatureResponded(bytes32,address,((uint256,uint256),uint256,uint8))",
    );

    let mut matching_event = None;
    for _ in 0..30 {
        let latest_block = client.get_block_number().await?;
        let filter = Filter::new()
            .address(contract_address)
            .from_block(from_block)
            .to_block(latest_block)
            .event_signature(signature_responded_topic);

        let events = client.get_logs(&filter).await?;
        if let Some(found) = events.into_iter().find_map(|log| {
            alloy::primitives::Log::new(
                log.address(),
                log.topics().to_vec(),
                log.data().data.clone(),
            )
            .and_then(|prim_log| {
                eth::SignatureResponded::decode_log(&prim_log)
                    .ok()
                    .filter(|event| {
                        event.requestId == expected_request_id && event.responder == requester
                    })
            })
        }) {
            matching_event = Some(found);
            break;
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let event =
        matching_event.ok_or_else(|| anyhow!("did not observe signature response on ethereum"))?;

    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&event.signature.bigR.x.to_be_bytes::<32>());
    let mut y_bytes = [0u8; 32];
    y_bytes.copy_from_slice(&event.signature.bigR.y.to_be_bytes::<32>());
    let x_field: &FieldBytes = FieldBytes::from_slice(&x_bytes);
    let y_field: &FieldBytes = FieldBytes::from_slice(&y_bytes);
    let encoded_r = EncodedPoint::from_affine_coordinates(x_field, y_field, false);
    let big_r = AffinePoint::from_encoded_point(&encoded_r)
        .into_option()
        .ok_or_else(|| anyhow!("invalid R component in signature"))?;

    let r_scalar = actions::x_coordinate::<k256::Secp256k1>(&big_r);
    let r_bytes = r_scalar.to_bytes();

    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&event.signature.s.to_be_bytes::<32>());

    let mut signature_bytes = [0u8; 64];
    signature_bytes[..32].copy_from_slice(r_bytes.as_slice());
    signature_bytes[32..].copy_from_slice(&s_bytes);

    let recovered_address =
        actions::recover_eth_address(&payload, &signature_bytes, event.signature.recoveryId);

    let network_public_key = cluster.root_public_key().await?;
    let mut network_pk = vec![0x04];
    network_pk.extend_from_slice(&network_public_key.as_bytes()[1..]);
    let encoded_network_pk =
        EncodedPoint::from_bytes(&network_pk).context("invalid network public key encoding")?;
    let network_affine = AffinePoint::from_encoded_point(&encoded_network_pk)
        .into_option()
        .ok_or_else(|| anyhow!("invalid network public key"))?;

    let sender_hex = format!("0x{}", hex::encode(requester));
    let epsilon = derive_epsilon_eth(LATEST_MPC_KEY_VERSION, &sender_hex, path);
    let user_affine = derive_key(network_affine, epsilon);
    let user_public_key = K256PublicKey::from_affine(user_affine)
        .map_err(|_| anyhow!("invalid derived public key"))?;
    let verifying_key = VerifyingKey::from(&user_public_key);
    let verifying_key = verifying_key.to_encoded_point(false);
    let secp_public_key =
        secp256k1::PublicKey::from_slice(verifying_key.as_bytes()).context("invalid secp key")?;
    let expected_address = actions::public_key_to_address(&secp_public_key);

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

    let (client, requester) = eth::client(&endpoint, &secret_key, chain_id)?;
    let contract = eth::ChainSignatures::new(contract_address, client.clone());

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
        payload: payload.into(),
        path: path.to_string(),
        keyVersion: LATEST_MPC_KEY_VERSION,
        algo: algo.to_string(),
        dest: dest.to_string(),
        params: params.to_string(),
    };

    let pending = contract
        .sign(request)
        .to(contract_address)
        .value(U256::from(1_u64))
        .send()
        .await?;
    let receipt = pending.get_receipt().await?;
    let from_block = receipt
        .block_number
        .context("missing block number in receipt")?;

    let expected_request_id = eth::compute_request_id(
        requester,
        payload,
        path,
        LATEST_MPC_KEY_VERSION,
        U256::from(chain_id),
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

    // Wait for the signature response
    let signature_responded_topic = alloy::primitives::keccak256(
        "SignatureResponded(bytes32,address,((uint256,uint256),uint256,uint8))",
    );

    let mut matching_event = None;
    for _ in 0..30 {
        let latest_block = client.get_block_number().await?;
        let filter = Filter::new()
            .address(contract_address)
            .from_block(from_block)
            .to_block(latest_block)
            .event_signature(signature_responded_topic);

        let events = client.get_logs(&filter).await?;
        if let Some(found) = events.into_iter().find_map(|log| {
            alloy::primitives::Log::new(
                log.address(),
                log.topics().to_vec(),
                log.data().data.clone(),
            )
            .and_then(|prim_log| {
                eth::SignatureResponded::decode_log(&prim_log)
                    .ok()
                    .filter(|event| {
                        event.requestId == expected_request_id && event.responder == requester
                    })
            })
        }) {
            matching_event = Some(found);
            break;
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let _event =
        matching_event.ok_or_else(|| anyhow!("did not observe signature response on ethereum"))?;

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

    let expected_request_bytes: [u8; 32] = expected_request_id.into();
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
    let (eth_client, _requester) = eth::client(
        &eth_ctx.sandbox.external_http_endpoint,
        &eth_ctx.sandbox.secret_key,
        eth_ctx.sandbox.chain_id,
    )?;
    let eth_contract = eth::ChainSignatures::new(eth_ctx.contract_address, eth_client);

    // Produce a few sign requests up front so nodes create initial checkpoints
    for i in 0..5 {
        submit_eth_sign_request(&eth_contract, i).await?;
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
        submit_eth_sign_request(&eth_contract, seed).await?;
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

async fn submit_eth_sign_request<P>(
    contract: &eth::ChainSignatures::ChainSignaturesInstance<P>,
    seed: usize,
) -> anyhow::Result<()>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    let payload = [seed as u8; 32];
    let request = eth::SignRequest {
        payload: payload.into(),
        path: format!("offline_test_{seed}"),
        keyVersion: LATEST_MPC_KEY_VERSION,
        algo: "secp256k1".to_string(),
        dest: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".to_string(),
        params: "{}".to_string(),
    };

    contract
        .sign(request)
        .value(U256::from(1_u64))
        .send()
        .await?
        .get_receipt()
        .await?;

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
