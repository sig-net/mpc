use anyhow::{anyhow, Context, Result};
use ethers::providers::Middleware;
use ethers::types::{Address, BlockNumber, TransactionRequest, U256};
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
    let contract = eth::ChainSignaturesContract::new(contract_address, client.clone());

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

    let call = contract.sign(request).value(U256::from(1_u64));
    let pending = call.send().await?;
    let receipt = pending.await?.context("sign transaction failed")?;
    let from_block = BlockNumber::Number(
        receipt
            .block_number
            .context("missing block number in receipt")?,
    );

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

    let mut matching_event = None;
    for _ in 0..30 {
        let events = contract
            .event::<eth::SignatureRespondedFilter>()
            .from_block(from_block)
            .query()
            .await?;
        if let Some(event) = events.into_iter().find(|event| {
            event.request_id == expected_request_id[..] && event.responder == requester
        }) {
            matching_event = Some(event);
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let event =
        matching_event.ok_or_else(|| anyhow!("did not observe signature response on ethereum"))?;

    let mut x_bytes = [0u8; 32];
    event.signature.big_r.x.to_big_endian(&mut x_bytes);
    let mut y_bytes = [0u8; 32];
    event.signature.big_r.y.to_big_endian(&mut y_bytes);
    let x_field: &FieldBytes = FieldBytes::from_slice(&x_bytes);
    let y_field: &FieldBytes = FieldBytes::from_slice(&y_bytes);
    let encoded_r = EncodedPoint::from_affine_coordinates(x_field, y_field, false);
    let big_r = AffinePoint::from_encoded_point(&encoded_r)
        .into_option()
        .ok_or_else(|| anyhow!("invalid R component in signature"))?;

    let r_scalar = actions::x_coordinate::<k256::Secp256k1>(&big_r);
    let r_bytes = r_scalar.to_bytes();

    let mut s_bytes = [0u8; 32];
    event.signature.s.to_big_endian(&mut s_bytes);

    let mut signature_bytes = [0u8; 64];
    signature_bytes[..32].copy_from_slice(r_bytes.as_slice());
    signature_bytes[32..].copy_from_slice(&s_bytes);

    let recovered_address =
        actions::recover_eth_address(&payload, &signature_bytes, event.signature.recovery_id);

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
    let expected_address = ethers::utils::public_key_to_address(&verifying_key);

    anyhow::ensure!(
        recovered_address == expected_address,
        "signature recovered address mismatch: expected {expected_address:?}, got {recovered_address:?}"
    );

    Ok(())
}

/// Test that checkpoints are properly cleaned up after responses are observed
#[test(tokio::test)]
async fn test_proper_indexer_checkpoint() -> Result<()> {
    for (name, value) in Chain::checkpoint_env_vars() {
        std::env::set_var(name, value);
    }

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
    let contract = eth::ChainSignaturesContract::new(contract_address, client.clone());

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

    let call = contract.sign(request).value(U256::from(1_u64));
    let pending = call.send().await?;
    let receipt = pending.await?.context("sign transaction failed")?;
    let from_block = BlockNumber::Number(
        receipt
            .block_number
            .context("missing block number in receipt")?,
    );

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
    let checkpoint_height_after_request = checkpoint.block_height;
    let checkpoint_interval = Chain::Ethereum
        .checkpoint_interval()
        .expect("ethereum checkpoint interval should be configured");
    tracing::info!(
        checkpoint_height_after_request,
        checkpoint_interval,
        pending_count = checkpoint.pending_requests.len(),
        "pending transactions in checkpoint"
    );

    // Wait for the signature response
    let mut matching_event = None;
    for _ in 0..30 {
        let events = contract
            .event::<eth::SignatureRespondedFilter>()
            .from_block(from_block)
            .query()
            .await?;
        if let Some(event) = events.into_iter().find(|event| {
            event.request_id == expected_request_id[..] && event.responder == requester
        }) {
            matching_event = Some(event);
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let _event =
        matching_event.ok_or_else(|| anyhow!("did not observe signature response on ethereum"))?;

    tracing::info!("signature response observed on-chain");

    // Checkpoints are emitted on interval boundaries. Produce enough non-contract
    // empty transfers so Anvil mines blocks and the indexer can publish the next
    // checkpoint after the response has been observed.
    produce_empty_eth_blocks(&client, checkpoint_interval).await?;

    let min_next_checkpoint_height =
        ((checkpoint_height_after_request / checkpoint_interval) + 1) * checkpoint_interval;
    let checkpoint = wait_node_checkpoint(
        &cluster,
        node_idx,
        Chain::Ethereum,
        min_next_checkpoint_height,
        Duration::from_secs(60),
    )
    .await?;

    tracing::info!(?checkpoint, "checkpoint after crossing checkpoint interval");
    tracing::info!(
        pending_count = checkpoint.pending_requests.len(),
        "pending transactions count after response"
    );

    let expected_request_bytes = expected_request_id.as_bytes();
    let request_still_present = checkpoint
        .pending_requests
        .iter()
        .any(|tx| tx.sign_id.request_id == *expected_request_bytes);

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
    let eth_contract = eth::ChainSignaturesContract::new(eth_ctx.contract_address, eth_client);

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

    anyhow::ensure!(
        node_recovered_checkpoint.block_height >= node_active_checkpoint.block_height,
        "restarted node should recover to at least the active checkpoint height via consensus"
    );

    let (active_checkpoint_after_restart, recovered_checkpoint_after_restart) =
        wait_matching_node_checkpoints(
            &cluster,
            active_idx,
            offline_idx,
            Chain::Ethereum,
            node_recovered_checkpoint
                .block_height
                .max(node_active_checkpoint.block_height),
            Duration::from_secs(20),
        )
        .await?;

    assert_eq!(
        active_checkpoint_after_restart, recovered_checkpoint_after_restart,
        "restarted node should converge to the same checkpoint as the active node via consensus"
    );

    let active_checkpoint_after_restart = wait_node_checkpoint(
        &cluster,
        active_idx,
        Chain::Ethereum,
        active_checkpoint_after_restart.block_height,
        Duration::from_secs(10),
    )
    .await?;

    assert!(
        active_checkpoint_after_restart.block_height
            >= recovered_checkpoint_after_restart.block_height,
        "active node checkpoint should not fall behind after peer recovery"
    );

    Ok(())
}

async fn submit_eth_sign_request(
    contract: &eth::ChainSignaturesContract<eth::SandboxMiddleware>,
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

    contract
        .sign(request)
        .value(U256::from(1_u64))
        .send()
        .await?
        .await?
        .context("sign transaction failed")?;

    Ok(())
}

async fn produce_empty_eth_blocks(
    client: &std::sync::Arc<eth::SandboxMiddleware>,
    block_count: u64,
) -> anyhow::Result<()> {
    // Use a non-contract sink address so these transactions only advance block height.
    let sink = Address::from_low_u64_be(0xdead_beef);

    for _ in 0..block_count {
        let tx = TransactionRequest::new()
            .to(sink)
            .value(U256::zero())
            .gas(U256::from(21_000_u64));

        client
            .send_transaction(tx, None)
            .await?
            .await?
            .context("empty block-pumping transaction failed")?;
    }

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

async fn wait_matching_node_checkpoints(
    nodes: &Cluster,
    left_idx: usize,
    right_idx: usize,
    chain: Chain,
    min_block_height: u64,
    timeout: Duration,
) -> anyhow::Result<(Checkpoint, Checkpoint)> {
    tokio::time::timeout(timeout, async {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;

            let left = nodes.fetch_checkpoints(left_idx).await?;
            let right = nodes.fetch_checkpoints(right_idx).await?;

            let Some(left_checkpoint) = left.get(&chain).cloned() else {
                continue;
            };
            let Some(right_checkpoint) = right.get(&chain).cloned() else {
                continue;
            };

            if left_checkpoint.block_height < min_block_height
                || right_checkpoint.block_height < min_block_height
            {
                continue;
            }

            if left_checkpoint == right_checkpoint {
                return Ok((left_checkpoint, right_checkpoint));
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "timed out waiting for nodes {left_idx} and {right_idx} to converge on checkpoint >= {min_block_height}"
        )
    })
}
