use std::str::FromStr;

use crate::actions::{self, add_latency, wait_for};
use crate::with_multichain_nodes;

use crypto_shared::{self, derive_epsilon, derive_key, x_coordinate, ScalarExt};
use integration_tests_chain_signatures::containers::{self, DockerClient};
use integration_tests_chain_signatures::MultichainConfig;
use k256::elliptic_curve::point::AffineCoordinates;
use mpc_recovery_node::kdf::into_eth_sig;
use mpc_recovery_node::protocol::presignature::PresignatureConfig;
use mpc_recovery_node::protocol::triple::TripleConfig;
use mpc_recovery_node::test_utils;
use mpc_recovery_node::types::LatestBlockHeight;
use mpc_recovery_node::util::NearPublicKeyExt;
use test_log::test;

#[test(tokio::test)]
async fn test_multichain_reshare() -> anyhow::Result<()> {
    let config = MultichainConfig::default();
    with_multichain_nodes(config.clone(), |mut ctx| {
        Box::pin(async move {
            let state = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert!(state.threshold == 2);
            assert!(state.participants.len() == 3);
            assert!(ctx.remove_participant(None).await.is_ok());
            // Going below T should error out
            assert!(ctx.remove_participant(None).await.is_err());
            assert!(ctx.add_participant().await.is_ok());
            assert!(ctx.remove_participant(None).await.is_ok());
            // make sure signing works after reshare
            let new_state = wait_for::running_mpc(&ctx, None).await?;
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            actions::single_signature_production(&ctx, &new_state).await
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_triples_and_presignatures() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_signature_basic() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            actions::single_signature_rogue_responder(&ctx, &state_0).await
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_signature_offline_node() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |mut ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 6).await?;
            wait_for::has_at_least_mine_triples(&ctx, 2).await?;

            // Kill the node then have presignature and signature generation only use the active set of nodes
            // to start generating presignatures and signatures.
            let account_id = near_workspaces::types::AccountId::from_str(
                state_0.participants.keys().last().unwrap().clone().as_ref(),
            )
            .unwrap();
            ctx.nodes.kill_node(&account_id).await?;

            // This could potentially fail and timeout the first time if the participant set picked up is the
            // one with the offline node. This is expected behavior for now if a user submits a request in between
            // a node going offline and the system hasn't detected it yet.
            let presig_res = wait_for::has_at_least_mine_presignatures(&ctx, 1).await;
            let sig_res = actions::single_signature_production(&ctx, &state_0).await;

            // Try again if the first attempt failed. This second portion should not be needed when the NEP
            // comes in for resumeable MPC.
            if presig_res.is_err() || sig_res.is_err() {
                // Retry if the first attempt failed.
                wait_for::has_at_least_mine_presignatures(&ctx, 1).await?;
                actions::single_signature_production(&ctx, &state_0).await?;
            }

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
#[ignore = "This test is too slow to run in CI"]
async fn test_signature_large_stockpile() -> anyhow::Result<()> {
    const SIGNATURE_AMOUNT: usize = 10;
    const NODES: usize = 8;
    const THRESHOLD: usize = 4;
    const MIN_TRIPLES: usize = 10;
    const MAX_TRIPLES: usize = 2 * NODES * MIN_TRIPLES;

    let triple_cfg = TripleConfig {
        // This is the min triples required by each node.
        min_triples: MIN_TRIPLES,
        // This is the total amount of triples that will be generated by all nodes.
        max_triples: MAX_TRIPLES,
        // This is the amount each node can introduce a triple generation protocol into the system.
        max_concurrent_introduction: 4,
        // This is the maximum amount of triples that can be generated concurrently by the whole system.
        max_concurrent_generation: 24,
    };
    let presig_cfg = PresignatureConfig {
        // this is the min presignatures required by each node
        min_presignatures: 10,
        // This is the total amount of presignatures that will be generated by all nodes.
        max_presignatures: 1000,
    };

    let config = MultichainConfig {
        triple_cfg,
        presig_cfg,
        nodes: NODES,
        threshold: THRESHOLD,
    };

    with_multichain_nodes(config, |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), NODES);
            wait_for::has_at_least_triples(&ctx, triple_cfg.min_triples).await?;
            wait_for::has_at_least_presignatures(&ctx, SIGNATURE_AMOUNT).await?;

            for _ in 0..SIGNATURE_AMOUNT {
                actions::single_signature_production(&ctx, &state_0).await?;
            }
            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_key_derivation() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 6).await?;
            wait_for::has_at_least_presignatures(&ctx, 3).await?;

            for _ in 0..3 {
                let mpc_pk: k256::AffinePoint = state_0.public_key.clone().into_affine_point();
                let (_, payload_hashed, account, tx_hash) = actions::request_sign(&ctx).await?;
                let sig = wait_for::signature_responded(&ctx, tx_hash).await?;

                let hd_path = "test";
                let derivation_epsilon = derive_epsilon(account.id(), hd_path);
                let user_pk = derive_key(mpc_pk, derivation_epsilon);
                let multichain_sig = into_eth_sig(
                    &user_pk,
                    &sig.big_r,
                    &sig.s,
                    k256::Scalar::from_bytes(&payload_hashed),
                )
                .unwrap();

                // start recovering the address and compare them:
                let user_pk_x = x_coordinate(&user_pk);
                let user_pk_y_parity = match user_pk.y_is_odd().unwrap_u8() {
                    1 => secp256k1::Parity::Odd,
                    0 => secp256k1::Parity::Even,
                    _ => unreachable!(),
                };
                let user_pk_x =
                    secp256k1::XOnlyPublicKey::from_slice(&user_pk_x.to_bytes()).unwrap();
                let user_secp_pk =
                    secp256k1::PublicKey::from_x_only_public_key(user_pk_x, user_pk_y_parity);
                let user_addr = actions::public_key_to_address(&user_secp_pk);
                let r = x_coordinate(&multichain_sig.big_r.affine_point);
                let s = multichain_sig.s;
                let signature_for_recovery: [u8; 64] = {
                    let mut signature = [0u8; 64];
                    signature[..32].copy_from_slice(&r.to_bytes());
                    signature[32..].copy_from_slice(&s.scalar.to_bytes());
                    signature
                };
                let recovered_addr = web3::signing::recover(
                    &payload_hashed,
                    &signature_for_recovery,
                    multichain_sig.recovery_id as i32,
                )
                .unwrap();
                assert_eq!(user_addr, recovered_addr);
            }

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_triples_persistence_for_generation() -> anyhow::Result<()> {
    let docker_client = DockerClient::default();
    let gcp_project_id = "test-triple-persistence";
    let docker_network = "test-triple-persistence";
    docker_client.create_network(docker_network).await?;
    let datastore =
        containers::Datastore::run(&docker_client, docker_network, gcp_project_id).await?;
    let datastore_url = datastore.local_address.clone();
    // verifies that @triple generation, the datastore triples are in sync with local generated triples
    test_utils::test_triple_generation(Some(datastore_url.clone())).await;
    Ok(())
}

#[test(tokio::test)]
async fn test_triples_persistence_for_deletion() -> anyhow::Result<()> {
    let docker_client = DockerClient::default();
    let gcp_project_id = "test-triple-persistence";
    let docker_network = "test-triple-persistence";
    docker_client.create_network(docker_network).await?;
    let datastore =
        containers::Datastore::run(&docker_client, docker_network, gcp_project_id).await?;
    let datastore_url = datastore.local_address.clone();
    // verifies that @triple deletion, the datastore is working as expected
    test_utils::test_triple_deletion(Some(datastore_url)).await;
    Ok(())
}

#[test(tokio::test)]
async fn test_latest_block_height() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;

            let gcp_services = ctx.nodes.gcp_services().await?;
            for gcp_service in &gcp_services {
                let latest = LatestBlockHeight::fetch(gcp_service).await?;
                assert!(latest.block_height > 10);
            }

            // test manually updating the latest block height
            let gcp_service = gcp_services[0].clone();
            let latest = LatestBlockHeight {
                account_id: gcp_service.account_id.clone(),
                block_height: 1000,
            };
            latest.store(&gcp_service).await?;
            let new_latest = LatestBlockHeight::fetch(&gcp_service).await?;
            assert_eq!(new_latest.block_height, latest.block_height);

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_signature_offline_node_back_online() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |mut ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 6).await?;
            wait_for::has_at_least_mine_triples(&ctx, 2).await?;

            // Kill the node then have presignature and signature generation only use the active set of nodes
            // to start generating presignatures and signatures.
            let account_id = near_workspaces::types::AccountId::from_str(
                state_0.participants.keys().last().unwrap().clone().as_ref(),
            )
            .unwrap();
            let killed_node_config = ctx.nodes.kill_node(&account_id).await?;

            // This could potentially fail and timeout the first time if the participant set picked up is the
            // one with the offline node. This is expected behavior for now if a user submits a request in between
            // a node going offline and the system hasn't detected it yet.
            let presig_res = wait_for::has_at_least_mine_presignatures(&ctx, 1).await;
            let sig_res = actions::single_signature_production(&ctx, &state_0).await;

            // Try again if the first attempt failed. This second portion should not be needed when the NEP
            // comes in for resumeable MPC.
            if presig_res.is_err() || sig_res.is_err() {
                // Retry if the first attempt failed.
                wait_for::has_at_least_mine_presignatures(&ctx, 1).await?;
                actions::single_signature_production(&ctx, &state_0).await?;
            }

            // Start the killed node again
            ctx.nodes.restart_node(killed_node_config).await?;

            wait_for::has_at_least_mine_triples(&ctx, 2).await?;
            wait_for::has_at_least_mine_presignatures(&ctx, 1).await?;
            // retry the same payload multiple times because we might pick a presignature that is not present in node 2 initially
            actions::single_payload_signature_production(&ctx, &state_0).await?;

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_lake_congestion() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |ctx| {
        Box::pin(async move {
            // Currently, with a 10+-1 latency it cannot generate enough tripplets in time
            // with a 5+-1 latency it fails to wait for signature response
            add_latency("lake-rpc", true, 1.0, 2_000, 200).await?;
            // Also mock lake indexer in high load that it becomes slower to finish process
            // sig req and write to s3
            // with a 1s latency it fails to wait for signature response in time
            add_latency("lake-s3", false, 1.0, 100, 10).await?;

            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            actions::single_signature_rogue_responder(&ctx, &state_0).await?;
            Ok(())
        })
    })
    .await
}
