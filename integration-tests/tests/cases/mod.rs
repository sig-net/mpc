use integration_tests::actions::{self, add_latency};
use integration_tests::cluster;

use k256::elliptic_curve::point::AffineCoordinates;
use mpc_contract::config::Config;
use mpc_contract::update::ProposeUpdateArgs;
use mpc_crypto::{self, derive_epsilon_near, derive_key, x_coordinate, ScalarExt};
use mpc_node::kdf::into_eth_sig;
use mpc_node::util::NearPublicKeyExt as _;
use test_log::test;

pub mod nightly;
pub mod store;
pub mod sync;

#[test(tokio::test)]
async fn test_multichain_reshare() -> anyhow::Result<()> {
    let mut nodes = cluster::spawn().disable_prestockpile().await?;

    nodes.wait().signable().await?;
    let _ = nodes.sign().await?;

    tracing::info!("!!! Add participant 3");
    nodes.join(None).await.unwrap();
    let _state = nodes.wait().running().signable().await.unwrap();
    let _ = nodes.sign().await.unwrap();

    tracing::info!("!!! Remove participant 0 and participant 2");
    let account_2 = nodes.account_id(2).clone();
    nodes.leave(Some(&account_2)).await.unwrap();
    let account_0 = nodes.account_id(0).clone();
    let node_cfg_0 = nodes.leave(Some(&account_0)).await.unwrap();
    nodes.wait().running().signable().await.unwrap();
    let _ = nodes.sign().await.unwrap();

    tracing::info!("!!! Try remove participant 3, should fail due to threshold");
    nodes.leave(None).await.unwrap_err();

    tracing::info!("!!! Add participant 5");
    nodes.join(None).await.unwrap();
    nodes.wait().running().signable().await.unwrap();
    let _ = nodes.sign().await.unwrap();

    tracing::info!("!!! Add back participant 0");
    nodes.join(Some(node_cfg_0)).await.unwrap();
    nodes.wait().running().signable().await.unwrap();
    let _ = nodes.sign().await.unwrap();

    Ok(())
}

#[test(tokio::test)]
async fn test_signature_basic() -> anyhow::Result<()> {
    let nodes = cluster::spawn().nodes(5).disable_prestockpile().await?;
    nodes.wait().signable().await?;
    nodes.sign().await?;

    Ok(())
}

#[test(tokio::test)]
async fn test_signature_rogue() -> anyhow::Result<()> {
    let nodes = cluster::spawn().await?;
    nodes.wait().signable().await?;
    nodes.sign().rogue_responder().await?;

    Ok(())
}

#[test(tokio::test)]
async fn test_signature_many() -> anyhow::Result<()> {
    let nodes = cluster::spawn()
        .disable_prestockpile()
        .with_config(|config| {
            config.protocol.presignature.min_presignatures = 10;
            config.protocol.presignature.max_presignatures = 100;
        })
        .await?;

    for idx in 0..10 {
        tracing::info!(idx, "producing signature");
        nodes.wait().signable().await?;
        nodes.sign().await?;
    }

    Ok(())
}

#[test(tokio::test)]
async fn test_signature_offline_node() -> anyhow::Result<()> {
    let mut nodes = cluster::spawn().await?;
    nodes.wait().signable().await?;
    let _ = nodes.sign().await?;

    // Kill the node then have presignatures and signature generation only use the active set of nodes
    // to start generating presignatures and signatures.
    let account_id = nodes.account_ids().into_iter().next_back().unwrap().clone();
    nodes.stop(&account_id).await.unwrap();

    nodes.wait().signable().await.unwrap();
    let outcome = nodes.sign().await.unwrap();
    dbg!(outcome);

    Ok(())
}

#[test(tokio::test)]
async fn test_key_derivation() -> anyhow::Result<()> {
    let nodes = cluster::spawn().await?;

    let hd_path = "test";
    let mpc_pk: k256::AffinePoint = nodes.root_public_key().await?.into_affine_point();
    for _ in 0..3 {
        nodes.wait().signable().await?;
        let outcome = nodes.sign().path(hd_path).await?;

        let derivation_epsilon = derive_epsilon_near(outcome.account.id(), hd_path);
        let user_pk = derive_key(mpc_pk, derivation_epsilon);
        let multichain_sig = into_eth_sig(
            &user_pk,
            &outcome.signature.big_r,
            &outcome.signature.s,
            k256::Scalar::from_bytes(outcome.payload_hash).unwrap(),
        )
        .unwrap();

        // start recovering the address and compare them:
        let user_pk_x = x_coordinate(&user_pk);
        let user_pk_y_parity = match user_pk.y_is_odd().unwrap_u8() {
            1 => secp256k1::Parity::Odd,
            0 => secp256k1::Parity::Even,
            _ => unreachable!(),
        };
        let user_pk_x = secp256k1::XOnlyPublicKey::from_slice(&user_pk_x.to_bytes()).unwrap();
        let user_secp_pk =
            secp256k1::PublicKey::from_x_only_public_key(user_pk_x, user_pk_y_parity);
        let user_addr = actions::public_key_to_address(&user_secp_pk);
        let r = x_coordinate(&multichain_sig.big_r);
        let s = multichain_sig.s;
        let signature_for_recovery: [u8; 64] = {
            let mut signature = [0u8; 64];
            signature[..32].copy_from_slice(&r.to_bytes());
            signature[32..].copy_from_slice(&s.to_bytes());
            signature
        };
        let recovered_addr = web3::signing::recover(
            &outcome.payload_hash,
            &signature_for_recovery,
            multichain_sig.recovery_id as i32,
        )
        .unwrap();
        assert_eq!(user_addr, recovered_addr);
    }

    Ok(())
}

#[test(tokio::test)]
async fn test_signature_offline_node_back_online() -> anyhow::Result<()> {
    let mut nodes = cluster::spawn().await?;
    nodes.wait().signable().await?;
    let _ = nodes.sign().await?;

    // Kill node 2
    let account_id = nodes.account_id(2).clone();
    let killed = nodes.kill_node(&account_id).await;

    // Start the killed node again
    nodes.restart_node(killed).await?;

    // Check that we can sign again
    nodes.wait().signable().await?;
    let _ = nodes.sign().await?;

    Ok(())
}

#[test(tokio::test)]
async fn test_lake_congestion() -> anyhow::Result<()> {
    let nodes = cluster::spawn().enable_toxiproxy().await?;
    // Currently, with a 10+-1 latency it cannot generate enough tripplets in time
    // with a 5+-1 latency it fails to wait for signature response
    add_latency(&nodes.nodes.proxy_name_for_node(0), true, 1.0, 2_000, 200).await?;
    add_latency(&nodes.nodes.proxy_name_for_node(1), true, 1.0, 2_000, 200).await?;
    add_latency(&nodes.nodes.proxy_name_for_node(2), true, 1.0, 2_000, 200).await?;

    // Also mock lake indexer in high load that it becomes slower to finish process
    // sig req and write to s3
    // with a 1s latency it fails to wait for signature response in time
    add_latency("lake-s3", false, 1.0, 100, 10).await?;

    nodes.wait().running().signable().await?;
    nodes.sign().await.unwrap();

    Ok(())
}

#[test(tokio::test)]
async fn test_multichain_reshare_with_lake_congestion() -> anyhow::Result<()> {
    let mut nodes = cluster::spawn().enable_toxiproxy().await?;

    // add latency to node1->rpc, but not node0->rpc
    add_latency(&nodes.nodes.proxy_name_for_node(1), true, 1.0, 1_000, 100).await?;
    // remove node2, node0 and node1 should still reach concensus
    // this fails if the latency above is too long (10s)
    nodes.leave(None).await.unwrap();

    let state = nodes.expect_running().await?;
    assert!(state.participants.len() == 2);

    // Going below T should error out
    nodes.leave(None).await.unwrap_err();
    let state = nodes.expect_running().await?;
    assert!(state.participants.len() == 2);

    nodes.join(None).await.unwrap();
    // add latency to node2->rpc
    add_latency(&nodes.nodes.proxy_name_for_node(2), true, 1.0, 1_000, 100).await?;
    let state = nodes.expect_running().await?;
    assert!(state.participants.len() == 3);

    nodes.leave(None).await.unwrap();
    let state = nodes.expect_running().await?;
    assert!(state.participants.len() == 2);

    // make sure signing works after reshare
    nodes.wait().signable().await?;
    nodes.sign().await.unwrap();

    Ok(())
}

#[test(tokio::test)]
async fn test_multichain_update_contract() -> anyhow::Result<()> {
    let nodes = cluster::spawn().await?;
    nodes.wait().signable().await?;
    nodes.sign().await.unwrap();

    // Perform update to the contract and see that the nodes are still properly running and picking
    // up the new contract by first upgrading the contract, then trying to generate a new signature.
    let id = nodes.propose_update_contract_default().await;
    nodes.vote_update(id).await;
    nodes.wait().signable().await?;
    nodes.sign().await.unwrap();

    // Now do a config update and see if that also updates the same:
    let id = nodes
        .propose_update(ProposeUpdateArgs {
            code: None,
            config: Some(Config::default()),
        })
        .await;
    nodes.vote_update(id).await;
    nodes.wait().signable().await?;
    nodes.sign().await.unwrap();

    Ok(())
}

#[test(tokio::test)]
async fn test_batch_random_signature() -> anyhow::Result<()> {
    let nodes = cluster::spawn().await?;
    actions::batch_random_signature_production(&nodes).await?;
    Ok(())
}

#[test(tokio::test)]
async fn test_batch_duplicate_signature() -> anyhow::Result<()> {
    let nodes = cluster::spawn().await?;
    actions::batch_duplicate_signature_production(&nodes).await?;
    Ok(())
}
