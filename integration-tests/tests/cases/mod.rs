use integration_tests::actions;
use integration_tests::cluster;
use integration_tests::utils;

use k256::elliptic_curve::point::AffineCoordinates;
use mpc_contract::config::Config;
use mpc_contract::update::ProposeUpdateArgs;
use mpc_crypto::{self, derive_epsilon_near, derive_key, x_coordinate, ScalarExt};
use mpc_node::kdf::into_eth_sig;
use mpc_node::protocol::cryptography::set_resharing_running_timeout;
use mpc_node::protocol::state::ResharingStatus;
use mpc_node::util::NearPublicKeyExt as _;
use mpc_node::web::StateView;
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use std::time::{Duration, Instant};
use test_log::test;

pub mod chains;
pub mod compat;
pub mod ethereum;
pub mod ethereum_stream;
pub mod helpers;
pub mod mpc;
pub mod nightly;
pub mod solana;
pub mod solana_stream;
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
    let nodes = cluster::spawn().await?;
    nodes.wait().signable().await?;
    nodes.sign().await?;

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

        let derivation_epsilon =
            derive_epsilon_near(LATEST_MPC_KEY_VERSION, outcome.account.id(), hd_path);
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
        let recovered_addr = actions::recover_eth_address(
            &outcome.payload_hash,
            &signature_for_recovery,
            multichain_sig.recovery_id,
        );
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

#[test(tokio::test)]
async fn test_resharing_offline_participant_recovers() -> anyhow::Result<()> {
    // have a short timeout for the resharing to complete in tests
    set_resharing_running_timeout(Duration::from_secs(20));

    let mut nodes = cluster::spawn().disable_prestockpile().await?;
    nodes.wait().signable().await?;
    let initial_state = nodes.expect_running().await?;
    let initial_epoch = initial_state.epoch;

    // Shutdown the node that will be offline during the resharing initially.
    // This node will not appear in our local cluster list but still be a part of the
    // contract participants. Meaning they're not kicked, just offline for resharing.
    // They will have to restart later for resharing to complete.
    let offline_account = nodes.account_id(0).clone();
    let offline_config = nodes.kill_node(&offline_account).await;

    // Start a new node that will be added during the resharing.
    let new_account = nodes.start(None).await?;

    // Voting in the new participant with threshold number of online participants
    let participant_accounts = nodes.participant_accounts().await?;
    let voters = participant_accounts
        .into_iter()
        .filter(|account| account.id() != &offline_account)
        .take(nodes.cfg.threshold)
        .collect::<Vec<_>>();
    utils::vote_join(&voters, nodes.contract().id(), new_account.id()).await?;

    // Wait for all online nodes to move to resharing state.
    nodes.wait().nodes_resharing().await?;

    // Now we should wait to see that we are still in the resharing state even after
    // a long time, since one participant is offline and cannot complete the resharing.
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert!(matches!(
        nodes.contract_state().await?,
        mpc_contract::ProtocolContractState::Resharing(_)
    ));

    // Restart the node that was offline during the resharing.
    nodes.restart_node(offline_config).await?;

    // We should now be able to complete the resharing.
    let final_state = nodes
        .wait()
        .running_on_epoch(initial_epoch + 1)
        .nodes_running()
        .await?;

    assert_eq!(
        final_state.participants.len(),
        initial_state.participants.len() + 1
    );
    assert!(final_state.participants.contains_key(new_account.id()));

    // sign to ensure everything is working
    nodes.wait().signable().await?;
    nodes.sign().await?;

    Ok(())
}

#[test(tokio::test)]
async fn test_resharing_running_participant_restart() -> anyhow::Result<()> {
    set_resharing_running_timeout(Duration::from_secs(20));

    let mut nodes = cluster::spawn().disable_prestockpile().await?;
    nodes.wait().signable().await?;
    let initial_state = nodes.expect_running().await?;
    let initial_epoch = initial_state.epoch;

    let target_account = nodes.account_id(0).clone();

    let new_account = nodes.start(None).await?;

    let participant_accounts = nodes.participant_accounts().await?;
    let voters = participant_accounts
        .iter()
        .take(nodes.cfg.threshold)
        .cloned()
        .collect::<Vec<_>>();
    utils::vote_join(&voters, nodes.contract().id(), new_account.id()).await?;

    nodes.wait().nodes_resharing().await?;

    {
        let states = nodes.fetch_states().await?;
        for (account_id, state) in nodes.account_ids().into_iter().zip(states.iter()) {
            match state {
                StateView::Resharing { phase, .. } => {
                    tracing::info!(%account_id, ?phase, "account resharing phase before kill");
                }
                other => {
                    tracing::info!(%account_id, ?other, "account state before kill");
                }
            }
        }
    }

    wait_for_resharing_phase(
        &nodes,
        &target_account,
        &[ResharingStatus::Running],
        Duration::from_secs(20),
        false,
    )
    .await?;

    let target_config = nodes.kill_node(&target_account).await;

    assert!(matches!(
        nodes.contract_state().await?,
        mpc_contract::ProtocolContractState::Resharing(_)
    ));

    nodes.restart_node(target_config).await?;

    wait_for_resharing_phase(
        &nodes,
        &target_account,
        &[ResharingStatus::Running],
        Duration::from_secs(20),
        true,
    )
    .await?;

    {
        let states = nodes.fetch_states().await?;
        for (account_id, state) in nodes.account_ids().into_iter().zip(states.iter()) {
            match state {
                StateView::Resharing { phase, .. } => {
                    tracing::info!(%account_id, ?phase, "account resharing phase after restart");
                }
                other => {
                    tracing::info!(%account_id, ?other, "account state after restart");
                }
            }
        }
    }

    let final_state = nodes
        .wait()
        .running_on_epoch(initial_epoch + 1)
        .nodes_running()
        .await?;

    assert_eq!(
        final_state.participants.len(),
        initial_state.participants.len() + 1
    );
    assert!(final_state.participants.contains_key(new_account.id()));

    nodes.wait().signable().await?;
    nodes.sign().await?;

    Ok(())
}

#[test(tokio::test)]
async fn test_resharing_possible_with_kicked_node_offline() -> anyhow::Result<()> {
    set_resharing_running_timeout(Duration::from_secs(20));

    let mut nodes = cluster::spawn().disable_prestockpile().await?;
    nodes.wait().signable().await?;
    let initial_state = nodes.expect_running().await?;

    let kick_account = nodes.account_id(1).clone();

    // set the node that is getting kicked offline
    let _ = nodes.kill_node(&kick_account).await;

    // kick node
    let participant_accounts = nodes.participant_accounts().await?;
    let voting_accounts = participant_accounts
        .into_iter()
        .filter(|account| account.id() != &kick_account)
        .take(initial_state.threshold)
        .collect::<Vec<_>>();
    utils::vote_leave(&voting_accounts, nodes.contract().id(), &kick_account).await?;

    // ensure that the kicked node is not a participant anymore
    let final_state = nodes
        .wait()
        .running_on_epoch(initial_state.epoch + 1)
        .await?;
    assert_eq!(
        final_state.participants.len(),
        initial_state.participants.len() - 1
    );
    assert!(!final_state.participants.contains_key(&kick_account));

    // sign to ensure everything is working
    nodes.wait().signable().await?;
    nodes.sign().await?;

    Ok(())
}

async fn wait_for_resharing_phase(
    nodes: &cluster::Cluster,
    account_id: &near_workspaces::AccountId,
    expected: &[ResharingStatus],
    timeout: Duration,
    allow_completion: bool,
) -> anyhow::Result<()> {
    let start = Instant::now();
    let allow_completion = allow_completion && expected.contains(&ResharingStatus::Running);
    loop {
        if let Some(idx) = nodes
            .account_ids()
            .iter()
            .position(|current| *current == account_id)
        {
            match nodes.fetch_state(idx).await? {
                StateView::Resharing { phase, .. } if expected.contains(&phase) => return Ok(()),
                StateView::Running { .. } if allow_completion => {
                    tracing::info!(
                        %account_id,
                        "node already returned to running state; treating as successful resharing phase"
                    );
                    return Ok(());
                }
                StateView::Resharing { phase, .. } => {
                    tracing::info!(
                        %account_id,
                        ?phase,
                        ?expected,
                        "node resharing phase does not yet match expectation"
                    );
                }
                state => {
                    tracing::info!(?state, %account_id, "node not yet in expected resharing phase");
                }
            }
        } else {
            tracing::info!(%account_id, "account not currently tracked in cluster while waiting for resharing phase");
        }

        if start.elapsed() > timeout {
            anyhow::bail!(
                "timed out waiting for {account_id} to reach resharing phase in {expected:?}"
            );
        }

        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
