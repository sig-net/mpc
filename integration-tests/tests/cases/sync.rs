use std::time::Duration;

use cait_sith::protocol::Participant;
use cait_sith::triples::{TriplePub, TripleShare};
use cait_sith::PresignOutput;
use elliptic_curve::CurveArithmetic;
use integration_tests::cluster;
use k256::Secp256k1;

use integration_tests::cluster::spawner::ClusterSpawner;
use mpc_node::mesh::Mesh;
use mpc_node::node_client::{self, NodeClient};
use mpc_node::protocol::contract::primitives::Participants;
use mpc_node::protocol::contract::RunningContractState;
use mpc_node::protocol::presignature::Presignature;
use mpc_node::protocol::sync::{SyncTask, SyncUpdate};
use mpc_node::protocol::triple::Triple;
use mpc_node::protocol::{ParticipantInfo, ProtocolState};
use mpc_node::rpc::ContractStateWatcher;
use mpc_node::storage::{triple_storage::TriplePair, PresignatureStorage, TripleStorage};

#[test_log::test(tokio::test)]
async fn test_state_sync_update() -> anyhow::Result<()> {
    let spawner = ClusterSpawner::default()
        .network("protocol-sync")
        .init_network()
        .await
        .unwrap();

    let redis = spawner.spawn_redis().await;
    let num_nodes = 3;
    let threshold = 2;
    let node0 = Participant::from(0);
    let node1 = Participant::from(1);
    let node2 = Participant::from(2);

    let node0_account_id = "p0_test.near".parse().unwrap();
    let node1_account_id = "p1_test.near".parse().unwrap();
    let node2_account_id = "p2_test.near".parse().unwrap();

    let sk = k256::SecretKey::random(&mut rand::thread_rng());
    let pk = sk.public_key();
    let ping_interval = Duration::from_millis(300);
    let client = NodeClient::new(&node_client::Options::default());
    let participants = participants(num_nodes);

    let node0_triples = redis.triple_storage(&node0_account_id);
    let node0_presignatures = redis.presignature_storage(&node0_account_id);
    let node1_triples = redis.triple_storage(&node1_account_id);
    let node1_presignatures = redis.presignature_storage(&node1_account_id);
    let node2_triples = redis.triple_storage(&node2_account_id);
    let node2_presignatures = redis.presignature_storage(&node2_account_id);

    node0_triples.clear().await;
    node0_presignatures.clear().await;
    node1_triples.clear().await;
    node1_presignatures.clear().await;
    node2_triples.clear().await;
    node2_presignatures.clear().await;

    let running_state = || {
        ProtocolState::Running(RunningContractState {
            epoch: 0,
            public_key: *pk.as_affine(),
            participants: participants.clone(),
            candidates: Default::default(),
            join_votes: Default::default(),
            leave_votes: Default::default(),
            threshold,
        })
    };

    let node0_ctx = start_sync_node(
        &client,
        &node0_account_id,
        node0_triples.clone(),
        node0_presignatures.clone(),
        running_state(),
        ping_interval,
    );
    let node1_ctx = start_sync_node(
        &client,
        &node1_account_id,
        node1_triples.clone(),
        node1_presignatures.clone(),
        running_state(),
        ping_interval,
    );
    let node2_ctx = start_sync_node(
        &client,
        &node2_account_id,
        node2_triples.clone(),
        node2_presignatures.clone(),
        running_state(),
        ping_interval,
    );

    // 9 artifacts in the network. Owner of `id` is `id % 3`.
    // Each node HOLDS all 9 artifacts, but OWNS only 3 by owner metadata.
    for id in 0u64..9u64 {
        let owner = owner_for_id(id);
        for (triples, presignatures) in [
            (&node0_triples, &node0_presignatures),
            (&node1_triples, &node1_presignatures),
            (&node2_triples, &node2_presignatures),
        ] {
            triples
                .reserve(id)
                .await
                .unwrap()
                .insert(dummy_pair(id), owner)
                .await;
            presignatures
                .reserve(id)
                .await
                .unwrap()
                .insert(dummy_presignature(id), owner)
                .await;
        }
    }

    // Initial assertions: each node holds all 9, and each owner has exactly 3 on each holder.
    assert_full_replication_and_ownership(&node0_triples, &node0_presignatures).await;
    assert_full_replication_and_ownership(&node1_triples, &node1_presignatures).await;
    assert_full_replication_and_ownership(&node2_triples, &node2_presignatures).await;

    // Pairwise sync requests: sender i syncs to all other nodes j != i.
    // Since all holders are in sync already, responses must be empty not_found lists.
    let senders = [
        (
            node0,
            &node0_triples,
            &node0_presignatures,
            &node1_ctx.sync_channel,
            &node2_ctx.sync_channel,
        ),
        (
            node1,
            &node1_triples,
            &node1_presignatures,
            &node0_ctx.sync_channel,
            &node2_ctx.sync_channel,
        ),
        (
            node2,
            &node2_triples,
            &node2_presignatures,
            &node0_ctx.sync_channel,
            &node1_ctx.sync_channel,
        ),
    ];

    for (sender, sender_triples, sender_presignatures, rx_a, rx_b) in senders {
        let mut owned_triples = sender_triples.fetch_owned(sender).await;
        owned_triples.sort();
        assert_eq!(owned_triples, owned_ids(sender));

        let mut owned_presignatures = sender_presignatures.fetch_owned(sender).await;
        owned_presignatures.sort();
        assert_eq!(owned_presignatures, owned_ids(sender));

        let update = SyncUpdate {
            from: sender,
            triples: owned_triples,
            presignatures: owned_presignatures,
        };

        let response_a = rx_a.request_update(update.clone()).await?;
        assert!(response_a.triples.is_empty());
        assert!(response_a.presignatures.is_empty());

        let response_b = rx_b.request_update(update).await?;
        assert!(response_b.triples.is_empty());
        assert!(response_b.presignatures.is_empty());
    }

    // Phase 1 final assertions: nothing was removed; all holders still keep all artifacts.
    assert_full_replication_and_ownership(&node0_triples, &node0_presignatures).await;
    assert_full_replication_and_ownership(&node1_triples, &node1_presignatures).await;
    assert_full_replication_and_ownership(&node2_triples, &node2_presignatures).await;

    // Phase 2: node0 loses all triples/presignatures.
    node0_triples.clear().await;
    node0_presignatures.clear().await;

    assert_eq!(node0_triples.len_generated().await, 0);
    assert_eq!(node0_presignatures.len_generated().await, 0);

    // Run pairwise syncs again.
    let senders_after_loss = [
        (
            node0,
            &node0_triples,
            &node0_presignatures,
            &node1_ctx.sync_channel,
            &node2_ctx.sync_channel,
        ),
        (
            node1,
            &node1_triples,
            &node1_presignatures,
            &node0_ctx.sync_channel,
            &node2_ctx.sync_channel,
        ),
        (
            node2,
            &node2_triples,
            &node2_presignatures,
            &node0_ctx.sync_channel,
            &node1_ctx.sync_channel,
        ),
    ];

    for (sender, sender_triples, sender_presignatures, rx_a, rx_b) in senders_after_loss {
        let mut owned_triples = sender_triples.fetch_owned(sender).await;
        owned_triples.sort();

        let mut owned_presignatures = sender_presignatures.fetch_owned(sender).await;
        owned_presignatures.sort();

        let update = SyncUpdate {
            from: sender,
            triples: owned_triples.clone(),
            presignatures: owned_presignatures.clone(),
        };

        let response_a = rx_a.request_update(update.clone()).await?;
        let response_b = rx_b.request_update(update).await?;

        // Node0 has no data anymore, so when others sync to node0, node0 should report all sender-owned ids as not_found.
        if sender == node1 || sender == node2 {
            let expected_owned = owned_ids(sender);
            assert_eq!(response_a.triples, expected_owned);
            assert_eq!(response_a.presignatures, expected_owned);
            assert!(response_b.triples.is_empty());
            assert!(response_b.presignatures.is_empty());
        } else {
            // sender == node0 has no owned data now, so receivers should not report missing sender-owned ids.
            assert!(response_a.triples.is_empty());
            assert!(response_a.presignatures.is_empty());
            assert!(response_b.triples.is_empty());
            assert!(response_b.presignatures.is_empty());
        }
    }

    // node1 and node2 should remove artifacts owned by node0 after syncing with empty node0 update.
    assert_owner_absent(&node1_triples, &node1_presignatures, node0).await;
    assert_owner_absent(&node2_triples, &node2_presignatures, node0).await;

    // Explicit prune checks: each of node1/node2 should keep 6 artifacts total after pruning owner0's 3 ids.
    assert_eq!(node1_triples.len_generated().await, 6);
    assert_eq!(node1_presignatures.len_generated().await, 6);
    assert_eq!(node2_triples.len_generated().await, 6);
    assert_eq!(node2_presignatures.len_generated().await, 6);

    // node1 and node2 must still keep artifacts owned by node1 and node2.
    assert_owner_present(&node1_triples, &node1_presignatures, node1).await;
    assert_owner_present(&node1_triples, &node1_presignatures, node2).await;
    assert_owner_present(&node2_triples, &node2_presignatures, node1).await;
    assert_owner_present(&node2_triples, &node2_presignatures, node2).await;

    // node0 stays empty.
    for id in 0u64..9u64 {
        assert!(!node0_triples.contains(id).await, "node0 should not hold triple={id}");
        assert!(
            !node0_presignatures.contains(id).await,
            "node0 should not hold presignature={id}"
        );
    }

    // Phase 3: node1 loses one node2-owned artifact. node2 syncs, detects low holder count,
    // and removes that owned artifact from its own storage.
    let node2_owned = owned_ids(node2);
    let victim = node2_owned[0];
    let keep_on_node1: Vec<u64> = node2_owned
        .iter()
        .copied()
        .filter(|id| *id != victim)
        .collect();

    // Force node1 to lose one node2-owned triple/presignature.
    node1_ctx
        .sync_channel
        .request_update(SyncUpdate {
            from: node2,
            triples: keep_on_node1.clone(),
            presignatures: keep_on_node1.clone(),
        })
        .await?;

    assert!(!node1_triples.contains_by_owner(victim, node2).await);
    assert!(!node1_presignatures.contains_by_owner(victim, node2).await);

    // Node2 syncs to node0 and node1 and observes what they don't have.
    let response_from_node0 = node0_ctx
        .sync_channel
        .request_update(SyncUpdate {
            from: node2,
            triples: node2_owned.clone(),
            presignatures: node2_owned.clone(),
        })
        .await?;
    let response_from_node1 = node1_ctx
        .sync_channel
        .request_update(SyncUpdate {
            from: node2,
            triples: node2_owned.clone(),
            presignatures: node2_owned.clone(),
        })
        .await?;

    // Compute surviving owner2 ids based on holder count >= threshold.
    // Holders = node2 itself + peers that did NOT report not_found for the id.
    let node0_missing_t: std::collections::HashSet<u64> =
        response_from_node0.triples.into_iter().collect();
    let node1_missing_t: std::collections::HashSet<u64> =
        response_from_node1.triples.into_iter().collect();

    let node0_missing_p: std::collections::HashSet<u64> =
        response_from_node0.presignatures.into_iter().collect();
    let node1_missing_p: std::collections::HashSet<u64> =
        response_from_node1.presignatures.into_iter().collect();

    let keep_node2_triples: Vec<u64> = node2_owned
        .iter()
        .copied()
        .filter(|id| {
            let holders = 1
                + usize::from(!node0_missing_t.contains(id))
                + usize::from(!node1_missing_t.contains(id));
            holders >= threshold
        })
        .collect();

    let keep_node2_presignatures: Vec<u64> = node2_owned
        .iter()
        .copied()
        .filter(|id| {
            let holders = 1
                + usize::from(!node0_missing_p.contains(id))
                + usize::from(!node1_missing_p.contains(id));
            holders >= threshold
        })
        .collect();

    // Apply the prune decision to node2 as owner.
    node2_ctx
        .sync_channel
        .request_update(SyncUpdate {
            from: node2,
            triples: keep_node2_triples.clone(),
            presignatures: keep_node2_presignatures.clone(),
        })
        .await?;

    // victim must be pruned on node2; the other two owner2 ids remain.
    assert!(!node2_triples.contains_by_owner(victim, node2).await);
    assert!(!node2_presignatures.contains_by_owner(victim, node2).await);

    for id in keep_on_node1 {
        assert!(node2_triples.contains_by_owner(id, node2).await);
        assert!(node2_presignatures.contains_by_owner(id, node2).await);
    }

    Ok(())
}

struct SyncNodeCtx {
    sync_channel: mpc_node::protocol::sync::SyncChannel,
}

fn start_sync_node(
    client: &NodeClient,
    account_id: &near_sdk::AccountId,
    triples: TripleStorage,
    presignatures: PresignatureStorage,
    state: ProtocolState,
    ping_interval: Duration,
) -> SyncNodeCtx {
    let (contract_watcher, _contract_tx) = ContractStateWatcher::with(account_id, state);
    let (synced_peer_tx, synced_peer_rx) = SyncTask::synced_nodes_channel();
    let mesh = Mesh::new(
        client,
        mpc_node::mesh::Options {
            ping_interval: ping_interval.as_millis() as u64,
        },
        account_id,
        synced_peer_rx,
    );
    let (sync_channel, sync_task) = SyncTask::new(
        client,
        triples,
        presignatures,
        mesh.watch(),
        contract_watcher,
        synced_peer_tx,
    );
    tokio::spawn(sync_task.run());

    SyncNodeCtx { sync_channel }
}

fn owner_for_id(id: u64) -> Participant {
    Participant::from((id % 3) as u32)
}

fn owned_ids(owner: Participant) -> Vec<u64> {
    let owner_idx: u64 = Into::<u32>::into(owner) as u64;
    vec![owner_idx, owner_idx + 3, owner_idx + 6]
}

async fn assert_full_replication_and_ownership(
    triples: &TripleStorage,
    presignatures: &PresignatureStorage,
) {
    assert_eq!(triples.len_generated().await, 9);
    assert_eq!(presignatures.len_generated().await, 9);

    for id in 0u64..9u64 {
        assert!(triples.contains(id).await, "missing triple={id}");
        assert!(
            presignatures.contains(id).await,
            "missing presignature={id}"
        );
    }

    for owner in [
        Participant::from(0u32),
        Participant::from(1u32),
        Participant::from(2u32),
    ] {
        for id in owned_ids(owner) {
            assert!(
                triples.contains_by_owner(id, owner).await,
                "triple={id} should be owned by {owner:?}"
            );
            assert!(
                presignatures.contains_by_owner(id, owner).await,
                "presignature={id} should be owned by {owner:?}"
            );
        }
    }
}

async fn assert_owner_present(
    triples: &TripleStorage,
    presignatures: &PresignatureStorage,
    owner: Participant,
) {
    for id in owned_ids(owner) {
        assert!(
            triples.contains_by_owner(id, owner).await,
            "triple={id} should be owned by {owner:?}"
        );
        assert!(
            presignatures.contains_by_owner(id, owner).await,
            "presignature={id} should be owned by {owner:?}"
        );
    }
}

async fn assert_owner_absent(
    triples: &TripleStorage,
    presignatures: &PresignatureStorage,
    owner: Participant,
) {
    for id in owned_ids(owner) {
        assert!(
            !triples.contains_by_owner(id, owner).await,
            "triple={id} should not be owned by {owner:?}"
        );
        assert!(
            !presignatures.contains_by_owner(id, owner).await,
            "presignature={id} should not be owned by {owner:?}"
        );
    }
}

#[test_log::test(tokio::test)]
async fn test_state_sync_e2e_large_outdated_stockpile() {
    // start the cluster of nodes immediately without waiting for them to be running.
    let mut spawner = cluster::spawn();
    {
        let worker = spawner.prespawn_sandbox().await.unwrap().clone();
        spawner.create_accounts(&worker).await;
    }
    // NOTE: cannot reliably get the first participant until running state is reached, so
    // this assumes that 0 and 1 is the first and second participants.
    let node0 = Participant::from(0);
    let node0_account_id = spawner.account_id(Into::<u32>::into(node0) as usize);
    let node1 = Participant::from(1);
    let node1_account_id = spawner.account_id(Into::<u32>::into(node1) as usize);
    let redis = spawner.prespawn_redis().await;

    // immediately add to triples/presignatures storage the triples/presignatures we want to invalidate.
    let node0_triples = redis.triple_storage(&node0_account_id);
    let node0_presignatures = redis.presignature_storage(&node0_account_id);
    let node1_triples = redis.triple_storage(&node1_account_id);
    let node1_presignatures = redis.presignature_storage(&node1_account_id);

    // insert triples that will be invalidated after a sync, since nobody else has them.
    // node0 is saying that they have 0 to 5, but node1 will sync and say they have 4 and 5 only.
    insert_triples(&node0_triples, node1, 0..=10000).await;
    insert_triples(&node1_triples, node1, 0..=5).await;
    insert_presignatures(&node0_presignatures, node1, 0..=10000).await;
    insert_presignatures(&node1_presignatures, node1, 0..=5).await;

    let _nodes = spawner
        .disable_prestockpile()
        .with_config(|cfg| {
            // Need these to be set otherwise we will be constantly taking our mock triples:
            cfg.protocol.triple.min_triples = 1;
            cfg.protocol.triple.max_triples = 1;
            cfg.protocol.presignature.min_presignatures = 1;
            cfg.protocol.presignature.max_presignatures = 1;
        })
        .await
        .unwrap();

    // Give some time for the first sync broadcast to finish.
    tokio::time::sleep(Duration::from_secs(5)).await;

    validate_triples(
        &node0_triples,
        node1,
        &[0, 1, 2, 3, 4, 5],
        &[6, 100, 500, 2030, 1337, 10000],
    )
    .await;
    validate_triples(
        &node1_triples,
        node1,
        &[0, 1, 2, 3, 4, 5],
        &[6, 100, 500, 2030, 1337, 10000],
    )
    .await;
    validate_presignatures(
        &node0_presignatures,
        node1,
        &[0, 1, 2, 3, 4, 5],
        &[6, 100, 500, 2030, 1337, 10000],
    )
    .await;
    validate_presignatures(
        &node0_presignatures,
        node1,
        &[0, 1, 2, 3, 4, 5],
        &[6, 100, 500, 2030, 1337, 10000],
    )
    .await;

    // TODO: add back being able to sign after sync. Need to be able to update the config from integration tests.
    // // Check that signing works as normal.
    // nodes.wait().signable().await.unwrap();
    // nodes.sign().await.unwrap();
}

async fn insert_triples(
    triples: &TripleStorage,
    node: Participant,
    range: impl IntoIterator<Item = u64>,
) {
    for id in range {
        triples
            .reserve(id)
            .await
            .unwrap()
            .insert(dummy_pair(id), node)
            .await;
    }
}

async fn validate_triples(
    triples: &TripleStorage,
    owner: Participant,
    valid: &[u64],
    invalid: &[u64],
) {
    for id in valid {
        assert!(
            triples.contains_by_owner(*id, owner).await,
            "triple={id} should be valid"
        );
    }

    for id in invalid {
        assert!(
            !triples.contains_by_owner(*id, owner).await,
            "triple={id} should be invalid"
        );
    }
}

async fn insert_presignatures(
    presignatures: &PresignatureStorage,
    node: Participant,
    range: impl IntoIterator<Item = u64>,
) {
    for id in range {
        presignatures
            .reserve(id)
            .await
            .unwrap()
            .insert(dummy_presignature(id), node)
            .await;
    }
}

async fn validate_presignatures(
    presignatures: &PresignatureStorage,
    owner: Participant,
    valid: &[u64],
    invalid: &[u64],
) {
    for id in valid {
        assert!(
            presignatures.contains_by_owner(*id, owner).await,
            "presignature={id} should be valid"
        );
    }

    for id in invalid {
        assert!(
            !presignatures.contains_by_owner(*id, owner).await,
            "presignature={id} should be invalid"
        );
    }
}

// TODO: cleanup and move this to a common test utils module
fn dummy_presignature(id: u64) -> Presignature {
    Presignature {
        id,
        output: PresignOutput {
            big_r: <Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            k: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            sigma: <Secp256k1 as CurveArithmetic>::Scalar::ONE,
        },
        participants: vec![Participant::from(1), Participant::from(2)],
    }
}

// TODO: cleanup and move this to a common test utils module
fn dummy_triple() -> Triple {
    Triple {
        share: TripleShare {
            a: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            b: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
            c: <Secp256k1 as CurveArithmetic>::Scalar::ZERO,
        },
        public: TriplePub {
            big_a: <k256::Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            big_b: <k256::Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            big_c: <k256::Secp256k1 as CurveArithmetic>::AffinePoint::default(),
            participants: vec![Participant::from(1), Participant::from(2)],
            threshold: 5,
        },
    }
}

// TODO: cleanup and move this to a common test utils module
fn participants(num_nodes: usize) -> Participants {
    let (_cipher_sk, cipher_pk) = mpc_keys::hpke::generate();
    let sign_sk = near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
    let mut participants = Participants::default();
    for i in 0..num_nodes {
        let id = Participant::from(i as u32);
        participants.insert(
            &id,
            ParticipantInfo {
                sign_pk: sign_sk.public_key(),
                cipher_pk: cipher_pk.clone(),
                id: id.into(),
                url: "http://localhost:3030".to_string(),
                account_id: format!("p{i}_test.near").parse().unwrap(),
            },
        );
    }
    participants
}

fn dummy_pair(id: u64) -> TriplePair {
    TriplePair {
        id,
        triple0: dummy_triple(),
        triple1: dummy_triple(),
    }
}
