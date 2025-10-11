use std::time::Duration;

use cait_sith::protocol::Participant;
use cait_sith::triples::{TriplePub, TripleShare};
use cait_sith::PresignOutput;
use elliptic_curve::CurveArithmetic;
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
use mpc_node::storage::{PresignatureStorage, TripleStorage};

/// Test syncing a very large state to ensure we don't hit networking or Redis limits.
/// This tests the scenario where a node has accumulated a large number of triples and
/// presignatures that need to be synced with other nodes.
#[test_log::test(tokio::test)]
async fn test_state_sync_very_large_update() -> anyhow::Result<()> {
    let spawner = ClusterSpawner::default()
        .network("protocol-sync-large")
        .init_network()
        .await
        .unwrap();

    let redis = spawner.spawn_redis().await;
    let num_nodes = 1;
    let threshold = 2;
    let node0_account_id = "p0_test.near".parse().unwrap();
    let node1 = Participant::from(1);

    let sk = k256::SecretKey::random(&mut rand::thread_rng());
    let pk = sk.public_key();
    let ping_interval = Duration::from_millis(300);
    let client = NodeClient::new(&node_client::Options::default());
    let participants = participants(num_nodes);
    let node0_triples = redis.triple_storage(&node0_account_id);
    let node0_presignatures = redis.presignature_storage(&node0_account_id);

    let (contract_watcher, _contract_tx) = ContractStateWatcher::with(
        &node0_account_id,
        ProtocolState::Running(RunningContractState {
            epoch: 0,
            public_key: *pk.as_affine(),
            participants: participants.clone(),
            candidates: Default::default(),
            join_votes: Default::default(),
            leave_votes: Default::default(),
            threshold,
        }),
    );

    let (synced_peer_tx, synced_peer_rx) = SyncTask::synced_nodes_channel();
    let mesh = Mesh::new(
        &client,
        mpc_node::mesh::Options {
            ping_interval: ping_interval.as_millis() as u64,
        },
        synced_peer_rx,
    );
    let (sync_channel, sync) = SyncTask::new(
        &client,
        node0_triples.clone(),
        node0_presignatures.clone(),
        mesh.watch(),
        contract_watcher,
        synced_peer_tx,
    );
    tokio::spawn(sync.run());

    // Insert a very large number of triples and presignatures
    // This should be large enough to potentially hit:
    // 1. HTTP payload size limits (typically ~10MB for many servers)
    // 2. Redis command size limits
    // 3. Serialization/deserialization limits
    let num_items = 50_000;
    tracing::info!(
        "Inserting {} triples and {} presignatures for node1",
        num_items,
        num_items
    );
    insert_triples(&node0_triples, node1, 0..num_items).await;
    insert_presignatures(&node0_presignatures, node1, 0..num_items).await;

    // Create a sync update with all these items
    let valid: Vec<u64> = (0..num_items).collect();

    let update = SyncUpdate {
        from: node1,
        triples: valid.clone(),
        presignatures: valid.clone(),
    };

    // Test that the sync update succeeds despite the large size
    tracing::info!("Requesting sync update with {} items", num_items);
    sync_channel.request_update(update).await;

    // Give enough time for sync to process the large update
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Validate that all items are still present
    validate_triples(&node0_triples, node1, &valid, &[]).await;
    validate_presignatures(&node0_presignatures, node1, &valid, &[]).await;

    tracing::info!("Large state sync test completed successfully");
    Ok(())
}

/// Test syncing when a node has a large stockpile that needs to be cleaned up.
/// This is similar to test_state_sync_e2e_large_outdated_stockpile but more focused
/// on the size limits.
#[test_log::test(tokio::test)]
async fn test_state_sync_large_outdated_cleanup() -> anyhow::Result<()> {
    let spawner = ClusterSpawner::default()
        .network("protocol-sync-large-cleanup")
        .init_network()
        .await
        .unwrap();

    let redis = spawner.spawn_redis().await;
    let num_nodes = 1;
    let threshold = 2;
    let node0_account_id = "p0_test.near".parse().unwrap();
    let node1 = Participant::from(1);

    let sk = k256::SecretKey::random(&mut rand::thread_rng());
    let pk = sk.public_key();
    let ping_interval = Duration::from_millis(300);
    let client = NodeClient::new(&node_client::Options::default());
    let participants = participants(num_nodes);
    let node0_triples = redis.triple_storage(&node0_account_id);
    let node0_presignatures = redis.presignature_storage(&node0_account_id);

    let (contract_watcher, _contract_tx) = ContractStateWatcher::with(
        &node0_account_id,
        ProtocolState::Running(RunningContractState {
            epoch: 0,
            public_key: *pk.as_affine(),
            participants: participants.clone(),
            candidates: Default::default(),
            join_votes: Default::default(),
            leave_votes: Default::default(),
            threshold,
        }),
    );

    let (synced_peer_tx, synced_peer_rx) = SyncTask::synced_nodes_channel();
    let mesh = Mesh::new(
        &client,
        mpc_node::mesh::Options {
            ping_interval: ping_interval.as_millis() as u64,
        },
        synced_peer_rx,
    );
    let (sync_channel, sync) = SyncTask::new(
        &client,
        node0_triples.clone(),
        node0_presignatures.clone(),
        mesh.watch(),
        contract_watcher,
        synced_peer_tx,
    );
    tokio::spawn(sync.run());

    // Insert a large number of outdated items that need to be cleaned up
    let num_outdated = 30_000;
    let num_valid = 100;
    
    tracing::info!(
        "Inserting {} outdated and {} valid items for node1",
        num_outdated,
        num_valid
    );
    
    // Insert many outdated items
    insert_triples(&node0_triples, node1, 0..num_outdated).await;
    insert_presignatures(&node0_presignatures, node1, 0..num_outdated).await;

    // Create an update where node1 only has a small subset of valid items
    let valid: Vec<u64> = (0..num_valid).collect();
    let some_invalid: Vec<u64> = vec![
        num_valid,
        num_valid + 100,
        num_valid + 500,
        num_outdated / 2,
        num_outdated - 1,
    ];

    let update = SyncUpdate {
        from: node1,
        triples: valid.clone(),
        presignatures: valid.clone(),
    };

    tracing::info!(
        "Requesting sync update to clean up {} outdated items",
        num_outdated - num_valid
    );
    sync_channel.request_update(update).await;

    // Give enough time for the large cleanup operation
    tokio::time::sleep(Duration::from_secs(15)).await;

    // Validate that valid items remain and some invalid items are removed
    validate_triples(&node0_triples, node1, &valid, &some_invalid).await;
    validate_presignatures(&node0_presignatures, node1, &valid, &some_invalid).await;

    tracing::info!("Large outdated cleanup test completed successfully");
    Ok(())
}

/// Test that sync works correctly when a node has an empty state (no triples/presignatures).
/// This is an edge case that should be handled gracefully.
#[test_log::test(tokio::test)]
async fn test_state_sync_empty_state() -> anyhow::Result<()> {
    let spawner = ClusterSpawner::default()
        .network("protocol-sync-empty")
        .init_network()
        .await
        .unwrap();

    let redis = spawner.spawn_redis().await;
    let num_nodes = 1;
    let threshold = 2;
    let node0_account_id = "p0_test.near".parse().unwrap();
    let node1 = Participant::from(1);

    let sk = k256::SecretKey::random(&mut rand::thread_rng());
    let pk = sk.public_key();
    let ping_interval = Duration::from_millis(300);
    let client = NodeClient::new(&node_client::Options::default());
    let participants = participants(num_nodes);
    let node0_triples = redis.triple_storage(&node0_account_id);
    let node0_presignatures = redis.presignature_storage(&node0_account_id);

    let (contract_watcher, _contract_tx) = ContractStateWatcher::with(
        &node0_account_id,
        ProtocolState::Running(RunningContractState {
            epoch: 0,
            public_key: *pk.as_affine(),
            participants: participants.clone(),
            candidates: Default::default(),
            join_votes: Default::default(),
            leave_votes: Default::default(),
            threshold,
        }),
    );

    let (synced_peer_tx, synced_peer_rx) = SyncTask::synced_nodes_channel();
    let mesh = Mesh::new(
        &client,
        mpc_node::mesh::Options {
            ping_interval: ping_interval.as_millis() as u64,
        },
        synced_peer_rx,
    );
    let (sync_channel, sync) = SyncTask::new(
        &client,
        node0_triples.clone(),
        node0_presignatures.clone(),
        mesh.watch(),
        contract_watcher,
        synced_peer_tx,
    );
    tokio::spawn(sync.run());

    // First insert some items
    insert_triples(&node0_triples, node1, 0..=10).await;
    insert_presignatures(&node0_presignatures, node1, 0..=10).await;

    // Then send a sync update with an empty state - node1 has lost everything
    let update = SyncUpdate {
        from: node1,
        triples: vec![],
        presignatures: vec![],
    };

    tracing::info!("Requesting sync update with empty state");
    sync_channel.request_update(update).await;

    // Give time for sync to process
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Validate that all items have been removed
    let all_removed: Vec<u64> = (0..=10).collect();
    validate_triples(&node0_triples, node1, &[], &all_removed).await;
    validate_presignatures(&node0_presignatures, node1, &[], &all_removed).await;

    tracing::info!("Empty state sync test completed successfully");
    Ok(())
}

/// Test concurrent sync updates from multiple sources to ensure no race conditions.
#[test_log::test(tokio::test)]
async fn test_state_sync_concurrent_updates() -> anyhow::Result<()> {
    let spawner = ClusterSpawner::default()
        .network("protocol-sync-concurrent")
        .init_network()
        .await
        .unwrap();

    let redis = spawner.spawn_redis().await;
    let num_nodes = 1;
    let threshold = 2;
    let node0_account_id = "p0_test.near".parse().unwrap();
    let node1 = Participant::from(1);
    let node2 = Participant::from(2);
    let node3 = Participant::from(3);

    let sk = k256::SecretKey::random(&mut rand::thread_rng());
    let pk = sk.public_key();
    let ping_interval = Duration::from_millis(300);
    let client = NodeClient::new(&node_client::Options::default());
    let participants = participants(num_nodes);
    let node0_triples = redis.triple_storage(&node0_account_id);
    let node0_presignatures = redis.presignature_storage(&node0_account_id);

    let (contract_watcher, _contract_tx) = ContractStateWatcher::with(
        &node0_account_id,
        ProtocolState::Running(RunningContractState {
            epoch: 0,
            public_key: *pk.as_affine(),
            participants: participants.clone(),
            candidates: Default::default(),
            join_votes: Default::default(),
            leave_votes: Default::default(),
            threshold,
        }),
    );

    let (synced_peer_tx, synced_peer_rx) = SyncTask::synced_nodes_channel();
    let mesh = Mesh::new(
        &client,
        mpc_node::mesh::Options {
            ping_interval: ping_interval.as_millis() as u64,
        },
        synced_peer_rx,
    );
    let (sync_channel, sync) = SyncTask::new(
        &client,
        node0_triples.clone(),
        node0_presignatures.clone(),
        mesh.watch(),
        contract_watcher,
        synced_peer_tx,
    );
    tokio::spawn(sync.run());

    // Insert different sets of items for different nodes
    insert_triples(&node0_triples, node1, 0..=100).await;
    insert_presignatures(&node0_presignatures, node1, 0..=100).await;
    
    insert_triples(&node0_triples, node2, 1000..=1100).await;
    insert_presignatures(&node0_presignatures, node2, 1000..=1100).await;
    
    insert_triples(&node0_triples, node3, 2000..=2100).await;
    insert_presignatures(&node0_presignatures, node3, 2000..=2100).await;

    // Send concurrent updates from all nodes
    let update1 = SyncUpdate {
        from: node1,
        triples: (0..=50).collect(),
        presignatures: (0..=50).collect(),
    };

    let update2 = SyncUpdate {
        from: node2,
        triples: (1000..=1050).collect(),
        presignatures: (1000..=1050).collect(),
    };

    let update3 = SyncUpdate {
        from: node3,
        triples: (2000..=2050).collect(),
        presignatures: (2000..=2050).collect(),
    };

    tracing::info!("Sending concurrent sync updates from multiple nodes");
    
    // Send all updates at once to test concurrent handling
    tokio::join!(
        sync_channel.request_update(update1),
        sync_channel.request_update(update2),
        sync_channel.request_update(update3)
    );

    // Give time for all updates to be processed
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Validate that each node's valid items remain and invalid items are removed
    validate_triples(
        &node0_triples,
        node1,
        &(0..=50).collect::<Vec<_>>(),
        &[51, 75, 100],
    )
    .await;
    validate_presignatures(
        &node0_presignatures,
        node1,
        &(0..=50).collect::<Vec<_>>(),
        &[51, 75, 100],
    )
    .await;

    validate_triples(
        &node0_triples,
        node2,
        &(1000..=1050).collect::<Vec<_>>(),
        &[1051, 1075, 1100],
    )
    .await;
    validate_presignatures(
        &node0_presignatures,
        node2,
        &(1000..=1050).collect::<Vec<_>>(),
        &[1051, 1075, 1100],
    )
    .await;

    validate_triples(
        &node0_triples,
        node3,
        &(2000..=2050).collect::<Vec<_>>(),
        &[2051, 2075, 2100],
    )
    .await;
    validate_presignatures(
        &node0_presignatures,
        node3,
        &(2000..=2050).collect::<Vec<_>>(),
        &[2051, 2075, 2100],
    )
    .await;

    tracing::info!("Concurrent updates test completed successfully");
    Ok(())
}

/// Test that SyncUpdate can handle very large data structures.
/// This is a unit test to verify large updates don't cause panics or issues.
#[test]
fn test_sync_update_large_creation() {
    // Create a very large sync update
    let num_items = 100_000;
    let update = SyncUpdate {
        from: Participant::from(1),
        triples: (0..num_items).collect(),
        presignatures: (0..num_items).collect(),
    };

    // Test that we can create and access a large update
    assert_eq!(update.from, Participant::from(1));
    assert_eq!(update.triples.len(), num_items as usize);
    assert_eq!(update.presignatures.len(), num_items as usize);
    assert!(!update.is_empty());
    
    // Test memory usage estimation
    let estimated_bytes = std::mem::size_of_val(&update) + 
        update.triples.len() * std::mem::size_of::<u64>() + 
        update.presignatures.len() * std::mem::size_of::<u64>();
    
    tracing::info!(
        "Created SyncUpdate with {} triples and {} presignatures, estimated memory: {:.2} MB",
        num_items,
        num_items,
        estimated_bytes as f64 / 1_048_576.0
    );

    // Serialization will be tested implicitly in integration tests when
    // sync_channel.request_update() is called with large updates
}

// Helper functions

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
            .insert(dummy_triple(id), node)
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

fn dummy_triple(id: u64) -> Triple {
    Triple {
        id,
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
