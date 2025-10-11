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

/// Test syncing with inconsistent storage states where different nodes have different views
/// of who owns what shares. This simulates real-world scenarios where nodes may have lost
/// or gained shares inconsistently.
///
/// The test creates random, inconsistent states across multiple nodes and then verifies that
/// after syncing, all nodes converge to a consistent state based on the authoritative owner's view.
#[test_log::test(tokio::test)]
async fn test_state_sync_inconsistent_triple_storage() -> anyhow::Result<()> {
    use rand::Rng;
    
    let spawner = ClusterSpawner::default()
        .network("protocol-sync-inconsistent")
        .init_network()
        .await
        .unwrap();

    let redis = spawner.spawn_redis().await;
    let num_nodes = 1; // We're simulating on one node's storage
    let threshold = 2;
    let node0_account_id = "p0_test.near".parse().unwrap();
    
    // Define multiple participants that will own different shares
    let owner1 = Participant::from(1);
    let owner2 = Participant::from(2);
    let owner3 = Participant::from(3);

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

    let mut rng = rand::thread_rng();
    let num_triples_per_owner = 50;

    // Step 1: Create inconsistent initial state
    // Each owner should have certain triples, but node0 has a random, inconsistent view
    tracing::info!("Creating inconsistent initial state...");
    
    let mut owner1_should_have = Vec::new();
    let mut owner2_should_have = Vec::new();
    let mut owner3_should_have = Vec::new();

    // Owner 1's triples: IDs 0-49
    for id in 0..num_triples_per_owner {
        owner1_should_have.push(id);
    }

    // Owner 2's triples: IDs 100-149
    for id in 100..(100 + num_triples_per_owner) {
        owner2_should_have.push(id);
    }

    // Owner 3's triples: IDs 200-249
    for id in 200..(200 + num_triples_per_owner) {
        owner3_should_have.push(id);
    }

    // Create inconsistent state: node0 has ALL of what owner claims PLUS random extras
    // After sync, the extras should be removed but the claimed ones should remain
    // This simulates stale data where the node has outdated shares
    
    // For owner1: insert ALL their triples + extra invalid ones
    let owner1_extra_count = 15;
    let mut owner1_stored: Vec<u64> = owner1_should_have.clone();
    
    // Add some extras that owner1 doesn't actually have
    for _ in 0..owner1_extra_count {
        let extra_id = rng.gen_range(1000..1100);
        owner1_stored.push(extra_id);
    }
    
    tracing::info!(
        "Owner1 should have {} triples, but node0 has {} (including {} extras)",
        owner1_should_have.len(),
        owner1_stored.len(),
        owner1_extra_count
    );
    
    for &id in &owner1_stored {
        insert_triples(&node0_triples, owner1, [id]).await;
    }

    // For owner2: insert ALL their triples + some extras
    let mut owner2_stored: Vec<u64> = owner2_should_have.clone();
    
    // Add random extras
    for _ in 0..10 {
        let extra_id = rng.gen_range(2000..2100);
        owner2_stored.push(extra_id);
    }
    
    tracing::info!(
        "Owner2 should have {} triples, but node0 has {} (including extras)",
        owner2_should_have.len(),
        owner2_stored.len()
    );
    
    for &id in &owner2_stored {
        insert_triples(&node0_triples, owner2, [id]).await;
    }

    // For owner3: insert ALL their triples + lots of extras
    let mut owner3_stored: Vec<u64> = owner3_should_have.clone();
    
    // Add many extras
    for _ in 0..30 {
        let extra_id = rng.gen_range(3000..3200);
        owner3_stored.push(extra_id);
    }
    
    tracing::info!(
        "Owner3 should have {} triples, but node0 has {} (including {} extras)",
        owner3_should_have.len(),
        owner3_stored.len(),
        30
    );
    
    for &id in &owner3_stored {
        insert_triples(&node0_triples, owner3, [id]).await;
    }

    // Step 2: Verify inconsistent state exists
    tracing::info!("Verifying inconsistent initial state...");
    
    let owner1_before = node0_triples.fetch_owned(owner1).await;
    let owner2_before = node0_triples.fetch_owned(owner2).await;
    let owner3_before = node0_triples.fetch_owned(owner3).await;
    
    tracing::info!(
        "Before sync - Owner1: {} items, Owner2: {} items, Owner3: {} items",
        owner1_before.len(),
        owner2_before.len(),
        owner3_before.len()
    );
    
    // Verify inconsistency exists
    assert_ne!(
        owner1_before.len(),
        owner1_should_have.len(),
        "Initial state should be inconsistent for owner1"
    );

    // Step 3: Send sync updates with the authoritative state
    // In reality, each owner would send their own state
    tracing::info!("Sending sync updates with authoritative state...");
    
    let update1 = SyncUpdate {
        from: owner1,
        triples: owner1_should_have.clone(),
        presignatures: vec![],
    };
    
    let update2 = SyncUpdate {
        from: owner2,
        triples: owner2_should_have.clone(),
        presignatures: vec![],
    };
    
    let update3 = SyncUpdate {
        from: owner3,
        triples: owner3_should_have.clone(),
        presignatures: vec![],
    };

    sync_channel.request_update(update1).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    sync_channel.request_update(update2).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    sync_channel.request_update(update3).await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Step 4: Verify convergence - all nodes should now have consistent state
    tracing::info!("Verifying convergence after sync...");
    
    let owner1_after = node0_triples.fetch_owned(owner1).await;
    let owner2_after = node0_triples.fetch_owned(owner2).await;
    let owner3_after = node0_triples.fetch_owned(owner3).await;
    
    tracing::info!(
        "After sync - Owner1: {} items, Owner2: {} items, Owner3: {} items",
        owner1_after.len(),
        owner2_after.len(),
        owner3_after.len()
    );
    
    // Verify that the state has converged to what each owner claims to have
    assert_eq!(
        owner1_after.len(),
        owner1_should_have.len(),
        "Owner1 should have exactly {} triples after sync",
        owner1_should_have.len()
    );
    
    assert_eq!(
        owner2_after.len(),
        owner2_should_have.len(),
        "Owner2 should have exactly {} triples after sync",
        owner2_should_have.len()
    );
    
    assert_eq!(
        owner3_after.len(),
        owner3_should_have.len(),
        "Owner3 should have exactly {} triples after sync",
        owner3_should_have.len()
    );
    
    // Verify that the actual IDs match
    let owner1_after_set: std::collections::HashSet<_> = owner1_after.into_iter().collect();
    let owner1_should_set: std::collections::HashSet<_> = owner1_should_have.into_iter().collect();
    assert_eq!(
        owner1_after_set, owner1_should_set,
        "Owner1's triples should match exactly"
    );
    
    let owner2_after_set: std::collections::HashSet<_> = owner2_after.into_iter().collect();
    let owner2_should_set: std::collections::HashSet<_> = owner2_should_have.into_iter().collect();
    assert_eq!(
        owner2_after_set, owner2_should_set,
        "Owner2's triples should match exactly"
    );
    
    let owner3_after_set: std::collections::HashSet<_> = owner3_after.into_iter().collect();
    let owner3_should_set: std::collections::HashSet<_> = owner3_should_have.into_iter().collect();
    assert_eq!(
        owner3_after_set, owner3_should_set,
        "Owner3's triples should match exactly"
    );

    tracing::info!("✅ Inconsistent triple storage sync test completed successfully");
    Ok(())
}

/// Test syncing with inconsistent presignature storage where different nodes have different
/// views of who owns what presignatures. This is similar to the triple test but focuses on
/// presignature synchronization.
#[test_log::test(tokio::test)]
async fn test_state_sync_inconsistent_presignature_storage() -> anyhow::Result<()> {
    use rand::Rng;
    
    let spawner = ClusterSpawner::default()
        .network("protocol-sync-inconsistent-presig")
        .init_network()
        .await
        .unwrap();

    let redis = spawner.spawn_redis().await;
    let num_nodes = 1;
    let threshold = 2;
    let node0_account_id = "p0_test.near".parse().unwrap();
    
    let owner1 = Participant::from(1);
    let owner2 = Participant::from(2);
    let owner3 = Participant::from(3);

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

    let mut rng = rand::thread_rng();
    let num_presigs_per_owner = 40;

    tracing::info!("Creating inconsistent presignature state...");
    
    // Define what each owner should have
    let mut owner1_should_have = Vec::new();
    for id in 0..num_presigs_per_owner {
        owner1_should_have.push(id);
    }

    let mut owner2_should_have = Vec::new();
    for id in 500..(500 + num_presigs_per_owner) {
        owner2_should_have.push(id);
    }

    let mut owner3_should_have = Vec::new();
    for id in 1000..(1000 + num_presigs_per_owner) {
        owner3_should_have.push(id);
    }

    // Create inconsistent state: store ALL claimed presignatures + extras
    // Sync should remove only the extras
    
    // Owner1: ALL presignatures + some extras
    let mut owner1_stored: Vec<u64> = owner1_should_have.clone();
    
    for _ in 0..15 {
        let extra_id = rng.gen_range(5000..5100);
        owner1_stored.push(extra_id);
    }
    
    tracing::info!(
        "Owner1 should have {} presignatures, but node0 has {}",
        owner1_should_have.len(),
        owner1_stored.len()
    );
    
    for &id in &owner1_stored {
        insert_presignatures(&node0_presignatures, owner1, [id]).await;
    }

    // Owner2: ALL presignatures + few extras
    let mut owner2_stored: Vec<u64> = owner2_should_have.clone();
    
    for _ in 0..5 {
        let extra_id = rng.gen_range(6000..6100);
        owner2_stored.push(extra_id);
    }
    
    tracing::info!(
        "Owner2 should have {} presignatures, but node0 has {}",
        owner2_should_have.len(),
        owner2_stored.len()
    );
    
    for &id in &owner2_stored {
        insert_presignatures(&node0_presignatures, owner2, [id]).await;
    }

    // Owner3: ALL presignatures + many extras
    let mut owner3_stored: Vec<u64> = owner3_should_have.clone();
    
    for _ in 0..25 {
        let extra_id = rng.gen_range(7000..7200);
        owner3_stored.push(extra_id);
    }
    
    tracing::info!(
        "Owner3 should have {} presignatures, but node0 has {}",
        owner3_should_have.len(),
        owner3_stored.len()
    );
    
    for &id in &owner3_stored {
        insert_presignatures(&node0_presignatures, owner3, [id]).await;
    }

    // Verify inconsistent state
    tracing::info!("Verifying inconsistent initial state...");
    
    let owner1_before = node0_presignatures.fetch_owned(owner1).await;
    let owner2_before = node0_presignatures.fetch_owned(owner2).await;
    let owner3_before = node0_presignatures.fetch_owned(owner3).await;
    
    tracing::info!(
        "Before sync - Owner1: {} presigs, Owner2: {} presigs, Owner3: {} presigs",
        owner1_before.len(),
        owner2_before.len(),
        owner3_before.len()
    );
    
    assert!(
        owner1_before.len() > owner1_should_have.len(),
        "Initial state should have extras for owner1 presignatures"
    );

    // Send sync updates with authoritative state
    tracing::info!("Sending sync updates with authoritative presignature state...");
    
    let update1 = SyncUpdate {
        from: owner1,
        triples: vec![],
        presignatures: owner1_should_have.clone(),
    };
    
    let update2 = SyncUpdate {
        from: owner2,
        triples: vec![],
        presignatures: owner2_should_have.clone(),
    };
    
    let update3 = SyncUpdate {
        from: owner3,
        triples: vec![],
        presignatures: owner3_should_have.clone(),
    };

    sync_channel.request_update(update1).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    sync_channel.request_update(update2).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    sync_channel.request_update(update3).await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Verify convergence
    tracing::info!("Verifying convergence after sync...");
    
    let owner1_after = node0_presignatures.fetch_owned(owner1).await;
    let owner2_after = node0_presignatures.fetch_owned(owner2).await;
    let owner3_after = node0_presignatures.fetch_owned(owner3).await;
    
    tracing::info!(
        "After sync - Owner1: {} presigs, Owner2: {} presigs, Owner3: {} presigs",
        owner1_after.len(),
        owner2_after.len(),
        owner3_after.len()
    );
    
    assert_eq!(
        owner1_after.len(),
        owner1_should_have.len(),
        "Owner1 should have exactly {} presignatures after sync",
        owner1_should_have.len()
    );
    
    assert_eq!(
        owner2_after.len(),
        owner2_should_have.len(),
        "Owner2 should have exactly {} presignatures after sync",
        owner2_should_have.len()
    );
    
    assert_eq!(
        owner3_after.len(),
        owner3_should_have.len(),
        "Owner3 should have exactly {} presignatures after sync",
        owner3_should_have.len()
    );
    
    // Verify exact ID matches
    let owner1_after_set: std::collections::HashSet<_> = owner1_after.into_iter().collect();
    let owner1_should_set: std::collections::HashSet<_> = owner1_should_have.into_iter().collect();
    assert_eq!(
        owner1_after_set, owner1_should_set,
        "Owner1's presignatures should match exactly"
    );
    
    let owner2_after_set: std::collections::HashSet<_> = owner2_after.into_iter().collect();
    let owner2_should_set: std::collections::HashSet<_> = owner2_should_have.into_iter().collect();
    assert_eq!(
        owner2_after_set, owner2_should_set,
        "Owner2's presignatures should match exactly"
    );
    
    let owner3_after_set: std::collections::HashSet<_> = owner3_after.into_iter().collect();
    let owner3_should_set: std::collections::HashSet<_> = owner3_should_have.into_iter().collect();
    assert_eq!(
        owner3_after_set, owner3_should_set,
        "Owner3's presignatures should match exactly"
    );

    tracing::info!("✅ Inconsistent presignature storage sync test completed successfully");
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
        if let Some(mut slot) = triples.reserve(id).await {
            slot.insert(dummy_triple(id), node).await;
        }
        // If reservation fails (already exists), that's ok - skip it
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
        if let Some(mut slot) = presignatures.reserve(id).await {
            slot.insert(dummy_presignature(id), node).await;
        }
        // If reservation fails (already exists), that's ok - skip it
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
