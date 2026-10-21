//! Tests checkpoint consensus alignment via peer-to-peer HTTP fetch.

use integration_tests::mpc_fixture::{mock_stream::MockStream, MpcFixtureBuilder};
use mpc_node::backlog::consensus::align_backlog_with_consensus;
use mpc_node::backlog::mock::BacklogTestExt;
use mpc_node::backlog::Backlog;
use mpc_node::mesh::connection::NodeStatus;
use mpc_node::mesh::MeshState;
use mpc_node::node_client::{NodeClient, Options as NodeClientOptions};
use mpc_node::protocol::ParticipantInfo;
use mpc_node::storage::CheckpointStorage;
use mpc_primitives::{Chain, ChainConfig as _, CheckpointDigest, SignId};
use near_sdk::AccountId;
use std::collections::HashSet;
use std::time::Duration;
use test_log::test;

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_web_server_serves_checkpoint() {
    let mut network = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .with_mock_stream(Chain::Ethereum, MockStream::default())
        .await
        .build()
        .await;

    network.wait_for_running().await;
    network.assert_triples(4, Duration::from_secs(30)).await;
    network
        .assert_presignatures(4, Duration::from_secs(30))
        .await;

    let chain = Chain::Ethereum;
    let interval = chain.checkpoint_interval().unwrap();

    // Create checkpoint on node 0
    let cp = network.nodes[0]
        .backlog
        .set_processed_block(chain, interval)
        .await
        .expect("auto-checkpoint");
    let digest = cp.digest();
    let hex_digest = hex::encode(digest);

    // Start web interface on node 0
    let account_id0: AccountId = "peer0.near".parse().unwrap();
    let port = network.nodes[0]
        .start_web_interface(account_id0)
        .await
        .expect("web interface");
    let url = format!("http://127.0.0.1:{port}");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Query the checkpoint endpoint directly
    let client = reqwest::Client::new();
    let query_url = format!("{url}/checkpoint?query=Ethereum:0x{hex_digest}");
    let resp = client
        .get(&query_url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("HTTP request should succeed");

    assert!(
        resp.status().is_success(),
        "checkpoint endpoint should return 200, got {}",
        resp.status()
    );

    let body = resp.bytes().await.unwrap();
    let response: mpc_node::web::CheckpointResponse =
        ciborium::from_reader(body.as_ref()).expect("should deserialize checkpoint");
    assert_eq!(response.version, mpc_node::CHECKPOINT_VERSION);
    let checkpoints = response.checkpoints;

    let retrieved = checkpoints
        .get(&chain)
        .expect("should have ethereum checkpoint");
    assert_eq!(
        retrieved.block_height, interval,
        "retrieved checkpoint height should match"
    );
    assert_eq!(
        retrieved.digest(),
        digest,
        "retrieved checkpoint digest should match"
    );
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_consensus_alignment_peer_fetch() {
    let mut network = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .with_mock_stream(Chain::Ethereum, MockStream::default())
        .await
        .build()
        .await;

    network.wait_for_running().await;
    network.assert_triples(4, Duration::from_secs(30)).await;
    network
        .assert_presignatures(4, Duration::from_secs(30))
        .await;

    let chain = Chain::Ethereum;
    let interval = chain.checkpoint_interval().unwrap();

    // Node 0: create checkpoint
    let cp = network.nodes[0]
        .backlog
        .set_processed_block(chain, interval)
        .await
        .expect("auto-checkpoint");
    let digest = cp.digest();
    let expected_height = cp.block_height;

    // Start web interface on node 0
    let account_id0: AccountId = "peer0.near".parse().unwrap();
    let port = network.nodes[0]
        .start_web_interface(account_id0.clone())
        .await
        .expect("web interface");
    let url = format!("http://127.0.0.1:{port}");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Sanity check: web server can serve the checkpoint
    {
        let client = reqwest::Client::new();
        let hex_digest = hex::encode(digest);
        let query_url = format!("{url}/checkpoint?query=Ethereum:0x{hex_digest}");
        let resp = client.get(&query_url).send().await.unwrap();
        let body = resp.bytes().await.unwrap();
        let response: mpc_node::web::CheckpointResponse =
            ciborium::from_reader(body.as_ref()).unwrap();
        assert_eq!(response.version, mpc_node::CHECKPOINT_VERSION);
        assert!(
            response.checkpoints.contains_key(&chain),
            "web server should serve the checkpoint"
        );
    }

    // Build MeshState with node 0 as active participant
    let mut mesh_state = MeshState::default();
    let mut info = ParticipantInfo::new(0);
    info.url = url;
    info.account_id = account_id0;
    mesh_state.update(
        cait_sith::protocol::Participant::from(0u32),
        NodeStatus::Active,
        info,
    );

    let (_cp_tx, mut checkpoints_rx) = tokio::sync::watch::channel(Some(CheckpointDigest {
        chain,
        height: expected_height,
        digest,
    }));
    let (_mesh_tx, mut mesh_rx) = tokio::sync::watch::channel(mesh_state);

    // Fresh persisted backlog (simulates a node that just started)
    let fresh_storage = CheckpointStorage::in_memory();
    let fresh_backlog = Backlog::persisted(fresh_storage.clone());

    let node_client = NodeClient::new(&NodeClientOptions::default());
    let my_account_id: AccountId = "fresh-node.near".parse().unwrap();

    // Call align_backlog_with_consensus
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        align_backlog_with_consensus(
            chain,
            &fresh_backlog,
            &mut checkpoints_rx,
            &mut mesh_rx,
            &node_client,
            &my_account_id,
        ),
    )
    .await;

    let result = result.expect("align_backlog_with_consensus should not hang");

    assert!(
        result.is_some(),
        "should have recovered to height {} from peer",
        expected_height
    );
    assert_eq!(result.unwrap(), expected_height);

    // Verify fresh backlog has the checkpoint
    let latest = fresh_backlog.checkpoints().latest(chain).await.unwrap();
    assert!(latest.is_some());
    assert_eq!(latest.unwrap().block_height, expected_height);

    // Verify persisted
    let persisted = fresh_storage.load_latest(chain).await.unwrap();
    assert!(persisted.is_some());
    assert_eq!(persisted.unwrap().block_height, expected_height);
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_consensus_alignment_consensus_changes_while_fetching() {
    let mut network = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .with_mock_stream(Chain::Ethereum, MockStream::default())
        .await
        .build()
        .await;

    network.wait_for_running().await;
    network.assert_triples(4, Duration::from_secs(30)).await;
    network
        .assert_presignatures(4, Duration::from_secs(30))
        .await;

    let chain = Chain::Ethereum;

    let account_id2: AccountId = "peer2.near".parse().unwrap();
    let port = network.nodes[2]
        .start_web_interface(account_id2.clone())
        .await
        .expect("web interface");
    let url = format!("http://127.0.0.1:{port}");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut mesh_state = MeshState::default();
    let mut info = ParticipantInfo::new(2);
    info.url = url;
    info.account_id = account_id2;
    mesh_state.update(
        cait_sith::protocol::Participant::from(2u32),
        NodeStatus::Active,
        info,
    );

    // Start with a non-matching digest; we'll change it to zero to abort the fetch loop.
    let (cp_tx, mut checkpoints_rx) = tokio::sync::watch::channel(Some(CheckpointDigest {
        chain,
        height: 9999,
        digest: [0xabu8; 32],
    }));
    let (_mesh_tx, mut mesh_rx) = tokio::sync::watch::channel(mesh_state);

    let fresh_storage = CheckpointStorage::in_memory();
    let fresh_backlog = Backlog::persisted(fresh_storage.clone());
    let fresh_backlog2 = fresh_backlog.clone();

    let node_client = NodeClient::new(&NodeClientOptions::default());
    let my_account_id: AccountId = "fresh-node.near".parse().unwrap();

    // Spawn alignment in background; keep cp_tx here to send the abort signal.
    let handle = tokio::spawn(async move {
        align_backlog_with_consensus(
            chain,
            &fresh_backlog2,
            &mut checkpoints_rx,
            &mut mesh_rx,
            &node_client,
            &my_account_id,
        )
        .await
    });

    // Let the fetch loop start, then change the consensus digest to zero (abort signal).
    tokio::time::sleep(Duration::from_secs(1)).await;
    cp_tx.send(None).unwrap();

    // The function should see the changed digest and return None.
    let result = tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("align should complete within timeout")
        .expect("spawned task should not panic");

    assert!(
        result.is_none(),
        "should return None when consensus digest changes to None"
    );

    assert!(fresh_backlog
        .checkpoints()
        .latest(chain)
        .await
        .unwrap()
        .is_none());
    let persisted = fresh_storage.load_latest(chain).await.unwrap();
    assert!(persisted.is_none());
}

/// A reset must converge divergent nodes on byte-identical local state.
///
/// This is the property the canonical reset checkpoint buys. Every node
/// rebuilds the same checkpoint from `(chain, height)` alone, so no node's
/// pre-reset backlog can survive into the state it restarts from. A reset that
/// merely rewound the cursor would leave each node holding whatever it had,
/// and their first post-reset checkpoints would not agree.
///
/// The mesh is left empty throughout: no peer has ever held this checkpoint,
/// so convergence must not depend on fetching it from one.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_reset_converges_divergent_nodes() {
    let chain = Chain::Ethereum;
    let interval = chain.checkpoint_interval().unwrap();
    let resume_after = interval * 2;

    let network = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .with_mock_stream(chain, MockStream::default())
        .await
        .build()
        .await;
    network.wait_for_running().await;

    // Diverge every node: a different pending request and a different cursor,
    // which is exactly the state that makes post-reset digests disagree if a
    // reset preserves it.
    for (index, node) in network.nodes.iter().enumerate() {
        let sign_id = SignId::new([index as u8 + 1; 32]);
        node.backlog.insert_mock_sign(sign_id, chain).await;
        node.backlog
            .set_processed_block(chain, interval * (index as u64 + 3))
            .await;
    }

    let digests_before: HashSet<[u8; 32]> = {
        let mut digests = HashSet::new();
        for node in &network.nodes {
            digests.insert(node.backlog.checkpoint(chain).await.unwrap().digest());
        }
        digests
    };
    assert_eq!(
        digests_before.len(),
        network.nodes.len(),
        "every node must produce a distinct checkpoint digest before reset"
    );

    // Governance settles the canonical reset checkpoint. Each node aligns
    // against it with no peer reachable.
    let settled = CheckpointDigest {
        chain,
        height: resume_after,
        digest: mpc_primitives::reset_checkpoint_digest(chain, resume_after),
    };
    let my_account_id: AccountId = "aligning.near".parse().unwrap();
    let node_client = NodeClient::new(&NodeClientOptions::default());

    for node in &network.nodes {
        let (_cp_tx, mut checkpoints_rx) = tokio::sync::watch::channel(Some(settled));
        let (_mesh_tx, mut mesh_rx) = tokio::sync::watch::channel(MeshState::default());

        let applied = tokio::time::timeout(
            Duration::from_secs(5),
            align_backlog_with_consensus(
                chain,
                &node.backlog,
                &mut checkpoints_rx,
                &mut mesh_rx,
                &node_client,
                &my_account_id,
            ),
        )
        .await
        .expect("a reset must not wait on peers");

        assert_eq!(applied, Some(resume_after));
    }

    // Every node now holds the same checkpoint, byte for byte, with an empty
    // backlog and the same cursor.
    let mut checkpoints_after = Vec::new();
    for node in &network.nodes {
        checkpoints_after.push(
            node.backlog
                .checkpoints()
                .latest(chain)
                .await
                .unwrap()
                .expect("every node should hold the reset checkpoint"),
        );
    }
    assert_eq!(
        checkpoints_after
            .iter()
            .map(|checkpoint| checkpoint.digest())
            .collect::<HashSet<_>>(),
        HashSet::from([mpc_primitives::reset_checkpoint_digest(chain, resume_after)]),
        "all nodes must converge on the canonical reset checkpoint"
    );
    for checkpoint in &checkpoints_after {
        assert_eq!(checkpoint.block_height, resume_after);
        assert!(
            checkpoint.pending_requests.is_empty(),
            "a node's pre-reset backlog must not survive the reset"
        );
    }

    // And the next checkpoint each produces agrees too, which is what lets
    // consensus settle again after a reset.
    let mut next_digests = HashSet::new();
    for node in &network.nodes {
        node.backlog
            .set_processed_block(chain, resume_after + interval)
            .await;
        next_digests.insert(node.backlog.checkpoint(chain).await.unwrap().digest());
    }
    assert_eq!(
        next_digests.len(),
        1,
        "post-reset checkpoints must agree across nodes"
    );
}
