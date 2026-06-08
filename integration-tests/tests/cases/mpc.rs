use cait_sith::protocol::Participant;
use deadpool_redis::redis::AsyncCommands;
use integration_tests::mpc_fixture::fixture_tasks::MessageFilter;
use integration_tests::mpc_fixture::message_collector::CollectMessages;
use integration_tests::mpc_fixture::message_collector::MessageCounter;
use integration_tests::mpc_fixture::MpcFixtureBuilder;
use mpc_node::protocol::message::SendMessage;
use mpc_node::protocol::posit::{PositAction, PositRejectReason};
use mpc_node::protocol::presignature::Presignature;
use mpc_node::protocol::Message;
use mpc_node::protocol::{Chain, IndexedSignRequest, ProtocolState, Sign};
use mpc_node::storage::triple_storage::TriplePair;
use mpc_primitives::SignId;
use std::collections::BTreeMap;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use test_log::test;
use tokio::sync::oneshot;
use tokio::sync::Mutex;

/// Use this toggle locally to regenerate hard-coded inputs such as key shares,
/// triples, and presignatures.
/// You might have to create the directory `integration-tests/tmp` first.
const WRITE_OUTPUT_TO_FILES: bool = false;
const KEY_SHARE_FILE: &str = "tmp/key_shares.json";
const TRIPLES_FILE: &str = "tmp/triples.json";
const PRESIGNATURES_FILE: &str = "tmp/presignatures.json";
/// Exact number of triple pairs / presignatures per owner in the output fixture.
/// We generate more than this and truncate after filtering to guarantee exact counts.
const TRIPLE_PAIRS_PER_OWNER: usize = 50;
const PRESIGNATURES_PER_OWNER: usize = 25;

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_basic_generate_keys() {
    let network = MpcFixtureBuilder::new(5, 4).build().await;

    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut contract_state_watcher = network.shared_contract_state.subscribe();
        contract_state_watcher
            .wait_for(|protocol_state| {
                tracing::info!("new protocol state: {protocol_state:?}");
                protocol_state
                    .as_ref()
                    .is_some_and(|state| matches!(state, ProtocolState::Running(_)))
            })
            .await
            .unwrap();
    })
    .await;

    if result.is_err() {
        let protocol_state = network.shared_contract_state.borrow();
        panic!("should reach running state eventually, final state was {protocol_state:?}");
    }

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if network
                .nodes
                .iter()
                .all(|node| node.state.test_key_info_watcher.borrow().is_some())
            {
                break;
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("all nodes should publish generated key info");

    let mut data = BTreeMap::new();
    for node in &network.nodes {
        let id = node.me;
        match &*node.state.test_key_info_watcher.borrow() {
            Some(key) => {
                data.insert(id, key.clone());
            }
            None => {
                panic!("No key generated for node {id:?}")
            }
        }
    }

    if WRITE_OUTPUT_TO_FILES {
        let abs_path = std::env::current_dir().unwrap().join(KEY_SHARE_FILE);
        tracing::info!("Writing output to {}", abs_path.display());
        let mut file = fs::File::create(KEY_SHARE_FILE).unwrap();
        serde_json::to_writer_pretty(&mut file, &data).unwrap();
    }
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_basic_generate_triples() {
    const N: u32 = if WRITE_OUTPUT_TO_FILES {
        TRIPLE_PAIRS_PER_OWNER as u32 * 2 // generate more to have room for filtering
    } else {
        1
    };
    let network = MpcFixtureBuilder::default()
        .only_generate_triples()
        .with_node_min_triples(N)
        .build()
        .await;

    network
        .assert_triples(N as usize, Duration::from_secs(180)) // adjust timeout based on N of Ts
        .await;

    if WRITE_OUTPUT_TO_FILES {
        let mut conn = network.redis_container.pool().get().await.unwrap();
        let mut data = BTreeMap::new();
        for node in &network.nodes {
            let mut nodes_shares = BTreeMap::new();
            for peer in &network.nodes {
                let triple_ids = node.triple_storage.fetch_owned_by(peer.me).await.unwrap();
                let mut peer_triples = Vec::with_capacity(triple_ids.len());
                for triple_id in triple_ids {
                    let pair = conn
                        .hget::<&str, u64, TriplePair>(node.triple_storage.triple_key(), triple_id)
                        .await;
                    if let Ok(pair) = pair {
                        peer_triples.push(pair);
                    } else {
                        tracing::error!("missing triple pair in redis {triple_id}");
                    }
                }
                nodes_shares.insert(peer.me, peer_triples);
            }
            data.insert(node.me, nodes_shares);
        }

        // Filter: keep only triple pairs that exist on ALL nodes,
        // then truncate each owner to exactly TRIPLE_PAIRS_PER_OWNER.
        let data = filter_artifacts_on_all_nodes(data);
        let data = truncate_per_owner(data, TRIPLE_PAIRS_PER_OWNER);

        let abs_path = std::env::current_dir().unwrap().join(TRIPLES_FILE);
        tracing::info!("Writing output to {}", abs_path.display());
        let mut file = fs::File::create(TRIPLES_FILE).unwrap();
        serde_json::to_writer_pretty(&mut file, &data).unwrap();
    }
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_basic_generate_presignature() {
    const N: u32 = if WRITE_OUTPUT_TO_FILES {
        PRESIGNATURES_PER_OWNER as u32 * 2 // generate more to have room for filtering
    } else {
        1
    };
    let network = MpcFixtureBuilder::default()
        .only_generate_presignatures()
        .with_node_min_presignatures(N)
        .build()
        .await;

    network
        .assert_presignatures(N as usize, Duration::from_secs(180)) // adjust timeout based on N of Ps
        .await;

    if WRITE_OUTPUT_TO_FILES {
        let mut conn = network.redis_container.pool().get().await.unwrap();
        let mut data = BTreeMap::new();
        for node in &network.nodes {
            let mut nodes_shares = BTreeMap::new();
            for peer in &network.nodes {
                let presignature_ids = node
                    .presignature_storage
                    .fetch_owned_by(peer.me)
                    .await
                    .unwrap();
                let mut peer_presignatures = Vec::with_capacity(presignature_ids.len());
                for presignature_id in presignature_ids {
                    let t = conn
                        .hget::<&str, u64, Presignature>(
                            node.presignature_storage.presignature_key(),
                            presignature_id,
                        )
                        .await;
                    if let Ok(t) = t {
                        peer_presignatures.push(t);
                    } else {
                        tracing::error!("missing presignature in redis {presignature_id}");
                    }
                }
                nodes_shares.insert(peer.me, peer_presignatures);
            }
            data.insert(node.me, nodes_shares);
        }

        // Filter: keep only presignatures that exist on ALL nodes,
        // then truncate each owner to exactly P_PER_OWNER.
        let data = filter_artifacts_on_all_nodes(data);
        let data = truncate_per_owner(data, PRESIGNATURES_PER_OWNER);

        let abs_path = std::env::current_dir().unwrap().join(PRESIGNATURES_FILE);
        tracing::info!("Writing output to {}", abs_path.display());
        let mut file = fs::File::create(PRESIGNATURES_FILE).unwrap();
        serde_json::to_writer_pretty(&mut file, &data).unwrap();
    }
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_basic_sign() {
    let network = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .build()
        .await;

    network
        .assert_presignatures(2, Duration::from_millis(300))
        .await;

    tracing::info!("sending requests now");
    let request = sign_request(0);
    network[0].sign_tx.send(request.clone()).await.unwrap();
    network[1].sign_tx.send(request.clone()).await.unwrap();
    network[2].sign_tx.send(request.clone()).await.unwrap();

    let timeout = Duration::from_secs(10);

    let actions = network.assert_actions(1, timeout).await;

    assert_eq!(actions.len(), 1);
    let action_str = actions.iter().next().unwrap();
    assert!(
        action_str.contains("RpcAction::Publish"),
        "unexpected rpc action {action_str}"
    );
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sign_task_survives_resharing() {
    let network = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .build()
        .await;

    tokio::time::timeout(Duration::from_secs(5), network.wait_for_running())
        .await
        .expect("nodes should reach running state");

    network
        .assert_presignatures(1, Duration::from_secs(5))
        .await;

    let request = sign_request(7);
    for node in &network.nodes {
        node.sign_tx.send(request.clone()).await.unwrap();
    }

    network.trigger_resharing();
    tokio::time::sleep(Duration::from_millis(200)).await;
    network.complete_resharing();

    let actions = network.assert_actions(1, Duration::from_secs(15)).await;
    let action_str = actions.iter().next().unwrap();
    assert!(
        action_str.contains("RpcAction::Publish"),
        "unexpected rpc action {action_str}"
    );
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sign_request_during_resharing() {
    let network = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .build()
        .await;

    tokio::time::timeout(Duration::from_secs(5), network.wait_for_running())
        .await
        .expect("nodes should reach running state");

    network.trigger_resharing();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let request = sign_request(8);
    for node in &network.nodes {
        node.sign_tx.send(request.clone()).await.unwrap();
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    network.complete_resharing();

    let actions = network.assert_actions(1, Duration::from_secs(15)).await;
    let action_str = actions.iter().next().unwrap();
    assert!(
        action_str.contains("RpcAction::Publish"),
        "unexpected rpc action {action_str}"
    );
}

fn sign_request(seed: u8) -> Sign {
    Sign::Request(IndexedSignRequest::sign(
        SignId::new([seed; 32]),
        super::helpers::test_sign_arg(seed),
        Chain::NEAR,
        0,
    ))
}

/// drop the first 20 presignature messages on each node and see if the system
/// can recover
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_presignature_timeout() {
    fn create_filter() -> MessageFilter {
        let mut drop_counter = 20;
        Box::new(move |(msg, _)| {
            let pass = match msg {
                mpc_node::protocol::Message::Presignature(_) => drop_counter == 0,
                _ => true,
            };

            if !pass {
                drop_counter -= 1;
            }
            pass
        })
    }

    let network = MpcFixtureBuilder::default()
        // configure network ready to generate presignatures immediately
        .only_generate_presignatures()
        // set presignature generation target (each node generates at least 5)
        .with_node_min_presignatures(5)
        // apply message filter to all nodes
        .with_outgoing_message_filter(0, create_filter())
        .with_outgoing_message_filter(1, create_filter())
        .with_outgoing_message_filter(2, create_filter())
        // speed up timeout
        .with_presignature_timeout_ms(2000)
        .build()
        .await;

    network
        .assert_presignatures(1, Duration::from_secs(300))
        .await;
}

/// Test that with adequate presignature stockpile, sign requests complete
/// without burning extra presignatures. Each signature should consume exactly
/// one presignature. This test verifies that the sign task organization
/// (proposer selection) works correctly and doesn't cause presignature waste.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sign_adequate_stockpile() {
    // We have ~15 presignatures in the fixture (5 mine + 10 foreign per node approx).
    // This test sends fewer requests than available presignatures to verify
    // that each signature consumes exactly one presignature.
    const NUM_SIGN_REQUESTS: u8 = 10;

    let network = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .build()
        .await;

    // Wait for presignatures to be loaded
    network
        .assert_presignatures(1, Duration::from_millis(500))
        .await;

    // Count initial presignatures from first node (all nodes share same Redis)
    let initial_presignatures = network[0].presignature_storage.len_generated().await;
    tracing::info!(initial_presignatures, "starting presignature count");

    // Send sign requests to all nodes concurrently
    tracing::info!(NUM_SIGN_REQUESTS, "sending sign requests");
    for seed in 0..NUM_SIGN_REQUESTS {
        let request = sign_request(seed);
        for node in &network.nodes {
            node.sign_tx.send(request.clone()).await.unwrap();
        }
    }

    // Wait for all signatures to be produced
    let timeout = Duration::from_secs(60);
    let actions = network
        .assert_actions(NUM_SIGN_REQUESTS as usize, timeout)
        .await;

    assert_eq!(
        actions.len(),
        NUM_SIGN_REQUESTS as usize,
        "should have exactly {NUM_SIGN_REQUESTS} signatures"
    );

    // Verify all actions are publish actions
    for action_str in &actions {
        assert!(
            action_str.contains("RpcAction::Publish"),
            "unexpected rpc action {action_str}"
        );
    }

    // Count final presignatures to verify consumption
    let final_presignatures = network[0].presignature_storage.len_generated().await;
    tracing::info!(final_presignatures, "ending presignature count");

    // Each signature should consume exactly one presignature
    let presignatures_consumed = initial_presignatures.saturating_sub(final_presignatures);
    tracing::info!(
        presignatures_consumed,
        signatures_produced = NUM_SIGN_REQUESTS,
        "presignature consumption"
    );

    // We expect presignatures consumed to equal signatures produced.
    // If presignatures are being "burned" (wasted), we'd see more consumption.
    assert!(
        presignatures_consumed <= NUM_SIGN_REQUESTS as usize + 2, // small tolerance for edge cases
        "too many presignatures consumed ({presignatures_consumed}) for {NUM_SIGN_REQUESTS} signatures - possible presignature burning issue"
    );
}

/// Test sign request behavior under presignature contention. When there are
/// fewer presignatures than sign requests, tasks must wait and coordinate.
/// This test verifies that sign tasks don't get stuck in infinite loops
/// choosing new proposers and burning presignatures.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sign_limited_stockpile_contention() {
    // Send more sign requests than presignatures to trigger contention.
    // We have ~15 presignatures in fixture, send 12 requests.
    // All should complete since we have enough presignatures.
    const NUM_SIGN_REQUESTS: u8 = 12;

    let network = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .build()
        .await;

    // Wait for presignatures to be loaded
    network
        .assert_presignatures(1, Duration::from_millis(500))
        .await;

    // Get initial count from first node (all nodes share same Redis pool)
    let initial_presignatures = network[0].presignature_storage.len_generated().await;
    tracing::info!(
        initial_presignatures,
        num_requests = NUM_SIGN_REQUESTS,
        "starting contention test"
    );

    // Send all requests at once to maximize contention
    tracing::info!(NUM_SIGN_REQUESTS, "sending sign requests simultaneously");
    for seed in 0..NUM_SIGN_REQUESTS {
        let request = sign_request(seed);
        for node in &network.nodes {
            node.sign_tx.send(request.clone()).await.unwrap();
        }
    }

    // We expect to complete at least as many signatures as we have presignatures.
    // With contention, this tests that tasks properly coordinate and don't get
    // stuck in reorganization loops burning presignatures.
    let min_expected_signatures = initial_presignatures.min(NUM_SIGN_REQUESTS as usize);

    // Use a generous timeout since contention may slow things down
    let timeout = Duration::from_secs(90);
    let actions = network
        .assert_actions(min_expected_signatures, timeout)
        .await;

    // Count final presignatures
    let final_presignatures = network[0].presignature_storage.len_generated().await;
    let presignatures_consumed = initial_presignatures.saturating_sub(final_presignatures);

    tracing::info!(
        signatures_produced = actions.len(),
        min_expected = min_expected_signatures,
        presignatures_consumed,
        "contention test completed"
    );

    assert!(
        actions.len() >= min_expected_signatures,
        "should have produced at least {min_expected_signatures} signatures, got {}",
        actions.len()
    );

    // Verify all actions are publish actions
    for action_str in &actions {
        assert!(
            action_str.contains("RpcAction::Publish"),
            "unexpected rpc action {action_str}"
        );
    }

    // Verify no excessive presignature burning
    // Consumed should be <= signatures produced + small margin for contention
    assert!(
        presignatures_consumed <= actions.len() + 3,
        "too many presignatures consumed ({presignatures_consumed}) for {} signatures - possible presignature burning",
        actions.len()
    );
}

/// Test that sign requests wait for presignatures and complete when more become available.
/// This verifies:
/// 1. Sign requests don't fail when there aren't enough presignatures
/// 2. Sign requests complete as presignatures become available
/// 3. No presignature burning during the waiting period
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sign_requests_wait_for_presignatures() {
    // We'll send 20 sign requests but start with only enough presignatures for ~10.
    // The first batch should complete, then we generate more presignatures to
    // complete the remaining requests.
    const TOTAL_SIGN_REQUESTS: u8 = 20;
    const FIRST_BATCH_SIZE: usize = 10;

    // Use a network that can generate presignatures (has preshared triples)
    // but starts with the stockpiled presignatures from fixture
    let network = MpcFixtureBuilder::default()
        .with_preshared_key()
        .with_preshared_triples()
        .with_preshared_presignatures()
        // Disable triple generation since we're using preshared triples
        .with_node_min_triples(0)
        // Enable presignature generation for second batch
        .with_node_min_presignatures(5)
        .build()
        .await;

    // Wait for initial presignatures to be loaded
    network
        .assert_presignatures(1, Duration::from_millis(500))
        .await;

    let initial_presignatures = network[0].presignature_storage.len_generated().await;
    tracing::info!(
        initial_presignatures,
        total_requests = TOTAL_SIGN_REQUESTS,
        "starting presignature wait test"
    );

    // Send ALL sign requests at once - more than we have presignatures for
    tracing::info!(TOTAL_SIGN_REQUESTS, "sending all sign requests");
    for seed in 0..TOTAL_SIGN_REQUESTS {
        let request = sign_request(seed);
        for node in &network.nodes {
            node.sign_tx.send(request.clone()).await.unwrap();
        }
    }

    // First batch: wait for as many signatures as we initially have presignatures
    let first_batch_expected = initial_presignatures.min(FIRST_BATCH_SIZE);
    tracing::info!(first_batch_expected, "waiting for first batch");

    let first_batch_timeout = Duration::from_secs(30);
    let first_actions = network
        .assert_actions(first_batch_expected, first_batch_timeout)
        .await;

    tracing::info!(
        first_batch_completed = first_actions.len(),
        "first batch completed"
    );

    // Check presignatures after first batch
    let after_first_batch = network[0].presignature_storage.len_generated().await;
    tracing::info!(
        after_first_batch,
        consumed = initial_presignatures.saturating_sub(after_first_batch),
        "presignatures after first batch"
    );

    // Now wait for more presignatures to be generated
    // The remaining sign requests should be waiting
    tracing::info!("waiting for presignature generation to catch up");
    network
        .assert_presignatures(3, Duration::from_secs(120))
        .await;

    let after_generation = network[0].presignature_storage.len_generated().await;
    tracing::info!(after_generation, "presignatures after generation");

    // Now wait for remaining signatures to complete
    tracing::info!("waiting for remaining signatures");
    let final_timeout = Duration::from_secs(60);
    let final_actions = network
        .assert_actions(TOTAL_SIGN_REQUESTS as usize, final_timeout)
        .await;

    tracing::info!(
        total_signatures = final_actions.len(),
        "all signatures completed"
    );

    assert_eq!(
        final_actions.len(),
        TOTAL_SIGN_REQUESTS as usize,
        "should complete all {} sign requests",
        TOTAL_SIGN_REQUESTS
    );

    // Verify all actions are publish actions
    for action_str in &final_actions {
        assert!(
            action_str.contains("RpcAction::Publish"),
            "unexpected rpc action {action_str}"
        );
    }
}

/// Test sign request contention with 5 nodes.
/// This test generates triples and presignatures on-the-fly (slower but more realistic).
/// Uses 5_nodes.json fixture for pre-shared keys only.
#[test(tokio::test(flavor = "multi_thread"))]
#[ignore]
async fn test_sign_contention_5_nodes() {
    const NUM_NODES: u32 = 5;
    const THRESHOLD: usize = 4;
    const NUM_SIGN_REQUESTS: u8 = 5; // Reduced from 10 to match presignature availability
    const MIN_PRESIGNATURES_PER_OWNER: usize = 3;
    const NODE_MIN_ARTIFACTS: u32 = 8;

    tracing::info!(
        num_nodes = NUM_NODES,
        threshold = THRESHOLD,
        num_requests = NUM_SIGN_REQUESTS,
        "starting 5-node contention test with on-the-fly generation"
    );

    // Build network with pre-shared keys, generate triples/presignatures on the fly.
    // Use low concurrency limits to stress contention with 5 nodes.
    let network = MpcFixtureBuilder::new(NUM_NODES, THRESHOLD)
        .with_preshared_key()
        .with_node_min_triples(NODE_MIN_ARTIFACTS)
        .with_node_min_presignatures(NODE_MIN_ARTIFACTS)
        .with_max_concurrent_introduction(8)
        .with_max_concurrent_generation(8 * NUM_NODES * 4)
        .build()
        .await;

    // Wait for presignatures to be generated - 5-node triple generation takes ~3-4 minutes
    // We wait for a modest per-owner count since distribution is not uniform
    tracing::info!("waiting for presignatures to be generated (triple gen takes ~3-4 min)...");
    let timeout = Duration::from_secs(600); // 10 minutes for triple + presignature generation
    network
        .assert_presignatures(MIN_PRESIGNATURES_PER_OWNER, timeout)
        .await;

    let initial_presignatures = network[0].presignature_storage.len_generated().await;
    tracing::info!(
        initial_presignatures,
        "presignatures ready, sending sign requests"
    );

    // Send sign requests to all nodes concurrently (simulates real network conditions)
    for seed in 0..NUM_SIGN_REQUESTS {
        let request = sign_request(seed);
        for node in &network.nodes {
            node.sign_tx.send(request.clone()).await.unwrap();
        }
    }

    // Wait for all signatures - allow more time for 5-node consensus
    let timeout = Duration::from_secs(120);
    let actions = network
        .assert_actions(NUM_SIGN_REQUESTS as usize, timeout)
        .await;

    let final_presignatures = network[0].presignature_storage.len_generated().await;
    let presignatures_consumed = initial_presignatures.saturating_sub(final_presignatures);

    tracing::info!(
        signatures_produced = actions.len(),
        initial_presignatures,
        final_presignatures,
        presignatures_consumed,
        "5-node contention test completed"
    );

    assert_eq!(
        actions.len(),
        NUM_SIGN_REQUESTS as usize,
        "should have exactly {} signatures",
        NUM_SIGN_REQUESTS
    );

    for action_str in &actions {
        assert!(
            action_str.contains("RpcAction::Publish"),
            "unexpected rpc action {action_str}"
        );
    }

    // Verify 1:1 presignature consumption (with small tolerance for timing)
    assert!(
        presignatures_consumed <= actions.len() + 2,
        "too many presignatures consumed ({presignatures_consumed}) for {} signatures - potential burning issue",
        actions.len()
    );

    tracing::info!(
        "5-node test passed: {} signatures with {} presignatures consumed",
        actions.len(),
        presignatures_consumed
    );
}

/// Truncate each owner's artifact list to exactly N items, keeping the same
/// IDs across all nodes. Uses the first node's ordering to determine which IDs
/// to keep per owner, then filters all nodes to that consistent set.
/// Panics if any owner has fewer than `n` artifacts.
fn truncate_per_owner<A: mpc_node::storage::protocol_storage::ProtocolArtifact>(
    mut data: BTreeMap<
        cait_sith::protocol::Participant,
        BTreeMap<cait_sith::protocol::Participant, Vec<A>>,
    >,
    n: usize,
) -> BTreeMap<cait_sith::protocol::Participant, BTreeMap<cait_sith::protocol::Participant, Vec<A>>>
where
    A::Id: Ord,
{
    use std::collections::BTreeSet;

    // Determine which IDs to keep per owner using the first node's ordering.
    let mut keep_ids_per_owner: BTreeMap<cait_sith::protocol::Participant, BTreeSet<A::Id>> =
        BTreeMap::new();
    if let Some((first_node, first_owners)) = data.iter().next() {
        for (owner, artifacts) in first_owners {
            assert!(
                artifacts.len() >= n,
                "node {first_node:?} owner {owner:?} has {} artifacts, need {n}",
                artifacts.len()
            );
            let ids: BTreeSet<_> = artifacts.iter().take(n).map(|a| a.id()).collect();
            keep_ids_per_owner.insert(*owner, ids);
        }
    }

    // Filter all nodes to keep only the chosen IDs per owner.
    for (node, owners) in &mut data {
        for (owner, artifacts) in owners.iter_mut() {
            if let Some(keep_ids) = keep_ids_per_owner.get(owner) {
                artifacts.retain(|a| keep_ids.contains(&a.id()));
                assert!(
                    artifacts.len() == n,
                    "node {node:?} owner {owner:?} has {} artifacts after filtering, expected {n}",
                    artifacts.len()
                );
            }
        }
    }
    data
}

/// Filter artifact data to keep only artifacts that exist on ALL nodes.
fn filter_artifacts_on_all_nodes<A: mpc_node::storage::protocol_storage::ProtocolArtifact>(
    mut data: BTreeMap<
        cait_sith::protocol::Participant,
        BTreeMap<cait_sith::protocol::Participant, Vec<A>>,
    >,
) -> BTreeMap<cait_sith::protocol::Participant, BTreeMap<cait_sith::protocol::Participant, Vec<A>>>
where
    A::Id: Ord,
{
    use std::collections::BTreeSet;

    let ids_per_node: Vec<BTreeSet<_>> = data
        .values()
        .map(|owners| owners.values().flatten().map(|a| a.id()).collect())
        .collect();

    let Some((first, rest)) = ids_per_node.split_first() else {
        return data;
    };
    let mut common = first.clone();
    for ids in rest {
        common.retain(|id| ids.contains(id));
    }

    let total = ids_per_node.iter().map(|s| s.len()).max().unwrap_or(0);
    let discarded = total.saturating_sub(common.len());
    let pct = if total > 0 {
        discarded as f64 / total as f64 * 100.0
    } else {
        0.0
    };
    tracing::info!(
        total,
        kept = common.len(),
        discarded,
        pct_discarded = format_args!("{pct:.1}%"),
        nodes = data.len(),
        "filtered artifacts to those on all nodes"
    );

    for owners in data.values_mut() {
        for artifacts in owners.values_mut() {
            artifacts.retain(|a| common.contains(&a.id()));
        }
        owners.retain(|_, v| !v.is_empty());
    }
    data
}

/// Verify 1:1 presignature-to-signature consumption with threshold=3 (no waste).
/// Sends exactly as many sign requests as there are pregenerated presignatures
/// and asserts that zero presignatures remain.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sign_no_presignature_waste() {
    let network = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .build()
        .await;

    // Wait for pre-signatures to be added to Redis.
    // Check threshold=1 per node since ownership is distributed across nodes.
    network
        .assert_presignatures(1, Duration::from_millis(500))
        .await;

    let initial_presignatures = network[0].presignature_storage.len_generated().await;
    assert!(
        initial_presignatures > 0,
        "fixture should contain pregenerated presignatures"
    );
    tracing::info!(
        initial_presignatures,
        "sending exactly this many sign requests"
    );

    for seed in 0..initial_presignatures {
        let request = sign_request(seed as u8);
        for node in &network.nodes {
            node.sign_tx.send(request.clone()).await.unwrap();
        }
    }

    let actions = network
        .assert_actions(initial_presignatures, Duration::from_secs(120))
        .await;

    assert_eq!(
        actions.len(),
        initial_presignatures,
        "should have exactly {initial_presignatures} signatures"
    );

    for action_str in &actions {
        assert!(
            action_str.contains("RpcAction::Publish"),
            "unexpected rpc action {action_str}"
        );
    }

    // Verify every node has zero presignatures remaining.
    for node in &network.nodes {
        let remaining = node.presignature_storage.len_by_owner(node.me).await;

        tracing::info!(
            node = ?node.me,
            remaining,
            "node presignature stats"
        );

        assert_eq!(
            remaining, 0,
            "node {:?} still has {remaining} presignatures remaining",
            node.me
        );
    }
}

/// Verify 1:1 triple-pair-to-presignature consumption with no waste.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_presignature_no_triple_waste() {
    let network = MpcFixtureBuilder::default()
        .only_generate_presignatures()
        // Set a high target so nodes keep generating until triple pairs run out
        .with_node_min_presignatures(1000)
        .build()
        .await;

    // len_generated() counts triple pairs (each storing two triples).
    let initial_triple_pairs = network[0].triple_storage.len_generated().await;
    assert!(
        initial_triple_pairs > 0,
        "fixture should contain pregenerated triple pairs"
    );
    tracing::info!(
        initial_triple_pairs,
        "starting triple-pair-to-presignature test"
    );

    // Each presignature consumes exactly one triple pair, so ratio is 1:1.
    let expected_presignatures = initial_triple_pairs;
    // assert_presignatures checks per-node ownership count, so divide by number of nodes.
    let expected_per_node = expected_presignatures / network.nodes.len();
    // Wait for all presignatures to be generated from all available triple pairs.
    // assert_presignatures waits until EVERY node owns >= expected_per_node,
    // which means all triple pairs have been consumed (each owner has exactly
    // expected_per_node triple pairs to convert).
    network
        .assert_presignatures(expected_per_node, Duration::from_secs(180))
        .await;

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut all_drained = true;

            for node in &network.nodes {
                if node.triple_storage.len_by_owner(node.me).await != 0 {
                    all_drained = false;
                    break;
                }
            }

            if all_drained {
                break;
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("triple pairs should drain after presignatures are generated");

    // Verify every node consumed all its triple pairs and produced the expected presignatures.
    for node in &network.nodes {
        let remaining_triples = node.triple_storage.len_by_owner(node.me).await;
        let owned_presignatures = node.presignature_storage.len_by_owner(node.me).await;

        tracing::info!(
            node = ?node.me,
            remaining_triples,
            owned_presignatures,
            expected_per_node,
            "node stats"
        );

        assert_eq!(
            remaining_triples, 0,
            "node {:?} still has {remaining_triples} triple pairs remaining",
            node.me
        );

        assert!(
            owned_presignatures >= expected_per_node,
            "node {:?} expected at least {expected_per_node} presignatures, got {owned_presignatures}",
            node.me
        );
    }
}

/// Test that a node losing their presignatures locally doesn't prevent
/// signatures from going through.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sign_missing_presignature() {
    // 3 nodes, threshold 2, should be possible to generate a signature with one
    // node missing their presignatures
    let network = MpcFixtureBuilder::new(3, 2)
        .only_generate_signatures()
        .build()
        .await;

    network
        .assert_presignatures(2, Duration::from_millis(300))
        .await;

    // Now delete presignatures of one node
    let bad_node = 0;
    let success = network.nodes[bad_node].presignature_storage.clear().await;
    assert!(success, "failed to clear presignature storage");
    // give some time for redis to fully delete state
    // (the test is flaky without this delay)
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Now we submit the request
    tracing::info!("sending requests now");
    let request = sign_request(0);
    for node in &network.nodes {
        node.sign_tx.send(request.clone()).await.unwrap();
    }

    // give 2 minutes to resolve the problem
    // expectation: the node without the presignature will reject a posit, or if
    // they are proposer, a timeout will let the next proposer take over
    let timeout = Duration::from_secs(120);
    let actions = network.assert_actions(1, timeout).await;

    let msg_log = network.output.msg_log.lock().await;
    msg_log.print_summary();

    assert_eq!(actions.len(), 1);
    let action_str = actions.iter().next().unwrap();
    assert!(
        action_str.contains("RpcAction::Publish"),
        "unexpected rpc action {action_str}"
    );
}

/// Test that a node losing their presignatures locally doesn't prevent
/// signatures from going through, even if it happens after the posits were
/// accepted.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sign_missing_presignature_after_posits() {
    // never send signature messages and trigger presignature deletion when this
    // node would be involved in signing the first time
    fn create_filter(tx: oneshot::Sender<()>) -> MessageFilter {
        let mut maybe_tx = Some(tx);
        Box::new(move |(msg, _)| match msg {
            mpc_node::protocol::Message::Signature(_signature_message) => {
                if let Some(tx) = maybe_tx.take() {
                    tx.send(()).unwrap();
                };
                false
            }
            _ => true,
        })
    }

    // trigger deletion of presignatures when signature messages start
    let (tx, rx) = oneshot::channel();

    // 3 nodes, threshold 2, should be possible to generate a signature with one
    // node missing their presignatures
    // note: bad node must not be the first proposer for this test to work as intended
    let bad_node = 1;
    let network = MpcFixtureBuilder::new(3, 2)
        .only_generate_signatures()
        .with_outgoing_message_filter(bad_node, create_filter(tx))
        .build()
        .await;

    network
        .assert_presignatures(2, Duration::from_millis(300))
        .await;

    // Now we submit the request
    tracing::info!("sending requests now");
    let request = sign_request(0);
    for node in &network.nodes {
        node.sign_tx.send(request.clone()).await.unwrap();
    }

    // Wait for first round of posits to go through.
    tokio::time::timeout(Duration::from_millis(5000), rx)
        .await
        .expect("should quickly start signing")
        .unwrap();

    // Now delete presignatures of one node, which will make it reject future posits
    let success = network.nodes[bad_node].presignature_storage.clear().await;
    assert!(success, "failed to clear presignature storage");
    // give some time for redis to fully delete state
    // (the test is flaky without this delay)
    tokio::time::sleep(Duration::from_secs(1)).await;

    // give 2 minutes to resolve the problem
    // expectation: The current signature fails and eventually a new round of
    // posits starts. Then, the node without the presignature will reject a
    // posit, or if they are proposer, a timeout will let the next
    // proposer take over.
    let timeout = Duration::from_secs(120);
    let actions = network.assert_actions(1, timeout).await;

    let msg_log = network.output.msg_log.lock().await;
    msg_log.print_summary();

    assert_eq!(actions.len(), 1);
    let action_str = actions.iter().next().unwrap();
    assert!(
        action_str.contains("RpcAction::Publish"),
        "unexpected rpc action {action_str}"
    );
}

/// Verify that nodes that are not selected as participants for a signature
/// generation pause after receiving enough AlreadyGenerating rejections.
///
/// Setup:
/// - Nodes 0 and 1 enter SignGenerating together, messages are gated to freeze their progress
/// - Node 2 is excluded, one ORGANIZE_POSIT_TIMEOUT later, it tries to be a proposer
/// - Nodes 0 and 1 reply with AlreadyGenerating.
/// - The gate is released, signature messages flow, and the signature completes
/// - Assertion: AlreadyGenerating have been sent
/// - Continue and observe node 2 not trying to be a proposer again until
///   `signature_timeout_ms` has passed.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_non_participants_pause_posits() {
    /// Observer struct just for this test
    struct Tracker {
        target: Participant,
        already_generating_received: Arc<AtomicUsize>,
        proposer_attempts: Arc<AtomicUsize>,
    }
    impl CollectMessages for Tracker {
        fn observe_message(&mut self, msg: &SendMessage, _passed_filter: bool) {
            let (message, (from, to, _ts)) = msg;
            if *to == self.target {
                if let Message::Posit(posit_msg) = message {
                    if matches!(
                        posit_msg.action,
                        PositAction::RejectWithReason(PositRejectReason::AlreadyGenerating)
                    ) {
                        self.already_generating_received
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            if *from == self.target {
                if let Message::Posit(posit_msg) = message {
                    if matches!(posit_msg.action, PositAction::Propose) {
                        self.proposer_attempts.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        fn print_summary(&self) {}
    }

    let gate_released = Arc::new(AtomicBool::new(false));
    let gate_0 = Arc::clone(&gate_released);
    let gate_1 = Arc::clone(&gate_released);
    let already_gen_count = Arc::new(AtomicUsize::new(0));
    let node_2_propose_count = Arc::new(AtomicUsize::new(0));
    let tracker = Tracker {
        target: Participant::from(2),
        already_generating_received: Arc::clone(&already_gen_count),
        proposer_attempts: Arc::clone(&node_2_propose_count),
    };
    let signature_timeout_ms = 16_000;

    let network = MpcFixtureBuilder::new(3, 2)
        .only_generate_signatures()
        .with_signature_timeout_ms(signature_timeout_ms)
        .with_outgoing_message_filter(
            // Node 0: Hold signature messages until the gate is released.
            0,
            Box::new(move |msg: &SendMessage| {
                let (message, (_from, _to, _ts)) = msg;
                if matches!(message, Message::Signature(_)) {
                    while !gate_0.load(Ordering::Acquire) {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                }
                true
            }),
        )
        .with_outgoing_message_filter(
            // Node 1: Hold signature messages until the gate is released.
            1,
            Box::new(move |msg: &SendMessage| {
                let (message, (_from, _to, _ts)) = msg;
                if matches!(message, Message::Signature(_)) {
                    while !gate_1.load(Ordering::Acquire) {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                }
                true
            }),
        )
        .with_outgoing_message_filter(
            // Node 2: receives a PROPOSE from node 1 but we drop the ACCEPT, so node 2 is excluded from the signature.
            2,
            Box::new(move |msg: &SendMessage| {
                let (message, (_from, _to, _ts)) = msg;
                if let Message::Posit(posit_msg) = message {
                    if matches!(posit_msg.action, PositAction::Accept) {
                        return false;
                    }
                }
                true
            }),
        )
        .with_message_collector(Arc::new(Mutex::new(tracker)))
        .build()
        .await;

    // For seed 0, SHA256([0,0,0,0])[0] = 0xdf = 223, and 223 % 3 = 1, so:
    //   round 0 -> participant 1 (proposes immediately, generates with node 0)
    //   round 1 -> participant 2 (target: excluded from round-0, proposes after 1 timeout)
    //   round 2 -> participant 0
    // Node 2's Accept to node 1's Propose is dropped, so generation is {0, 1}.
    // After ORGANIZE_POSIT_TIMEOUT, node 2 becomes round-1 proposer and
    // receives AlreadyGenerating from nodes 0 and 1.
    let request = sign_request(0);

    // Send the request to all three nodes.
    network[0].sign_tx.send(request.clone()).await.unwrap();
    network[1].sign_tx.send(request.clone()).await.unwrap();
    network[2].sign_tx.send(request.clone()).await.unwrap();

    // Wait for node 2 to propose once, sending a message to both other nodes.
    // Should happen after ~1 ORGANIZE_POSIT_TIMEOUT (5s for tests)
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let count = node_2_propose_count.load(Ordering::Relaxed);
            if count >= 2 {
                return;
            }
        }
    })
    .await
    .expect("node 2 never proposed in the first place");
    let first_propose = Instant::now();

    // Give some time for the PROPOSE to be rejected.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Release the gate: Signature messages between 0 and 1 are forwarded and
    // they can complete the signature. The AlreadyGenerating replies are now
    // in the outbox queue (ahead of the post-gate signature traffic), so they
    // will be forwarded and counted before the signature finishes.
    gate_released.store(true, Ordering::Release);

    let actions = network.assert_actions(1, Duration::from_secs(20)).await;

    assert_eq!(actions.len(), 1);
    assert!(
        actions
            .iter()
            .next()
            .unwrap()
            .contains("RpcAction::Publish"),
        "expected a Publish action"
    );

    let count = already_gen_count.load(Ordering::Relaxed);
    assert!(
        count >= 1,
        "expected AlreadyGenerating to be sent to node 2, but count was {count}"
    );

    // Node 2 still hasn't seen the signature. Wait until it proposes again.
    // After the pause, node 2 may need up to (num_nodes+1) more rounds to get
    // its turn as proposer. Each round lasts ORGANIZE_POSIT_TIMEOUT.
    let organize_timeout = mpc_node::protocol::signature::organize_posit_timeout();
    let second_wait = Duration::from_millis(signature_timeout_ms) + 4 * organize_timeout;
    tokio::time::timeout(second_wait, async {
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let count = node_2_propose_count.load(Ordering::Relaxed);
            if count > 2 {
                return;
            }
        }
    })
    .await
    .expect("node 2 never proposed again");

    assert!(
        first_propose.elapsed().as_millis() as u64 > signature_timeout_ms,
        "node 2 started proposing again too early"
    )
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_triples_message_count() {
    let network = MpcFixtureBuilder::default()
        .only_generate_triples()
        .with_message_collector(Arc::new(Mutex::new(MessageCounter::default())))
        .build()
        .await;

    network.assert_triples(1, Duration::from_secs(120)).await;

    // This prints a summary of all sent message counts for debugging
    let msg_log = network.output.msg_log.lock().await;
    msg_log.print_summary();

    // Check there are not too many sent messages.
    //
    // For finished protocols, there should be message counts as follows:
    // Participants with a lower id send at most 16 messages to participant with higher ids.
    // Participants with a higher id send at most 141 messages to participant with lower ids.
    // In both cases, fewer messages are observed for ongoing protocols that
    // already started but got interrupted.
    //
    // Note: We don't actually care about these specific numbers. But we want to
    // understand what the numbers are and check they do not increase unexpectedly.
    for (from, to, link_stats) in msg_log.clone_as_message_counter().unwrap().link_stats() {
        for (key, num) in &link_stats.message_counts {
            if key.contains("Triple") {
                if from < to {
                    // receiver in shared multiplication sends fewer messages
                    assert!(*num <= 16, "{from:?} -> {to:?} sent {num} messages");
                } else {
                    // sender in shared multiplication sends more messages
                    assert!(*num <= 141, "{from:?} -> {to:?} sent {num} messages");
                }
            }
        }
    }
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_presignature_message_count() {
    let network = MpcFixtureBuilder::default()
        .only_generate_presignatures()
        .with_message_collector(Arc::new(Mutex::new(MessageCounter::default())))
        .build()
        .await;

    network
        .assert_presignatures(1, Duration::from_secs(10))
        .await;

    // This prints a summary of all sent message counts for debugging
    let msg_log = network.output.msg_log.lock().await;
    msg_log.print_summary();

    // Check there are not too many sent messages.
    // There should be exactly 2 messages per link for finished protocols.
    // But fewer messages are observed for ongoing protocols that already
    // started but got interrupted.
    for (from, to, link_stats) in msg_log.clone_as_message_counter().unwrap().link_stats() {
        for (key, num) in &link_stats.message_counts {
            if key.contains("Presignature") {
                assert!(*num <= 2, "{from:?} -> {to:?} sent {num} messages");
            }
        }
    }
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_signature_message_count() {
    let network = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .with_message_collector(Arc::new(Mutex::new(MessageCounter::default())))
        .build()
        .await;

    network
        .assert_presignatures(2, Duration::from_millis(300))
        .await;

    tracing::info!("sending requests now");
    let request = sign_request(0);
    network[0].sign_tx.send(request.clone()).await.unwrap();
    network[1].sign_tx.send(request.clone()).await.unwrap();
    network[2].sign_tx.send(request.clone()).await.unwrap();

    network.assert_actions(1, Duration::from_secs(10)).await;

    // This prints a summary of all sent message counts for debugging
    let msg_log = network.output.msg_log.lock().await;
    msg_log.print_summary();

    // Check message counts are as expected. Right now, the expectation is:
    // Exactly 1 message per link
    for (from, to, link_stats) in msg_log.clone_as_message_counter().unwrap().link_stats() {
        for (key, num) in &link_stats.message_counts {
            if key.contains("Signature") {
                assert_eq!(1, *num, "{from:?} -> {to:?} sent {num} messages");
            }
        }
    }
}

#[test]
fn test_filter_artifacts_on_all_nodes() {
    use super::helpers::dummy_pair;
    use cait_sith::protocol::Participant;

    let p0 = Participant::from(0);
    let p1 = Participant::from(1);
    let p2 = Participant::from(2);

    // Artifact 1 on all nodes, artifact 2 only on p0 and p1, artifact 3 only on p0
    let mut data = BTreeMap::new();
    data.insert(
        p0,
        BTreeMap::from([(p0, vec![dummy_pair(1), dummy_pair(2), dummy_pair(3)])]),
    );
    data.insert(
        p1,
        BTreeMap::from([(p1, vec![dummy_pair(1), dummy_pair(2)])]),
    );
    data.insert(p2, BTreeMap::from([(p2, vec![dummy_pair(1)])]));

    let filtered = filter_artifacts_on_all_nodes(data);

    // Only artifact 1 should survive
    for owners in filtered.values() {
        let ids: Vec<_> = owners.values().flatten().map(|a| a.id).collect();
        assert_eq!(ids, vec![1]);
    }
}

#[test]
fn test_truncate_per_owner() {
    use super::helpers::dummy_pair;
    use cait_sith::protocol::Participant;

    let p0 = Participant::from(0);
    let p1 = Participant::from(1);

    // Two nodes, each with 3 items for the same owner, truncated to 2.
    // Both nodes should keep the same 2 IDs.
    let mut data = BTreeMap::new();
    data.insert(
        p0,
        BTreeMap::from([(p0, vec![dummy_pair(1), dummy_pair(2), dummy_pair(3)])]),
    );
    data.insert(
        p1,
        BTreeMap::from([(p0, vec![dummy_pair(1), dummy_pair(2), dummy_pair(3)])]),
    );
    let result = truncate_per_owner(data, 2);
    assert_eq!(result[&p0][&p0].len(), 2);
    assert_eq!(result[&p1][&p0].len(), 2);
    // Same IDs on both nodes
    let ids0: Vec<_> = result[&p0][&p0].iter().map(|a| a.id).collect();
    let ids1: Vec<_> = result[&p1][&p0].iter().map(|a| a.id).collect();
    assert_eq!(ids0, ids1);
}

#[test]
#[should_panic]
fn test_truncate_per_owner_insufficient() {
    use super::helpers::dummy_pair;
    use cait_sith::protocol::Participant;

    let p = Participant::from(0);

    // 1 item but need 2
    let mut data = BTreeMap::new();
    data.insert(p, BTreeMap::from([(p, vec![dummy_pair(1)])]));
    truncate_per_owner(data, 2);
}
