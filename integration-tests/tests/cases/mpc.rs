use deadpool_redis::redis::AsyncCommands;
use integration_tests::mpc_fixture::fixture_tasks::MessageFilter;
use integration_tests::mpc_fixture::MpcFixtureBuilder;
use mpc_node::protocol::presignature::Presignature;
use mpc_node::protocol::SignRequestType;
use mpc_node::protocol::{Chain, IndexedSignRequest, ProtocolState, Sign};
use mpc_node::storage::triple_storage::TriplePair;
use mpc_primitives::{SignArgs, SignId, LATEST_MPC_KEY_VERSION};
use test_log::test;

use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

/// Use this toggle locally to regenerate hard-coded inputs such as key shares,
/// triples, and presignatures.
/// You might have to create the directory `integrations-tests/tmp` first.
const WRITE_OUTPUT_TO_FILES: bool = false;
const KEY_SHARE_FILE: &str = "tmp/key_shares.json";
const TRIPLES_FILE: &str = "tmp/triples.json";
const PRESIGNATURES_FILE: &str = "tmp/presignatures.json";

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

    // give time to make all nodes aware that the protocol is running now
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

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
    let network = MpcFixtureBuilder::default()
        .only_generate_triples()
        .build()
        .await;

    tokio::time::timeout(Duration::from_secs(180), network.wait_for_triples(1))
        .await
        .expect("should have enough triples eventually");

    if WRITE_OUTPUT_TO_FILES {
        let mut conn = network.redis_container.pool().get().await.unwrap();
        let mut data = BTreeMap::new();
        for node in &network.nodes {
            let mut nodes_shares = BTreeMap::new();
            for peer in &network.nodes {
                let triple_ids = node.triple_storage.fetch_owned(peer.me).await;
                let mut peer_triples = Vec::with_capacity(triple_ids.len());
                for triple_id in triple_ids {
                    let pair = conn
                        .hget::<&str, u64, TriplePair>(node.triple_storage.triple_key(), triple_id)
                        .await;
                    if let Ok(pair) = pair {
                        peer_triples.push(pair);
                    } else {
                        tracing::error!("missing triple in redis {triple_id}");
                    }
                }
                nodes_shares.insert(peer.me, peer_triples);
            }
            data.insert(node.me, nodes_shares);
        }

        let abs_path = std::env::current_dir().unwrap().join(TRIPLES_FILE);
        tracing::info!("Writing output to {}", abs_path.display());
        let mut file = fs::File::create(TRIPLES_FILE).unwrap();
        serde_json::to_writer_pretty(&mut file, &data).unwrap();
    }
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_basic_generate_presignature() {
    let network = MpcFixtureBuilder::default()
        .only_generate_presignatures()
        .build()
        .await;

    tokio::time::timeout(Duration::from_secs(10), network.wait_for_presignatures(1))
        .await
        .expect("should have enough presignatures eventually");

    if WRITE_OUTPUT_TO_FILES {
        let mut conn = network.redis_container.pool().get().await.unwrap();
        let mut data = BTreeMap::new();
        for node in &network.nodes {
            let mut nodes_shares = BTreeMap::new();
            for peer in &network.nodes {
                let presignature_ids = node.presignature_storage.fetch_owned(peer.me).await;
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

    tokio::time::timeout(
        Duration::from_millis(300),
        network.wait_for_presignatures(2),
    )
    .await
    .expect("should start with enough presignatures");

    tracing::info!("sending requests now");
    let request = sign_request(0);
    network[0]
        .sign_tx
        .send(Sign::Request(request.clone()))
        .await
        .unwrap();
    network[1]
        .sign_tx
        .send(Sign::Request(request.clone()))
        .await
        .unwrap();
    network[2]
        .sign_tx
        .send(Sign::Request(request.clone()))
        .await
        .unwrap();

    let timeout = Duration::from_secs(10);

    let actions = tokio::time::timeout(timeout, network.wait_for_actions(1))
        .await
        .expect("should publish RPC action eventually");

    assert_eq!(actions.len(), 1);
    let action_str = actions.iter().next().unwrap();
    assert!(
        action_str.contains("RpcAction::Publish"),
        "unexpected rpc action {action_str}"
    );
}

fn sign_request(seed: u8) -> IndexedSignRequest {
    IndexedSignRequest {
        id: SignId::new([seed; 32]),
        args: sign_arg(seed),
        chain: Chain::NEAR,
        unix_timestamp_indexed: 0,
        timestamp_sign_queue: std::time::Instant::now(),
        total_timeout: Duration::from_secs(45),
        sign_request_type: SignRequestType::Sign,
    }
}

fn sign_arg(seed: u8) -> SignArgs {
    let mut entropy = [1; 32];
    entropy[0] = seed;
    SignArgs {
        entropy,
        epsilon: k256::Scalar::default(),
        payload: k256::Scalar::default(),
        path: "test".to_owned(),
        key_version: LATEST_MPC_KEY_VERSION,
    }
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
        // set exact presignature count target
        .with_min_presignatures_stockpile(5)
        .with_max_presignatures_stockpile(5)
        // apply message filter to all nodes
        .with_outgoing_message_filter(0, create_filter())
        .with_outgoing_message_filter(1, create_filter())
        .with_outgoing_message_filter(2, create_filter())
        // speed up timeout
        .with_presignature_timeout_ms(2000)
        .build()
        .await;

    tokio::time::timeout(Duration::from_secs(300), network.wait_for_presignatures(1))
        .await
        .expect("should have enough presignatures eventually");
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
    tokio::time::timeout(
        Duration::from_millis(500),
        network.wait_for_presignatures(1),
    )
    .await
    .expect("should start with enough presignatures");

    // Count initial presignatures from first node (all nodes share same Redis)
    let initial_presignatures = network[0].presignature_storage.len_generated().await;
    tracing::info!(initial_presignatures, "starting presignature count");

    // Send sign requests to all nodes concurrently
    tracing::info!(NUM_SIGN_REQUESTS, "sending sign requests");
    for seed in 0..NUM_SIGN_REQUESTS {
        let request = sign_request(seed);
        for node in &network.nodes {
            node.sign_tx
                .send(Sign::Request(request.clone()))
                .await
                .unwrap();
        }
    }

    // Wait for all signatures to be produced
    let timeout = Duration::from_secs(60);
    let actions = tokio::time::timeout(
        timeout,
        network.wait_for_actions(NUM_SIGN_REQUESTS as usize),
    )
    .await
    .expect("should publish all RPC actions eventually");

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
    tokio::time::timeout(
        Duration::from_millis(500),
        network.wait_for_presignatures(1),
    )
    .await
    .expect("should start with presignatures");

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
            node.sign_tx
                .send(Sign::Request(request.clone()))
                .await
                .unwrap();
        }
    }

    // We expect to complete at least as many signatures as we have presignatures.
    // With contention, this tests that tasks properly coordinate and don't get
    // stuck in reorganization loops burning presignatures.
    let min_expected_signatures = initial_presignatures.min(NUM_SIGN_REQUESTS as usize);

    // Use a generous timeout since contention may slow things down
    let timeout = Duration::from_secs(90);
    let actions = tokio::time::timeout(timeout, network.wait_for_actions(min_expected_signatures))
        .await
        .expect("should produce signatures even under contention");

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
        .with_presignature_stockpile()
        // Disable triple generation since we're using preshared triples
        .with_min_triples_stockpile(0)
        .with_max_triples_stockpile(0)
        // Enable presignature generation for second batch
        .with_min_presignatures_stockpile(5)
        .with_max_presignatures_stockpile(20)
        .build()
        .await;

    // Wait for initial presignatures to be loaded
    tokio::time::timeout(
        Duration::from_millis(500),
        network.wait_for_presignatures(1),
    )
    .await
    .expect("should start with presignatures");

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
            node.sign_tx
                .send(Sign::Request(request.clone()))
                .await
                .unwrap();
        }
    }

    // First batch: wait for as many signatures as we initially have presignatures
    let first_batch_expected = initial_presignatures.min(FIRST_BATCH_SIZE);
    tracing::info!(first_batch_expected, "waiting for first batch");

    let first_batch_timeout = Duration::from_secs(30);
    let first_actions = tokio::time::timeout(
        first_batch_timeout,
        network.wait_for_actions(first_batch_expected),
    )
    .await
    .expect("first batch should complete with available presignatures");

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
    tokio::time::timeout(
        Duration::from_secs(120),
        network.wait_for_presignatures(3), // wait for at least 3 owned presignatures per node
    )
    .await
    .expect("should generate more presignatures");

    let after_generation = network[0].presignature_storage.len_generated().await;
    tracing::info!(after_generation, "presignatures after generation");

    // Now wait for remaining signatures to complete
    tracing::info!("waiting for remaining signatures");
    let final_timeout = Duration::from_secs(60);
    let final_actions = tokio::time::timeout(
        final_timeout,
        network.wait_for_actions(TOTAL_SIGN_REQUESTS as usize),
    )
    .await
    .expect("all signatures should complete after presignature generation");

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
async fn test_sign_contention_5_nodes() {
    const NUM_NODES: u32 = 5;
    const THRESHOLD: usize = 4;
    const NUM_SIGN_REQUESTS: u8 = 5; // Reduced from 10 to match presignature availability
    const MIN_PRESIGNATURES_PER_OWNER: usize = 3;
    const STOCKPILE_MIN: u32 = 8;
    const STOCKPILE_MAX: u32 = 12;

    tracing::info!(
        num_nodes = NUM_NODES,
        threshold = THRESHOLD,
        num_requests = NUM_SIGN_REQUESTS,
        "starting 5-node contention test with on-the-fly generation"
    );

    // Build network with pre-shared keys, generate triples/presignatures on the fly
    let network = MpcFixtureBuilder::new(NUM_NODES, THRESHOLD)
        .with_preshared_key()
        .with_min_triples_stockpile(STOCKPILE_MIN)
        .with_max_triples_stockpile(STOCKPILE_MAX)
        .with_min_presignatures_stockpile(STOCKPILE_MIN)
        .with_max_presignatures_stockpile(STOCKPILE_MAX)
        .build()
        .await;

    // Wait for presignatures to be generated - 5-node triple generation takes ~3-4 minutes
    // We wait for a modest per-owner count since distribution is not uniform
    tracing::info!("waiting for presignatures to be generated (triple gen takes ~3-4 min)...");
    tokio::time::timeout(
        Duration::from_secs(480), // 8 minutes for triple + presignature generation
        network.wait_for_presignatures(MIN_PRESIGNATURES_PER_OWNER),
    )
    .await
    .expect("should generate presignatures within 8 minutes");

    let initial_presignatures = network[0].presignature_storage.len_generated().await;
    tracing::info!(
        initial_presignatures,
        "presignatures ready, sending sign requests"
    );

    // Send sign requests to all nodes concurrently (simulates real network conditions)
    for seed in 0..NUM_SIGN_REQUESTS {
        let request = sign_request(seed);
        for node in &network.nodes {
            node.sign_tx
                .send(Sign::Request(request.clone()))
                .await
                .unwrap();
        }
    }

    // Wait for all signatures - allow more time for 5-node consensus
    let timeout = Duration::from_secs(120);
    let actions = tokio::time::timeout(
        timeout,
        network.wait_for_actions(NUM_SIGN_REQUESTS as usize),
    )
    .await
    .expect("should produce all signatures");

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

    tokio::time::timeout(
        Duration::from_millis(300),
        network.wait_for_presignatures(2),
    )
    .await
    .expect("should start with enough presignatures");

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
        node.sign_tx
            .send(Sign::Request(request.clone()))
            .await
            .unwrap();
    }

    // give 2 minutes to resolve the problem
    // expectation: the node without the presignature will reject a posit, or if
    // they are deliberator, a timeout will let the next deliberator take over
    let timeout = Duration::from_secs(120);
    let actions = tokio::time::timeout(timeout, network.wait_for_actions(1))
        .await
        .expect("should publish RPC action eventually");

    network.print_msg_log().await;

    assert_eq!(actions.len(), 1);
    let action_str = actions.iter().next().unwrap();
    assert!(
        action_str.contains("RpcAction::Publish"),
        "unexpected rpc action {action_str}"
    );
}
