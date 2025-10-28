use deadpool_redis::redis::AsyncCommands;
use integration_tests::mpc_fixture::fixture_tasks::MessageFilter;
use integration_tests::mpc_fixture::MpcFixtureBuilder;
use mpc_node::protocol::presignature::Presignature;
use mpc_node::protocol::triple::Triple;
use mpc_node::protocol::SignRequestType;
use mpc_node::protocol::{Chain, IndexedSignRequest, ProtocolState};
use mpc_primitives::{SignArgs, SignId, LATEST_MPC_KEY_VERSION};
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

#[tokio::test(flavor = "multi_thread")]
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

#[tokio::test(flavor = "multi_thread")]
async fn test_basic_generate_triples() {
    let network = MpcFixtureBuilder::default()
        .only_generate_triples()
        .build()
        .await;

    tokio::time::timeout(Duration::from_secs(60), network.wait_for_triples(1))
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
                    let t = conn
                        .hget::<&str, u64, Triple>(node.triple_storage.triple_key(), triple_id)
                        .await;
                    if let Ok(t) = t {
                        peer_triples.push(t);
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

#[tokio::test(flavor = "multi_thread")]
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

#[tokio::test(flavor = "multi_thread")]
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
    network[0].sign_tx.send(request.clone()).await.unwrap();
    network[1].sign_tx.send(request.clone()).await.unwrap();
    network[2].sign_tx.send(request.clone()).await.unwrap();

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
        timestamp_sign_queue: None,
        total_timeout: Duration::from_secs(45),
        participants: None,
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
#[tokio::test(flavor = "multi_thread")]
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

/// Test proposer re-election when the initial proposer fails to propose a posit.
/// This simulates a scenario where the proposer is offline or misses the sign request.
#[tokio::test(flavor = "multi_thread")]
async fn test_proposer_reelection_on_idle() {
    let network = MpcFixtureBuilder::default()
        .only_generate_signatures()
        // Speed up the proposer re-election timeout to 5 seconds for faster testing
        .with_proposer_reelection_timeout_ms(5000)
        .build()
        .await;

    tokio::time::timeout(
        Duration::from_millis(300),
        network.wait_for_presignatures(2),
    )
    .await
    .expect("should start with enough presignatures");

    tracing::info!("Presignatures ready, sending sign request");

    // Send a sign request
    let request = sign_request(0);
    
    network[0].sign_tx.send(request.clone()).await.unwrap();
    network[1].sign_tx.send(request.clone()).await.unwrap();
    network[2].sign_tx.send(request.clone()).await.unwrap();

    // Wait for the signature to complete
    let timeout = Duration::from_secs(15);

    let actions = tokio::time::timeout(timeout, network.wait_for_actions(1))
        .await
        .expect("should publish RPC action eventually");

    assert_eq!(actions.len(), 1);
    let action_str = actions.iter().next().unwrap();
    assert!(
        action_str.contains("RpcAction::Publish"),
        "unexpected rpc action {action_str}"
    );
    
    tracing::info!("Successfully completed signature");
}

/// Test that when a proposer completely fails (drops posits), another node
/// takes over and successfully completes the signature.
#[tokio::test(flavor = "multi_thread")]
async fn test_proposer_reelection_with_filter() {
    // Create a filter that drops only Signature Posit messages from node 0
    // This allows presignature generation to proceed normally while simulating
    // a failed signature proposer
    fn create_signature_posit_drop_filter() -> MessageFilter {
        Box::new(move |(msg, _)| {
            match msg {
                mpc_node::protocol::Message::Posit(posit_msg) => {
                    // Only drop signature posits, allow triple and presignature posits through
                    if matches!(posit_msg.id, mpc_node::protocol::message::PositProtocolId::Signature(_, _)) {
                        tracing::info!("Dropping Signature Posit message to simulate failed proposer");
                        false
                    } else {
                        true
                    }
                }
                _ => true,
            }
        })
    }

    let network = MpcFixtureBuilder::default()
        // Use preshared triples to skip triple generation and speed up presignature generation
        .with_preshared_triples()
        // Apply filter to node 0 to drop only its signature posit messages
        .with_outgoing_message_filter(0, create_signature_posit_drop_filter())
        // Speed up the proposer re-election timeout to 5 seconds
        .with_proposer_reelection_timeout_ms(5000)
        .build()
        .await;

    // Wait for presignatures to be generated
    // We need at least 2: one for the failed proposal, one for the retry
    tokio::time::timeout(
        Duration::from_secs(20),
        network.wait_for_presignatures(3),
    )
    .await
    .expect("should start with enough presignatures");

    tracing::info!("Presignatures ready, sending sign request");

    // Send a sign request - node 0 should be selected as proposer based on round-robin
    // but will fail to send posits. After idle timeout, another node should take over.
    let request = sign_request(42); // Use specific entropy
    
    network[0].sign_tx.send(request.clone()).await.unwrap();
    network[1].sign_tx.send(request.clone()).await.unwrap();
    network[2].sign_tx.send(request.clone()).await.unwrap();

    // Wait for signature completion - should succeed via proposer re-election
    // Give it enough time for multiple re-elections if needed (5s timeout + processing time)
    let timeout = Duration::from_secs(25);

    let actions = tokio::time::timeout(timeout, network.wait_for_actions(1))
        .await
        .expect("should publish RPC action eventually after proposer re-election");

    assert_eq!(actions.len(), 1);
    let action_str = actions.iter().next().unwrap();
    assert!(
        action_str.contains("RpcAction::Publish"),
        "unexpected rpc action {action_str}"
    );
    
    tracing::info!("Successfully completed signature after proposer re-election");
}
