use cait_sith::protocol::Participant;
use deadpool_redis::redis::AsyncCommands;
use integration_tests::mpc_fixture::fixture_tasks::MessageFilter;
use integration_tests::mpc_fixture::{MpcFixtureBuilder, SignatureDropper};
use mpc_node::protocol::presignature::Presignature;
use mpc_node::protocol::signature::{reset_signature_retry_backoff, set_signature_retry_backoff};
use mpc_node::protocol::triple::Triple;
use mpc_node::protocol::SignRequestType;
use mpc_node::protocol::{Chain, IndexedSignRequest, ProtocolState};
use mpc_primitives::{SignArgs, SignId, LATEST_MPC_KEY_VERSION};
use rand::{rngs::StdRng, seq::IteratorRandom, SeedableRng};
use std::collections::{BTreeMap, BTreeSet};
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

#[tokio::test(flavor = "multi_thread")]
async fn test_sign_request_retries_after_failure() {
    const NUM_NODES: usize = 3;

    let mut droppers = Vec::with_capacity(NUM_NODES);

    let mut builder = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .with_signature_timeout_ms(1_000);

    for idx in 0..NUM_NODES {
        let participant = Participant::from(idx as u32);
        let (dropper, filter) = SignatureDropper::new(participant);
        builder = builder.with_outgoing_message_filter(idx, filter);
        droppers.push(dropper);
    }

    let network = builder.build().await;

    for dropper in &droppers {
        dropper.enable();
    }

    // Signature timeout should abort the task in 1seconds.
    let drop_handle = {
        let droppers = droppers.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            for dropper in &droppers {
                dropper.disable();
            }
        })
    };

    tokio::time::timeout(
        Duration::from_millis(300),
        network.wait_for_presignatures(2),
    )
    .await
    .expect("should start with enough presignatures");

    let request = sign_request(1);
    for node in &network.nodes {
        node.sign_tx.send(request.clone()).await.unwrap();
    }

    let start = std::time::Instant::now();
    let actions = tokio::time::timeout(Duration::from_secs(20), network.wait_for_actions(1))
        .await
        .expect("should publish RPC action eventually");

    drop_handle.await.unwrap();

    let dropped_messages: usize = droppers.iter().map(SignatureDropper::dropped).sum();
    assert!(
        actions
            .iter()
            .any(|action| action.contains("RpcAction::Publish")),
        "unexpected rpc actions: {actions:?}"
    );
    assert!(
        dropped_messages > 0,
        "expected test filter to drop at least one signature message"
    );
    assert!(
        start.elapsed() >= Duration::from_secs(2),
        "signature completed too quickly, expected a retry delay"
    );
}

struct RetryBackoffGuard;

impl Drop for RetryBackoffGuard {
    fn drop(&mut self) {
        reset_signature_retry_backoff();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sign_request_retries_multiple_times() {
    let _guard = RetryBackoffGuard;
    set_signature_retry_backoff(10, 100);

    const NUM_NODES: usize = 3;
    const TARGET_ATTEMPTS: usize = 10;

    let mut signature_droppers = Vec::with_capacity(NUM_NODES);

    let mut builder = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .with_signature_timeout_ms(200);

    for idx in 0..NUM_NODES {
        let participant = Participant::from(idx as u32);
        let (dropper, filter) = SignatureDropper::new(participant);
        builder = builder.with_outgoing_message_filter(idx, filter);
        signature_droppers.push(dropper);
    }

    let network = builder.build().await;

    tokio::time::timeout(
        Duration::from_millis(300),
        network.wait_for_presignatures(2),
    )
    .await
    .expect("should start with enough presignatures");

    {
        let mut log = network.output.msg_log.lock().await;
        log.clear();
    }

    for dropper in &signature_droppers {
        dropper.enable();
    }

    let request = sign_request(3);
    for node in &network.nodes {
        node.sign_tx.send(request.clone()).await.unwrap();
    }

    let required_messages = TARGET_ATTEMPTS * (network.nodes.len() - 1);

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let signature_messages = {
                let log = network.output.msg_log.lock().await;
                log.iter()
                    .filter(|entry| entry.starts_with("Signature"))
                    .count()
            };

            if signature_messages >= required_messages {
                break signature_messages;
            }

            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("expected at least ten signature retries before timeout");

    for dropper in &signature_droppers {
        dropper.disable();
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    let dropped_messages: usize = signature_droppers
        .iter()
        .map(SignatureDropper::dropped)
        .sum();

    assert!(
        dropped_messages > 0,
        "expected to drop at least one signature message before retries succeeded"
    );

    let actions = tokio::time::timeout(Duration::from_secs(10), network.wait_for_actions(1))
        .await
        .expect("signature should eventually publish after retries");

    assert!(
        actions
            .iter()
            .any(|action| action.contains("RpcAction::Publish")),
        "unexpected rpc actions: {actions:?}"
    );

    let signature_messages = {
        let log = network.output.msg_log.lock().await;
        log.iter()
            .filter(|entry| entry.starts_with("Signature"))
            .count()
    };

    let attempts = signature_messages / (network.nodes.len() - 1);
    assert!(
        attempts >= TARGET_ATTEMPTS,
        "expected at least {TARGET_ATTEMPTS} retries, observed {attempts}"
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

fn initial_proposer_for_request(
    request: &IndexedSignRequest,
    participants: &[Participant],
    stable: &BTreeSet<Participant>,
) -> Participant {
    assert!(
        !participants.is_empty(),
        "expected at least one participant in the mesh snapshot"
    );

    let mut ordered_participants = participants.to_vec();
    ordered_participants.sort();

    let entropy = request.args.entropy;
    let offset = entropy[0] as usize;

    for round in 0..512 {
        let idx = (offset + round) % ordered_participants.len();
        let candidate = ordered_participants[idx];
        if stable.contains(&candidate) {
            return candidate;
        }
    }

    let mut rng = StdRng::from_seed(entropy);
    *stable
        .iter()
        .choose(&mut rng)
        .expect("stable set should not be empty")
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
