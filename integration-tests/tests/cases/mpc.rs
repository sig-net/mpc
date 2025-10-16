use cait_sith::protocol::Participant;
use deadpool_redis::redis::AsyncCommands;
use futures::future::join_all;
use integration_tests::mpc_fixture::fixture_tasks::MessageFilter;
use integration_tests::mpc_fixture::MpcFixtureBuilder;
use mpc_node::protocol::presignature::Presignature;
use mpc_node::protocol::triple::Triple;
use mpc_node::protocol::SignRequestType;
use mpc_node::protocol::{Chain, IndexedSignRequest, ProtocolState};
use mpc_node::storage::{PresignatureStorage, TripleStorage};
use mpc_primitives::{SignArgs, SignId, LATEST_MPC_KEY_VERSION};
use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
async fn test_concurrent_sign_requests() {
    const REQUEST_COUNT: usize = 20;
    const PRESIGNATURE_STOCKPILE_TARGET: u32 = REQUEST_COUNT as u32;
    const PRESIGNATURE_BUFFER: u32 = REQUEST_COUNT as u32;
    const TRIPLE_WARMUP_MARGIN: usize = if REQUEST_COUNT / 4 > 4 {
        REQUEST_COUNT / 4
    } else {
        4
    };
    const TRIPLE_BUFFER: u32 = PRESIGNATURE_BUFFER;
    const PRESIGNATURE_MIN_INITIAL: u32 = 0;
    const STOCKPILE_CAPACITY_MULTIPLIER: u32 = 4;

    let triple_warmup_min = PRESIGNATURE_STOCKPILE_TARGET + TRIPLE_WARMUP_MARGIN as u32;
    let triple_capacity = TRIPLE_BUFFER.saturating_mul(STOCKPILE_CAPACITY_MULTIPLIER);
    let triple_warmup_max = triple_warmup_min + triple_capacity;
    let triple_post_min = PRESIGNATURE_STOCKPILE_TARGET;
    let triple_post_max = triple_warmup_max;
    let presignature_min = PRESIGNATURE_STOCKPILE_TARGET;
    let presignature_capacity = PRESIGNATURE_BUFFER.saturating_mul(STOCKPILE_CAPACITY_MULTIPLIER);
    let presignature_max = presignature_min + presignature_capacity;

    let network = MpcFixtureBuilder::default()
        .with_preshared_key()
        .with_preshared_triples()
        .with_presignature_stockpile()
        .with_min_triples_stockpile(triple_warmup_min)
        .with_max_triples_stockpile(triple_warmup_max)
        .with_min_presignatures_stockpile(PRESIGNATURE_MIN_INITIAL)
        .with_max_presignatures_stockpile(presignature_max)
        .build()
        .await;

    let storage_handles: Vec<_> = network
        .nodes
        .iter()
        .map(|node| (node.triple_storage.clone(), node.me))
        .collect();

    let presignature_handles: Vec<_> = network
        .nodes
        .iter()
        .map(|node| (node.presignature_storage.clone(), node.me))
        .collect();

    let fetch_triple_counts = |handles: &Vec<(TripleStorage, Participant)>| {
        join_all(handles.iter().cloned().map(|(storage, owner)| async move {
            storage.len_by_owner(owner).await
        }))
    };

    let fetch_presignature_counts =
        |handles: &Vec<(PresignatureStorage, Participant)>| {
        join_all(handles.iter().cloned().map(|(storage, owner)| async move {
            storage.len_by_owner(owner).await
        }))
    };

    let initial_triple_counts: Vec<usize> = fetch_triple_counts(&storage_handles).await;

    tokio::time::sleep(Duration::from_secs(30)).await;

    let post_warmup_counts: Vec<usize> = fetch_triple_counts(&storage_handles).await;

    assert!(
        post_warmup_counts
            .iter()
            .zip(initial_triple_counts.iter())
            .all(|(after, before)| *after >= *before + 1),
        "triple stockpile did not grow during warm-up. before={initial_triple_counts:?} after={post_warmup_counts:?}"
    );

    let triple_target = triple_post_min as usize;
    let mut triple_counts = post_warmup_counts.clone();
    let triple_deadline = Instant::now() + Duration::from_secs(120);

    while !triple_counts.iter().all(|count| *count >= triple_target) {
        if Instant::now() >= triple_deadline {
            panic!(
                "triple stockpile did not reach baseline. target={triple_target} counts={triple_counts:?}"
            );
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
        let next_counts = fetch_triple_counts(&storage_handles).await;

        if !next_counts
            .iter()
            .zip(triple_counts.iter())
            .any(|(next, prev)| next > prev)
        {
            tracing::info!(?next_counts, "triple stockpile stagnant while waiting for baseline");
        }

        triple_counts = next_counts;
    }

    tracing::info!(?triple_counts, triple_target, "triple baseline reached");

    for node in &network.nodes {
        node.config.send_modify(|config| {
            config.protocol.triple.min_triples = triple_post_min;
            config.protocol.triple.max_triples = triple_post_max;
            config.protocol.presignature.min_presignatures = presignature_min;
            config.protocol.presignature.max_presignatures = presignature_max;
        });
    }

    tokio::time::sleep(Duration::from_secs(1)).await;

    let presignature_target = presignature_min as usize;
    let mut presignature_counts = fetch_presignature_counts(&presignature_handles).await;
    let presignature_deadline = Instant::now() + Duration::from_secs(180);

    while !presignature_counts
        .iter()
        .all(|count| *count >= presignature_target)
    {
        if Instant::now() >= presignature_deadline {
            panic!(
                "presignature stockpile did not reach baseline. target={presignature_target} counts={presignature_counts:?}"
            );
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
        let next_counts = fetch_presignature_counts(&presignature_handles).await;

        if !next_counts
            .iter()
            .zip(presignature_counts.iter())
            .any(|(next, prev)| next > prev)
        {
            tracing::info!(
                ?next_counts,
                "presignature stockpile stagnant while waiting for baseline"
            );
        }

        presignature_counts = next_counts;
    }

    tracing::info!(?presignature_counts, presignature_target, "presignature baseline reached");

    let sign_channels: Vec<_> = network
        .nodes
        .iter()
        .map(|node| node.sign_tx.clone())
        .collect();

    let requests: Vec<_> = (10..10 + REQUEST_COUNT as u8).map(sign_request).collect();

    join_all(requests.iter().cloned().map(|request| {
        let senders = sign_channels.clone();
        async move {
            for tx in senders {
                tx.send(request.clone())
                    .await
                    .expect("failed to send sign request");
            }
        }
    }))
    .await;

    let rpc_actions = Arc::clone(&network.output.rpc_actions);
    let actions = {
        let timeout = Duration::from_secs(60);
        let start = Instant::now();

        loop {
            let actions_snapshot = { rpc_actions.lock().await.clone() };

            let missing: Vec<_> = requests
                .iter()
                .map(|request| hex::encode(request.id.request_id))
                .filter(|sign_id_hex| {
                    !actions_snapshot
                        .iter()
                        .any(|action| action.contains(sign_id_hex))
                })
                .collect();

            if missing.is_empty() {
                break actions_snapshot;
            }

            if start.elapsed() >= timeout {
                panic!(
                    "timed out waiting for publish actions. missing ids: {:?}",
                    missing
                );
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };

    assert!(
        actions.len() >= REQUEST_COUNT,
        "expected at least {REQUEST_COUNT} publish actions, got {}",
        actions.len()
    );

    assert!(
        actions
            .iter()
            .all(|action| action.contains("RpcAction::Publish")),
        "found unexpected rpc actions: {actions:?}"
    );

    for request in &requests {
        let sign_id_hex = hex::encode(request.id.request_id);
        assert!(
            actions.iter().any(|action| action.contains(&sign_id_hex)),
            "missing publish action for request {sign_id_hex}"
        );
    }
}

fn sign_request(seed: u8) -> IndexedSignRequest {
    IndexedSignRequest {
        id: SignId::new([seed; 32]),
        args: sign_arg(seed),
        chain: Chain::NEAR,
        unix_timestamp_indexed: 0,
        timestamp_sign_queue: None,
        total_timeout: Duration::from_secs(120),
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
