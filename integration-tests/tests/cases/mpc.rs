use deadpool_redis::redis::AsyncCommands;
use integration_tests::mpc_fixture::MpcFixtureBuilder;
use mpc_node::protocol::presignature::Presignature;
use mpc_node::protocol::triple::Triple;
use mpc_node::protocol::{Chain, IndexedSignRequest, ProtocolState};
use mpc_primitives::{SignArgs, SignId};
use std::collections::BTreeMap;
use std::fs;
use std::time::{Duration, Instant};

/// Use this toggle locally to regenerate hard-coded inputs such as key shares,
/// triples, and presignatures.
/// You might have to create the directory `integrations-tests/tmp` first.
const WRITE_OUTPUT_TO_FILES: bool = true;
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
        .with_preshared_key()
        .with_min_presignatures_stockpile(0)
        .with_max_presignatures_stockpile(0)
        .build()
        .await;

    tokio::time::timeout(Duration::from_secs(180), network.wait_for_triples(1))
        .await
        .expect("should have enough triples eventually");

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

    if WRITE_OUTPUT_TO_FILES {
        let abs_path = std::env::current_dir().unwrap().join(TRIPLES_FILE);
        tracing::info!("Writing output to {}", abs_path.display());
        let mut file = fs::File::create(TRIPLES_FILE).unwrap();
        serde_json::to_writer_pretty(&mut file, &data).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_basic_generate_presignature() {
    let network = MpcFixtureBuilder::default()
        .with_preshared_key()
        .with_preshared_triples()
        .with_min_triples_stockpile(0)
        .with_max_triples_stockpile(0)
        .build()
        .await;

    tokio::time::timeout(Duration::from_secs(10), network.wait_for_presignatures(1))
        .await
        .expect("should have enough presignatures eventually");

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

    if WRITE_OUTPUT_TO_FILES {
        let abs_path = std::env::current_dir().unwrap().join(PRESIGNATURES_FILE);
        tracing::info!("Writing output to {}", abs_path.display());
        let mut file = fs::File::create(PRESIGNATURES_FILE).unwrap();
        serde_json::to_writer_pretty(&mut file, &data).unwrap();
    }
}

// TODO: this fails with invalid signature
#[tokio::test(flavor = "multi_thread")]
async fn test_basic_sign() {
    let network = MpcFixtureBuilder::default()
        .with_preshared_key()
        .with_presignature_stockpile()
        .with_min_triples_stockpile(0)
        .with_max_triples_stockpile(0)
        .with_min_presignatures_stockpile(0)
        .with_max_presignatures_stockpile(0)
        .build()
        .await;

    tokio::time::timeout(Duration::from_secs(10), network.wait_for_presignatures(2))
        .await
        .expect("should have enough presignatures eventually");
    tracing::info!("sending requests now");

    let request = sign_request(0);
    network[0].sign_tx.send(request.clone()).await.unwrap();
    network[1].sign_tx.send(request.clone()).await.unwrap();
    network[2].sign_tx.send(request.clone()).await.unwrap();

    let timeout = Duration::from_secs(10);
    let interval = Duration::from_millis(100);
    let deadline = Instant::now() + timeout;

    loop {
        let actions = network.rpc_actions.lock().await;

        if actions.len() >= 1 {
            assert_eq!(actions.len(), 1);
            break;
        }

        if Instant::now() >= deadline {
            panic!("Timeout: expected 1 rpc_action but got {}", actions.len());
        }

        drop(actions);
        tokio::time::sleep(interval).await;
    }

    // tracing::info!("printing all messages between nodes");
    // let out = &mut std::fs::File::create("network_msg.txt").unwrap();
    // for line in network.msg_log.lock().await.iter() {
    //     tracing::info!("{line}");
    //     writeln!(out, "{line}").unwrap();
    // }
}

fn sign_request(seed: u8) -> IndexedSignRequest {
    IndexedSignRequest {
        id: SignId::new([seed; 32]),
        args: sign_arg(seed),
        chain: Chain::NEAR,
        unix_timestamp_indexed: 0,
        timestamp_sign_queue: None,
        total_timeout: Duration::from_secs(45),
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
        key_version: 0,
    }
}
