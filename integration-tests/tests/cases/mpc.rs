use integration_tests::mpc::TestMpcNetworkBuilder;
use mpc_node::protocol::{Chain, IndexedSignRequest, ProtocolState};
use mpc_primitives::{SignArgs, SignId};
use std::time::{Duration, Instant};

#[tokio::test(flavor = "multi_thread")]
async fn test_basic_generate_keys() {
    let network = TestMpcNetworkBuilder::new(5, 4).build().await;

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
}

#[tokio::test(flavor = "multi_thread")]
async fn test_basic_generate_triples() {
    let network = TestMpcNetworkBuilder::default()
        .with_preshared_key()
        .build()
        .await;

    tokio::time::timeout(Duration::from_secs(180), network.wait_for_triples(1))
        .await
        .expect("should have enough triples eventually");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_basic_generate_presignature() {
    let network = TestMpcNetworkBuilder::default()
        .with_preshared_key()
        .with_stockpiled_triples(1)
        .build()
        .await;

    tokio::time::timeout(Duration::from_secs(10), network.wait_for_presignatures(1))
        .await
        .expect("should have enough presignatures eventually");
}

// TODO: this fails with invalid signature
#[tokio::test(flavor = "multi_thread")]
async fn test_basic_sign() {
    let network = TestMpcNetworkBuilder::default()
        .with_preshared_key()
        .with_stockpiled_triples(1)
        .with_presignature_stockpile()
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
