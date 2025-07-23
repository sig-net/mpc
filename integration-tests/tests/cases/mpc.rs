use integration_tests::mpc::TestMpcNetwork;
use mpc_node::protocol::{Chain, IndexedSignRequest};
use mpc_primitives::{SignArgs, SignId};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn test_basic_mpc() {
    let mut network = TestMpcNetwork::new().await;

    network.start().await;

    tokio::time::timeout(Duration::from_secs(600), network.wait_for_presignatures(2))
        .await
        .expect("should have enough presignatures eventually");
    tracing::info!("sending requests now");

    network[0].sign_tx.send(sign_request(0)).await.unwrap();
    network[1].sign_tx.send(sign_request(1)).await.unwrap();
    network[2].sign_tx.send(sign_request(2)).await.unwrap();

    // TODO(jakmeier): better async handling, we should check for results and stop early when we see it
    tokio::time::sleep(Duration::from_secs(60)).await;

    // TODO(jakmeier): not working yet, the actual signature never starts (but presignatures and triple protocols seem to work fine)
    // I'm getting:
    // mpc_node::protocol::signature: timeout waiting for pending sign request sign_id=SignId("0202020202020202020202020202020202020202020202020202020202020202") timeout=45s
    // mpc_node::protocol::signature: signature posit sign_id=SignId("0202020202020202020202020202020202020202020202020202020202020202") internal_action_str="Reply"
    // received enough REJECTs, aborting protocol id=(SignId("0202020202020202020202020202020202020202020202020202020202020202"), 10326593524880077242) rejects={Participant(1)}
    // signature posit action was rejected sign_id=SignId("0202020202020202020202020202020202020202020202020202020202020202") presignature_id=10326593524880077242 from=Participant(1)
    let actions = network.rpc_actions.lock().await;
    assert_eq!(actions.len(), 1,);
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
