//! Component test that combine the MPC network combined with a chain stream  as input and output.

use integration_tests::mpc_fixture::{mock_stream::MockStream, MpcFixtureBuilder};
use mpc_node::protocol::IndexedSignRequest;
use mpc_primitives::{Chain, SignId};
use std::time::Duration;
use test_log::test;

fn sign_request(seed: u8) -> IndexedSignRequest {
    IndexedSignRequest::sign(
        SignId::new([seed; 32]),
        super::helpers::test_sign_arg(seed),
        Chain::Solana,
        0,
    )
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sign() {
    let network = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .with_mock_stream(MockStream::default())
        .await
        .build()
        .await;

    tracing::info!("sending requests now");
    let request = [sign_request(0)];
    network[0].mock_streams[0].sign_requests(&request).await;
    network[1].mock_streams[0].sign_requests(&request).await;
    network[2].mock_streams[0].sign_requests(&request).await;

    network[0].mock_streams[0].progress_block_height(1).await;
    network[1].mock_streams[0].progress_block_height(1).await;
    network[2].mock_streams[0].progress_block_height(1).await;

    let timeout = Duration::from_secs(10);

    let actions = network.assert_actions(1, timeout).await;

    assert_eq!(actions.len(), 1);
    let action_str = actions.iter().next().unwrap();
    assert!(
        action_str.contains("RpcAction::Publish"),
        "unexpected rpc action {action_str}"
    );
}
