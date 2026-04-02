//! Component test that combine the MPC network combined with a chain stream  as input and output.

use integration_tests::mpc_fixture::{mock_stream::MockStream, MpcFixtureBuilder};
use mpc_node::protocol::IndexedSignRequest;
use mpc_primitives::{Chain, SignId};
use std::time::Duration;
use test_log::test;

fn sign_request(seed: u16) -> IndexedSignRequest {
    let bytes = [seed.to_be_bytes()[0], seed.to_be_bytes()[1]].repeat(16);
    IndexedSignRequest::sign(
        SignId::new(bytes.try_into().unwrap()),
        super::helpers::test_sign_arg(seed.to_be_bytes()[0]),
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

// WIP/TODO: This should fill up some channels and assert the effect of it.
// Right now, it just runs through all presignatures and then gets stuck as there are no Ps left.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_channel_contention() {
    let network = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .with_mock_stream(MockStream::default())
        .await
        .build()
        .await;

    // send requests in batches of 50 per block
    for outer in 0..1000 {
        let requests = (0..50)
            .map(|inner| sign_request(outer * 50 + inner))
            .collect::<Vec<_>>();

        tracing::info!(outer, "sending request now");
        network[0].mock_streams[0].sign_requests(&requests).await;
        network[1].mock_streams[0].sign_requests(&requests).await;
        network[2].mock_streams[0].sign_requests(&requests).await;
    }
    network[0].mock_streams[0]
        .progress_block_height(50_000)
        .await;
    network[1].mock_streams[0]
        .progress_block_height(50_000)
        .await;
    network[2].mock_streams[0]
        .progress_block_height(50_000)
        .await;

    // there are only enough presignatures for 75 signatures in the fixture
    let actions = network.assert_actions(75, Duration::from_secs(10)).await;

    assert_eq!(actions.len(), 75);
    let action_str = actions.iter().next().unwrap();
    assert!(
        action_str.contains("RpcAction::Publish"),
        "unexpected rpc action {action_str}"
    );

    // TODO: check the system is still operative
}
