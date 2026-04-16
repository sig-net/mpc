//! Component test that combine the MPC network combined with a chain stream  as input and output.

use integration_tests::mpc_fixture::{mock_stream::MockStream, MpcFixtureBuilder};
use mpc_node::protocol::IndexedSignRequest;
use mpc_primitives::{Chain, SignId};
use std::time::Duration;
use test_log::test;

fn sign_request(seed: u32) -> IndexedSignRequest {
    let bytes = [
        seed.to_be_bytes()[0],
        seed.to_be_bytes()[1],
        seed.to_be_bytes()[2],
        seed.to_be_bytes()[3],
    ]
    .repeat(8);
    IndexedSignRequest::sign(
        SignId::new(bytes.try_into().unwrap()),
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
    // TODO: abstraction to send to all
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

async fn check_channel_contention(
    num_blocks: usize,
    req_per_block: usize,
    expected_signatures: usize,
) {
    let network = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .with_mock_stream(MockStream::default())
        .await
        .build()
        .await;

    let num_nodes = 3;
    for outer in 0..(num_blocks as u16) {
        let requests = (0..req_per_block)
            .map(|inner| sign_request(outer as u32 * req_per_block as u32 + inner as u32))
            .collect::<Vec<_>>();

        for i in 0..num_nodes {
            network[i].mock_streams[0].sign_requests(&requests).await;
        }
    }

    for i in 0..num_nodes {
        network[i].mock_streams[0]
            .progress_block_height(num_blocks)
            .await;
    }

    let actions = network
        .assert_actions(expected_signatures, Duration::from_secs(60))
        .await;

    assert_eq!(actions.len(), expected_signatures);
    let action_str = actions.iter().next().unwrap();
    assert!(
        action_str.contains("RpcAction::Publish"),
        "unexpected rpc action {action_str}"
    );
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_channel_contention_many_requests_per_block() {
    check_channel_contention(1, 50, 50).await;
}
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_channel_contention_multiple_blocks_at_once() {
    check_channel_contention(5, 10, 50).await;
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_channel_contention_show_limit() {
    // There are exactly enough presignatures in the fixture input for 75 signatures.
    check_channel_contention(6, 50, 75).await;
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_channel_contention_10k_requests() {
    // sending 100 x 100 requests at once
    check_channel_contention(100, 100, 75).await;
}

#[test(tokio::test(flavor = "multi_thread"))]
#[allow(non_snake_case)]
async fn test_channel_contention_1M_requests() {
    // sending 1000 x 1000 requests at once
    check_channel_contention(1000, 1000, 75).await;
}
