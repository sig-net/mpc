//! Component tests that combine the MPC network combined with a chain stream as
//! input and output.

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

/// Simple test, mostly just here to check the MockStream setup is working.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_sign() {
    let network = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .with_mock_stream(Chain::Solana, MockStream::default())
        .await
        .build()
        .await;

    tracing::info!("sending requests now");
    network
        .process_sign_requests(Chain::Solana, &[sign_request(0)])
        .await;

    let timeout = Duration::from_secs(10);
    let actions = network.assert_actions(1, timeout).await;

    assert_eq!(actions.len(), 1);
    let action_str = actions.iter().next().unwrap();
    assert!(
        action_str.contains("RpcAction::Publish"),
        "unexpected rpc action {action_str}"
    );
}

/// Common checker function called with different parameters in test cases below.
async fn check_channel_contention(
    // number of blocks with requests to send
    num_blocks: usize,
    // number of requests within each block
    req_per_block: usize,
    // how many signatures should be generated successfully, usually
    // `num_blocks` * `req_per_block`
    expected_signatures: usize,
    // add an observation delay between nodes
    observation_delay: Option<Duration>,
) {
    let num_nodes = 3;
    let threshold = 2;
    let network = MpcFixtureBuilder::new(num_nodes as u32, threshold)
        .only_generate_signatures()
        .with_mock_stream(Chain::Solana, MockStream::default())
        .await
        .build()
        .await;

    // prepare blocks but do not send process them, yet
    for outer in 0..(num_blocks as u16) {
        let requests = (0..req_per_block)
            .map(|inner| sign_request(outer as u32 * req_per_block as u32 + inner as u32))
            .collect::<Vec<_>>();

        for i in 0..num_nodes {
            network[i]
                .mock_streams
                .get(&Chain::Solana)
                .unwrap()
                .prepare_block_of_sign_requests(&requests)
                .await;
        }
    }

    // start sending requests, with optional observation delays between nodes
    for i in 0..num_nodes {
        network[i]
            .mock_streams
            .get(&Chain::Solana)
            .unwrap()
            .progress_block_height(num_blocks)
            .await;
        if let Some(delay) = observation_delay {
            tokio::time::sleep(delay).await;
        }
    }

    let actions = network
        .assert_actions(expected_signatures, Duration::from_secs(120))
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
    check_channel_contention(1, 50, 50, None).await;
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_channel_contention_multiple_blocks_at_once() {
    check_channel_contention(5, 10, 50, None).await;
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_channel_contention_multiple_blocks_at_once_delayed() {
    // TODO: delay should be > ORGANIZE_POSIT_TIMEOUT but right now the system can't handle it
    let delay = mpc_node::protocol::signature::organize_posit_timeout() / 2;
    check_channel_contention(5, 10, 50, Some(delay)).await;
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_channel_contention_show_limit() {
    // There are exactly enough presignatures in the fixture input for 75 signatures.
    check_channel_contention(6, 50, 75, None).await;
}

// TODO(jakmeier): find out how to make this test work in CI, is is working just
// fine locally
#[ignore = "fails in CI"]
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_channel_contention_10k_requests() {
    // sending 100 x 100 requests at once
    check_channel_contention(100, 100, 75, None).await;
}

// TODO(jakmeier): find out how to make this test work in CI, is is working just
// fine locally
#[ignore = "fails in CI"]
#[test(tokio::test(flavor = "multi_thread"))]
#[allow(non_snake_case)]
async fn test_channel_contention_1M_requests() {
    // sending 1000 x 1000 requests at once
    check_channel_contention(1000, 1000, 75, None).await;
}

/// A missed respond event leaves a stale task that clogs other nodes' inboxes.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_missed_respond_event_clogs_inbox() {
    run_stale_task_test(true).await;
}

/// Control: same setup but with respond event delivered — no clog.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_respond_event_prevents_clog() {
    run_stale_task_test(false).await;
}

/// Shared implementation for the clog / no-clog test pair.
async fn run_stale_task_test(drop_respond_event: bool) {
    use cait_sith::protocol::Participant;
    use integration_tests::mpc_fixture::message_collector::CollectMessages;
    use integration_tests::mpc_fixture::mock_chain::EventDelivery;
    use mpc_node::protocol::message::{PositProtocolId, SendMessage};
    use mpc_node::protocol::Message;
    use mpc_node::stream::ChainEvent;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[derive(Default, Clone, Debug)]
    struct MessageCounts {
        posit: usize,
        signature: usize,
    }

    #[derive(Default)]
    struct SignatureTracker {
        counts: Arc<std::sync::Mutex<HashMap<(Participant, SignId), MessageCounts>>>,
    }

    impl CollectMessages for SignatureTracker {
        fn observe_message(&mut self, msg: &SendMessage, _passed_filter: bool) {
            let (message, (from, _to, _ts)) = msg;
            match message {
                Message::Posit(posit_msg) => {
                    if let PositProtocolId::Signature(sign_id, ..) = posit_msg.id {
                        self.counts
                            .lock()
                            .unwrap()
                            .entry((*from, sign_id))
                            .or_default()
                            .posit += 1;
                    }
                }
                Message::Signature(sig_msg) => {
                    self.counts
                        .lock()
                        .unwrap()
                        .entry((*from, sig_msg.id))
                        .or_default()
                        .signature += 1;
                }
                _ => {}
            }
        }
        fn print_summary(&self) {}
    }

    let node_0 = Participant::from(0);
    let node_1 = Participant::from(1);
    let node_2 = Participant::from(2);
    let bad_request_seed = 3u32;
    let bad_sign_id = sign_request(bad_request_seed).id;
    let signature_timeout_ms = 5_000;

    let tracker = SignatureTracker::default();
    let tracker_counts = Arc::clone(&tracker.counts);

    let mut builder = MpcFixtureBuilder::new(3, 2)
        .only_generate_signatures()
        .with_signature_timeout_ms(signature_timeout_ms)
        .with_mock_stream(Chain::Solana, MockStream::default())
        .await
        // Exclude node 2 from generation for the bad request by dropping its Accept.
        .with_outgoing_message_filter(
            2,
            Box::new(move |msg: &SendMessage| {
                let (message, (_from, _to, _ts)) = msg;
                if let Message::Posit(posit_msg) = message {
                    if let PositProtocolId::Signature(sign_id, ..) = posit_msg.id {
                        if sign_id == bad_sign_id
                            && matches!(
                                posit_msg.action,
                                mpc_node::protocol::posit::PositAction::Accept
                            )
                        {
                            return false;
                        }
                    }
                }
                true
            }),
        )
        .with_message_collector(Arc::new(Mutex::new(tracker)));

    if drop_respond_event {
        builder = builder.with_chain_event_filter(
            2,
            Box::new(move |event: &ChainEvent| {
                if let ChainEvent::Respond(respond) = event {
                    if respond.request_id == bad_sign_id.request_id {
                        return EventDelivery::Drop;
                    }
                }
                EventDelivery::Deliver
            }),
        );
    }

    let network = builder.build().await;

    let per_request_timeout = Duration::from_secs(60);

    // Send requests with delays so the stale task has time to send proposals.
    let mut completed = 0u32;
    for seed in 0..20 {
        network
            .process_sign_requests(Chain::Solana, &[sign_request(seed)])
            .await;

        match tokio::time::timeout(
            per_request_timeout,
            network.wait_for_actions(completed as usize + 1),
        )
        .await
        {
            Ok(_) => {
                completed += 1;
                tracing::info!(seed, completed, "request completed successfully");
            }
            Err(_) => {
                tracing::info!(seed, completed, "request timed out — clog detected");
                break;
            }
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    if drop_respond_event {
        // Clog: bad request must have been processed, but not all 20.
        assert!(
            completed > bad_request_seed,
            "expected more than {bad_request_seed} successful requests (including the bad one), got {completed}"
        );
        assert!(
            completed < 20,
            "expected clog to prevent some requests, but all 20 completed"
        );

        // Bad request: nodes 0+1 generated, node 2 was excluded.
        let n0_bad = tracker_counts
            .lock()
            .unwrap()
            .get(&(node_0, bad_sign_id))
            .cloned()
            .unwrap_or_default();
        let n1_bad = tracker_counts
            .lock()
            .unwrap()
            .get(&(node_1, bad_sign_id))
            .cloned()
            .unwrap_or_default();
        let n2_bad = tracker_counts
            .lock()
            .unwrap()
            .get(&(node_2, bad_sign_id))
            .cloned()
            .unwrap_or_default();
        assert!(
            n0_bad.signature > 0 && n1_bad.signature > 0,
            "bad request: nodes 0+1 should have exchanged signature messages (n0={}, n1={})",
            n0_bad.signature,
            n1_bad.signature
        );
        assert_eq!(
            n2_bad.signature, 0,
            "bad request: node 2 should have 0 signature messages, got {}",
            n2_bad.signature
        );

        // Send a fresh request and verify nodes 0+1 are durably silent.
        let fresh_seed = completed + 100;
        let new_sign_id = sign_request(fresh_seed).id;
        let n2_bad_before = tracker_counts
            .lock()
            .unwrap()
            .get(&(node_2, bad_sign_id))
            .cloned()
            .unwrap_or_default()
            .posit;

        network
            .process_sign_requests(Chain::Solana, &[sign_request(fresh_seed)])
            .await;

        tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                let ready = {
                    let counts = tracker_counts.lock().unwrap();
                    let bad_posits = counts
                        .get(&(node_2, bad_sign_id))
                        .map_or(0, |c| c.posit.saturating_sub(n2_bad_before));
                    let new_posits = counts.get(&(node_2, new_sign_id)).map_or(0, |c| c.posit);
                    bad_posits >= 2 && new_posits >= 2
                };
                if ready {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("node 2 should be sending posit messages for both bad and new requests");

        // Two snapshots with a quiet period prove durable silence.
        let n0_snap1 = tracker_counts
            .lock()
            .unwrap()
            .get(&(node_0, new_sign_id))
            .cloned()
            .unwrap_or_default();
        let n1_snap1 = tracker_counts
            .lock()
            .unwrap()
            .get(&(node_1, new_sign_id))
            .cloned()
            .unwrap_or_default();

        let quiet_period = 2 * mpc_node::protocol::signature::organize_posit_timeout();
        tokio::time::sleep(quiet_period).await;

        let n0_snap2 = tracker_counts
            .lock()
            .unwrap()
            .get(&(node_0, new_sign_id))
            .cloned()
            .unwrap_or_default();
        let n1_snap2 = tracker_counts
            .lock()
            .unwrap()
            .get(&(node_1, new_sign_id))
            .cloned()
            .unwrap_or_default();

        assert_eq!(
            n0_snap1.posit + n0_snap1.signature,
            0,
            "node 0 sent messages for new request — expected 0 (spawner clogged)"
        );
        assert_eq!(
            n1_snap1.posit + n1_snap1.signature,
            0,
            "node 1 sent messages for new request — expected 0 (spawner clogged)"
        );
        assert_eq!(
            n0_snap2.posit + n0_snap2.signature,
            0,
            "node 0 sent messages during quiet period — clog is not durable"
        );
        assert_eq!(
            n1_snap2.posit + n1_snap2.signature,
            0,
            "node 1 sent messages during quiet period — clog is not durable"
        );
    } else {
        // Respond event cleans up the stale task — all requests complete.
        assert_eq!(
            completed, 20,
            "expected all 20 requests to complete (respond event prevents clog), got {completed}"
        );
    }
}
