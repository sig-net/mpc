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

    let actions = network
        .assert_publish_actions(1, Duration::from_secs(10))
        .await;

    let action_str = actions.first().unwrap();
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

    let timeout = Duration::from_secs(150);
    let actions = network
        .assert_publish_actions(expected_signatures, timeout)
        .await;

    let action_str = actions.first().unwrap();
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
    // Half the organize/posit timeout, so no node reaches its round deadline
    // before the last one has observed the block.
    let delay = mpc_node::protocol::request::organize_posit_timeout() / 2;
    check_channel_contention(5, 10, 50, Some(delay)).await;
}

/// A request must settle even when nodes permanently disagree about who is
/// active.
///
/// Every node hides one peer — its successor in participant order — for the
/// whole run. Each node's active set therefore still holds `threshold`
/// participants (itself plus three peers), so `wait_for_active_participants`
/// never blocks and any stall here is attributable to proposer election alone.
///
/// The invariant under test: nodes must agree on the proposer, and on the round
/// they are in, regardless of their local active sets. An election that derives
/// either from the local active set breaks this — disagreeing views put nodes on
/// different rounds, proposals then arrive as future-round messages and are
/// buffered instead of accepted, accepts never reach `threshold`, and the
/// request never settles.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_divergent_active_views_still_converge() {
    let num_nodes = 5;
    let threshold = 4;
    let network = MpcFixtureBuilder::new(num_nodes, threshold)
        .only_generate_signatures()
        .with_mock_stream(Chain::Solana, MockStream::default())
        .await
        .build()
        .await;

    let participants = network.sorted_participants();
    for node in network.nodes.iter() {
        let index = participants
            .iter()
            .position(|p| *p == node.me)
            .expect("node is a participant");
        let hidden = participants[(index + 1) % participants.len()];
        let mut view = node.mesh.borrow().clone();
        view.remove(hidden);
        // Must not be silently dropped: without the divergent views installed
        // the request settles trivially and the test proves nothing.
        node.mesh.send(view).expect("mesh receivers are alive");
    }

    network
        .process_sign_requests(Chain::Solana, &[sign_request(0)])
        .await;

    // The request is settled once a publish action appears.
    network
        .assert_publish_actions(1, Duration::from_secs(90))
        .await;
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

/// A missed respond event leaves a stale task but does not clog other nodes' inboxes.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_missed_respond_event_does_not_clog_inbox() {
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
    use mpc_primitives::ChainEvent;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{Mutex, Notify};

    #[derive(Default, Clone, Debug)]
    struct MessageCounts {
        posit: usize,
        signature: usize,
    }

    /// Tracks the number of posit and signature messages observed for each participant and sign request.
    #[derive(Default)]
    struct SignatureTracker {
        /// Keyed by (participant, sign_id) to count messages per participant and request.
        counts: Arc<std::sync::Mutex<HashMap<(Participant, SignId), MessageCounts>>>,
        /// Notifies when a posit message has been observed, so the test can wait for it.
        posit_delivered: Arc<Notify>,
    }

    impl CollectMessages for SignatureTracker {
        /// Observes messages and counts posit and signature messages per participant and sign request.
        fn observe_message(&mut self, msg: &SendMessage, passed_filter: bool) {
            if !passed_filter {
                return;
            }
            let SendMessage { message, from, .. } = msg;
            match message {
                Message::Posit(posit_msg) => {
                    if let PositProtocolId::Signature(sign_id, ..) = posit_msg.id {
                        self.counts
                            .lock()
                            .unwrap()
                            .entry((*from, sign_id))
                            .or_default()
                            .posit += 1;
                        self.posit_delivered.notify_one();
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

    /// Waits for a posit message from a specific participant and sign request to be observed, or times out.
    async fn wait_for_delivered_posit(
        counts: &Arc<std::sync::Mutex<HashMap<(Participant, SignId), MessageCounts>>>,
        posit_delivered: &Notify,
        from: Participant,
        id: SignId,
        timeout: Duration,
    ) -> bool {
        tokio::time::timeout(timeout, async {
            loop {
                if counts
                    .lock()
                    .unwrap()
                    .get(&(from, id))
                    .is_some_and(|c| c.posit > 0)
                {
                    return;
                }
                posit_delivered.notified().await;
            }
        })
        .await
        .is_ok()
    }

    let node_0 = Participant::from(0);
    let node_1 = Participant::from(1);
    let node_2 = Participant::from(2);
    let bad_request_seed = 3u32;
    let bad_sign_id = sign_request(bad_request_seed).id;
    let signature_timeout_ms = 5_000;

    let tracker = SignatureTracker::default();
    let tracker_counts = Arc::clone(&tracker.counts);
    let posit_delivered = Arc::clone(&tracker.posit_delivered);

    let mut builder = MpcFixtureBuilder::new(3, 2)
        .only_generate_signatures()
        .with_signature_timeout_ms(signature_timeout_ms)
        .with_mock_stream(Chain::Solana, MockStream::default())
        .await
        // Exclude node 2 from generation for the bad request by dropping its Accept.
        .with_outgoing_message_filter(
            2,
            Box::new(move |msg: &SendMessage| {
                let SendMessage { message, .. } = msg;
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

    // Timeout for each request to complete, after which we assume a clog has occurred.
    let per_request_timeout = Duration::from_secs(60);
    // Time we wait for a stale posit to be observed from node 2, after which we continue sending requests.
    let stale_posit_timeout = Duration::from_secs(30);

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

        // If we dropped the respond event and this is the bad request, wait for node 2 to propose a stale posit.
        if drop_respond_event && seed == bad_request_seed {
            assert!(
                wait_for_delivered_posit(
                    &tracker_counts,
                    &posit_delivered,
                    node_2,
                    bad_sign_id,
                    stale_posit_timeout,
                )
                .await,
                "node 2's stale task never proposed for {bad_sign_id:?} \
                 within {stale_posit_timeout:?}"
            );
        }
    }

    if drop_respond_event {
        // Even with a missed respond event causing a stale task on node 2,
        // all 20 requests must complete successfully because nodes 0 and 1 drop the stale posit messages.
        assert_eq!(
            completed, 20,
            "expected all 20 requests to complete (backpressure dropping prevents clog), got {completed}"
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

        // Send a fresh request and verify it is successfully signed.
        let fresh_seed = completed + 100;
        network
            .process_sign_requests(Chain::Solana, &[sign_request(fresh_seed)])
            .await;

        let actions = network
            .assert_actions(completed as usize + 1, Duration::from_secs(30))
            .await;
        assert_eq!(actions.len(), completed as usize + 1);
    } else {
        // Respond event cleans up the stale task — all requests complete.
        assert_eq!(
            completed, 20,
            "expected all 20 requests to complete (respond event prevents clog), got {completed}"
        );
    }
}
