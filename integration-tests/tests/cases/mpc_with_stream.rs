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

/// When node 2 misses the respond event for a failed generation, its stale
/// task keeps proposing and eventually clogs other nodes' message inboxes.
///
/// Scenario:
/// - Requests 0..2 succeed normally. Respond events clean up all tasks.
/// - Request 3: node 2 is excluded from generation (Accept dropped) AND
///   misses the respond event → stale task keeps proposing.
/// - Requests 4+: node 2's stale posit messages fill dead-letter inboxes on
///   nodes 0+1 (POSIT_INBOX_CHANNEL_SIZE=4 under test-feature). Once full,
///   handle_posit blocks → SignatureSpawner freezes → no more signatures.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_missed_respond_event_clogs_inbox() {
    run_stale_task_test(true).await;
}

/// Control test: same setup as [`test_missed_respond_event_clogs_inbox`] but
/// node 2 DOES receive the respond event. The respond event aborts node 2's
/// stale task, so the dead-letter inbox never fills and all requests complete.
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_respond_event_prevents_clog() {
    run_stale_task_test(false).await;
}

/// Shared implementation for the clog / no-clog test pair.
///
/// When `drop_respond_event` is true, node 2 misses the respond event for the
/// bad request and the system clogs. When false, the respond event cleans up
/// the stale task and all requests complete.
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
        // Drop node 2's Accept for the bad request so it is excluded from
        // generation. Dropping Accept guarantees node 2 is never selected
        // as a participant (the fast mock completes cait-sith in milliseconds,
        // so dropping Signature messages wouldn't prevent completion).
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
                    if respond.request_id() == bad_sign_id.request_id {
                        return EventDelivery::Drop;
                    }
                }
                EventDelivery::Deliver
            }),
        );
    }

    let network = builder.build().await;

    let per_request_timeout = Duration::from_secs(60);

    // Send requests one at a time with delays between them so the stale task
    // (if any) has time to send proposals.
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

        // Give the stale task time to send proposals between requests.
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    if drop_respond_event {
        // With missed respond event: clog should have occurred.
        // At minimum, the bad request itself must have been sent and completed
        // by nodes 0+1 (even though node 2 was excluded).
        assert!(
            completed > bad_request_seed,
            "expected more than {bad_request_seed} successful requests (including the bad one), got {completed}"
        );
        assert!(
            completed < 20,
            "expected clog to prevent some requests, but all 20 completed"
        );

        // Verify the bad request: nodes 0+1 generated, node 2 did not.
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

        // Verify clog: send a fresh request (not the timed-out one), wait for
        // node 2 to be active on both sign_ids, then check nodes 0+1 are silent.
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

        let n0_new = tracker_counts
            .lock()
            .unwrap()
            .get(&(node_0, new_sign_id))
            .cloned()
            .unwrap_or_default();
        let n1_new = tracker_counts
            .lock()
            .unwrap()
            .get(&(node_1, new_sign_id))
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            n0_new.posit + n0_new.signature,
            0,
            "node 0 sent messages for new request — expected 0 (spawner clogged)"
        );
        assert_eq!(
            n1_new.posit + n1_new.signature,
            0,
            "node 1 sent messages for new request — expected 0 (spawner clogged)"
        );
    } else {
        // Without missed respond event: respond event cleans up the stale task,
        // so all requests should complete without clogging.
        assert_eq!(
            completed, 20,
            "expected all 20 requests to complete (respond event prevents clog), got {completed}"
        );
    }
}
