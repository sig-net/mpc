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

/// Demonstrates that when a node participates in generation but its generation
/// times out (while other nodes complete), and it never receives the respond
/// event, the stale task keeps sending Posit messages that eventually clog the
/// other nodes' message inboxes.
///
/// The clogging cascade:
/// 1. Nodes 0+1 complete generation, their tasks exit, inboxes removed
/// 2. Node 2's generation times out → falls back to Organizing → keeps proposing
/// 3. handle_posit on nodes 0+1 creates dead-letter inboxes for the completed sign_id
/// 4. Dead-letter inbox fills (POSIT_INBOX_CHANNEL_SIZE=4 under test-feature)
/// 5. handle_posit blocks → SignatureSpawner blocks → MessageInbox blocks
/// 6. Nodes 0+1 can no longer process any new signatures
#[test(tokio::test(flavor = "multi_thread"))]
async fn test_missed_respond_clogs_inbox() {
    use cait_sith::protocol::Participant;
    use integration_tests::mpc_fixture::message_collector::CollectMessages;
    use mpc_node::protocol::message::{PositProtocolId, SendMessage};
    use mpc_node::protocol::Message;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    struct PostClogTracker {
        tracking_active: Arc<AtomicBool>,
        node_01_propose_count: Arc<AtomicUsize>,
        node_01_signature_count: Arc<AtomicUsize>,
        node_2_propose_count: Arc<AtomicUsize>,
    }
    impl CollectMessages for PostClogTracker {
        fn observe_message(&mut self, msg: &SendMessage, _passed_filter: bool) {
            if !self.tracking_active.load(Ordering::Relaxed) {
                return;
            }
            let (message, (from, _to, _ts)) = msg;
            let from_node_01 = *from == Participant::from(0) || *from == Participant::from(1);
            match message {
                Message::Posit(posit_msg) => {
                    if let PositProtocolId::Signature(..) = posit_msg.id {
                        if from_node_01 {
                            self.node_01_propose_count.fetch_add(1, Ordering::Relaxed);
                        } else {
                            self.node_2_propose_count.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Message::Signature(_) if from_node_01 => {
                    self.node_01_signature_count.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }
        fn print_summary(&self) {}
    }

    use std::sync::atomic::AtomicBool;
    let tracking_active = Arc::new(AtomicBool::new(false));
    let node_01_propose_count = Arc::new(AtomicUsize::new(0));
    let node_01_signature_count = Arc::new(AtomicUsize::new(0));
    let node_2_propose_count = Arc::new(AtomicUsize::new(0));

    let tracker = PostClogTracker {
        tracking_active: Arc::clone(&tracking_active),
        node_01_propose_count: Arc::clone(&node_01_propose_count),
        node_01_signature_count: Arc::clone(&node_01_signature_count),
        node_2_propose_count: Arc::clone(&node_2_propose_count),
    };

    let node_2 = Participant::from(2);
    let signature_timeout_ms = 5_000;

    let network = MpcFixtureBuilder::new(3, 2)
        .only_generate_signatures()
        .with_signature_timeout_ms(signature_timeout_ms)
        .with_mock_stream(Chain::Solana, MockStream::default())
        .await
        // Drop Signature protocol messages from node 0 → node 2.
        // Nodes 0+1 can still complete with threshold=2 messages between them.
        // Node 2's generation will time out because it never receives protocol messages.
        .with_outgoing_message_filter(
            0,
            Box::new(move |msg: &SendMessage| {
                let (message, (_from, to, _ts)) = msg;
                !(matches!(message, Message::Signature(_)) && *to == node_2)
            }),
        )
        .with_outgoing_message_filter(
            1,
            Box::new(move |msg: &SendMessage| {
                let (message, (_from, to, _ts)) = msg;
                !(matches!(message, Message::Signature(_)) && *to == node_2)
            }),
        )
        .with_message_collector(Arc::new(Mutex::new(tracker)))
        .build()
        .await;

    // Send first sign request — nodes 0+1 will complete, node 2's generation will time out
    network
        .process_sign_requests(Chain::Solana, &[sign_request(0)])
        .await;

    let actions = network.assert_actions(1, Duration::from_secs(30)).await;
    assert_eq!(actions.len(), 1);

    // Start tracking messages after the first signature is published.
    // From this point, nodes 0+1 should have no generators in flight.
    tracking_active.store(true, Ordering::Relaxed);

    // Wait for node 2's generation to time out and start proposing again,
    // then for enough proposals to fill the dead-letter inbox on nodes 0+1.
    //
    // After generation_timeout (5s), node 2 re-enters Organizing and cycles
    // through rounds. It is proposer ~1/3 of rounds (round-robin with 3 active
    // nodes in the mesh). Each round takes ORGANIZE_POSIT_TIMEOUT (5s).
    // With POSIT_INBOX_CHANNEL_SIZE=4, we need 5 Propose messages to block
    // (4 to fill the channel + 1 that blocks on send).
    // Time: generation_timeout + 5 proposals × 3 rounds/proposal × ORGANIZE_POSIT_TIMEOUT
    //     = 5s + 5 × 3 × 5s = 80s
    let organize_timeout = mpc_node::protocol::signature::organize_posit_timeout();
    let clog_wait = Duration::from_millis(signature_timeout_ms) + 18 * organize_timeout;
    tokio::time::sleep(clog_wait).await;

    // Verify nodes 0+1 have no signature generators in flight: they should not
    // have sent any Posit or Signature protocol messages since tracking started.
    let n01_posits = node_01_propose_count.load(Ordering::Relaxed);
    let n01_sigs = node_01_signature_count.load(Ordering::Relaxed);
    let n2_posits = node_2_propose_count.load(Ordering::Relaxed);
    assert_eq!(
        n01_posits, 0,
        "nodes 0+1 sent {n01_posits} posit messages after completing — expected 0 (no generators in flight)"
    );
    assert_eq!(
        n01_sigs, 0,
        "nodes 0+1 sent {n01_sigs} signature messages after completing — expected 0 (no generators in flight)"
    );
    assert!(
        n2_posits > 0,
        "node 2 should have sent posit messages (stale task proposing), but count was 0"
    );

    // Send another sign request — should NOT be processable because nodes 0+1 are clogged.
    // Their SignatureSpawner is blocked on a dead-letter inbox send, so it cannot
    // process new Sign::Request or Posit messages.
    network
        .process_sign_requests(Chain::Solana, &[sign_request(1)])
        .await;

    let result = tokio::time::timeout(Duration::from_secs(30), network.wait_for_actions(2)).await;

    assert!(
        result.is_err(),
        "expected second signature to NOT be produced (inbox clogged), but it was"
    );
}
