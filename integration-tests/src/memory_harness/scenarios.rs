use std::time::Duration;

use cait_sith::protocol::Participant;
use mpc_node::protocol::message::{MessageChannel, PositProtocolId};
use mpc_node::protocol::posit::PositAction;
use mpc_node::protocol::presignature::FullPresignatureId;
use mpc_node::rpc::ContractStateWatcher;
use mpc_primitives::{RequestKind, SignId};
use rand::SeedableRng;
use sha2::Digest as _;

use super::config::MemoryHarnessConfig;
use super::diagnostics::{HighWaterMarkTracker, MemorySnapshot, MemorySummary};
use super::gate::StartingGate;
use super::participant::{build_contract_participants, messages, SimulatedParticipant};

/// Helper to compute deterministic protocol IDs based on PRNG seed, scenario index, and repeat iteration.
/// Uses wide 64-bit strides ensuring zero ID aliasing across scenarios (100B stride),
/// iterations (100M stride, supporting up to 1000 repeats), and peers (1M stride, supporting up to 100 peers).
pub fn deterministic_base_id(
    seed: u64,
    scenario_idx: u64,
    iteration: usize,
    peer_idx: usize,
) -> u64 {
    (seed % 10_000) * 1_000_000_000_000
        + scenario_idx * 100_000_000_000
        + (iteration as u64) * 100_000_000
        + (peer_idx as u64) * 1_000_000
}

/// Wait for allocator decay to reclaim freed pages.
/// Emits periodic tiny allocations across worker tasks to mirror background node heartbeats
/// so synchronous decay advances without needing `background_thread:true`.
async fn wait_for_allocator_decay(wait: Duration) {
    if wait.is_zero() {
        return;
    }
    let step = Duration::from_millis(100);
    let steps = (wait.as_millis() / step.as_millis()).max(1);
    for _ in 0..steps {
        tokio::time::sleep(step).await;
        let mut ticks = Vec::with_capacity(8);
        for _ in 0..8 {
            ticks.push(tokio::spawn(async {
                let buf = std::hint::black_box(vec![0u8; 64]);
                drop(buf);
            }));
        }
        for t in ticks {
            let _ = t.await;
        }
    }
}

/// Core scenario executions for MemoryHarness.
pub struct MemoryScenarios;

impl MemoryScenarios {
    /// SCENARIO 1: Orphan Inbox Subscriber Channel Accumulation
    ///
    /// Simulates peers flooding thousands of messages for unjoined/abandoned protocol IDs.
    /// In production, `MessageInbox` creates an `mpsc::channel(4096)` for every novel protocol ID,
    /// but only cleans it up on explicit `Unsubscribe`. When a node never joins the round,
    /// the channel leaks in memory forever.
    pub async fn bench_orphan_inbox_accumulation(
        config: &MemoryHarnessConfig,
        participants: &[SimulatedParticipant],
        iteration: usize,
        baseline_rss: u64,
    ) -> anyhow::Result<MemorySummary> {
        anyhow::ensure!(
            participants.len() >= 2,
            "scenario requires at least 2 participants"
        );
        let node0 = &participants[0];
        let peers = &participants[1..];

        let contract_participants = build_contract_participants(participants);
        let mut rng = rand::rngs::StdRng::seed_from_u64(config.seed + iteration as u64);
        let root_sk = k256::SecretKey::random(&mut rng);
        let (contract_watcher, _contract_tx) = ContractStateWatcher::with_running(
            &node0.account_id,
            root_sk.public_key().to_projective().to_affine(),
            config.threshold,
            contract_participants,
        );

        let (inbox, _outbox, channel) = MessageChannel::new();
        let inbox_handle = tokio::spawn(inbox.run(node0.cipher_sk.clone(), contract_watcher));

        // Let inbox initialize
        tokio::time::sleep(Duration::from_millis(50)).await;

        let initial_snapshot = MemorySnapshot::current();
        let tracker = HighWaterMarkTracker::start(config.sample_interval);

        let total_messages = config.items_per_batch;
        let gate = StartingGate::new(peers.len());
        let mut handles = Vec::new();

        let msgs_per_peer = total_messages / peers.len();
        for (peer_idx, peer) in peers.iter().enumerate() {
            let peer = peer.clone();
            let channel_inbox = channel.clone();
            let node0_pk = node0.cipher_pk.clone();
            let gate_barrier = gate.barrier();
            let seed = config.seed;
            let payload_bytes = config.payload_bytes;

            handles.push(tokio::spawn(async move {
                gate_barrier.wait().await;
                let base_id = deterministic_base_id(seed, 1, iteration, peer_idx + 1);
                let mut sent = 0;

                for i in 0..msgs_per_peer {
                    let id = base_id + i as u64;
                    // Generate distinct unjoined Triple, Presignature, and Signature messages
                    let msg = match i % 3 {
                        0 => messages::triple(id, 0, peer.participant, payload_bytes),
                        1 => messages::presignature(id, peer.participant, payload_bytes),
                        _ => {
                            let hash: [u8; 32] =
                                sha2::Sha256::digest(format!("sign-{id}").as_bytes()).into();
                            let sign_id = SignId::from(hash);
                            messages::signature(sign_id, id, peer.participant, payload_bytes)
                        }
                    };

                    let ciphered = peer.encrypt_batch(&[msg], &node0_pk).unwrap();
                    let _ = channel_inbox.send_inbox(ciphered).await;
                    sent += 1;
                }
                sent
            }));
        }

        // Release workers and start synchronized clock
        let start_time = gate.start().await;

        let mut actual_sent = 0;
        for h in handles {
            actual_sent += h.await?;
        }

        // Wait for inbox queue to process all messages into subscriber maps
        tokio::time::sleep(Duration::from_millis(200)).await;

        let duration = start_time.elapsed();
        let peak_rss = tracker.stop();

        // Teardown component and allow allocator decay to reclaim freed pages
        inbox_handle.abort();
        let _ = inbox_handle.await;
        wait_for_allocator_decay(config.decay_wait).await;
        let final_snapshot = MemorySnapshot::current();

        Ok(MemorySummary::calculate(
            "orphan_inbox_accumulation",
            iteration,
            baseline_rss,
            initial_snapshot,
            peak_rss,
            final_snapshot,
            duration,
            actual_sent,
            config.max_allowed_leak_bytes,
        ))
    }

    /// SCENARIO 2: Burst Posit Queue Flood
    ///
    /// Floods thousands of posit messages (`TriplePosit`, `PresignaturePosit`, `SignaturePosit`)
    /// into `MessageInbox`. Demonstrates memory consumption of the 16,777,216 element
    /// posit channels under high burst traffic.
    pub async fn bench_burst_posit_flood(
        config: &MemoryHarnessConfig,
        participants: &[SimulatedParticipant],
        iteration: usize,
        baseline_rss: u64,
    ) -> anyhow::Result<MemorySummary> {
        anyhow::ensure!(
            participants.len() >= 2,
            "scenario requires at least 2 participants"
        );
        let node0 = &participants[0];
        let peers = &participants[1..];

        let contract_participants = build_contract_participants(participants);
        let mut rng = rand::rngs::StdRng::seed_from_u64(config.seed + 100 + iteration as u64);
        let root_sk = k256::SecretKey::random(&mut rng);
        let (contract_watcher, _contract_tx) = ContractStateWatcher::with_running(
            &node0.account_id,
            root_sk.public_key().to_projective().to_affine(),
            config.threshold,
            contract_participants,
        );

        let (inbox, _outbox, channel) = MessageChannel::new();
        let inbox_handle = tokio::spawn(inbox.run(node0.cipher_sk.clone(), contract_watcher));

        tokio::time::sleep(Duration::from_millis(50)).await;

        let initial_snapshot = MemorySnapshot::current();
        let tracker = HighWaterMarkTracker::start(config.sample_interval);

        let total_posits = config.posit_burst_count;
        let gate = StartingGate::new(peers.len());
        let mut handles = Vec::new();
        let posits_per_peer = total_posits / peers.len();

        for (peer_idx, peer) in peers.iter().enumerate() {
            let peer = peer.clone();
            let channel_inbox = channel.clone();
            let node0_pk = node0.cipher_pk.clone();
            let gate_barrier = gate.barrier();
            let seed = config.seed;

            handles.push(tokio::spawn(async move {
                gate_barrier.wait().await;
                let base_id = deterministic_base_id(seed, 2, iteration, peer_idx + 1);
                let mut sent = 0;

                for i in 0..posits_per_peer {
                    let id = base_id + i as u64;
                    let posit_id = match i % 3 {
                        0 => PositProtocolId::Triple(id),
                        1 => PositProtocolId::Presignature(FullPresignatureId::from_pair(id)),
                        _ => {
                            let hash: [u8; 32] =
                                sha2::Sha256::digest(format!("posit-sign-{id}").as_bytes()).into();
                            let sign_id = SignId::from(hash);
                            PositProtocolId::signature(sign_id, RequestKind::Sign, id, 0)
                        }
                    };

                    let msg = messages::posit(posit_id, peer.participant, PositAction::Accept);
                    let ciphered = peer.encrypt_batch(&[msg], &node0_pk).unwrap();
                    let _ = channel_inbox.send_inbox(ciphered).await;
                    sent += 1;
                }
                sent
            }));
        }

        // Release workers and start synchronized clock
        let start_time = gate.start().await;

        let mut actual_sent = 0;
        for h in handles {
            actual_sent += h.await?;
        }

        // Wait for inbox to ingest ciphertexts into the posit channels
        tokio::time::sleep(Duration::from_millis(250)).await;

        let duration = start_time.elapsed();
        let peak_rss = tracker.stop();

        // Teardown component before final snapshot
        inbox_handle.abort();
        let _ = inbox_handle.await;
        wait_for_allocator_decay(config.decay_wait).await;
        let final_snapshot = MemorySnapshot::current();

        Ok(MemorySummary::calculate(
            "burst_posit_flood",
            iteration,
            baseline_rss,
            initial_snapshot,
            peak_rss,
            final_snapshot,
            duration,
            actual_sent,
            config.max_allowed_leak_bytes,
        ))
    }

    /// SCENARIO 3: Generator Concurrency Surge
    ///
    /// Simulates sudden surge of concurrent triple and presignature generation requests.
    /// Drives real `cait_sith` cryptographic state machines and `MessageChannel` protocol
    /// subscriber channels to evaluate memory allocation and retention under concurrency surges.
    pub async fn bench_generator_concurrency_surge(
        config: &MemoryHarnessConfig,
        participants: &[SimulatedParticipant],
        iteration: usize,
        baseline_rss: u64,
    ) -> anyhow::Result<MemorySummary> {
        anyhow::ensure!(
            participants.len() >= 2,
            "scenario requires at least 2 participants"
        );
        let node0 = &participants[0];
        let participant_ids: Vec<Participant> =
            participants.iter().map(|p| p.participant).collect();

        let contract_participants = build_contract_participants(participants);
        let mut rng = rand::rngs::StdRng::seed_from_u64(config.seed + 300 + iteration as u64);
        let root_sk = k256::SecretKey::random(&mut rng);
        let (contract_watcher, _contract_tx) = ContractStateWatcher::with_running(
            &node0.account_id,
            root_sk.public_key().to_projective().to_affine(),
            config.threshold,
            contract_participants,
        );

        let (inbox, _outbox, channel) = MessageChannel::new();
        let inbox_handle = tokio::spawn(inbox.run(node0.cipher_sk.clone(), contract_watcher));

        tokio::time::sleep(Duration::from_millis(50)).await;

        let initial_snapshot = MemorySnapshot::current();
        let tracker = HighWaterMarkTracker::start(config.sample_interval);

        let surge_count = config.surge_generators;
        let gate = StartingGate::new(surge_count);
        let seed = config.seed;

        let mut generator_handles = Vec::with_capacity(surge_count);
        for i in 0..surge_count {
            let id = deterministic_base_id(seed, 4, iteration, 0) + i as u64;
            let p_ids = participant_ids.clone();
            let me = node0.participant;
            let threshold = config.threshold;
            let gate_barrier = gate.barrier();
            let chan = channel.clone();

            generator_handles.push(tokio::spawn(async move {
                // Initialize Cait-Sith multi-party state machine
                let protocol = cait_sith::triples::generate_triple_many::<k256::Secp256k1, 2>(
                    &p_ids, me, threshold,
                )
                .expect("failed to initialize cait_sith protocol");

                // Subscribe dedicated protocol channel in MessageInbox
                let sub = chan.subscribe_triple(id).await;

                gate_barrier.wait().await;

                // Hold protocol state machine and channel active during surge window
                tokio::time::sleep(Duration::from_millis(60)).await;
                drop(protocol);
                drop(sub);
            }));
        }

        // Release all concurrent generators simultaneously and start clock
        let start_time = gate.start().await;

        for h in generator_handles {
            h.await?;
        }

        // Allow channels and tasks to drain
        tokio::time::sleep(Duration::from_millis(50)).await;

        let duration = start_time.elapsed();
        let peak_rss = tracker.stop();

        // Teardown inbox component before final snapshot
        inbox_handle.abort();
        let _ = inbox_handle.await;
        wait_for_allocator_decay(config.decay_wait).await;
        let final_snapshot = MemorySnapshot::current();

        Ok(MemorySummary::calculate(
            "generator_concurrency_surge",
            iteration,
            baseline_rss,
            initial_snapshot,
            peak_rss,
            final_snapshot,
            duration,
            surge_count,
            config.max_allowed_leak_bytes,
        ))
    }
}
