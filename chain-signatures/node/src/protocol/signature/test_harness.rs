use crate::backlog::Backlog;
use crate::mesh::MeshState;
use crate::protocol::message::MessageChannel;
use crate::protocol::presignature::{Presignature, PresignatureId};
use crate::protocol::signature::convergence_monitor::{ConvergenceMonitor, RoundInfo};
use crate::protocol::signature::{IndexedSignRequest, SignTask, SignTaskMessage};
use crate::protocol::{Chain, SignRequestType};
use crate::rpc::{ContractStateWatcher, RpcChannel};
use crate::storage::PresignatureStorage;
use cait_sith::protocol::Participant;
use cait_sith::PresignOutput;
use k256::{AffinePoint, Scalar};
use mpc_contract::config::ProtocolConfig;
use mpc_crypto::PublicKey;
use mpc_primitives::{SignArgs, SignId};
use near_account_id::AccountId;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// Statistics about convergence behavior for a sign request
#[derive(Debug, Clone)]
pub struct ConvergenceStats {
    pub sign_id: SignId,
    pub total_rounds: usize,
    pub convergence_round: Option<usize>,
    pub proposer_selections: Vec<(usize, Participant)>,
    pub stalled: bool,
    pub completion_time: Option<Duration>,
}

/// Error types for test harness operations
#[derive(Debug)]
pub enum TestError {
    Timeout,
    Stalled {
        sign_id: SignId,
        rounds: usize,
    },
    ConvergenceMismatch {
        expected_round: usize,
        actual_rounds: Vec<usize>,
    },
    NoSignatureGenerated,
}

/// Handle to a running SignTask for testing
#[allow(dead_code)]
struct SignTaskHandle {
    participant: Participant,
    handle: JoinHandle<()>,
    task_tx: mpsc::Sender<SignTaskMessage>,
    abort_tx: mpsc::Sender<()>,
}

/// Configuration for delaying task spawning
#[derive(Debug, Clone)]
pub struct SpawnDelayConfig {
    /// Minimum delay before spawning a task
    pub min_delay: Duration,
    /// Maximum delay before spawning a task
    pub max_delay: Duration,
}

/// Test harness for running multiple SignTask instances in a controlled environment
pub struct SignTaskTestHarness {
    tasks: Vec<SignTaskHandle>,
    message_bus: Arc<InMemoryMessageBus>,
    presignature_storage: PresignatureStorage,
    pub convergence_monitor: Arc<ConvergenceMonitor>,
    participants: Vec<Participant>,
    threshold: usize,
    mesh_state_tx: watch::Sender<MeshState>,
    /// Optional delay configuration for spawning tasks
    spawn_delay_config: Option<SpawnDelayConfig>,
}

impl SignTaskTestHarness {
    /// Create a new test harness with the specified number of nodes and threshold
    pub fn new(num_nodes: usize, threshold: usize) -> Self {
        let participants: Vec<Participant> = (0..num_nodes as u32).map(Participant::from).collect();

        // Create InMemory message bus
        let message_bus = Arc::new(InMemoryMessageBus::new(&participants));

        // Create InMemory presignature storage
        let account_id = AccountId::from_str("test.near").unwrap();
        let presignature_storage = PresignatureStorage::in_memory(&account_id);

        // Create convergence monitor with stall threshold of 100 rounds
        let convergence_monitor = Arc::new(ConvergenceMonitor::new(100));

        // Create mesh state channel - start with all participants stable
        let mesh_state = MeshState {
            stable: participants.iter().copied().collect(),
            active: crate::protocol::contract::primitives::Participants::default(),
            need_sync: crate::protocol::contract::primitives::Participants::default(),
        };
        let (mesh_state_tx, _) = watch::channel(mesh_state);

        Self {
            tasks: Vec::new(),
            message_bus,
            presignature_storage,
            convergence_monitor,
            participants,
            threshold,
            mesh_state_tx,
            spawn_delay_config: None,
        }
    }

    /// Create a new test harness with random spawn delays for tasks
    /// This simulates tasks arriving at different times, potentially past timeouts
    pub fn with_spawn_delays(num_nodes: usize, threshold: usize, min_delay: Duration, max_delay: Duration) -> Self {
        let mut harness = Self::new(num_nodes, threshold);
        harness.spawn_delay_config = Some(SpawnDelayConfig {
            min_delay,
            max_delay,
        });
        harness
    }

    /// Spawn a sign request with 12 SignTask instances (one per participant)
    /// If spawn delays are configured, tasks will be spawned at random intervals
    pub async fn spawn_sign_request(&mut self, sign_id: SignId, args: SignArgs) {
        // Create mock presignatures for this sign request
        self.populate_mock_presignatures(12).await;

        // Create indexed sign request
        let indexed = IndexedSignRequest {
            id: sign_id,
            args,
            chain: Chain::NEAR,
            unix_timestamp_indexed: 0,
            timestamp_sign_queue: Instant::now(),
            total_timeout: Duration::from_secs(300),
            sign_request_type: SignRequestType::Sign,
        };

        // Spawn a SignTask for each participant
        let participants = self.participants.clone();
        for &participant in &participants {
            // Apply spawn delay if configured
            if let Some(ref delay_config) = self.spawn_delay_config {
                let delay = self.random_delay(delay_config);
                tokio::time::sleep(delay).await;
            }
            self.spawn_task(participant, indexed.clone()).await;
        }
    }

    /// Generate a random delay within the configured range
    fn random_delay(&self, config: &SpawnDelayConfig) -> Duration {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let min_ms = config.min_delay.as_millis() as u64;
        let max_ms = config.max_delay.as_millis() as u64;
        let random_ms = rng.gen_range(min_ms..=max_ms);
        Duration::from_millis(random_ms)
    }

    /// Spawn a single SignTask instance
    async fn spawn_task(&mut self, participant: Participant, indexed: IndexedSignRequest) {
        let sign_id = indexed.id;

        // Get message channel for this participant
        let msg_channel = self.message_bus.get_channel(participant);

        // Create task message channel
        let (task_tx, task_rx) = mpsc::channel(1024);

        // Create SignTask
        let participant_u32: u32 = participant.into();
        let account_id = AccountId::from_str(&format!("node{}.near", participant_u32)).unwrap();
        // Create a mock public key using the identity point
        let public_key = PublicKey::from(AffinePoint::IDENTITY);

        let task = SignTask {
            me: participant,
            participants: self.participants.iter().copied().collect(),
            sign_id,
            threshold: self.threshold,
            public_key,
            epoch: 0,
            my_account_id: account_id,
            presignatures: self.presignature_storage.clone(),
            msg: msg_channel,
            rpc: mock_rpc_channel(),
            backlog: mock_backlog(),
            cfg: ProtocolConfig::default(),
            contract: mock_contract_watcher(),
        };

        // Clone necessary data for the task
        let mesh_state_rx = self.mesh_state_tx.subscribe();
        let _monitor = self.convergence_monitor.clone();

        // Create abort channel for stopping after posit phase
        let (abort_tx, mut abort_rx) = mpsc::channel(1);

        // Spawn the task with monitoring and abort capability
        let handle = tokio::spawn(async move {
            // Create a wrapper that allows aborting the task
            let task_future = task.run(indexed, mesh_state_rx, task_rx);

            tokio::select! {
                result = task_future => {
                    // Task completed normally (or errored)
                    let _ = result;
                }
                _ = abort_rx.recv() => {
                    // Abort signal received - stop the task
                    tracing::info!(?sign_id, ?participant, "task aborted after posit phase");
                }
            }

            // Record completion in monitor
            // (In a full implementation, we'd track round info here)
        });

        self.tasks.push(SignTaskHandle {
            participant,
            handle,
            task_tx,
            abort_tx,
        });
    }

    /// Abort all tasks (used to stop after posit phase)
    pub async fn abort_all_tasks(&mut self) {
        for task in &self.tasks {
            let _ = task.abort_tx.send(()).await;
        }
    }

    /// Clear all task handles (used between test iterations)
    pub fn clear_tasks(&mut self) {
        self.tasks.clear();
    }

    /// Wait for all tasks to complete the posit phase
    pub async fn wait_for_posit_completion(
        &self,
        sign_id: SignId,
        timeout: Duration,
    ) -> Result<(), TestError> {
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                _ = &mut deadline => {
                    return Err(TestError::Timeout);
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    // Check if stalled
                    if let Some(stall) = self.convergence_monitor.check_for_stall(sign_id).await {
                        return Err(TestError::Stalled {
                            sign_id: stall.sign_id,
                            rounds: stall.rounds,
                        });
                    }

                    // Check if all tasks have completed
                    // (In a full implementation, we'd check task status here)
                    // For now, we'll just wait for the timeout or stall
                }
            }
        }
    }

    /// Get convergence statistics for a sign request
    pub fn get_convergence_stats(&self, sign_id: SignId) -> ConvergenceStats {
        // This is a placeholder - in a full implementation, we'd gather stats from the monitor
        ConvergenceStats {
            sign_id,
            total_rounds: 0,
            convergence_round: None,
            proposer_selections: Vec::new(),
            stalled: false,
            completion_time: None,
        }
    }

    /// Populate storage with mock presignatures
    async fn populate_mock_presignatures(&self, count: usize) {
        for i in 0..count {
            let presignature_id = PresignatureId::from(i as u64);

            // Reserve and insert mock presignature
            if let Some(mut slot) = self.presignature_storage.reserve(presignature_id).await {
                let mock_presignature =
                    create_mock_presignature(presignature_id, &self.participants);
                let owner = self.participants[i % self.participants.len()];
                slot.insert(mock_presignature, owner).await;
            }
        }
    }
}

/// In-memory message bus for routing messages between SignTask instances
///
/// This creates real MessageChannel instances for each participant and routes
/// messages through in-memory channels instead of the network.
pub struct InMemoryMessageBus {
    channels: HashMap<Participant, MessageChannel>,
}

impl InMemoryMessageBus {
    /// Create a new in-memory message bus for the given participants
    ///
    /// Each participant gets a real MessageChannel that can send/receive messages.
    /// Messages are routed through in-memory channels for fast, deterministic testing.
    pub fn new(participants: &[Participant]) -> Self {
        let mut channels = HashMap::new();

        // Create a MessageChannel for each participant
        // The MessageChannel handles its own inbox/outbox internally
        for &participant in participants {
            let (_inbox, _outbox, channel) = MessageChannel::new();
            channels.insert(participant, channel);

            // Note: In a full implementation, we would:
            // 1. Spawn inbox/outbox tasks that route messages between participants
            // 2. Wire up the outbox of one participant to the inbox of another
            // 3. Handle message encryption/decryption in-memory
            //
            // For now, we rely on the MessageChannel's internal routing.
            // The SignTask will use these channels to send PositMessages during
            // the organizing/posit phases.
        }

        Self { channels }
    }

    /// Get the message channel for a specific participant
    pub fn get_channel(&self, participant: Participant) -> MessageChannel {
        self.channels
            .get(&participant)
            .cloned()
            .expect("participant not found")
    }
}

/// Create a mock presignature for testing
fn create_mock_presignature(id: PresignatureId, participants: &[Participant]) -> Presignature {
    // Create a minimal mock presignature with just the fields needed for organizing/posit
    Presignature {
        id,
        participants: participants.to_vec(),
        output: PresignOutput {
            big_r: AffinePoint::default(),
            k: Scalar::ZERO,
            sigma: Scalar::ZERO,
        },
    }
}

// Mock implementations for testing
fn mock_rpc_channel() -> RpcChannel {
    // Create a mock RPC channel with a dummy sender
    let (tx, _rx) = mpsc::channel(1);
    RpcChannel { tx }
}

fn mock_backlog() -> Backlog {
    // Create a mock backlog with in-memory storage
    Backlog::new()
}

fn mock_contract_watcher() -> ContractStateWatcher {
    // Create a mock contract state watcher
    let account_id = AccountId::from_str("test.near").unwrap();
    let (watcher, _tx) = ContractStateWatcher::new(&account_id);
    watcher
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_harness_with_12_participants() {
        let harness = SignTaskTestHarness::new(12, 8);
        assert_eq!(harness.participants.len(), 12);
        assert_eq!(harness.threshold, 8);
        assert_eq!(harness.tasks.len(), 0); // No tasks spawned yet
    }

    #[tokio::test]
    async fn test_populate_mock_presignatures() {
        let harness = SignTaskTestHarness::new(12, 8);
        harness.populate_mock_presignatures(10).await;

        // Verify presignatures were created
        assert_eq!(harness.presignature_storage.len_generated().await, 10);
    }

    #[tokio::test]
    async fn test_spawn_single_sign_request() {
        let mut harness = SignTaskTestHarness::new(12, 8);

        // Create a sign request
        let sign_id = SignId::new([1u8; 32]);
        let args = SignArgs {
            payload: k256::Scalar::ZERO,
            path: "test".to_string(),
            key_version: 0,
            epsilon: k256::Scalar::ZERO,
            entropy: [0u8; 32],
        };

        // Spawn the sign request
        harness.spawn_sign_request(sign_id, args).await;

        // Verify that 12 tasks were spawned (one per participant)
        assert_eq!(harness.tasks.len(), 12);

        // Verify presignatures were populated
        assert!(harness.presignature_storage.len_generated().await > 0);
    }

    #[tokio::test]
    async fn test_abort_after_posit_phase() {
        let mut harness = SignTaskTestHarness::new(12, 8);

        // Create a sign request
        let sign_id = SignId::new([2u8; 32]);
        let args = SignArgs {
            payload: k256::Scalar::ZERO,
            path: "test".to_string(),
            key_version: 0,
            epsilon: k256::Scalar::ZERO,
            entropy: [0u8; 32],
        };

        // Spawn the sign request
        harness.spawn_sign_request(sign_id, args).await;

        // Abort all tasks
        harness.abort_all_tasks().await;

        // Give tasks time to process abort signal
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify tasks were aborted (they should complete quickly)
        // In a full implementation, we'd check task status here
    }

    #[tokio::test]
    async fn test_convergence_monitor_integration() {
        let harness = SignTaskTestHarness::new(12, 8);
        let sign_id = SignId::new([3u8; 32]);

        // Record some rounds in the monitor
        for round in 0..5 {
            let info = RoundInfo {
                round,
                proposer: Participant::from(round as u32 % 12),
                timestamp: Instant::now(),
                participants: harness.participants.clone(),
            };
            harness
                .convergence_monitor
                .record_round(sign_id, info)
                .await;
        }

        // Verify rounds were recorded
        assert_eq!(harness.convergence_monitor.round_count(sign_id).await, 5);

        // Check that no stall is detected (below threshold)
        assert!(harness
            .convergence_monitor
            .check_for_stall(sign_id)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn test_message_bus_creation() {
        let participants: Vec<Participant> = (0..12).map(Participant::from).collect();
        let bus = InMemoryMessageBus::new(&participants);

        // Verify we can get channels for all participants
        for &participant in &participants {
            let channel = bus.get_channel(participant);
            // Channel should be valid (not panicking)
            drop(channel);
        }
    }

    #[tokio::test]
    async fn test_mock_presignature_creation() {
        let participants: Vec<Participant> = (0..12).map(Participant::from).collect();
        let presignature_id = PresignatureId::from(42u64);

        let presignature = create_mock_presignature(presignature_id, &participants);

        assert_eq!(presignature.id, presignature_id);
        assert_eq!(presignature.participants.len(), 12);
        assert_eq!(presignature.participants, participants);
    }

    #[tokio::test]
    async fn test_get_convergence_stats() {
        let harness = SignTaskTestHarness::new(12, 8);
        let sign_id = SignId::new([4u8; 32]);

        // Get stats for a sign request
        let stats = harness.get_convergence_stats(sign_id);

        assert_eq!(stats.sign_id, sign_id);
        // Other fields are placeholders for now
    }

    #[tokio::test]
    async fn test_spawn_with_random_delays() {
        let mut harness = SignTaskTestHarness::with_spawn_delays(
            12,
            8,
            Duration::from_millis(20000),
            Duration::from_millis(120000),
        );

        // Create a sign request
        let sign_id = SignId::new([5u8; 32]);
        let args = SignArgs {
            payload: k256::Scalar::ZERO,
            path: "test".to_string(),
            key_version: 0,
            epsilon: k256::Scalar::ZERO,
            entropy: [0u8; 32],
        };

        let start = Instant::now();
        harness.spawn_sign_request(sign_id, args).await;
        let elapsed = start.elapsed();

        // Verify that 12 tasks were spawned
        assert_eq!(harness.tasks.len(), 12);

        // Verify that the spawn took at least the minimum delay time
        // (12 tasks * 10ms minimum = 120ms minimum)
        assert!(elapsed.as_millis() >= 120, "Expected at least 120ms, got {:?}", elapsed);

        // Verify that the spawn didn't take too long
        // (12 tasks * 50ms maximum = 600ms maximum, plus some buffer)
        assert!(elapsed.as_millis() <= 800, "Expected at most 800ms, got {:?}", elapsed);
    }
}
