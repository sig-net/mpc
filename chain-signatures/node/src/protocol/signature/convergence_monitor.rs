use cait_sith::protocol::Participant;
use mpc_primitives::SignId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Information about a single round in the organizing/posit phase
#[derive(Debug, Clone)]
pub struct RoundInfo {
    pub round: usize,
    pub proposer: Participant,
    pub timestamp: Instant,
    pub participants: Vec<Participant>,
}

/// Report generated when a stall is detected
#[derive(Debug, Clone)]
pub struct StallReport {
    pub sign_id: SignId,
    pub rounds: usize,
    pub round_history: Vec<RoundInfo>,
}

/// Monitors convergence behavior across multiple SignTask instances
/// Tracks round progression and detects stalls
pub struct ConvergenceMonitor {
    /// History of rounds per SignId
    round_history: Arc<RwLock<HashMap<SignId, Vec<RoundInfo>>>>,
    /// Threshold for detecting stalls (number of rounds)
    stall_threshold: usize,
}

impl ConvergenceMonitor {
    /// Create a new ConvergenceMonitor with the specified stall threshold
    pub fn new(stall_threshold: usize) -> Self {
        Self {
            round_history: Arc::new(RwLock::new(HashMap::new())),
            stall_threshold,
        }
    }

    /// Record a round for a specific SignTask
    pub async fn record_round(&self, sign_id: SignId, info: RoundInfo) {
        let mut history = self.round_history.write().await;
        history.entry(sign_id).or_insert_with(Vec::new).push(info);
    }

    /// Check if a SignTask has stalled (exceeded the round threshold)
    /// Returns Some(StallReport) if stalled, None otherwise
    pub async fn check_for_stall(&self, sign_id: SignId) -> Option<StallReport> {
        let history = self.round_history.read().await;

        if let Some(rounds) = history.get(&sign_id) {
            if let Some(last_round) = rounds.last() {
                if last_round.round >= self.stall_threshold {
                    return Some(StallReport {
                        sign_id,
                        rounds: last_round.round,
                        round_history: rounds.clone(),
                    });
                }
            }
        }

        None
    }

    /// Get the round at which all tasks converged (if they did)
    /// Returns the round number where convergence occurred, or None if not yet converged
    pub async fn get_convergence_round(&self, sign_id: SignId) -> Option<usize> {
        let history = self.round_history.read().await;

        if let Some(rounds) = history.get(&sign_id) {
            // For now, we consider convergence to be when we have at least one round recorded
            // In a full implementation, this would check that all tasks agree on the same round
            if let Some(last_round) = rounds.last() {
                return Some(last_round.round);
            }
        }

        None
    }

    /// Get all recorded rounds for a SignId
    pub async fn get_rounds(&self, sign_id: SignId) -> Vec<RoundInfo> {
        let history = self.round_history.read().await;
        history.get(&sign_id).cloned().unwrap_or_default()
    }

    /// Clear all history for a specific SignId
    pub async fn clear_sign_id(&self, sign_id: SignId) {
        let mut history = self.round_history.write().await;
        history.remove(&sign_id);
    }

    /// Clear all history
    pub async fn clear_all(&self) {
        let mut history = self.round_history.write().await;
        history.clear();
    }

    /// Get the number of rounds recorded for a SignId
    pub async fn round_count(&self, sign_id: SignId) -> usize {
        let history = self.round_history.read().await;
        history.get(&sign_id).map(|r| r.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_record_round_from_single_task() {
        let monitor = ConvergenceMonitor::new(100);
        let sign_id = SignId::new([1u8; 32]);

        let info = RoundInfo {
            round: 0,
            proposer: Participant::from(0),
            timestamp: Instant::now(),
            participants: vec![Participant::from(0), Participant::from(1)],
        };

        monitor.record_round(sign_id, info).await;

        let rounds = monitor.get_rounds(sign_id).await;
        assert_eq!(rounds.len(), 1);
        assert_eq!(rounds[0].round, 0);
        assert_eq!(rounds[0].proposer, Participant::from(0));
    }

    #[tokio::test]
    async fn test_record_rounds_from_multiple_tasks() {
        let monitor = ConvergenceMonitor::new(100);
        let sign_id = SignId::new([1u8; 32]);

        // Simulate multiple tasks recording rounds
        for round in 0..5 {
            let info = RoundInfo {
                round,
                proposer: Participant::from(round as u32 % 3),
                timestamp: Instant::now(),
                participants: vec![
                    Participant::from(0),
                    Participant::from(1),
                    Participant::from(2),
                ],
            };
            monitor.record_round(sign_id, info).await;
        }

        let rounds = monitor.get_rounds(sign_id).await;
        assert_eq!(rounds.len(), 5);

        // Verify rounds are in order
        for (i, round_info) in rounds.iter().enumerate() {
            assert_eq!(round_info.round, i);
        }
    }

    #[tokio::test]
    async fn test_stall_detection_below_threshold() {
        let monitor = ConvergenceMonitor::new(100);
        let sign_id = SignId::new([1u8; 32]);

        // Record rounds below threshold
        for round in 0..50 {
            let info = RoundInfo {
                round,
                proposer: Participant::from(0),
                timestamp: Instant::now(),
                participants: vec![Participant::from(0)],
            };
            monitor.record_round(sign_id, info).await;
        }

        let stall = monitor.check_for_stall(sign_id).await;
        assert!(stall.is_none(), "Should not detect stall below threshold");
    }

    #[tokio::test]
    async fn test_stall_detection_at_threshold() {
        let monitor = ConvergenceMonitor::new(100);
        let sign_id = SignId::new([1u8; 32]);

        // Record rounds up to threshold
        for round in 0..=100 {
            let info = RoundInfo {
                round,
                proposer: Participant::from(0),
                timestamp: Instant::now(),
                participants: vec![Participant::from(0)],
            };
            monitor.record_round(sign_id, info).await;
        }

        let stall = monitor.check_for_stall(sign_id).await;
        assert!(stall.is_some(), "Should detect stall at threshold");

        let report = stall.unwrap();
        assert_eq!(report.sign_id, sign_id);
        assert_eq!(report.rounds, 100);
        assert_eq!(report.round_history.len(), 101); // 0..=100
    }

    #[tokio::test]
    async fn test_stall_detection_above_threshold() {
        let monitor = ConvergenceMonitor::new(10);
        let sign_id = SignId::new([1u8; 32]);

        // Record rounds well above threshold
        for round in 0..50 {
            let info = RoundInfo {
                round,
                proposer: Participant::from(0),
                timestamp: Instant::now(),
                participants: vec![Participant::from(0)],
            };
            monitor.record_round(sign_id, info).await;
        }

        let stall = monitor.check_for_stall(sign_id).await;
        assert!(stall.is_some(), "Should detect stall above threshold");

        let report = stall.unwrap();
        assert_eq!(report.rounds, 49); // Last round recorded
    }

    #[tokio::test]
    async fn test_convergence_detection() {
        let monitor = ConvergenceMonitor::new(100);
        let sign_id = SignId::new([1u8; 32]);

        // No rounds recorded yet
        assert_eq!(monitor.get_convergence_round(sign_id).await, None);

        // Record some rounds
        for round in 0..5 {
            let info = RoundInfo {
                round,
                proposer: Participant::from(0),
                timestamp: Instant::now(),
                participants: vec![Participant::from(0)],
            };
            monitor.record_round(sign_id, info).await;
        }

        // Should return the last round
        let convergence_round = monitor.get_convergence_round(sign_id).await;
        assert_eq!(convergence_round, Some(4));
    }

    #[tokio::test]
    async fn test_clear_sign_id() {
        let monitor = ConvergenceMonitor::new(100);
        let sign_id = SignId::new([1u8; 32]);

        // Record some rounds
        for round in 0..5 {
            let info = RoundInfo {
                round,
                proposer: Participant::from(0),
                timestamp: Instant::now(),
                participants: vec![Participant::from(0)],
            };
            monitor.record_round(sign_id, info).await;
        }

        assert_eq!(monitor.round_count(sign_id).await, 5);

        // Clear the sign_id
        monitor.clear_sign_id(sign_id).await;
        assert_eq!(monitor.round_count(sign_id).await, 0);
    }

    #[tokio::test]
    async fn test_clear_all() {
        let monitor = ConvergenceMonitor::new(100);

        // Record rounds for multiple sign_ids
        for request_id in 1..=3 {
            let mut id_bytes = [0u8; 32];
            id_bytes[0] = request_id as u8;
            let sign_id = SignId::new(id_bytes);

            for round in 0..5 {
                let info = RoundInfo {
                    round,
                    proposer: Participant::from(0),
                    timestamp: Instant::now(),
                    participants: vec![Participant::from(0)],
                };
                monitor.record_round(sign_id, info).await;
            }
        }

        // Verify all have rounds
        for request_id in 1..=3 {
            let mut id_bytes = [0u8; 32];
            id_bytes[0] = request_id as u8;
            let sign_id = SignId::new(id_bytes);
            assert_eq!(monitor.round_count(sign_id).await, 5);
        }

        // Clear all
        monitor.clear_all().await;

        // Verify all are cleared
        for request_id in 1..=3 {
            let mut id_bytes = [0u8; 32];
            id_bytes[0] = request_id as u8;
            let sign_id = SignId::new(id_bytes);
            assert_eq!(monitor.round_count(sign_id).await, 0);
        }
    }

    #[tokio::test]
    async fn test_multiple_sign_ids() {
        let monitor = ConvergenceMonitor::new(100);

        let sign_id_1 = SignId::new([1u8; 32]);
        let sign_id_2 = SignId::new([2u8; 32]);

        // Record different numbers of rounds for each
        for round in 0..3 {
            let info = RoundInfo {
                round,
                proposer: Participant::from(0),
                timestamp: Instant::now(),
                participants: vec![Participant::from(0)],
            };
            monitor.record_round(sign_id_1, info).await;
        }

        for round in 0..7 {
            let info = RoundInfo {
                round,
                proposer: Participant::from(1),
                timestamp: Instant::now(),
                participants: vec![Participant::from(1)],
            };
            monitor.record_round(sign_id_2, info).await;
        }

        assert_eq!(monitor.round_count(sign_id_1).await, 3);
        assert_eq!(monitor.round_count(sign_id_2).await, 7);

        let rounds_1 = monitor.get_rounds(sign_id_1).await;
        let rounds_2 = monitor.get_rounds(sign_id_2).await;

        assert_eq!(rounds_1.len(), 3);
        assert_eq!(rounds_2.len(), 7);
        assert_eq!(rounds_1[0].proposer, Participant::from(0));
        assert_eq!(rounds_2[0].proposer, Participant::from(1));
    }
}
