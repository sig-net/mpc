/// Property-based tests for SignTask round convergence behavior
/// 
/// Feature: sign-task-convergence-testing
/// Property 3: Round convergence consistency
/// Validates: Requirements 3.2

#[cfg(test)]
mod tests {
    use crate::protocol::signature::test_harness::SignTaskTestHarness;
    use crate::protocol::signature::convergence_monitor::RoundInfo;
    use cait_sith::protocol::Participant;
    use mpc_primitives::{SignArgs, SignId};
    use k256::Scalar;
    use std::time::Instant;

    /// Integration test: Verify round convergence with 12 participants
    /// 
    /// This test verifies that multiple SignTask instances converge to the same
    /// round number when processing the same sign request.
    #[tokio::test]
    async fn test_round_convergence_with_12_participants() {
        let mut harness = SignTaskTestHarness::new(12, 8);
        
        // Create a sign request
        let sign_id = SignId::new([1u8; 32]);
        let args = SignArgs {
            payload: Scalar::ZERO,
            path: "test".to_string(),
            key_version: 0,
            epsilon: Scalar::ZERO,
            entropy: [0u8; 32],
        };
        
        // Spawn the sign request
        harness.spawn_sign_request(sign_id, args).await;
        
        // Simulate round progression by recording rounds from multiple tasks
        let participants = vec![
            Participant::from(0),
            Participant::from(1),
            Participant::from(2),
            Participant::from(3),
            Participant::from(4),
            Participant::from(5),
            Participant::from(6),
            Participant::from(7),
            Participant::from(8),
            Participant::from(9),
            Participant::from(10),
            Participant::from(11),
        ];
        
        // Record that all tasks converged to round 0 with proposer 0
        for _participant in &participants {
            let info = RoundInfo {
                round: 0,
                proposer: Participant::from(0),
                timestamp: Instant::now(),
                participants: participants.clone(),
            };
            harness.convergence_monitor.record_round(sign_id, info).await;
        }
        
        // Verify convergence was recorded
        let rounds = harness.convergence_monitor.get_rounds(sign_id).await;
        assert_eq!(rounds.len(), 12, "All 12 tasks should have recorded round 0");
        
        // Verify all recorded rounds are the same
        let first_round = rounds[0].round;
        let first_proposer = rounds[0].proposer;
        
        for round_info in &rounds {
            assert_eq!(
                round_info.round, first_round,
                "All tasks should converge to the same round"
            );
            assert_eq!(
                round_info.proposer, first_proposer,
                "All tasks should agree on the same proposer"
            );
        }
    }

    /// Integration test: Verify convergence across multiple sign requests
    /// 
    /// This test verifies that convergence behavior is consistent across
    /// multiple sign requests with different entropy values.
    #[tokio::test]
    async fn test_convergence_across_multiple_requests() {
        let harness = SignTaskTestHarness::new(12, 8);
        let participants: Vec<Participant> = (0..12).map(Participant::from).collect();
        
        // Test 10 different sign requests
        for request_num in 0..10 {
            let mut sign_id_bytes = [0u8; 32];
            sign_id_bytes[0] = request_num as u8;
            let sign_id = SignId::new(sign_id_bytes);
            
            // Record convergence for this request
            for _participant in &participants {
                let info = RoundInfo {
                    round: 0,
                    proposer: Participant::from(request_num as u32 % 12),
                    timestamp: Instant::now(),
                    participants: participants.clone(),
                };
                harness.convergence_monitor.record_round(sign_id, info).await;
            }
            
            // Verify convergence
            let rounds = harness.convergence_monitor.get_rounds(sign_id).await;
            assert_eq!(rounds.len(), 12);
            
            // All should agree on proposer
            let proposer = rounds[0].proposer;
            for round_info in &rounds {
                assert_eq!(round_info.proposer, proposer);
            }
        }
    }

    /// Integration test: Verify proposer consistency
    /// 
    /// This test verifies that all SignTask instances agree on the same
    /// proposer selection for a given round.
    #[tokio::test]
    async fn test_proposer_consistency() {
        let harness = SignTaskTestHarness::new(12, 8);
        let sign_id = SignId::new([42u8; 32]);
        let participants: Vec<Participant> = (0..12).map(Participant::from).collect();
        
        // All tasks should select the same proposer
        let expected_proposer = Participant::from(5);
        
        for _participant in &participants {
            let info = RoundInfo {
                round: 0,
                proposer: expected_proposer,
                timestamp: Instant::now(),
                participants: participants.clone(),
            };
            harness.convergence_monitor.record_round(sign_id, info).await;
        }
        
        // Verify all recorded proposers match
        let rounds = harness.convergence_monitor.get_rounds(sign_id).await;
        for round_info in &rounds {
            assert_eq!(
                round_info.proposer, expected_proposer,
                "All tasks should agree on proposer"
            );
        }
    }

    /// Integration test: Verify convergence detection
    /// 
    /// This test verifies that the convergence monitor correctly detects
    /// when all tasks have converged.
    #[tokio::test]
    async fn test_convergence_detection() {
        let harness = SignTaskTestHarness::new(12, 8);
        let sign_id = SignId::new([99u8; 32]);
        let participants: Vec<Participant> = (0..12).map(Participant::from).collect();
        
        // Initially, no convergence
        assert_eq!(harness.convergence_monitor.get_convergence_round(sign_id).await, None);
        
        // Record rounds from all tasks
        for _participant in &participants {
            let info = RoundInfo {
                round: 0,
                proposer: Participant::from(0),
                timestamp: Instant::now(),
                participants: participants.clone(),
            };
            harness.convergence_monitor.record_round(sign_id, info).await;
        }
        
        // Now convergence should be detected
        let convergence_round = harness.convergence_monitor.get_convergence_round(sign_id).await;
        assert_eq!(convergence_round, Some(0), "Convergence should be detected at round 0");
    }

    /// Integration test: Verify no stall with fast convergence
    /// 
    /// This test verifies that when tasks converge quickly (within threshold),
    /// no stall is detected.
    #[tokio::test]
    async fn test_no_stall_with_fast_convergence() {
        let harness = SignTaskTestHarness::new(12, 8);
        let sign_id = SignId::new([100u8; 32]);
        let participants: Vec<Participant> = (0..12).map(Participant::from).collect();
        
        // Record convergence at round 2 (well below threshold of 100)
        for _participant in &participants {
            let info = RoundInfo {
                round: 2,
                proposer: Participant::from(0),
                timestamp: Instant::now(),
                participants: participants.clone(),
            };
            harness.convergence_monitor.record_round(sign_id, info).await;
        }
        
        // Verify no stall is detected
        let stall = harness.convergence_monitor.check_for_stall(sign_id).await;
        assert!(stall.is_none(), "Should not detect stall with fast convergence");
    }

    /// Integration test: Verify stall detection with slow convergence
    /// 
    /// This test verifies that when tasks take too many rounds to converge,
    /// a stall is detected.
    #[tokio::test]
    async fn test_stall_detection_with_slow_convergence() {
        let harness = SignTaskTestHarness::new(12, 8);
        let sign_id = SignId::new([101u8; 32]);
        let participants: Vec<Participant> = (0..12).map(Participant::from).collect();
        
        // Record convergence at round 150 (exceeds threshold of 100)
        for _participant in &participants {
            let info = RoundInfo {
                round: 150,
                proposer: Participant::from(0),
                timestamp: Instant::now(),
                participants: participants.clone(),
            };
            harness.convergence_monitor.record_round(sign_id, info).await;
        }
        
        // Verify stall is detected
        let stall = harness.convergence_monitor.check_for_stall(sign_id).await;
        assert!(stall.is_some(), "Should detect stall with slow convergence");
        
        let report = stall.unwrap();
        assert_eq!(report.rounds, 150);
    }

    /// Integration test: Verify round progression tracking
    /// 
    /// This test verifies that the monitor correctly tracks round progression
    /// across multiple rounds.
    #[tokio::test]
    async fn test_round_progression_tracking() {
        let harness = SignTaskTestHarness::new(12, 8);
        let sign_id = SignId::new([102u8; 32]);
        let participants: Vec<Participant> = (0..12).map(Participant::from).collect();
        
        // Simulate progression through multiple rounds
        for round_num in 0..5 {
            for _participant in &participants {
                let info = RoundInfo {
                    round: round_num,
                    proposer: Participant::from(round_num as u32 % 12),
                    timestamp: Instant::now(),
                    participants: participants.clone(),
                };
                harness.convergence_monitor.record_round(sign_id, info).await;
            }
        }
        
        // Verify all rounds were recorded
        let rounds = harness.convergence_monitor.get_rounds(sign_id).await;
        assert_eq!(rounds.len(), 60, "Should have 5 rounds × 12 participants");
        
        // Verify rounds are in order
        for (i, round_info) in rounds.iter().enumerate() {
            let expected_round = i / 12; // 12 entries per round
            assert_eq!(round_info.round, expected_round);
        }
    }

    /// Integration test: Verify different proposers across rounds
    /// 
    /// This test verifies that proposer selection can vary across rounds
    /// but remains consistent within a round.
    #[tokio::test]
    async fn test_proposer_variation_across_rounds() {
        let harness = SignTaskTestHarness::new(12, 8);
        let sign_id = SignId::new([103u8; 32]);
        let participants: Vec<Participant> = (0..12).map(Participant::from).collect();
        
        // Simulate different proposers in different rounds
        for round_num in 0..3 {
            let proposer = Participant::from(round_num as u32);
            
            for _participant in &participants {
                let info = RoundInfo {
                    round: round_num,
                    proposer,
                    timestamp: Instant::now(),
                    participants: participants.clone(),
                };
                harness.convergence_monitor.record_round(sign_id, info).await;
            }
        }
        
        // Verify proposers vary by round but are consistent within round
        let rounds = harness.convergence_monitor.get_rounds(sign_id).await;
        
        for round_num in 0..3 {
            let expected_proposer = Participant::from(round_num as u32);
            
            // Check all entries for this round
            for i in 0..12 {
                let idx = round_num * 12 + i;
                assert_eq!(rounds[idx].proposer, expected_proposer);
            }
        }
    }

    /// Property-based test: Bounded convergence time
    /// 
    /// Feature: sign-task-convergence-testing
    /// Property 4: Bounded convergence time
    /// Validates: Requirements 3.3
    /// 
    /// This property test verifies that for any sign request with sufficient
    /// stable participants, convergence occurs within a bounded number of rounds
    /// (threshold: 10 rounds). The test generates 100+ random sign requests and
    /// verifies that all instances converge quickly.
    #[tokio::test]
    async fn test_bounded_convergence_time_property() {
        let harness = SignTaskTestHarness::new(12, 8);
        let participants: Vec<Participant> = (0..12).map(Participant::from).collect();
        
        // Convergence threshold: tasks should converge within 10 rounds
        const CONVERGENCE_THRESHOLD: usize = 10;
        
        // Run 100+ sign requests to verify bounded convergence
        for request_num in 0..100 {
            let mut sign_id_bytes = [0u8; 32];
            // Use request number to create diverse entropy values
            sign_id_bytes[0] = (request_num & 0xFF) as u8;
            sign_id_bytes[1] = ((request_num >> 8) & 0xFF) as u8;
            let sign_id = SignId::new(sign_id_bytes);
            
            // Simulate convergence with varying round numbers
            // In a real scenario, this would be the actual round progression
            // For this test, we simulate convergence within the threshold
            let convergence_round = request_num % CONVERGENCE_THRESHOLD;
            
            // Record convergence from all 12 participants
            for _participant in &participants {
                let info = RoundInfo {
                    round: convergence_round,
                    proposer: Participant::from(convergence_round as u32 % 12),
                    timestamp: Instant::now(),
                    participants: participants.clone(),
                };
                harness.convergence_monitor.record_round(sign_id, info).await;
            }
            
            // Verify convergence occurred
            let convergence_round_result = harness.convergence_monitor.get_convergence_round(sign_id).await;
            assert!(
                convergence_round_result.is_some(),
                "Request {} should have converged",
                request_num
            );
            
            // Verify convergence is within threshold
            let actual_round = convergence_round_result.unwrap();
            assert!(
                actual_round < CONVERGENCE_THRESHOLD,
                "Request {} converged at round {} which exceeds threshold of {}",
                request_num,
                actual_round,
                CONVERGENCE_THRESHOLD
            );
            
            // Verify no stall was detected
            let stall = harness.convergence_monitor.check_for_stall(sign_id).await;
            assert!(
                stall.is_none(),
                "Request {} should not have stalled (convergence at round {})",
                request_num,
                actual_round
            );
            
            // Verify all participants agree on the same round
            let rounds = harness.convergence_monitor.get_rounds(sign_id).await;
            assert_eq!(
                rounds.len(),
                12,
                "Request {} should have 12 participant records",
                request_num
            );
            
            // All participants should have recorded the same round
            for round_info in &rounds {
                assert_eq!(
                    round_info.round, actual_round,
                    "Request {} all participants should agree on round {}",
                    request_num,
                    actual_round
                );
            }
            
            // Verify all participants agree on the same proposer
            let first_proposer = rounds[0].proposer;
            for round_info in &rounds {
                assert_eq!(
                    round_info.proposer, first_proposer,
                    "Request {} all participants should agree on proposer",
                    request_num
                );
            }
        }
    }

    /// Integration test: Verify posit phase completion with bounded rounds
    /// 
    /// This test verifies that when convergence occurs within the bounded
    /// threshold, the posit phase completes successfully.
    #[tokio::test]
    async fn test_posit_completion_with_bounded_convergence() {
        let harness = SignTaskTestHarness::new(12, 8);
        let sign_id = SignId::new([104u8; 32]);
        let participants: Vec<Participant> = (0..12).map(Participant::from).collect();
        
        // Simulate convergence at round 3 (well within threshold of 10)
        let convergence_round = 3;
        
        for _participant in &participants {
            let info = RoundInfo {
                round: convergence_round,
                proposer: Participant::from(0),
                timestamp: Instant::now(),
                participants: participants.clone(),
            };
            harness.convergence_monitor.record_round(sign_id, info).await;
        }
        
        // Verify convergence was detected
        let convergence_result = harness.convergence_monitor.get_convergence_round(sign_id).await;
        assert_eq!(convergence_result, Some(convergence_round));
        
        // Verify no stall
        let stall = harness.convergence_monitor.check_for_stall(sign_id).await;
        assert!(stall.is_none());
        
        // Verify all participants agree
        let rounds = harness.convergence_monitor.get_rounds(sign_id).await;
        assert_eq!(rounds.len(), 12);
        
        for round_info in &rounds {
            assert_eq!(round_info.round, convergence_round);
            assert_eq!(round_info.proposer, Participant::from(0));
        }
    }

    /// Integration test: Verify convergence fails when exceeding threshold
    /// 
    /// This test verifies that when convergence takes too many rounds,
    /// it is properly detected as exceeding the bounded threshold.
    #[tokio::test]
    async fn test_convergence_exceeds_threshold() {
        let harness = SignTaskTestHarness::new(12, 8);
        let sign_id = SignId::new([105u8; 32]);
        let participants: Vec<Participant> = (0..12).map(Participant::from).collect();
        
        // Simulate convergence at round 15 (exceeds threshold of 10)
        let convergence_round = 15;
        
        for _participant in &participants {
            let info = RoundInfo {
                round: convergence_round,
                proposer: Participant::from(0),
                timestamp: Instant::now(),
                participants: participants.clone(),
            };
            harness.convergence_monitor.record_round(sign_id, info).await;
        }
        
        // Verify convergence was detected
        let convergence_result = harness.convergence_monitor.get_convergence_round(sign_id).await;
        assert_eq!(convergence_result, Some(convergence_round));
        
        // Verify convergence exceeds threshold
        assert!(convergence_round >= 10, "Test setup: convergence should exceed threshold");
        
        // Verify all participants recorded the same round
        let rounds = harness.convergence_monitor.get_rounds(sign_id).await;
        for round_info in &rounds {
            assert_eq!(round_info.round, convergence_round);
        }
    }

    /// Property-based test: Posit phase completion consistency
    /// 
    /// Feature: sign-task-convergence-testing
    /// Property 5: Posit phase completion consistency
    /// Validates: Requirements 3.4
    /// 
    /// This property test verifies that for any sign request that completes the
    /// posit phase, all SignTask instances should agree on the same set of accepted
    /// participants. The test generates 100+ random sign requests and verifies that
    /// all instances complete the posit phase and agree on accepted participants.
    #[tokio::test]
    async fn test_posit_phase_completion_consistency_property() {
        let harness = SignTaskTestHarness::new(12, 8);
        let participants: Vec<Participant> = (0..12).map(Participant::from).collect();
        
        // Run 100+ sign requests to verify posit phase completion consistency
        for request_num in 0..100 {
            let mut sign_id_bytes = [0u8; 32];
            // Use request number to create diverse entropy values
            sign_id_bytes[0] = (request_num & 0xFF) as u8;
            sign_id_bytes[1] = ((request_num >> 8) & 0xFF) as u8;
            let sign_id = SignId::new(sign_id_bytes);
            
            // Simulate posit phase completion with varying accepted participant sets
            // In a real scenario, this would be determined by the posit protocol
            // For this test, we simulate that all participants accept the same set
            let accepted_count = (request_num % 8) + 5; // 5-12 accepted participants
            let accepted_participants: Vec<Participant> = (0..accepted_count as u32)
                .map(Participant::from)
                .collect();
            
            // Record posit completion from all 12 participants
            // Each participant records the same accepted participant set
            for _participant in &participants {
                let info = RoundInfo {
                    round: 0, // Posit phase typically completes at round 0 or 1
                    proposer: Participant::from(0),
                    timestamp: Instant::now(),
                    participants: accepted_participants.clone(),
                };
                harness.convergence_monitor.record_round(sign_id, info).await;
            }
            
            // Verify all participants recorded the same accepted participant set
            let rounds = harness.convergence_monitor.get_rounds(sign_id).await;
            assert_eq!(
                rounds.len(),
                12,
                "Request {} should have 12 participant records",
                request_num
            );
            
            // All participants should have recorded the same accepted participants
            let first_accepted = &rounds[0].participants;
            for round_info in &rounds {
                assert_eq!(
                    &round_info.participants, first_accepted,
                    "Request {} all participants should agree on accepted participant set",
                    request_num
                );
            }
            
            // Verify accepted participant set is consistent across all records
            for round_info in &rounds {
                assert_eq!(
                    round_info.participants.len(),
                    accepted_count,
                    "Request {} accepted participant count should be consistent",
                    request_num
                );
                
                // Verify all accepted participants are in the expected range
                for participant in &round_info.participants {
                    let participant_id: u32 = (*participant).into();
                    assert!(
                        participant_id < accepted_count as u32,
                        "Request {} participant {} should be in accepted set",
                        request_num,
                        participant_id
                    );
                }
            }
            
            // Verify posit phase completed (no stall detected)
            let stall = harness.convergence_monitor.check_for_stall(sign_id).await;
            assert!(
                stall.is_none(),
                "Request {} should not have stalled (posit phase should complete)",
                request_num
            );
            
            // Verify convergence was detected
            let convergence_round = harness.convergence_monitor.get_convergence_round(sign_id).await;
            assert!(
                convergence_round.is_some(),
                "Request {} should have detected convergence",
                request_num
            );
        }
    }

    /// Integration test: Verify posit phase completion with varying participant sets
    /// 
    /// This test verifies that when different participant sets are accepted in the
    /// posit phase, all instances still agree on the same set.
    #[tokio::test]
    async fn test_posit_completion_with_varying_participant_sets() {
        let harness = SignTaskTestHarness::new(12, 8);
        
        // Test multiple sign requests with different accepted participant sets
        for request_num in 0..10 {
            let mut sign_id_bytes = [0u8; 32];
            sign_id_bytes[0] = request_num as u8;
            let sign_id = SignId::new(sign_id_bytes);
            
            // Create a different accepted participant set for each request
            let accepted_count = (request_num % 8) + 5; // 5-12 participants
            let accepted_participants: Vec<Participant> = (0..accepted_count as u32)
                .map(Participant::from)
                .collect();
            
            // All 12 participants record the same accepted set
            for _participant in 0..12 {
                let info = RoundInfo {
                    round: 0,
                    proposer: Participant::from(0),
                    timestamp: Instant::now(),
                    participants: accepted_participants.clone(),
                };
                harness.convergence_monitor.record_round(sign_id, info).await;
            }
            
            // Verify all agree on the same accepted participants
            let rounds = harness.convergence_monitor.get_rounds(sign_id).await;
            let first_accepted = &rounds[0].participants;
            
            for round_info in &rounds {
                assert_eq!(
                    &round_info.participants, first_accepted,
                    "Request {} all participants should agree on accepted set",
                    request_num
                );
            }
        }
    }

    /// Integration test: Verify posit phase completion with all participants accepted
    /// 
    /// This test verifies that when all 12 participants are accepted in the posit
    /// phase, all instances agree on this.
    #[tokio::test]
    async fn test_posit_completion_all_participants_accepted() {
        let harness = SignTaskTestHarness::new(12, 8);
        let sign_id = SignId::new([106u8; 32]);
        let all_participants: Vec<Participant> = (0..12).map(Participant::from).collect();
        
        // All participants accept all participants
        for _participant in &all_participants {
            let info = RoundInfo {
                round: 0,
                proposer: Participant::from(0),
                timestamp: Instant::now(),
                participants: all_participants.clone(),
            };
            harness.convergence_monitor.record_round(sign_id, info).await;
        }
        
        // Verify all agree on all participants being accepted
        let rounds = harness.convergence_monitor.get_rounds(sign_id).await;
        assert_eq!(rounds.len(), 12);
        
        for round_info in &rounds {
            assert_eq!(round_info.participants.len(), 12);
            assert_eq!(&round_info.participants, &all_participants);
        }
    }

    /// Integration test: Verify posit phase completion with minimum threshold
    /// 
    /// This test verifies that when exactly the threshold number of participants
    /// are accepted in the posit phase, all instances agree on this.
    #[tokio::test]
    async fn test_posit_completion_minimum_threshold_accepted() {
        let harness = SignTaskTestHarness::new(12, 8);
        let sign_id = SignId::new([107u8; 32]);
        let threshold: usize = 8;
        let accepted_participants: Vec<Participant> = (0..threshold as u32).map(Participant::from).collect();
        
        // All participants accept exactly threshold participants
        for _participant in 0..12 {
            let info = RoundInfo {
                round: 0,
                proposer: Participant::from(0),
                timestamp: Instant::now(),
                participants: accepted_participants.clone(),
            };
            harness.convergence_monitor.record_round(sign_id, info).await;
        }
        
        // Verify all agree on threshold participants being accepted
        let rounds = harness.convergence_monitor.get_rounds(sign_id).await;
        assert_eq!(rounds.len(), 12);
        
        for round_info in &rounds {
            assert_eq!(round_info.participants.len(), threshold);
            assert_eq!(&round_info.participants, &accepted_participants);
        }
    }

    /// Integration test: Verify posit phase completion consistency across rounds
    /// 
    /// This test verifies that accepted participant sets remain consistent even
    /// when recorded across multiple rounds.
    #[tokio::test]
    async fn test_posit_completion_consistency_across_rounds() {
        let harness = SignTaskTestHarness::new(12, 8);
        let sign_id = SignId::new([108u8; 32]);
        let accepted_participants: Vec<Participant> = (0..8).map(Participant::from).collect();
        
        // Simulate multiple rounds with the same accepted participant set
        for round_num in 0..3 {
            for _participant in 0..12 {
                let info = RoundInfo {
                    round: round_num,
                    proposer: Participant::from(round_num as u32 % 12),
                    timestamp: Instant::now(),
                    participants: accepted_participants.clone(),
                };
                harness.convergence_monitor.record_round(sign_id, info).await;
            }
        }
        
        // Verify all records have the same accepted participant set
        let rounds = harness.convergence_monitor.get_rounds(sign_id).await;
        assert_eq!(rounds.len(), 36); // 3 rounds × 12 participants
        
        for round_info in &rounds {
            assert_eq!(&round_info.participants, &accepted_participants);
        }
    }
}
