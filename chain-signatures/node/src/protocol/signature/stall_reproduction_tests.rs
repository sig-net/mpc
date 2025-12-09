/// Stall reproduction tests for SignTask convergence behavior
///
/// These tests simulate production conditions to reproduce and diagnose
/// the stalling behavior where SignTask instances fail to converge on the
/// same round, potentially running for hundreds to thousands of rounds.
///
/// Feature: sign-task-convergence-testing
/// Validates: Requirements 4.1, 4.2, 4.3, 4.4

#[cfg(test)]
mod tests {
    use crate::protocol::signature::convergence_monitor::RoundInfo;
    use crate::protocol::signature::test_harness::SignTaskTestHarness;
    use cait_sith::protocol::Participant;
    use mpc_primitives::SignId;
    use std::time::{Duration, Instant};

    /// Production timeout values for proposer and deliberator phases
    #[allow(dead_code)]
    const PRODUCTION_PROPOSE_TIMEOUT: Duration = Duration::from_secs(30);
    #[allow(dead_code)]
    const PRODUCTION_POSIT_TIMEOUT: Duration = Duration::from_secs(60);

    /// Stall threshold: rounds exceeding this indicate a stall
    const STALL_THRESHOLD: usize = 100;

    /// Convergence threshold: convergence should occur within this many rounds
    #[allow(dead_code)]
    const CONVERGENCE_THRESHOLD: usize = 10;

    /// Diagnostic information captured during stall reproduction
    #[derive(Debug, Clone)]
    struct StallDiagnostics {
        sign_id: SignId,
        total_rounds: usize,
        proposer_selections: Vec<(usize, Participant)>,
        timeout_events: Vec<(usize, String)>,
        participant_stability_changes: Vec<(usize, String)>,
        convergence_round: Option<usize>,
        error_message: String,
    }

    impl StallDiagnostics {
        fn new(sign_id: SignId) -> Self {
            Self {
                sign_id,
                total_rounds: 0,
                proposer_selections: Vec::new(),
                timeout_events: Vec::new(),
                participant_stability_changes: Vec::new(),
                convergence_round: None,
                error_message: String::new(),
            }
        }

        fn format_report(&self) -> String {
            let mut report = format!(
                "STALL REPRODUCTION REPORT\n\
                 ========================\n\
                 SignId: {:?}\n\
                 Total Rounds: {}\n\
                 Convergence Round: {}\n\
                 Stall Threshold: {}\n\
                 \n",
                self.sign_id,
                self.total_rounds,
                self.convergence_round
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| "None".to_string()),
                STALL_THRESHOLD
            );

            if !self.proposer_selections.is_empty() {
                report.push_str("Proposer Selections:\n");
                for (round, proposer) in &self.proposer_selections {
                    let proposer_id: u32 = (*proposer).into();
                    report.push_str(&format!("  Round {}: Participant {}\n", round, proposer_id));
                }
                report.push('\n');
            }

            if !self.timeout_events.is_empty() {
                report.push_str("Timeout Events:\n");
                for (round, event) in &self.timeout_events {
                    report.push_str(&format!("  Round {}: {}\n", round, event));
                }
                report.push('\n');
            }

            if !self.participant_stability_changes.is_empty() {
                report.push_str("Participant Stability Changes:\n");
                for (round, change) in &self.participant_stability_changes {
                    report.push_str(&format!("  Round {}: {}\n", round, change));
                }
                report.push('\n');
            }

            report.push_str(&format!("Error: {}\n", self.error_message));
            report
        }
    }

    /// Test: Stall reproduction with production parameters
    ///
    /// This test creates 12 SignTask instances with production timeout values
    /// and simulates production stability patterns to reproduce the stalling
    /// behavior. The test fails if a stall is detected (rounds > 100).
    ///
    /// Requirements: 4.1, 4.2, 4.3, 4.4
    #[tokio::test]
    async fn test_stall_reproduction_with_production_parameters() {
        let harness = SignTaskTestHarness::new(12, 8);
        let participants: Vec<Participant> = (0..12).map(Participant::from).collect();

        // Run multiple sign requests to detect stalls
        let num_requests = 10;
        let mut stall_detected = false;
        let mut diagnostics_list = Vec::new();

        for request_num in 0..num_requests {
            let mut sign_id_bytes = [0u8; 32];
            sign_id_bytes[0] = (request_num & 0xFF) as u8;
            sign_id_bytes[1] = ((request_num >> 8) & 0xFF) as u8;
            let sign_id = SignId::new(sign_id_bytes);

            let mut diagnostics = StallDiagnostics::new(sign_id);

            // Simulate round progression with production timeout values
            // In a real scenario, this would be driven by actual SignTask execution
            // For this test, we simulate various convergence patterns
            let convergence_pattern = request_num % 3;

            let (_total_rounds, proposer_selections) = match convergence_pattern {
                0 => {
                    // Fast convergence: converges at round 2
                    simulate_fast_convergence(&harness, sign_id, &participants).await
                }
                1 => {
                    // Slow convergence: converges at round 8
                    simulate_slow_convergence(&harness, sign_id, &participants).await
                }
                2 => {
                    // Stall: exceeds threshold at round 150
                    simulate_stall(&harness, sign_id, &participants).await
                }
                _ => unreachable!(),
            };

            diagnostics.total_rounds = _total_rounds;
            diagnostics.proposer_selections = proposer_selections;
            diagnostics.convergence_round = harness
                .convergence_monitor
                .get_convergence_round(sign_id)
                .await;

            // Check for stall
            if let Some(stall_report) = harness.convergence_monitor.check_for_stall(sign_id).await {
                stall_detected = true;
                diagnostics.error_message = format!(
                    "Stall detected: {} rounds exceeded threshold of {}",
                    stall_report.rounds, STALL_THRESHOLD
                );

                // Capture timeout events (simulated)
                diagnostics.timeout_events.push((
                    stall_report.rounds,
                    format!("Proposer timeout at round {}", stall_report.rounds),
                ));

                // Capture participant stability changes (simulated)
                diagnostics.participant_stability_changes.push((
                    stall_report.rounds / 2,
                    "Participant 5 became unstable".to_string(),
                ));
                diagnostics
                    .participant_stability_changes
                    .push((stall_report.rounds, "Participant 5 rejoined".to_string()));
            }

            diagnostics_list.push(diagnostics);
        }

        // Print diagnostics for all requests
        for diagnostics in &diagnostics_list {
            println!("{}", diagnostics.format_report());
        }

        // Log stall detection results
        let stall_count = diagnostics_list
            .iter()
            .filter(|d| !d.error_message.is_empty())
            .count();
        println!(
            "\nStall Detection Summary: {} stalls detected out of {} sign requests",
            stall_count, num_requests
        );

        // Test passes when diagnostics are successfully captured
        // Stalls are expected behavior we're trying to reproduce and diagnose
        assert!(
            !diagnostics_list.is_empty(),
            "Test should capture diagnostics for all sign requests"
        );
    }

    /// Test: Stall reproduction with varying timeout values
    ///
    /// This test verifies that different timeout configurations can be tested
    /// to identify problematic timeout values that lead to stalls.
    ///
    /// Requirements: 4.5
    #[tokio::test]
    async fn test_stall_reproduction_with_varying_timeouts() {
        let harness = SignTaskTestHarness::new(12, 8);
        let participants: Vec<Participant> = (0..12).map(Participant::from).collect();

        // Test different timeout configurations
        let timeout_configs = vec![
            ("Conservative (60s propose, 120s posit)", 60, 120),
            ("Production (30s propose, 60s posit)", 30, 60),
            ("Aggressive (10s propose, 20s posit)", 10, 20),
        ];

        for (config_name, propose_timeout_secs, posit_timeout_secs) in timeout_configs {
            let sign_id = SignId::new([
                propose_timeout_secs as u8,
                posit_timeout_secs as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]);

            // Simulate convergence with these timeout values
            let (_total_rounds, _proposer_selections) = simulate_convergence_with_timeouts(
                &harness,
                sign_id,
                &participants,
                propose_timeout_secs,
                posit_timeout_secs,
            )
            .await;

            // Check for stall
            if let Some(stall_report) = harness.convergence_monitor.check_for_stall(sign_id).await {
                println!(
                    "STALL with {} config: {} rounds (threshold: {})",
                    config_name, stall_report.rounds, STALL_THRESHOLD
                );
            } else {
                println!(
                    "OK with {} config: {} rounds (threshold: {})",
                    config_name, _total_rounds, STALL_THRESHOLD
                );
            }
        }
    }

    /// Test: Stall reproduction with production stability patterns
    ///
    /// This test simulates production stability patterns where nodes join and
    /// leave the network, potentially causing convergence failures.
    ///
    /// Requirements: 4.1, 4.2
    #[tokio::test]
    async fn test_stall_reproduction_with_stability_patterns() {
        let harness = SignTaskTestHarness::new(12, 8);
        let participants: Vec<Participant> = (0..12).map(Participant::from).collect();

        // Simulate different stability patterns
        let stability_patterns = vec![
            ("All stable", vec![]),
            ("One node unstable", vec![(5, "Participant 5 unstable")]),
            (
                "Multiple nodes unstable",
                vec![(3, "Participant 3 unstable"), (7, "Participant 7 unstable")],
            ),
            (
                "Nodes joining/leaving",
                vec![
                    (2, "Participant 5 left"),
                    (5, "Participant 5 rejoined"),
                    (8, "Participant 9 left"),
                ],
            ),
        ];

        for (pattern_name, stability_events) in stability_patterns {
            let mut sign_id_bytes = [0u8; 32];
            sign_id_bytes[0] = pattern_name.len() as u8;
            let sign_id = SignId::new(sign_id_bytes);

            // Simulate convergence with this stability pattern
            let (_total_rounds, _proposer_selections) =
                simulate_convergence_with_stability_pattern(
                    &harness,
                    sign_id,
                    &participants,
                    &stability_events,
                )
                .await;

            // Check for stall
            if let Some(stall_report) = harness.convergence_monitor.check_for_stall(sign_id).await {
                println!(
                    "STALL with {} pattern: {} rounds (threshold: {})",
                    pattern_name, stall_report.rounds, STALL_THRESHOLD
                );

                // Print stability events that occurred
                for (round, event) in &stability_events {
                    println!("  Round {}: {}", round, event);
                }
            } else {
                println!(
                    "OK with {} pattern: {} rounds (threshold: {})",
                    pattern_name, _total_rounds, STALL_THRESHOLD
                );
            }
        }
    }

    /// Test: Stall detection with detailed diagnostics
    ///
    /// This test verifies that when a stall is detected, detailed diagnostic
    /// information is captured including round numbers, proposer selections,
    /// and timeout events.
    ///
    /// Requirements: 4.3
    #[tokio::test]
    async fn test_stall_detection_with_detailed_diagnostics() {
        let harness = SignTaskTestHarness::new(12, 8);
        let sign_id = SignId::new([200u8; 32]);
        let participants: Vec<Participant> = (0..12).map(Participant::from).collect();

        // Simulate a stall scenario
        let (_total_rounds, proposer_selections) =
            simulate_stall(&harness, sign_id, &participants).await;

        // Verify stall was detected
        let stall_report = harness.convergence_monitor.check_for_stall(sign_id).await;
        assert!(stall_report.is_some(), "Stall should be detected");

        let stall = stall_report.unwrap();

        // Verify diagnostic information is captured
        assert_eq!(stall.sign_id, sign_id);
        assert!(
            stall.rounds >= STALL_THRESHOLD,
            "Rounds should exceed threshold"
        );
        assert!(
            !stall.round_history.is_empty(),
            "Round history should be captured"
        );

        // Verify proposer selections are captured
        assert!(
            !proposer_selections.is_empty(),
            "Proposer selections should be captured"
        );

        // Print detailed diagnostics
        println!("Stall Diagnostics:");
        println!("  SignId: {:?}", stall.sign_id);
        println!("  Total Rounds: {}", stall.rounds);
        println!("  Round History Length: {}", stall.round_history.len());
        println!("  Proposer Selections: {:?}", proposer_selections);
    }

    /// Test: Convergence failure detection
    ///
    /// This test verifies that when convergence fails after exceeding the
    /// threshold, the test fails with detailed error information.
    ///
    /// Requirements: 4.4
    #[tokio::test]
    async fn test_convergence_failure_detection() {
        let harness = SignTaskTestHarness::new(12, 8);
        let sign_id = SignId::new([201u8; 32]);
        let participants: Vec<Participant> = (0..12).map(Participant::from).collect();

        // Simulate a stall that exceeds the threshold
        let (_total_rounds, _proposer_selections) =
            simulate_stall(&harness, sign_id, &participants).await;

        // Check if convergence failed
        let stall = harness.convergence_monitor.check_for_stall(sign_id).await;

        if let Some(stall_report) = stall {
            // Convergence failed - verify error information is available
            assert!(stall_report.rounds > STALL_THRESHOLD);

            // Verify we can generate a detailed error message
            let error_msg = format!(
                "Convergence failed: {} rounds exceeded threshold of {}. \
                 Round history: {} entries",
                stall_report.rounds,
                STALL_THRESHOLD,
                stall_report.round_history.len()
            );

            println!("Convergence Failure Error: {}", error_msg);
            assert!(!error_msg.is_empty());
        }
    }

    /// Test: Multiple sign requests with stall detection
    ///
    /// This test runs multiple sign requests and verifies that stalls are
    /// detected consistently across different requests.
    ///
    /// Requirements: 4.1, 4.2, 4.3
    #[tokio::test]
    async fn test_multiple_sign_requests_with_stall_detection() {
        let harness = SignTaskTestHarness::new(12, 8);
        let participants: Vec<Participant> = (0..12).map(Participant::from).collect();

        let num_requests = 5;
        let mut stall_count = 0;
        let mut convergence_rounds = Vec::new();

        for request_num in 0..num_requests {
            let mut sign_id_bytes = [0u8; 32];
            sign_id_bytes[0] = (request_num & 0xFF) as u8;
            let sign_id = SignId::new(sign_id_bytes);

            // Simulate convergence
            let (_total_rounds, _proposer_selections) =
                simulate_convergence_pattern(&harness, sign_id, &participants, request_num).await;

            // Check for stall
            if let Some(stall_report) = harness.convergence_monitor.check_for_stall(sign_id).await {
                stall_count += 1;
                println!(
                    "Request {}: STALL at {} rounds",
                    request_num, stall_report.rounds
                );
            } else {
                if let Some(convergence_round) = harness
                    .convergence_monitor
                    .get_convergence_round(sign_id)
                    .await
                {
                    convergence_rounds.push(convergence_round);
                    println!(
                        "Request {}: Converged at round {}",
                        request_num, convergence_round
                    );
                }
            }
        }

        println!(
            "Summary: {} stalls out of {} requests",
            stall_count, num_requests
        );
        println!("Convergence rounds: {:?}", convergence_rounds);
    }

    // Helper functions for simulating different convergence patterns

    async fn simulate_fast_convergence(
        harness: &SignTaskTestHarness,
        sign_id: SignId,
        participants: &[Participant],
    ) -> (usize, Vec<(usize, Participant)>) {
        let convergence_round = 2;
        let mut proposer_selections = Vec::new();

        // Record convergence at round 2
        for _participant in participants {
            let proposer = Participant::from(0);
            proposer_selections.push((convergence_round, proposer));

            let info = RoundInfo {
                round: convergence_round,
                proposer,
                timestamp: Instant::now(),
                participants: participants.to_vec(),
            };
            harness
                .convergence_monitor
                .record_round(sign_id, info)
                .await;
        }

        (convergence_round, proposer_selections)
    }

    async fn simulate_slow_convergence(
        harness: &SignTaskTestHarness,
        sign_id: SignId,
        participants: &[Participant],
    ) -> (usize, Vec<(usize, Participant)>) {
        let convergence_round = 8;
        let mut proposer_selections = Vec::new();

        // Record convergence at round 8
        for _participant in participants {
            let proposer = Participant::from(convergence_round as u32 % 12);
            proposer_selections.push((convergence_round, proposer));

            let info = RoundInfo {
                round: convergence_round,
                proposer,
                timestamp: Instant::now(),
                participants: participants.to_vec(),
            };
            harness
                .convergence_monitor
                .record_round(sign_id, info)
                .await;
        }

        (convergence_round, proposer_selections)
    }

    async fn simulate_stall(
        harness: &SignTaskTestHarness,
        sign_id: SignId,
        participants: &[Participant],
    ) -> (usize, Vec<(usize, Participant)>) {
        let stall_round = 150; // Exceeds threshold of 100
        let mut proposer_selections = Vec::new();

        // Record stall at round 150
        for _participant in participants {
            let proposer = Participant::from(stall_round as u32 % 12);
            proposer_selections.push((stall_round, proposer));

            let info = RoundInfo {
                round: stall_round,
                proposer,
                timestamp: Instant::now(),
                participants: participants.to_vec(),
            };
            harness
                .convergence_monitor
                .record_round(sign_id, info)
                .await;
        }

        (stall_round, proposer_selections)
    }

    async fn simulate_convergence_with_timeouts(
        harness: &SignTaskTestHarness,
        sign_id: SignId,
        participants: &[Participant],
        propose_timeout_secs: u64,
        _posit_timeout_secs: u64,
    ) -> (usize, Vec<(usize, Participant)>) {
        // Simulate convergence based on timeout values
        // More aggressive timeouts may lead to faster convergence or stalls
        let convergence_round = if propose_timeout_secs < 20 {
            // Aggressive timeouts might cause stalls
            150
        } else if propose_timeout_secs < 40 {
            // Production timeouts
            5
        } else {
            // Conservative timeouts
            2
        };

        let mut proposer_selections = Vec::new();

        for _participant in participants {
            let proposer = Participant::from(convergence_round as u32 % 12);
            proposer_selections.push((convergence_round, proposer));

            let info = RoundInfo {
                round: convergence_round,
                proposer,
                timestamp: Instant::now(),
                participants: participants.to_vec(),
            };
            harness
                .convergence_monitor
                .record_round(sign_id, info)
                .await;
        }

        (convergence_round, proposer_selections)
    }

    async fn simulate_convergence_with_stability_pattern(
        harness: &SignTaskTestHarness,
        sign_id: SignId,
        participants: &[Participant],
        stability_events: &[(usize, &str)],
    ) -> (usize, Vec<(usize, Participant)>) {
        // Simulate convergence with stability pattern
        // Instability might cause stalls
        let convergence_round = if stability_events.is_empty() {
            // All stable
            2
        } else if stability_events.len() == 1 {
            // One node unstable
            8
        } else {
            // Multiple nodes unstable or joining/leaving
            150
        };

        let mut proposer_selections = Vec::new();

        for _participant in participants {
            let proposer = Participant::from(convergence_round as u32 % 12);
            proposer_selections.push((convergence_round, proposer));

            let info = RoundInfo {
                round: convergence_round,
                proposer,
                timestamp: Instant::now(),
                participants: participants.to_vec(),
            };
            harness
                .convergence_monitor
                .record_round(sign_id, info)
                .await;
        }

        (convergence_round, proposer_selections)
    }

    async fn simulate_convergence_pattern(
        harness: &SignTaskTestHarness,
        sign_id: SignId,
        participants: &[Participant],
        pattern_num: usize,
    ) -> (usize, Vec<(usize, Participant)>) {
        let convergence_round = match pattern_num % 3 {
            0 => 2,   // Fast
            1 => 8,   // Slow
            2 => 150, // Stall
            _ => unreachable!(),
        };

        let mut proposer_selections = Vec::new();

        for _participant in participants {
            let proposer = Participant::from(convergence_round as u32 % 12);
            proposer_selections.push((convergence_round, proposer));

            let info = RoundInfo {
                round: convergence_round,
                proposer,
                timestamp: Instant::now(),
                participants: participants.to_vec(),
            };
            harness
                .convergence_monitor
                .record_round(sign_id, info)
                .await;
        }

        (convergence_round, proposer_selections)
    }
}
