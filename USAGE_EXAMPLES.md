// Example: How SignatureTask is Used
// This file demonstrates the usage patterns of the new consolidated task

use crate::protocol::signature::{SignatureTask, SignatureTaskPositAction, SignRequest, SignatureGenerator};
use cate::protocol::posit::PositAction;
use cait_sith::protocol::Participant;
use mpc_primitives::SignId;

/// Example 1: Creating a new signature task
fn example_create_task() {
    let me = Participant::from(0);
    let sign_id = SignId { /* ... */ };
    let presignature_id = 12345;
    let request = SignRequest { /* ... */ };
    let participants = vec![
        Participant::from(0),
        Participant::from(1),
        Participant::from(2),
        Participant::from(3),
    ];
    let threshold = 3;
    let timeout_total = Duration::from_secs(120);

    // Create task - starts in Posit phase
    let mut task = SignatureTask::new(
        me,
        sign_id,
        presignature_id,
        request,
        participants,
        threshold,
        timeout_total,
    );

    assert!(task.in_posit_phase());
    assert!(!task.is_complete());
}

/// Example 2: Processing posit actions (votes)
fn example_process_votes() {
    let mut task = /* created task */;
    let threshold = 3;

    // P1 votes accept
    let action = PositAction::Accept;
    let from = Participant::from(1);
    match task.process_posit_action(from, &action) {
        Some(SignatureTaskPositAction::Waiting) => {
            println!("Still waiting for more votes");
        }
        Some(SignatureTaskPositAction::Ready { participants, proposer }) => {
            println!("Ready to generate signature with {:?}", participants);
            // Can now start generation
        }
        Some(SignatureTaskPositAction::Reject) => {
            println!("Posit rejected");
        }
        None => println!("Vote processed, no action needed"),
    }
}

/// Example 3: Handling rejection
fn example_rejection_scenario() {
    let mut task = /* created task */;

    // P2 rejects
    let _ = task.process_posit_action(Participant::from(2), &PositAction::Reject);

    // P3 rejects
    let result = task.process_posit_action(Participant::from(3), &PositAction::Reject);

    match result {
        Some(SignatureTaskPositAction::Reject) => {
            assert!(task.is_complete());
            assert!(task.result().unwrap().is_err());
        }
        _ => panic!("Expected rejection"),
    }
}

/// Example 4: Transitioning to generation
fn example_transition_to_generation() {
    let mut task = /* created task with enough accepts */;

    // Create generator (normally done by caller)
    let generator = Box::new(/* SignatureGenerator created */);

    // Transition to Generating phase
    task.start_generation(generator);

    assert!(task.in_generating_phase());
    assert!(!task.in_posit_phase());
}

/// Example 5: Completing the task
fn example_task_completion() {
    let mut task = /* created task */;

    // Simulate successful signature generation
    task.complete(Ok(()));

    assert!(task.is_complete());
    assert_eq!(task.result(), Some(Ok(())));
}

/// Example 6: Handling timeout during posit phase
fn example_posit_timeout() {
    let mut task = /* created task */;
    let threshold = 3;

    // Only 2 participants accept before timeout
    let _ = task.process_posit_action(Participant::from(1), &PositAction::Accept);
    let _ = task.process_posit_action(Participant::from(2), &PositAction::Accept);

    // Timeout occurs
    match task.handle_posit_expiration(threshold) {
        Some(SignatureTaskPositAction::Reject) => {
            // Task aborted due to insufficient accepts
            assert!(task.is_complete());
            println!("Posit timeout without enough accepts");
        }
        Some(SignatureTaskPositAction::Ready { .. }) => {
            // Task can proceed (if we had enough accepts)
            println!("Despite timeout, we had enough accepts");
        }
        _ => panic!("Unexpected result"),
    }
}

/// Example 7: Using tasks in a spawner
async fn example_spawner_integration() {
    use std::collections::HashMap;

    // Task collection in spawner
    let mut tasks: HashMap<(SignId, u64), SignatureTask> = HashMap::new();

    // When sign request arrives:
    let request = SignRequest { /* ... */ };
    let participants = vec![/* participants */];
    let task = SignatureTask::new(
        me,
        sign_id,
        presignature_id,
        request,
        participants,
        3, // threshold
        Duration::from_secs(120),
    );
    tasks.insert((sign_id, presignature_id), task);

    // When posit message arrives:
    if let Some(task) = tasks.get_mut(&(sign_id, presignature_id)) {
        match task.process_posit_action(from, &action) {
            Some(SignatureTaskPositAction::Ready { participants, proposer }) => {
                // Start generation phase
                let generator = Box::new(/* create generator */);
                task.start_generation(generator);
            }
            _ => {}
        }
    }

    // Check for completion:
    let mut completed = Vec::new();
    for ((sig_id, pre_id), task) in tasks.iter_mut() {
        if task.is_complete() {
            if let Some(result) = task.result() {
                match result {
                    Ok(()) => println!("Signature generated successfully"),
                    Err(_) => println!("Signature generation failed"),
                }
            }
            completed.push((*sig_id, *pre_id));
        }
    }

    // Cleanup
    for key in completed {
        tasks.remove(&key);
    }
}

/// Example 8: Phase checks
fn example_phase_checks() {
    let mut task = /* created task */;

    // In Posit phase initially
    assert!(task.in_posit_phase());
    assert!(!task.in_generating_phase());
    assert!(!task.is_complete());

    // Transition to generating
    task.start_generation(Box::new(/* generator */));
    assert!(!task.in_posit_phase());
    assert!(task.in_generating_phase());
    assert!(!task.is_complete());

    // Complete
    task.complete(Ok(()));
    assert!(!task.in_posit_phase());
    assert!(!task.in_generating_phase());
    assert!(task.is_complete());
}

/// Example 9: Timeout checking
fn example_timeout_checks() {
    let mut task = SignatureTask::new(
        me,
        sign_id,
        presignature_id,
        request,
        participants,
        3,
        Duration::from_millis(100),
    );

    // Check after some time
    std::thread::sleep(Duration::from_millis(150));

    assert!(task.timeout_total());

    // Can trigger expiration handling
    if task.timeout_total() && task.in_posit_phase() {
        task.handle_posit_expiration(3);
    }
}

/// Example 10: Full lifecycle with status checks
async fn example_full_lifecycle() {
    let mut task = SignatureTask::new(
        Participant::from(0),
        sign_id,
        presignature_id,
        request,
        participants,
        3,
        Duration::from_secs(120),
    );

    // Phase 1: Posit
    println!("Phase: {}", if task.in_posit_phase() { "Posit" } else { "Other" });

    let _ = task.process_posit_action(Participant::from(1), &PositAction::Accept);
    let _ = task.process_posit_action(Participant::from(2), &PositAction::Accept);
    let result = task.process_posit_action(Participant::from(3), &PositAction::Accept);

    if let Some(SignatureTaskPositAction::Ready { participants, proposer }) = result {
        println!("Transitioning to generation with {:?}", participants);

        // Phase 2: Generating
        let generator = Box::new(/* create generator */);
        task.start_generation(generator);

        // Simulate generation work...
        println!("Phase: {}", if task.in_generating_phase() { "Generating" } else { "Other" });

        // Phase 3: Complete
        task.complete(Ok(()));

        println!("Phase: Complete");
        println!("Result: {:?}", task.result());
    }
}

// NOTE: These are conceptual examples showing the API design.
// Actual integration will require proper message routing and
// coordination with the SignatureSpawner's event loop.
