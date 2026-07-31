pub mod common;
use common::init_env;

use serde_json::json;

#[tokio::test]
async fn test_join() -> anyhow::Result<()> {
    let (worker, contract, accounts, _) = init_env().await;

    let alice = worker.dev_create_account().await?;

    let execution = alice
        .call(contract.id(), "join")
        .args_json(json!({
            "url": "127.0.0.1",
            "cipher_pk": vec![1u8; 32],
            "sign_pk": "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
        }))
        .transact()
        .await?;

    assert!(execution.is_success());

    let state: mpc_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    match state {
        mpc_contract::ProtocolContractState::Running(r) => {
            assert!(r.candidates.contains_key(alice.id()));
        }
        _ => panic!("should be in running state"),
    };

    // try join again, still ok, because not become participant yet
    let execution = alice
        .call(contract.id(), "join")
        .args_json(json!({
            "url": "127.0.0.1",
            "cipher_pk": vec![1u8; 32],
            "sign_pk": "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
        }))
        .transact()
        .await?;
    assert!(execution.is_success());

    // participant try join again, should fail
    let execution = accounts[0]
        .call(contract.id(), "join")
        .args_json(json!({
            "url": "127.0.0.1",
            "cipher_pk": vec![1u8; 32],
            "sign_pk": "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
        }))
        .transact()
        .await?;
    assert!(execution.is_failure());
    Ok(())
}

#[tokio::test]
async fn test_remove_candidacy() -> anyhow::Result<()> {
    let (worker, contract, accounts, _) = init_env().await;

    // Create a new account to join as candidate
    let alice = worker.dev_create_account().await?;
    let execution = alice
        .call(contract.id(), "join")
        .args_json(json!({
            "url": "127.0.0.1",
            "cipher_pk": vec![1u8; 32],
            "sign_pk": "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
        }))
        .transact()
        .await?;
    assert!(execution.is_success());

    // Verify alice is in candidates
    let state: mpc_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    match state {
        mpc_contract::ProtocolContractState::Running(r) => {
            assert!(r.candidates.contains_key(alice.id()));
        }
        _ => panic!("should be in running state"),
    };

    // Vote for alice to join
    let execution = accounts[0]
        .call(contract.id(), "vote_join")
        .args_json(json!({
            "candidate": alice.id()
        }))
        .transact()
        .await?;
    assert!(execution.is_success());

    // Verify votes exist for alice
    let state: mpc_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    match state {
        mpc_contract::ProtocolContractState::Running(state) => {
            assert!(state.candidates.contains_key(alice.id()));
            assert!(state.join_votes.contains_key(alice.id()));
            assert_eq!(state.join_votes.votes.get(alice.id()).unwrap().len(), 1);
        }
        _ => panic!("should be in running state"),
    };

    // Alice revokes her join request
    let execution = alice
        .call(contract.id(), "remove_candidacy")
        .transact()
        .await?;
    assert!(execution.is_success());

    // Verify alice is no longer in candidates and votes are cleaned up
    let state: mpc_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    match state {
        mpc_contract::ProtocolContractState::Running(r) => {
            assert!(!r.candidates.contains_key(alice.id()));
            assert!(!r.join_votes.contains_key(alice.id()));
        }
        _ => panic!("should be in running state"),
    };

    // Try to revoke again, should fail (not a candidate anymore)
    let execution = alice
        .call(contract.id(), "remove_candidacy")
        .transact()
        .await?;
    assert!(execution.is_failure());

    // Random account tries to revoke (was never a candidate)
    let bob = worker.dev_create_account().await?;
    let execution = bob
        .call(contract.id(), "remove_candidacy")
        .transact()
        .await?;
    assert!(execution.is_failure());

    // Participant tries to revoke (not a candidate, is a participant)
    let execution = accounts[0]
        .call(contract.id(), "remove_candidacy")
        .transact()
        .await?;
    assert!(execution.is_failure());

    Ok(())
}

#[tokio::test]
async fn test_vote_join() -> anyhow::Result<()> {
    let (worker, contract, accounts, _) = init_env().await;

    let alice = worker.dev_create_account().await?;
    let execution = alice
        .call(contract.id(), "join")
        .args_json(json!({
            "url": "127.0.0.1",
            "cipher_pk": vec![1u8; 32],
            "sign_pk": "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
        }))
        .transact()
        .await?;
    assert!(execution.is_success());

    // vote by first candidate should success, but vote not pass threshold yet
    let execution = accounts[0]
        .call(contract.id(), "vote_join")
        .args_json(json!({
            "candidate": alice.id()
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let vote_pass: bool = execution.json().unwrap();
    assert!(!vote_pass);

    // vote by candidate itself should fail
    let execution = alice
        .call(contract.id(), "vote_join")
        .args_json(json!({
            "candidate": alice.id()
        }))
        .transact()
        .await?;
    assert!(execution.is_failure());

    // vote by second candidate should success, and vote pass threshold
    let execution = accounts[1]
        .call(contract.id(), "vote_join")
        .args_json(json!({
            "candidate": alice.id()
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let vote_pass: bool = execution.json().unwrap();
    assert!(vote_pass);

    // another try to join should fail, because it's in Resharing state now
    let bob = worker.dev_create_account().await?;
    let execution = bob
        .call(contract.id(), "join")
        .args_json(json!({
            "url": "127.0.0.1",
            "cipher_pk": vec![1u8; 32],
            "sign_pk": "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
        }))
        .transact()
        .await?;
    assert!(execution.is_failure());

    Ok(())
}

#[tokio::test]
async fn test_vote_leave() -> anyhow::Result<()> {
    let (worker, contract, accounts, _) = init_env().await;

    let alice = worker.dev_create_account().await?;
    let bob = worker.dev_create_account().await?;
    let execution = alice
        .call(contract.id(), "join")
        .args_json(json!({
            "url": "127.0.0.1",
            "cipher_pk": vec![1u8; 32],
            "sign_pk": "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    // now alice is candidate, bob is just a random account

    // alice should not have permission to vote leave
    let execution = alice
        .call(contract.id(), "vote_leave")
        .args_json(json!({
            "kick": accounts[0].id(),
        }))
        .transact()
        .await?;
    assert!(execution.is_failure());

    // bob should not have permission to vote leave
    let execution = bob
        .call(contract.id(), "vote_leave")
        .args_json(json!({
            "kick": accounts[0].id(),
        }))
        .transact()
        .await?;
    assert!(execution.is_failure());

    // participant should have permission to vote leave
    let execution = accounts[1]
        .call(contract.id(), "vote_leave")
        .args_json(json!({
            "kick": accounts[0].id(),
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let vote_pass: bool = execution.json().unwrap();
    assert!(!vote_pass);

    let execution = accounts[2]
        .call(contract.id(), "vote_leave")
        .args_json(json!({
            "kick": accounts[0].id(),
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let vote_pass: bool = execution.json().unwrap();
    assert!(vote_pass);

    let state: mpc_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    match state {
        mpc_contract::ProtocolContractState::Resharing(r) => {
            assert!(!r
                .new_participants
                .participants
                .contains_key(accounts[0].id()));
            assert!(!r
                .new_participants
                .account_to_participant_id
                .contains_key(accounts[0].id()));
        }
        _ => panic!("should be in resharing state"),
    };

    // Complete resharing and verify the removed participant is fully gone
    let execution = accounts[1]
        .call(contract.id(), "vote_reshared")
        .args_json(json!({ "epoch": 1 }))
        .transact()
        .await?;
    assert!(execution.is_success());

    let execution = accounts[2]
        .call(contract.id(), "vote_reshared")
        .args_json(json!({ "epoch": 1 }))
        .transact()
        .await?;
    assert!(execution.is_success());

    let state: mpc_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    match state {
        mpc_contract::ProtocolContractState::Running(r) => {
            assert!(
                !r.participants.contains_key(accounts[0].id()),
                "removed participant must not be in participants"
            );
            assert!(
                !r.participants
                    .account_to_participant_id
                    .contains_key(accounts[0].id()),
                "removed participant must not be in account_to_participant_id"
            );
        }
        _ => panic!("should be in running state after resharing"),
    };

    Ok(())
}

#[tokio::test]
async fn test_vote_pk() -> anyhow::Result<()> {
    let (_, contract, accounts, _) = init_env().await;

    let key: String = contract.view("public_key").await.unwrap().json().unwrap();

    let execution = accounts[2]
        .call(contract.id(), "vote_pk")
        .args_json(json!({
            "public_key": key
        }))
        .transact()
        .await?;
    assert!(execution.is_success());

    let key2 = "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae";
    let execution = accounts[2]
        .call(contract.id(), "vote_pk")
        .args_json(json!({
            "public_key": key2
        }))
        .transact()
        .await?;
    assert!(execution.is_failure());

    Ok(())
}

#[tokio::test]
async fn test_vote_reshare() -> anyhow::Result<()> {
    let (worker, contract, accounts, _) = init_env().await;

    // in running state, vote current epoch will success
    let execution = accounts[2]
        .call(contract.id(), "vote_reshared")
        .args_json(json!({
            "epoch": 0
        }))
        .transact()
        .await?;
    assert!(execution.is_success());

    // in running state, vote other epoch will fail
    let execution = accounts[2]
        .call(contract.id(), "vote_reshared")
        .args_json(json!({
            "epoch": 1
        }))
        .transact()
        .await?;
    assert!(execution.is_failure());

    // join a new candidate
    let alice = worker.dev_create_account().await?;
    let execution = alice
        .call(contract.id(), "join")
        .args_json(json!({
            "url": "127.0.0.1",
            "cipher_pk": vec![1u8; 32],
            "sign_pk": "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
        }))
        .transact()
        .await?;
    assert!(execution.is_success());

    // vote to make it participant
    let execution = accounts[0]
        .call(contract.id(), "vote_join")
        .args_json(json!({
            "candidate": alice.id()
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let vote_pass: bool = execution.json().unwrap();
    assert!(!vote_pass);
    let execution = accounts[1]
        .call(contract.id(), "vote_join")
        .args_json(json!({
            "candidate": alice.id()
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let vote_pass: bool = execution.json().unwrap();
    assert!(vote_pass);
    let state: mpc_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    match state {
        mpc_contract::ProtocolContractState::Resharing(r) => {
            assert!(r.new_participants.participants.contains_key(alice.id()));
        }
        _ => panic!("should be in resharing state"),
    };

    // now we can vote reshared:
    let execution = accounts[0]
        .call(contract.id(), "vote_reshared")
        .args_json(json!({
            "epoch": 1
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let vote_pass: bool = execution.json().unwrap();
    assert!(!vote_pass);

    // not participant cannot vote
    let bob = worker.dev_create_account().await?;
    let execution = bob
        .call(contract.id(), "vote_reshared")
        .args_json(json!({
            "epoch": 1
        }))
        .transact()
        .await?;
    assert!(execution.is_failure());

    // new participant also cannot vote
    let execution = alice
        .call(contract.id(), "vote_reshared")
        .args_json(json!({
            "epoch": 1
        }))
        .transact()
        .await?;
    assert!(execution.is_failure());

    // Completion is gated by the old threshold (2), so the second old-participant
    // vote finishes resharing even though the new committee has 4 participants.
    let execution = accounts[1]
        .call(contract.id(), "vote_reshared")
        .args_json(json!({
            "epoch": 1
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let vote_pass: bool = execution.json().unwrap();
    assert!(vote_pass);

    let state: mpc_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    match state {
        mpc_contract::ProtocolContractState::Running(r) => {
            assert!(r.epoch == 1);
            assert!(r.participants.contains_key(alice.id()));
            // The reshared key adopts the new threshold for 4 participants.
            assert_eq!(r.threshold, mpc_contract::utils::compute_threshold(4));
            assert_eq!(r.threshold, 3);
        }
        _ => panic!("should be in running state"),
    };

    Ok(())
}

#[tokio::test]
async fn test_cancel_resharing() -> anyhow::Result<()> {
    let (worker, contract, accounts, _) = init_env().await;

    let initial_state: mpc_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    let mpc_contract::ProtocolContractState::Running(initial_state) = initial_state else {
        panic!("expected running state");
    };

    let alice = worker.dev_create_account().await?;
    let execution = alice
        .call(contract.id(), "join")
        .args_json(json!({
            "url": "127.0.0.1",
            "cipher_pk": vec![1u8; 32],
            "sign_pk": "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
        }))
        .transact()
        .await?;
    assert!(execution.is_success());

    let execution = accounts[0]
        .call(contract.id(), "vote_join")
        .args_json(json!({
            "candidate": alice.id()
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let vote_pass: bool = execution.json().unwrap();
    assert!(!vote_pass);

    let execution = accounts[1]
        .call(contract.id(), "vote_join")
        .args_json(json!({
            "candidate": alice.id()
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let vote_pass: bool = execution.json().unwrap();
    assert!(vote_pass);

    let state: mpc_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    assert!(
        matches!(state, mpc_contract::ProtocolContractState::Resharing(_)),
        "should be in resharing state",
    );

    let execution = accounts[0]
        .call(contract.id(), "vote_cancel_resharing")
        .args_json(json!({}))
        .transact()
        .await?;
    assert!(execution.is_success());
    let cancel_pass: bool = execution.json().unwrap();
    assert!(!cancel_pass);

    // Cancellation is gated by the old threshold (2), so the second vote reverts
    // the network to running.
    let execution = accounts[1]
        .call(contract.id(), "vote_cancel_resharing")
        .args_json(json!({}))
        .transact()
        .await?;
    assert!(execution.is_success());
    let cancel_pass: bool = execution.json().unwrap();
    assert!(cancel_pass);

    let state: mpc_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    match state {
        mpc_contract::ProtocolContractState::Running(running_state) => {
            assert_eq!(running_state.epoch, initial_state.epoch);
            // Cancelling leaves the key shares untouched, so the threshold is the
            // exact original value.
            assert_eq!(running_state.threshold, initial_state.threshold);
            assert_eq!(running_state.public_key, initial_state.public_key);
            assert_eq!(
                running_state.participants.participants,
                initial_state.participants.participants
            );
            // the rest should be reset to empty
            assert!(running_state.candidates.is_empty());
            assert!(running_state.join_votes.is_empty());
            assert!(running_state.leave_votes.is_empty());
        }
        _ => panic!("should be back in running state"),
    }

    Ok(())
}

/// The threshold is recomputed on every resharing, so adding and then removing a
/// participant should move it in lockstep with the participant count.
#[tokio::test]
async fn test_threshold_changes_with_participants() -> anyhow::Result<()> {
    let (worker, contract, accounts, _) = init_env().await;

    async fn running(contract: &near_workspaces::Contract) -> mpc_contract::RunningContractState {
        let state: mpc_contract::ProtocolContractState =
            contract.view("state").await.unwrap().json().unwrap();
        match state {
            mpc_contract::ProtocolContractState::Running(r) => r,
            other => panic!("expected running state, got {}", other.name()),
        }
    }

    // Initially there are 3 participants: threshold = compute_threshold(3) = 2.
    let state = running(&contract).await;
    assert_eq!(state.participants.participants.len(), 3);
    assert_eq!(
        state.threshold,
        mpc_contract::utils::compute_threshold(3),
        "initial threshold should match the formula"
    );
    assert_eq!(state.threshold, 2);

    // --- Add a 4th participant -------------------------------------------------
    let alice = worker.dev_create_account().await?;
    let execution = alice
        .call(contract.id(), "join")
        .args_json(json!({
            "url": "127.0.0.1",
            "cipher_pk": vec![1u8; 32],
            "sign_pk": "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
        }))
        .transact()
        .await?;
    assert!(execution.is_success());

    // Two votes (the current threshold) move the network into resharing.
    for voter in &accounts[0..2] {
        let execution = voter
            .call(contract.id(), "vote_join")
            .args_json(json!({ "candidate": alice.id() }))
            .transact()
            .await?;
        assert!(execution.is_success());
    }

    // Completion is gated by the old threshold (2), so the 2nd old-participant
    // vote finishes resharing.
    for (i, voter) in accounts.iter().enumerate().take(2) {
        let execution = voter
            .call(contract.id(), "vote_reshared")
            .args_json(json!({ "epoch": 1 }))
            .transact()
            .await?;
        assert!(execution.is_success());
        let pass: bool = execution.json().unwrap();
        assert_eq!(
            pass,
            i == 1,
            "reshare should complete on the 2nd vote (old threshold 2)"
        );
    }

    let state = running(&contract).await;
    assert_eq!(state.participants.participants.len(), 4);
    assert!(state.participants.participants.contains_key(alice.id()));
    assert_eq!(
        state.threshold,
        mpc_contract::utils::compute_threshold(4),
        "threshold should grow after adding a participant"
    );
    assert_eq!(state.threshold, 3);

    // --- Remove a participant --------------------------------------------------
    // Kick alice; three votes (the current threshold) trigger resharing.
    for (i, voter) in accounts.iter().enumerate() {
        let execution = voter
            .call(contract.id(), "vote_leave")
            .args_json(json!({ "kick": alice.id() }))
            .transact()
            .await?;
        assert!(execution.is_success());
        let pass: bool = execution.json().unwrap();
        assert_eq!(
            pass,
            i == 2,
            "leave should trigger resharing only on the 3rd vote"
        );
    }

    // The old committee had 4 participants (old threshold 3), so completion is
    // gated by 3 votes even though the new committee shrinks to 3.
    for (i, voter) in accounts.iter().enumerate() {
        let execution = voter
            .call(contract.id(), "vote_reshared")
            .args_json(json!({ "epoch": 2 }))
            .transact()
            .await?;
        assert!(execution.is_success());
        let pass: bool = execution.json().unwrap();
        assert_eq!(
            pass,
            i == 2,
            "reshare should complete on the 3rd vote (old threshold 3)"
        );
    }

    let state = running(&contract).await;
    assert_eq!(state.participants.participants.len(), 3);
    assert!(!state.participants.participants.contains_key(alice.id()));
    assert_eq!(
        state.threshold,
        mpc_contract::utils::compute_threshold(3),
        "threshold should shrink back after removing a participant"
    );
    assert_eq!(state.threshold, 2);

    Ok(())
}

#[tokio::test]
async fn test_vote_threshold_votes_accumulate() -> anyhow::Result<()> {
    // 7 participants, threshold 5 ─ valid changes are to 6 (compute(7)=5, max=6).
    // We use `init_env_with_participant_count` here because the default
    // 3-participant setup has no room for a threshold change (min=2, max=2,
    // current=2).
    let (worker, contract, accounts, _sk) =
        common::init_env_with_participant_count(7, 5).await;

    // A single vote for new_threshold=6 is not enough to trigger resharing
    // (threshold is 5).
    let execution = accounts[0]
        .call(contract.id(), "vote_threshold")
        .args_json(json!({ "new_threshold": 6 }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let pass: bool = execution.json().unwrap();
    assert!(!pass, "a single vote must not start resharing");

    let state: mpc_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    match state {
        mpc_contract::ProtocolContractState::Running(running) => {
            assert_eq!(
                running.threshold_votes.votes.get(&6).map(|s| s.len()),
                Some(1),
                "vote should be recorded under the proposed threshold"
            );
        }
        other => panic!("expected running state, got {}", other.name()),
    }

    // A duplicate vote from the same voter does not double-count.
    let execution = accounts[0]
        .call(contract.id(), "vote_threshold")
        .args_json(json!({ "new_threshold": 6 }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let pass: bool = execution.json().unwrap();
    assert!(!pass, "duplicate vote must not start resharing");

    // Four more distinct voters (total 5) trigger resharing.
    for account in &accounts[1..5] {
        let execution = account
            .call(contract.id(), "vote_threshold")
            .args_json(json!({ "new_threshold": 6 }))
            .transact()
            .await?;
        assert!(execution.is_success());
    }
    // The 5th vote should have triggered resharing.
    let state: mpc_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    assert!(
        matches!(state, mpc_contract::ProtocolContractState::Resharing(_)),
        "5 votes must trigger resharing when threshold is 5"
    );

    // Non-participants are rejected.
    let bob_account = worker.dev_create_account().await?;
    let execution = bob_account
        .call(contract.id(), "vote_threshold")
        .args_json(json!({ "new_threshold": 6 }))
        .transact()
        .await?;
    assert!(
        execution.is_failure(),
        "non-participants must not be able to vote"
    );

    Ok(())
}

/// A participant who switches their vote from one valid threshold to
/// another must only back the new threshold — the old vote is removed.
#[tokio::test]
async fn test_vote_threshold_changes_vote() -> anyhow::Result<()> {
    // 10 participants, threshold 7 — valid alternatives: 8, 9.
    let (_, contract, accounts, _sk) =
        common::init_env_with_participant_count(10, 7).await;

    // Vote for threshold 8.
    let execution = accounts[0]
        .call(contract.id(), "vote_threshold")
        .args_json(json!({ "new_threshold": 8 }))
        .transact()
        .await?;
    assert!(execution.is_success());

    let state: mpc_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    match &state {
        mpc_contract::ProtocolContractState::Running(running) => {
            assert_eq!(
                running.threshold_votes.votes.get(&8).map(|s| s.len()),
                Some(1),
                "vote should be recorded under threshold 8"
            );
            assert!(
                running.threshold_votes.votes.get(&9).is_none(),
                "no vote should exist for threshold 9 yet"
            );
        }
        other => panic!("expected running state, got {}", other.name()),
    }

    // Switch to threshold 9; the vote for 8 must disappear.
    let execution = accounts[0]
        .call(contract.id(), "vote_threshold")
        .args_json(json!({ "new_threshold": 9 }))
        .transact()
        .await?;
    assert!(execution.is_success());

    let state: mpc_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    match &state {
        mpc_contract::ProtocolContractState::Running(running) => {
            assert!(
                running.threshold_votes.votes.get(&8).is_none(),
                "vote for threshold 8 must be removed after switching to 9"
            );
            assert_eq!(
                running.threshold_votes.votes.get(&9).map(|s| s.len()),
                Some(1),
                "vote should now be recorded under threshold 9"
            );
        }
        other => panic!("expected running state, got {}", other.name()),
    }

    Ok(())
}

#[tokio::test]
async fn test_vote_threshold_validation() -> anyhow::Result<()> {
    // Use the configurable helper here — the default 3-participant setup has
    // no room for a threshold change (min=2, max=2, current=2), so the only
    // possible error is ThresholdUnchanged.  We need enough participants for
    // the full range of validation errors to be reachable.
    let (_, contract, accounts, _sk) =
        common::init_env_with_participant_count(7, 5).await;

    // new_threshold == current threshold (5) is rejected as a no-op.
    let execution = accounts[0]
        .call(contract.id(), "vote_threshold")
        .args_json(json!({ "new_threshold": 5 }))
        .transact()
        .await?;
    assert!(execution.is_failure(), "no-op threshold must be rejected");

    // new_threshold > participants.len() (7) is rejected.
    let execution = accounts[0]
        .call(contract.id(), "vote_threshold")
        .args_json(json!({ "new_threshold": 8 }))
        .transact()
        .await?;
    assert!(
        execution.is_failure(),
        "threshold above participant count must be rejected"
    );

    // new_threshold == participants.len() (7) is rejected (no fault tolerance).
    let execution = accounts[0]
        .call(contract.id(), "vote_threshold")
        .args_json(json!({ "new_threshold": 7 }))
        .transact()
        .await?;
    assert!(
        execution.is_failure(),
        "threshold equal to participant count must be rejected"
    );

    // new_threshold < compute_threshold(7) (5) is rejected.
    let execution = accounts[0]
        .call(contract.id(), "vote_threshold")
        .args_json(json!({ "new_threshold": 4 }))
        .transact()
        .await?;
    assert!(
        execution.is_failure(),
        "threshold below compute_threshold must be rejected"
    );

    // new_threshold == 0 is rejected.
    let execution = accounts[0]
        .call(contract.id(), "vote_threshold")
        .args_json(json!({ "new_threshold": 0 }))
        .transact()
        .await?;
    assert!(execution.is_failure(), "zero threshold must be rejected");

    Ok(())
}

#[tokio::test]
async fn test_vote_threshold_triggers_resharing() -> anyhow::Result<()> {
    // 7 participants, threshold 5 ─ valid changes are to 6.
    let (_, contract, accounts, _sk) =
        common::init_env_with_participant_count(7, 5).await;

    // Raise the threshold from 5 → 6. Current threshold is 5, so 5 votes
    // are required.
    for account in &accounts[..5] {
        let execution = account
            .call(contract.id(), "vote_threshold")
            .args_json(json!({ "new_threshold": 6 }))
            .transact()
            .await?;
        assert!(execution.is_success());
    }

    let state: mpc_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    match state {
        mpc_contract::ProtocolContractState::Resharing(r) => {
            // Same participant set, just a new threshold.
            assert_eq!(
                r.old_participants.participants,
                r.new_participants.participants
            );
            assert_eq!(r.old_participants.participants.len(), 7);
            assert_eq!(r.threshold, 5, "old threshold must stay put");
            assert_eq!(
                r.new_threshold, 6,
                "new threshold must match the proposed value"
            );
        }
        other => panic!("expected resharing state, got {}", other.name()),
    }

    // Completion is gated by the *old* threshold (5).
    for account in &accounts[..5] {
        let execution = account
            .call(contract.id(), "vote_reshared")
            .args_json(json!({ "epoch": 1 }))
            .transact()
            .await?;
        assert!(execution.is_success());
    }

    let state: mpc_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    match state {
        mpc_contract::ProtocolContractState::Running(r) => {
            assert_eq!(r.threshold, 6, "running state adopts the new threshold");
            assert_eq!(r.epoch, 1, "epoch must bump after resharing");
            assert_eq!(r.participants.participants.len(), 7);
        }
        other => panic!("expected running state, got {}", other.name()),
    }

    Ok(())
}
