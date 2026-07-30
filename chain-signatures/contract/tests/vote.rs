pub mod common;
use common::init_env;

use serde_json::json;

use near_workspaces::types::NearToken;

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
        .deposit(NearToken::from_near(1))
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
        .deposit(NearToken::from_near(1))
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
        .deposit(NearToken::from_near(1))
        .transact()
        .await?;
    assert!(execution.is_failure());
    Ok(())
}

#[tokio::test]
async fn test_join_requires_deposit() -> anyhow::Result<()> {
    let (worker, contract, _, _) = init_env().await;
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

    assert!(execution.is_failure());
    Ok(())
}

#[tokio::test]
async fn test_join_rejects_oversized_url() -> anyhow::Result<()> {
    let (worker, contract, _, _) = init_env().await;
    let alice = worker.dev_create_account().await?;

    // Deposit is attached so the call can only fail on the url length check.
    let execution = alice
        .call(contract.id(), "join")
        .args_json(json!({
            "url": "a".repeat(mpc_contract::MAX_JOIN_URL_LEN + 1),
            "cipher_pk": vec![1u8; 32],
            "sign_pk": "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
        }))
        .deposit(NearToken::from_near(1))
        .transact()
        .await?;

    assert!(execution.is_failure());
    Ok(())
}

#[tokio::test]
async fn test_join_refunds_excess_deposit() -> anyhow::Result<()> {
    let (worker, contract, _, _) = init_env().await;

    let alice = worker.dev_create_account().await?;
    let balance = alice.view_account().await?.balance;
    let execution = alice
        .call(contract.id(), "join")
        .args_json(json!({
            "url": "127.0.0.1",
            "cipher_pk": vec![1u8; 32],
            "sign_pk": "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
        }))
        .deposit(NearToken::from_near(2))
        .transact()
        .await?;
    assert!(execution.is_success());

    let new_balance = alice.view_account().await?.balance;
    let spent = balance.as_millinear() - new_balance.as_millinear();
    assert!(
        spent < 1100,
        "excess deposit should be refunded; spent {spent} milliNEAR"
    );
    assert!(
        spent >= 1000,
        "required join deposit should remain with the contract; spent {spent} milliNEAR"
    );

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
        .deposit(NearToken::from_near(1))
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
        .deposit(NearToken::from_near(1))
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
        .deposit(NearToken::from_near(1))
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
        .deposit(NearToken::from_near(1))
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
        .deposit(NearToken::from_near(1))
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
        .deposit(NearToken::from_near(1))
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
        .deposit(NearToken::from_near(1))
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
