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
