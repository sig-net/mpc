use std::str::FromStr;

use mpc_contract::{
    config::Config,
    primitives::{CandidateInfo, Candidates, Participants, SignRequest},
    update::ProposeUpdateArgs,
};
use mpc_keys::hpke;
use mpc_primitives::{SignId, Signature};
use near_account_id::AccountId;
use near_primitives::borsh;
use near_sdk::PublicKey;
use serde_json::json;

const PAYLOAD: [u8; 32] = [
    12, 1, 2, 0, 4, 5, 6, 8, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 44,
];

const SIGN_PK: &str = "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae";

pub fn sign_command(contract_id: &AccountId, caller_id: &AccountId) -> anyhow::Result<String> {
    let sign_request = SignRequest {
        payload: PAYLOAD,
        path: "test".into(),
        key_version: 0,
    };

    let request_json = format!(
        "'{}'",
        serde_json::to_string(&json!({"request": sign_request}))?
    );

    Ok(format!(
        "near call {contract_id} sign {request_json} --accountId {caller_id} --gas 300000000000000 --deposit 1"
    ))
}

pub fn respond_command(contract_id: &AccountId, caller_id: &AccountId) -> anyhow::Result<String> {
    let payload_hashed = alloy::primitives::keccak256(PAYLOAD);
    let path = "test";
    let key_version = 0;

    let sign_id = SignId::from_parts(caller_id, &payload_hashed, path, key_version);
    let big_r = serde_json::from_value(
        "02EC7FA686BB430A4B700BDA07F2E07D6333D9E33AEEF270334EB2D00D0A6FEC6C".into(),
    )?; // Fake BigR
    let s = serde_json::from_value(
        "20F90C540EE00133C911EA2A9ADE2ABBCC7AD820687F75E011DFEEC94DB10CD6".into(),
    )?; // Fake S

    let signature = Signature {
        big_r,
        s,
        recovery_id: 0,
    };

    let request_json = format!(
        "'{}'",
        serde_json::to_string(&json!({"sign_id": sign_id, "signature": signature})).unwrap()
    );

    Ok(format!(
        "near call {contract_id} respond {request_json} --accountId {caller_id} --gas 300000000000000"
    ))
}

pub fn join_command(contract_id: &AccountId, caller_id: &AccountId) -> anyhow::Result<String> {
    let url = "http://localhost:3030";
    let (_, cipher_pk) = hpke::generate();
    let sign_pk = PublicKey::from_str(SIGN_PK)?;

    let join_json = format!(
        "'{}'",
        serde_json::to_string(&json!({"url": url, "cipher_pk": cipher_pk, "sign_pk": sign_pk}))?
    );

    Ok(format!(
        "near call {contract_id} join {join_json} --accountId {caller_id} --gas 300000000000000"
    ))
}

pub fn proposed_updates_command(
    contract_id: &AccountId,
    caller_id: &AccountId,
) -> anyhow::Result<String> {
    let args = ProposeUpdateArgs {
        code: None,
        config: Some(Config::default()),
    };

    let borsh_args = borsh::to_vec(&args)?;

    let base64_encoded = near_primitives::serialize::to_base64(borsh_args.as_slice());

    Ok(format!(
        "near call {contract_id} propose_update --base64 {base64_encoded:?} --accountId {caller_id} --gas 300000000000000"
    ))
}

pub fn init_command(contract_id: &AccountId, caller_id: &AccountId) -> anyhow::Result<String> {
    let threshold: usize = 1;
    let candidates: Candidates = dummy_candidates();

    let init_json = format!(
        "'{}'",
        serde_json::to_string(&json!({"threshold": threshold, "candidates": candidates}))?
    );

    Ok(format!(
        "near call {contract_id} init {init_json} --accountId {caller_id} --gas 300000000000000"
    ))
}

pub fn init_running_command(
    contract_id: &AccountId,
    caller_id: &AccountId,
) -> anyhow::Result<String> {
    let init_running_json = format!(
        "'{}'",
        serde_json::to_string(
            &json!({"epoch": 0, "participants": Participants::from(dummy_candidates()), "threshold": 2,"public_key": PublicKey::from_str(SIGN_PK)? })
        )?
    );

    Ok(format!(
        "near call {contract_id} init_running {init_running_json} --accountId {caller_id} --gas 300000000000000"
    ))
}

pub fn dummy_candidates() -> Candidates {
    let mut candidates = Candidates::new();
    let names: Vec<AccountId> = vec![
        "alice.near".parse().unwrap(),
        "bob.near".parse().unwrap(),
        "caesar.near".parse().unwrap(),
    ];

    for account_id in names {
        candidates.insert(
            account_id.clone(),
            CandidateInfo {
                account_id,
                url: "127.0.0.1".into(),
                cipher_pk: [0; 32],
                sign_pk: PublicKey::from_str(SIGN_PK).unwrap(),
            },
        );
    }
    candidates
}
