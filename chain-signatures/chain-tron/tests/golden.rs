//! Golden vectors from recorded mainnet fixtures (`tests/fixtures`):
//! proto round-trip, ref-block derivation, assembly, signing, and txID all
//! reproduce recorded transactions byte-for-byte. Captured from TronGrid
//! `gettransactionbyid` (USDT transfers, block #86891375).

use mpc_chain_tron::pb::{
    Contract, ContractType, Message, RawTransaction, Transaction, TriggerSmartContract,
};
use mpc_chain_tron::{parse_hex, NowBlock, TronAddress};
use prost_types::Any;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const FIXTURES: [&str; 3] = [
    "tests/fixtures/usdt-transfer-1.json",
    "tests/fixtures/usdt-transfer-2.json",
    "tests/fixtures/usdt-transfer-3.json",
];

/// Validity window and energy-fee cap; observed on recorded transfers.
const EXPIRATION_MS: i64 = 300_000;
const FEE_LIMIT_SUN: i64 = 50_000_000;
const TRIGGER_SMART_CONTRACT_TYPE_URL: &str = "type.googleapis.com/protocol.TriggerSmartContract";

/// Test-local assembly of raw transactions from structured parameters.
fn build_raw(
    owner: &TronAddress,
    contract: &TronAddress,
    call_data: &[u8],
    reference: &NowBlock,
    now_ms: i64,
) -> RawTransaction {
    let trigger = TriggerSmartContract {
        owner_address: owner.as_bytes().to_vec(),
        contract_address: contract.as_bytes().to_vec(),
        call_value: 0,
        data: call_data.to_vec(),
        call_token_value: 0,
        token_id: 0,
    };
    let contract = Contract {
        r#type: ContractType::TriggerSmartContract as i32,
        parameter: Some(Any {
            type_url: TRIGGER_SMART_CONTRACT_TYPE_URL.to_string(),
            value: trigger.encode_to_vec(),
        }),
        permission_id: 0,
    };
    let (ref_block_bytes, ref_block_hash) = reference.reference_fields();
    RawTransaction {
        ref_block_bytes,
        ref_block_num: 0,
        ref_block_hash,
        expiration: now_ms + EXPIRATION_MS,
        timestamp: now_ms,
        fee_limit: FEE_LIMIT_SUN,
        contract: vec![contract],
    }
}

fn fixture(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn tx_fixture() -> Value {
    fixture("tests/fixtures/usdt-transfer-1.json")
}

fn raw_from_fixture(tx: &Value) -> RawTransaction {
    RawTransaction::parse(&hex::decode(tx["raw_data_hex"].as_str().unwrap()).unwrap()).unwrap()
}

fn reference_block_fixture() -> NowBlock {
    let block = fixture("tests/fixtures/block-86891375.json");
    NowBlock {
        block_id: alloy::primitives::B256::from_slice(
            &hex::decode(block["blockID"].as_str().unwrap()).unwrap(),
        ),
        number: block["block_header"]["raw_data"]["number"]
            .as_u64()
            .unwrap(),
        timestamp: block["block_header"]["raw_data"]["timestamp"]
            .as_u64()
            .unwrap(),
    }
}

#[test]
fn recorded_transactions_round_trip_byte_identically() {
    for path in FIXTURES {
        let fixture = fixture(path);
        let raw_bytes = hex::decode(fixture["raw_data_hex"].as_str().unwrap()).unwrap();

        let raw = RawTransaction::decode(raw_bytes.as_slice()).unwrap();
        assert_eq!(raw.encode_to_vec(), raw_bytes, "{path}: re-encode differs");

        let txid = hex::encode(Sha256::digest(&raw_bytes));
        assert_eq!(
            txid,
            fixture["txID"].as_str().unwrap(),
            "{path}: txid mismatch"
        );
    }
}

#[test]
fn reference_fields_match_recorded_block() {
    let (ref_bytes, ref_hash) = reference_block_fixture().reference_fields();
    let tx = tx_fixture();
    let raw = tx["raw_data"].as_object().unwrap();
    assert_eq!(
        hex::encode(&ref_bytes),
        raw["ref_block_bytes"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(&ref_hash),
        raw["ref_block_hash"].as_str().unwrap()
    );
}

#[test]
fn built_transaction_matches_recorded_bytes() {
    let tx = tx_fixture();
    let raw_json = &tx["raw_data"];
    let param = &raw_json["contract"][0]["parameter"]["value"];

    let built = build_raw(
        &TronAddress::from_evm(parse_hex(param["owner_address"].as_str().unwrap()).unwrap()),
        &TronAddress::from_evm(parse_hex(param["contract_address"].as_str().unwrap()).unwrap()),
        &hex::decode(param["data"].as_str().unwrap()).unwrap(),
        &reference_block_fixture(),
        raw_json["timestamp"].as_i64().unwrap(),
    );
    assert_eq!(
        hex::encode(built.encode_to_vec()),
        tx["raw_data_hex"].as_str().unwrap()
    );
}

#[test]
fn signing_reproduces_recorded_signature_and_txid() {
    let tx = tx_fixture();
    let unsigned = hex::decode(tx["raw_data_hex"].as_str().unwrap()).unwrap();

    let sig = hex::decode(tx["signature"][0].as_str().unwrap()).unwrap();
    let r: &[u8; 32] = sig[0..32].try_into().unwrap();
    let s: &[u8; 32] = sig[32..64].try_into().unwrap();
    let v = sig[64];

    let (signed, txid) = RawTransaction::parse(&unsigned)
        .unwrap()
        .sign_and_hash(r, s, v)
        .unwrap();
    let decoded = Transaction::decode(signed.as_slice()).unwrap();
    assert_eq!(decoded.signature[0], sig);
    assert_eq!(
        hex::encode(txid),
        tx["txID"].as_str().unwrap(),
        "txid must be sha256(raw_data)"
    );
}

#[test]
fn unpacked_parameter_matches_contract_call() {
    let tx = tx_fixture();
    let raw = raw_from_fixture(&tx);
    let contract = &raw.contract[0];
    let any = contract.parameter.as_ref().unwrap();
    assert_eq!(
        any.type_url,
        "type.googleapis.com/protocol.TriggerSmartContract"
    );
    let trigger = TriggerSmartContract::decode(any.value.as_slice()).unwrap();
    assert_eq!(
        hex::encode(&trigger.owner_address),
        tx["raw_data"]["contract"][0]["parameter"]["value"]["owner_address"]
            .as_str()
            .unwrap()
    );
    // USDT transfer calldata: selector + two 32-byte args.
    assert_eq!(trigger.data.len(), 68);
}

#[test]
fn parse_accepts_and_rejects() {
    let tx = tx_fixture();
    RawTransaction::parse(&hex::decode(tx["raw_data_hex"].as_str().unwrap()).unwrap()).unwrap();

    // Garbage is rejected.
    assert!(RawTransaction::parse(&[0xff, 0xff]).is_err());

    // Missing ref block is rejected.
    let mut bare = raw_from_fixture(&tx);
    bare.ref_block_bytes = Vec::new();

    assert!(RawTransaction::parse(&bare.encode_to_vec()).is_err());

    // A second contract is rejected.
    let mut extra = raw_from_fixture(&tx);
    extra.contract.push(extra.contract[0].clone());
    assert!(RawTransaction::parse(&extra.encode_to_vec()).is_err());

    // A contract type other than TriggerSmartContract is rejected.
    let mut typed = raw_from_fixture(&tx);
    typed.contract[0].r#type = 1;
    assert!(RawTransaction::parse(&typed.encode_to_vec()).is_err());
}

#[test]
fn signature_recovers_to_owner_address() {
    let tx = tx_fixture();
    let raw = raw_from_fixture(&tx);
    let digest = Sha256::digest(raw.encode_to_vec());

    let sig = hex::decode(tx["signature"][0].as_str().unwrap()).unwrap();
    let r: &[u8; 32] = sig[0..32].try_into().unwrap();
    let s: &[u8; 32] = sig[32..64].try_into().unwrap();
    let v = sig[64];

    let signature = k256::ecdsa::Signature::from_scalars(
        k256::FieldBytes::from(*r),
        k256::FieldBytes::from(*s),
    )
    .unwrap();
    let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(
        &digest,
        &signature,
        k256::ecdsa::RecoveryId::new(v == 1, false),
    )
    .unwrap();
    let pubkey = recovered.to_encoded_point(false);
    let evm = alloy::primitives::keccak256(&pubkey.as_bytes()[1..]);
    let derived = TronAddress::from_evm(alloy::primitives::Address::from_slice(&evm[12..]));

    let owner_hex = tx["raw_data"]["contract"][0]["parameter"]["value"]["owner_address"]
        .as_str()
        .unwrap();
    let expected = TronAddress::from_evm(parse_hex(owner_hex).unwrap());
    assert_eq!(derived, expected);
}
