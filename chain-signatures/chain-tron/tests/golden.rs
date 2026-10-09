//! Golden vectors from recorded mainnet fixtures (`tests/fixtures`):
//! proto round-trip, ref-block derivation, assembly, signing, and txID all
//! reproduce recorded transactions byte-for-byte. Captured from TronGrid
//! `gettransactionbyid` (USDT transfers, block #86891375).

use mpc_chain_tron::pb::{Message, RawTransaction, Transaction, TriggerSmartContract};
use mpc_chain_tron::{parse_hex, NowBlock, TronAddress, TronIntent};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const FIXTURES: [&str; 3] = [
    "tests/fixtures/usdt-transfer-1.json",
    "tests/fixtures/usdt-transfer-2.json",
    "tests/fixtures/usdt-transfer-3.json",
];

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

    let intent = TronIntent {
        owner: TronAddress::from_evm(parse_hex(param["owner_address"].as_str().unwrap()).unwrap()),
        contract: TronAddress::from_evm(
            parse_hex(param["contract_address"].as_str().unwrap()).unwrap(),
        ),
        call_data: hex::decode(param["data"].as_str().unwrap()).unwrap(),
    };
    let built = intent.raw_transaction(
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
    bare.contract.push(bare.contract[0].clone());
    use mpc_chain_tron::Message as _;
    assert!(RawTransaction::parse(&bare.encode_to_vec()).is_err());
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
