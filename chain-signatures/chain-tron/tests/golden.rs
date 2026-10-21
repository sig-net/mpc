//! Golden vectors from recorded mainnet fixtures (`tests/fixtures`):
//! proto round-trip, ref-block derivation, assembly, signing, and txID all
//! reproduce recorded transactions byte-for-byte. Captured from TronGrid
//! `gettransactionbyid` (USDT transfers, block #86891375).

mod common;

use common::build_raw;
use mpc_chain_tron::pb::{
    Message, RawTransaction, Transaction, TriggerSmartContract, TRIGGER_SMART_CONTRACT_TYPE_URL,
};
use mpc_chain_tron::{parse_hex, NowBlock, TronAddress};
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
    assert_eq!(any.type_url, TRIGGER_SMART_CONTRACT_TYPE_URL);
    let trigger = TriggerSmartContract::decode(any.value.as_slice()).unwrap();
    assert_eq!(
        hex::encode(&trigger.owner_address),
        tx["raw_data"]["contract"][0]["parameter"]["value"]["owner_address"]
            .as_str()
            .unwrap()
    );
    // USDT transfer calldata: selector + two 32-byte args.
    assert_eq!(trigger.data.len(), 68);

    // The raw transaction should parse correctly and the owner address should match the trigger's owner address.
    let raw =
        RawTransaction::parse(&hex::decode(tx["raw_data_hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(raw.owner_address().unwrap(), trigger.owner_address);
}

#[test]
fn parse_accepts_and_rejects() {
    let tx = tx_fixture();
    RawTransaction::parse(&hex::decode(tx["raw_data_hex"].as_str().unwrap()).unwrap()).unwrap();

    // Garbage is rejected.
    assert!(RawTransaction::parse(&[0xff, 0xff]).is_err());

    // Missing reference fields are rejected.
    let mut bare = raw_from_fixture(&tx);
    bare.ref_block_bytes = Vec::new();
    assert!(RawTransaction::parse(&bare.encode_to_vec()).is_err());
    let mut bare = raw_from_fixture(&tx);
    bare.ref_block_hash = Vec::new();
    assert!(RawTransaction::parse(&bare.encode_to_vec()).is_err());
    let mut bare = raw_from_fixture(&tx);
    bare.expiration = 0;
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

/// The contract's parameter must be a `TriggerSmartContract` — matching
/// `Any` type URL and 21-byte `0x41`-prefixed addresses — or java-tron
/// rejects the signed transaction at broadcast.
#[test]
fn parse_rejects_malformed_trigger_parameters() {
    let tx = tx_fixture();

    let mut missing = raw_from_fixture(&tx);
    missing.contract[0].parameter = None;
    assert!(RawTransaction::parse(&missing.encode_to_vec()).is_err());

    let mut wrong_url = raw_from_fixture(&tx);
    wrong_url.contract[0].parameter.as_mut().unwrap().type_url =
        "type.googleapis.com/protocol.TransferContract".to_string();
    assert!(RawTransaction::parse(&wrong_url.encode_to_vec()).is_err());

    let reparameterized =
        |mut raw: RawTransaction, mutate: &dyn Fn(&mut TriggerSmartContract)| -> Vec<u8> {
            let any = raw.contract[0].parameter.as_mut().unwrap();
            let mut trigger = TriggerSmartContract::decode(any.value.as_slice()).unwrap();
            mutate(&mut trigger);
            any.value = trigger.encode_to_vec();
            raw.encode_to_vec()
        };

    for malformed in [
        reparameterized(raw_from_fixture(&tx), &|t| {
            t.contract_address.remove(0);
        }),
        reparameterized(raw_from_fixture(&tx), &|t| {
            t.contract_address[0] = 0x42;
        }),
        reparameterized(raw_from_fixture(&tx), &|t| {
            t.owner_address.remove(0);
        }),
    ] {
        assert!(RawTransaction::parse(&malformed).is_err());
    }
}

/// parse admits only the canonical encoding: anything that decodes but
/// re-encodes differently would desync the payload preimage (the submitted
/// bytes) from the txID preimage (the re-encoded transaction).
#[test]
fn parse_requires_the_canonical_encoding() {
    let tx = tx_fixture();

    // An unknown field (30) decodes but re-encodes away.
    let mut memo = hex::decode(tx["raw_data_hex"].as_str().unwrap()).unwrap();
    memo.extend_from_slice(&[0xf0, 0x01]);
    assert!(RawTransaction::parse(&memo).is_err());

    // A non-minimal length varint (`88 00` = 8) names the same field but
    // re-encodes minimally.
    let mut padded = hex::decode(tx["raw_data_hex"].as_str().unwrap()).unwrap();
    assert_eq!(&padded[4..6], &[0x22, 0x08], "field 4, length 8");
    padded[5] = 0x88;
    padded.insert(6, 0x00);
    assert!(RawTransaction::parse(&padded).is_err());
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
