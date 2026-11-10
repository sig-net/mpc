//! Shared fixtures for the watcher and expiry tests: entries with
//! real serialized transactions, a recorded-block ladder, and the
//! mockito stubs that serve them.

use std::sync::Arc;
use std::time::Duration;

use mockito::Matcher;
use mpc_chain_integration_core::utils::retry::RetryConfig;
use mpc_chain_integration_core::{MockStateManager, StateManager};
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Calldata, Chain, CompactMaybe, SignId, TronTxParams,
};
use mpc_tron_wire::pb::RawTransaction;
use mpc_tron_wire::{to_unsigned_tron_tx, TronAddress};
use url::Url;

use crate::config::TronConfig;

pub(crate) const RETRY: RetryConfig = RetryConfig {
    min_delay: Duration::from_millis(1),
    max_delay: Duration::from_millis(1),
    max_times: 2,
    jitter: false,
};

pub(crate) fn test_config(endpoint: Url) -> TronConfig {
    TronConfig {
        endpoint,
        poll_interval: Duration::from_millis(10),
        request_timeout: Duration::from_secs(2),
        retry: RETRY,
        ..TronConfig::default()
    }
}

/// Watcher entry keyed by the seed (txID's first byte); the request id
/// mirrors it, as `to_bidirectional_tx` builds it.
pub(crate) fn watcher_tx(seed: u8) -> (BidirectionalTxId, SignId, Arc<BidirectionalTx>) {
    let mut id = [0u8; 32];
    *id.first_mut().unwrap() = seed;
    let tx = Arc::new(BidirectionalTx {
        id: BidirectionalTxId(id),
        sender: [0u8; 32],
        serialized_transaction: vec![],
        source_chain: mpc_primitives::Chain::Midnight,
        target_chain: mpc_primitives::Chain::Tron,
        caip2_id: "tron:mainnet".to_string(),
        key_version: 0,
        deposit: 0,
        path: String::new(),
        algo: "secp256k1".to_string(),
        dest: "tron:mainnet".to_string(),
        params: String::new(),
        output_deserialization_schema: vec![],
        respond_serialization_schema: vec![],
        request_id: id,
        from_address: [0u8; 20],
        nonce: 0,
    });
    (BidirectionalTxId(id), SignId::new(id), tx)
}

/// The same entry carrying a non-empty output schema — admission
/// refuses these today; the watcher must still handle it.
pub(crate) fn schema_carrying_tx(seed: u8) -> (BidirectionalTxId, SignId, Arc<BidirectionalTx>) {
    let (tx_id, sign_id, tx) = watcher_tx(seed);
    let mut with_schema = (*tx).clone();
    with_schema.output_deserialization_schema = br#"[{"name":"output","type":"bool"}]"#.to_vec();
    (tx_id, sign_id, with_schema.into())
}

/// The expiry tests' shared fixture: a server answering both heads
/// plus a fresh state.
pub(crate) async fn expiry_stack() -> (mockito::ServerGuard, TronConfig, MockStateManager) {
    let server = mockito::Server::new_async().await;
    let config = test_config(server.url().parse().unwrap());
    let mut server = server;
    nowblock_mock(&mut server);
    (server, config, MockStateManager::new())
}

pub(crate) fn nowblock_mock(server: &mut mockito::ServerGuard) {
    server
        .mock("POST", "/wallet/getnowblock")
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{ "blockID": "{}",
             "block_header": {{ "raw_data": {{ "number": 42, "timestamp": 1730000000000 }} }} }}"#,
            hex::encode([0xau8; 32])
        ))
        .create();
}

pub(crate) fn receipt_stub(
    server: &mut mockito::ServerGuard,
    seed: u8,
    body: String,
) -> mockito::Mock {
    let tx_id = watcher_tx(seed).0;
    server
        .mock("POST", "/walletsolidity/gettransactioninfobyid")
        .match_body(Matcher::PartialJson(serde_json::json!({
            "value": hex::encode(tx_id.0)
        })))
        .with_header("content-type", "application/json")
        .with_body(body)
}

/// Proto3 omits the zero `SUCESS`, so success prints only the nested
/// verdict.
pub(crate) fn success_body(seed: u8) -> String {
    receipt_body(seed, "", "SUCCESS")
}

/// Failure prints `FAILED` above the specific member.
pub(crate) fn failure_body(seed: u8, member: &str) -> String {
    receipt_body(seed, r#", "result": "FAILED""#, member)
}

/// Synthetic: a real failure always carries the top-level `FAILED`,
/// which would classify; the unknown member must stand alone.
pub(crate) fn unclassifiable_body(seed: u8) -> String {
    receipt_body(seed, "", "WEIRD")
}

pub(crate) fn receipt_body(seed: u8, top_level: &str, nested: &str) -> String {
    let tx_id = watcher_tx(seed).0;
    format!(
        r#"{{ "id": "{}", "blockNumber": 71896097, "fee": 472800{top_level}, "receipt": {{ "result": "{nested}" }} }}"#,
        hex::encode(tx_id.0)
    )
}

/// Solidified-head timestamp the expiry tests pin against; its block
/// number (41) sits behind the live head's 42, so an attestation at 41
/// proves the scan reads solidified state.
/// The fixtures' assembly anchor: 2024-10-03T00:00:00Z, 100 s
/// before [`SOLIDITY_TS`].
pub(crate) const ASSEMBLED_AT: u64 = 1_728_000_000_000;

pub(crate) const SOLIDITY_TS: u64 = 1_728_000_100_000;

pub(crate) fn solidity_nowblock_mock(server: &mut mockito::ServerGuard) {
    solidity_head_at(server, 41);
}

/// The tests' solidified chain: `ts(n) = SOLIDITY_TS − (45 − n)·3 s`,
/// empty blocks. Resident txids stub their number ahead of the
/// ladder — mockito answers the first matching stub.
pub(crate) const LADDER_TOP: u64 = 45;

pub(crate) fn ladder_ts(number: u64) -> i64 {
    SOLIDITY_TS as i64 - (LADDER_TOP - number) as i64 * 3_000
}

pub(crate) fn solid_block_mock(server: &mut mockito::ServerGuard, number: u64, txids: &[[u8; 32]]) {
    let transactions: Vec<String> = txids
        .iter()
        .map(|id| format!(r#"{{ "txID": "{}" }}"#, hex::encode(id)))
        .collect();
    server
        .mock("POST", "/walletsolidity/getblockbynum")
        .match_body(Matcher::PartialJson(serde_json::json!({ "num": number })))
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{ "blockID": "{}",
             "block_header": {{ "raw_data": {{ "number": {number}, "timestamp": {} }} }},
             "transactions": [{}] }}"#,
            hex::encode([number as u8; 32]),
            ladder_ts(number),
            transactions.join(",")
        ))
        .create();
}

pub(crate) fn solid_block_ladder(server: &mut mockito::ServerGuard, resident: &[(u64, [u8; 32])]) {
    for number in 0..=LADDER_TOP {
        let txids: Vec<_> = resident
            .iter()
            .filter(|(at, _)| *at == number)
            .map(|(_, id)| *id)
            .collect();
        solid_block_mock(server, number, &txids);
    }
}

/// Every `getblockbynum` reads absent.
pub(crate) fn solid_block_absent(server: &mut mockito::ServerGuard) {
    server
        .mock("POST", "/walletsolidity/getblockbynum")
        .with_header("content-type", "application/json")
        .with_body("{}")
        .create();
}

pub(crate) fn solidity_head_at(server: &mut mockito::ServerGuard, number: u64) {
    server
        .mock("POST", "/walletsolidity/getnowblock")
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{ "blockID": "{}",
             "block_header": {{ "raw_data": {{ "number": {number}, "timestamp": {} }} }} }}"#,
            hex::encode([0x9u8; 32]),
            ladder_ts(number)
        ))
        .create();
}

pub(crate) fn success_receipt(id: &BidirectionalTxId) -> String {
    format!(
        r#"{{ "id": "{}", "blockNumber": 71896097, "fee": 472800, "receipt": {{ "result": "SUCCESS" }} }}"#,
        hex::encode(id.0)
    )
}

pub(crate) fn receipt_for(server: &mut mockito::ServerGuard, id: &BidirectionalTxId, body: String) {
    server
        .mock("POST", "/walletsolidity/gettransactioninfobyid")
        .match_body(Matcher::PartialJson(serde_json::json!({
            "value": hex::encode(id.0)
        })))
        .with_header("content-type", "application/json")
        .with_body(body)
        .create();
}

/// [`receipt_for`] asserting exactly one fetch.
pub(crate) fn receipt_for_once(
    server: &mut mockito::ServerGuard,
    id: &BidirectionalTxId,
    body: String,
) -> mockito::Mock {
    server
        .mock("POST", "/walletsolidity/gettransactioninfobyid")
        .match_body(Matcher::PartialJson(serde_json::json!({
            "value": hex::encode(id.0)
        })))
        .with_header("content-type", "application/json")
        .with_body(body)
        .expect(1)
        .create()
}

/// An entry whose serialized bytes carry `expiration`; the id is
/// those bytes' txID, as admission derives it.
pub(crate) fn expiry_tx(
    seed: u8,
    source: Chain,
    expiration: u64,
) -> (BidirectionalTxId, SignId, Arc<BidirectionalTx>) {
    expiry_tx_assembled_at(ASSEMBLED_AT + seed as u64, seed, source, expiration)
}

/// [`expiry_tx`] with an explicit assembly time — a lying one puts
/// the tx's real inclusion below the walkable span.
pub(crate) fn expiry_tx_assembled_at(
    timestamp: u64,
    seed: u8,
    source: Chain,
    expiration: u64,
) -> (BidirectionalTxId, SignId, Arc<BidirectionalTx>) {
    let params = TronTxParams {
        ref_block_bytes: [0x00, 0x03],
        ref_block_hash: [0x03; 8],
        timestamp,
        expiration,
        contract_address: {
            let mut address = [0xcd; 21];
            address[0] = 0x41;
            address
        },
        fee_limit: 0,
        call_value: 0,
        calldata: CompactMaybe {
            is_some: false,
            value: Calldata {
                selector: [0; 4],
                no_words: 0,
                words: Vec::new(),
            },
        },
    };
    let owner = TronAddress::from_evm(alloy::primitives::Address::from_slice(&[0xab; 20]));
    let raw = to_unsigned_tron_tx(&params, owner).unwrap();
    let (_, sign_id, base) = watcher_tx(seed);
    let mut tx = (*base).clone();
    tx.id = BidirectionalTxId(RawTransaction::parse(&raw).unwrap().txid());
    tx.serialized_transaction = raw;
    tx.source_chain = source;
    (tx.id, sign_id, Arc::new(tx))
}

/// Registers an `expiry_tx` as an `Executing` backlog entry.
pub(crate) async fn pending_expiry_entry(
    state: &MockStateManager,
    seed: u8,
    source: Chain,
    expiration: u64,
) -> (BidirectionalTxId, SignId, Arc<BidirectionalTx>) {
    let entry = expiry_tx(seed, source, expiration);
    state.add_pending_execution(Arc::clone(&entry.2)).await;
    entry
}

/// A pending entry that also carries a watch.
pub(crate) async fn watched_expiry_entry(
    state: &MockStateManager,
    seed: u8,
    source: Chain,
    expiration: u64,
) -> (BidirectionalTxId, SignId, Arc<BidirectionalTx>) {
    let entry = pending_expiry_entry(state, seed, source, expiration).await;
    state
        .watch_execution(Chain::Tron, Arc::clone(&entry.2))
        .await;
    entry
}
