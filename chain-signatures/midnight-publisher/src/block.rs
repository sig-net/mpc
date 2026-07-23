//! Decode a finalized Midnight block into per-transaction cross-contract-call
//! provenance.
//!
//! Mechanism only: no contract-address filtering, no request-id recompute, no
//! proof checks. Every contract call of every transaction is reported with its
//! raw provenance; a separate crate owns the security semantics.
//!
//! WHAT THIS SEAM DELIBERATELY DOES NOT DO: recover the values a transaction
//! wrote. A transcript carries no `Op::Insert` record, so reading writes out of
//! one means either modelling the VM's stack effects by hand or replaying the
//! program against the contract's pre-state. Both are unnecessary, because the
//! chain answers that question directly: `midnight_contractState(addr, block)`
//! minus the same read at the parent block IS the set of writes that block made
//! to that contract. A sequential indexer already holds the parent's state, so
//! this costs one read per block and is exact by construction, with no VM
//! semantics to get wrong. `tests::state_diff_yields_the_notify` pins that
//! equivalence against a captured SGN2 notify and the real state either side of
//! it.
//!
//! What a state diff CANNOT answer is which transaction performed a write, and
//! SGN2 Step 3 needs exactly that: the transaction that posted a notification
//! must also contain a contract call on the caller that notification names. That
//! is what this seam supplies, taken straight from the ledger's own
//! `Effects.claimed_contract_calls` and each call's `communication_commitment`.
//!
//! Pipeline (all types pinned to the rc.4 ledger via `midnight-node-ledger-helpers`):
//!   ledger `Transaction` bytes
//!     -> `Transaction::calls()`                        (all contract calls, both segments)
//!     -> per `ContractCall`, its two transcripts       (guaranteed / fallible)
//!        -> `Transcript.effects.claimed_contract_calls` (Step 3, caller side)
//!        -> `ContractCall.communication_commitment`     (Step 3, callee side)

use anyhow::Context as _;
use midnight_node_ledger_helpers::fork::raw_block_data::RawTransaction;
use midnight_node_ledger_helpers::{
    ContractEffects, DefaultDB, ProofMarker, PureGeneratorPedersen, Signature, Transaction,
};

/// The rc.4 ledger transaction type, exactly as the toolkit's own
/// `show_transaction` deserializes `RawTransaction::Midnight(bytes)`.
type Tx = Transaction<Signature, ProofMarker, PureGeneratorPedersen, DefaultDB>;

/// One entry of a transcript's `claimed_contract_calls` effects set: a call this
/// transcript asserts it made into another contract.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClaimedCall {
    /// Position of the claimed call within the claiming transcript.
    pub position: u64,
    /// Callee contract address, hex.
    pub address: String,
    /// Callee entry-point hash, hex.
    pub entry_point: String,
    /// Callee `communication_commitment`, hex (little-endian `Fr` bytes).
    pub commitment: String,
}

/// One contract call, carrying both sides of its cross-call provenance.
///
/// The Step-3 link is `claimed[i].commitment == communication_commitment` of the
/// callee's own `BlockCall` in the same transaction: that pair is what ties a
/// caller to the singleton call it made.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BlockCall {
    /// The contract this call executes against (`ContractCall.address`), hex.
    pub address: String,
    /// This call's own commitment (callee side), hex little-endian `Fr`.
    pub communication_commitment: String,
    /// Calls this call's transcripts claim to have made (caller side), sorted
    /// for a deterministic response.
    pub claimed: Vec<ClaimedCall>,
}

/// The contract calls of a single transaction.
///
/// Grouped per transaction on purpose: Step 3 asks whether ONE transaction
/// called both the singleton and the caller the notification names, and a
/// block-flat list could not answer that without ambiguity when two
/// transactions in the same block both notify.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BlockTransaction {
    /// Position of this transaction within the block.
    pub index: usize,
    pub calls: Vec<BlockCall>,
}

/// `GET /block` response.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BlockResponse {
    pub transactions: Vec<BlockTransaction>,
    /// Transactions this response deliberately survived rather than failed on,
    /// one human-readable reason each. A block carries every transaction on the
    /// chain, including shapes this build does not know, so one undecodable
    /// transaction must never cost the caller the rest of the block. Non-empty
    /// means `transactions` is NOT known to be complete for this block.
    pub skipped: Vec<String>,
}

/// The `claimed_contract_calls` of one transcript, decoded and ordered.
fn claimed_calls(effects: &ContractEffects<DefaultDB>) -> Vec<ClaimedCall> {
    let mut claimed: Vec<ClaimedCall> = effects
        .claimed_contract_calls
        .iter()
        // `iter()` yields `Arc<Sp<ClaimedContractCallsValue>>`; deref to the value.
        .map(|entry| {
            let c = &**entry;
            ClaimedCall {
                position: c.0,
                address: hex::encode(c.1 .0 .0),
                entry_point: hex::encode(c.2 .0),
                commitment: hex::encode(c.3.as_le_bytes()),
            }
        })
        .collect();
    // HashSet iteration order is unstable; sort for a deterministic response.
    claimed.sort_by(|a, b| {
        a.position
            .cmp(&b.position)
            .then_with(|| a.commitment.cmp(&b.commitment))
    });
    claimed
}

/// Every contract call of a decoded transaction, with its provenance.
pub(crate) fn calls_from_tx(tx: &Tx) -> Vec<BlockCall> {
    tx.calls()
        .map(|(_segment, call)| {
            let claimed = [
                call.guaranteed_transcript.as_deref(),
                call.fallible_transcript.as_deref(),
            ]
            .into_iter()
            .flatten()
            .flat_map(|transcript| claimed_calls(&transcript.effects))
            .collect();
            BlockCall {
                address: hex::encode(call.address.0 .0),
                communication_commitment: hex::encode(call.communication_commitment.as_le_bytes()),
                claimed,
            }
        })
        .collect()
}

/// Deserialize the tagged rc.4 ledger `Transaction` bytes (the `midnight_tx`
/// argument already unwrapped from the `send_mn_transaction` extrinsic).
pub(crate) fn decode_transaction(tx_bytes: &[u8]) -> anyhow::Result<Tx> {
    midnight_node_ledger_helpers::deserialize(tx_bytes)
        .context("tagged-deserialize ledger Transaction")
}

/// Decode a fetched block's transactions (Step 1 output) into a `BlockResponse`.
/// Only `Midnight` transactions carry ledger `Transaction` bytes; system
/// transactions are ignored.
///
/// One undecodable transaction costs that transaction, never the block: a tx
/// version this build does not know yet would otherwise fail the request and
/// hide every other call beside it. Whatever is dropped is reported in
/// `BlockResponse.skipped` so the loss is visible to the caller.
pub(crate) fn decode_block(txs: &[RawTransaction]) -> anyhow::Result<BlockResponse> {
    let mut transactions = Vec::new();
    let mut skipped = Vec::new();
    for (index, tx) in txs.iter().enumerate() {
        if let RawTransaction::Midnight(bytes) = tx {
            match decode_transaction(bytes) {
                Ok(decoded) => transactions.push(BlockTransaction {
                    index,
                    calls: calls_from_tx(&decoded),
                }),
                Err(reason) => skipped.push(format!("tx[{index}]: {reason:#}")),
            }
        }
    }
    Ok(BlockResponse {
        transactions,
        skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_node_ledger_helpers::ContractState;

    /// The deployed singleton and caller of the captured SGN2 flow, and the
    /// request the caller submitted. Recapture the fixtures and these together.
    const SIGNET_ADDR: &str = "aa5d96c2de9af9dfc9fe046c30954a07c32ae1e1c976bf6088f8757d06ff3f47";
    const CALLER_ADDR: &str = "dcd470fbc066befe0b6cddcf273dc9a838832ccbb8327f2625ec7028b0a6f0d2";
    const REQUEST_ID: &str = "abf32e141d471192a834779b0a8960aa05a7f94534564f477420eef80f588c48";

    /// A fixture's transaction bytes, decoded with the ledger's OWN
    /// `RawTransaction` codec rather than by hand-picking hex out of the JSON.
    /// Upstream's full `SerializedTx` also carries `context` + `tx_hash`, which
    /// our captured fixtures omit, so only the `tx` field is deserialized.
    fn fixture_tx_bytes(path: &str) -> Vec<u8> {
        #[derive(serde::Deserialize)]
        struct FixtureTx {
            tx: RawTransaction,
        }
        let raw = std::fs::read_to_string(path).expect("fixture is readable");
        let fixture: FixtureTx = serde_json::from_str(&raw).expect("fixture holds a RawTransaction");
        fixture.tx.as_bytes().to_vec()
    }

    /// A contract's decoded state tree, from a captured `contract-state[v8]` blob.
    fn fixture_state(path: &str) -> crate::state::Node {
        let raw = std::fs::read(path).expect("state fixture is readable");
        let state: ContractState<DefaultDB> =
            midnight_node_ledger_helpers::deserialize(&raw[..]).expect("deserialize ContractState");
        crate::state::walk(state.data.get_ref()).expect("walk the state tree")
    }

    /// Every `(map key hex, cell atoms)` pair reachable in a walked state tree.
    fn map_entries(node: &crate::state::Node) -> Vec<(String, Vec<String>)> {
        let mut out = Vec::new();
        match node {
            crate::state::Node::Map { entries } => {
                for entry in entries {
                    if let crate::state::Node::Cell { atoms } = &entry.value {
                        out.push((entry.key.clone(), atoms.clone()));
                    }
                    out.extend(map_entries(&entry.value));
                }
            }
            crate::state::Node::Array { children } => {
                for child in children {
                    out.extend(map_entries(child));
                }
            }
            _ => {}
        }
        out
    }

    /// THE load-bearing test for this seam's design: what a block wrote is the
    /// difference between the contract's state at that block and at its parent.
    /// No transcript is decoded here at all.
    ///
    /// The fixtures are the singleton's real state read from the node either side
    /// of the notify block 1366. The stored map key renders as one hex string, so
    /// `SignetMapKey{count: 0, requestId}` appears as the request id alone (the
    /// zero count trims away).
    #[test]
    fn state_diff_yields_the_notify() {
        let before = fixture_state("tests/fixtures/singleton-pre-state-1365.mn");
        let after = fixture_state("tests/fixtures/singleton-post-state-1366.mn");

        let before_entries = map_entries(&before);
        let written: Vec<_> = map_entries(&after)
            .into_iter()
            .filter(|entry| !before_entries.contains(entry))
            .collect();

        // Exactly two writes: the per-request notification counter, and the
        // notification itself.
        assert_eq!(written.len(), 2, "counter init + notify: {written:?}");
        assert!(
            written
                .iter()
                .any(|(key, atoms)| key == REQUEST_ID && atoms == &vec!["01".to_string()]),
            "the per-request counter must be initialised: {written:?}"
        );
        assert!(
            written.iter().any(|(key, atoms)| key == REQUEST_ID
                && atoms == &vec!["01".to_string(), format!("{CALLER_ADDR}04")]),
            "the notification is version 1, the caller address and field 4: {written:?}"
        );
    }

    /// The Step-3 evidence this seam exists to provide: within ONE transaction,
    /// the caller's call claims a call whose commitment is the singleton call's
    /// own `communication_commitment`.
    #[test]
    fn notify_tx_links_caller_to_singleton_in_one_transaction() {
        let bytes = fixture_tx_bytes("tests/fixtures/notify-tx.mn");
        let tx = decode_transaction(&bytes).expect("deserialize ledger Transaction");
        let calls = calls_from_tx(&tx);

        let caller = calls
            .iter()
            .find(|c| c.address == CALLER_ADDR)
            .expect("the caller's contract call");
        let singleton = calls
            .iter()
            .find(|c| c.address == SIGNET_ADDR)
            .expect("the singleton's contract call");

        let claim = caller
            .claimed
            .iter()
            .find(|claim| claim.address == SIGNET_ADDR)
            .expect("the caller must claim a call on the singleton");
        assert_eq!(
            claim.commitment, singleton.communication_commitment,
            "the claimed commitment must be the singleton call's own commitment"
        );
    }

    /// The pre-SGN2 reference transaction still decodes and yields a well-formed
    /// response. It may carry zero contract calls; that is asserted as
    /// well-formed, not required.
    #[test]
    fn reference_tx_fixture_decodes_and_extracts() {
        let bytes = fixture_tx_bytes("tests/fixtures/serialized_tx.mn");
        let tx = decode_transaction(&bytes).expect("deserialize ledger Transaction");
        let response = decode_block(&[RawTransaction::Midnight(bytes.clone())])
            .expect("decode a single-transaction block");

        assert!(response.skipped.is_empty(), "{:?}", response.skipped);
        assert_eq!(response.transactions.len(), 1);
        assert_eq!(response.transactions[0].calls.len(), calls_from_tx(&tx).len());
        let json = serde_json::to_string(&response).unwrap();
        assert!(
            json.starts_with("{\"transactions\":"),
            "well-formed response: {json}"
        );
    }

    /// A block carries every transaction on the chain. One this build cannot
    /// deserialize must cost that transaction only: the real calls beside it
    /// still come back, and the drop is reported.
    #[test]
    fn decode_block_survives_an_undecodable_transaction() {
        let good = fixture_tx_bytes("tests/fixtures/notify-tx.mn");

        let response = decode_block(&[
            RawTransaction::Midnight(vec![0xde, 0xad, 0xbe, 0xef]),
            RawTransaction::Midnight(good),
        ])
        .expect("an undecodable transaction must not fail the block");

        assert_eq!(
            response.transactions.len(),
            1,
            "the real transaction beside the poisoned one must still decode"
        );
        assert!(
            response.transactions[0]
                .calls
                .iter()
                .any(|c| c.address == SIGNET_ADDR),
            "the singleton call must survive"
        );
        assert_eq!(
            response.skipped.len(),
            1,
            "the drop must be reported: {:?}",
            response.skipped
        );
        assert!(
            response.skipped[0].starts_with("tx[0]:"),
            "the report must name the dropped transaction: {:?}",
            response.skipped
        );
    }
}
