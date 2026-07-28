//! Transaction decode over the ledger's own `Transaction`.
//!
//! Provenance only: these calls attribute a block's requests to the contract that made
//! them, so a blob that will not deserialize is skipped rather than failing the read.

use midnight_ledger_v9::structure::{
    ContractAction, ContractCall, ProofMarker, Signature, Transaction,
};
use midnight_storage::DefaultDB;
use midnight_transient_crypto::commitment::PureGeneratorPedersen;

/// A block's decoded `send_mn_transaction` calls.
///
/// Nothing deserializes these on the read path; the derive exists so the golden
/// comparison below can parse a committed expectation into the same type.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct DecodedTransactions {
    pub transactions: Vec<DecodedTransaction>,
    pub skipped: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct DecodedTransaction {
    pub index: usize,
    pub calls: Vec<DecodedCall>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct DecodedCall {
    pub address: String,
    pub communication_commitment: String,
    pub claimed: Vec<ClaimedCall>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct ClaimedCall {
    pub address: String,
    pub entry_point: String,
    pub commitment: String,
}

type ChainTx = Transaction<Signature, ProofMarker, PureGeneratorPedersen, DefaultDB>;

pub fn decode_transactions(blobs: &[Vec<u8>]) -> DecodedTransactions {
    let mut transactions = Vec::new();
    let mut skipped = Vec::new();
    for (index, blob) in blobs.iter().enumerate() {
        match midnight_serialize::tagged_deserialize::<ChainTx>(&mut &blob[..]) {
            Ok(tx) => transactions.push(DecodedTransaction {
                index,
                calls: calls_of(&tx),
            }),
            Err(err) => skipped.push(format!("{index}: {err}")),
        }
    }
    DecodedTransactions {
        transactions,
        skipped,
    }
}

fn calls_of(tx: &ChainTx) -> Vec<DecodedCall> {
    let Transaction::Standard(standard) = tx else {
        return Vec::new();
    };
    let mut calls = Vec::new();
    for entry in standard.intents.iter() {
        let (_segment, intent) = &*entry;
        for action in intent.actions.iter_deref() {
            let ContractAction::Call(call) = action else {
                continue;
            };
            calls.push(DecodedCall {
                address: hex::encode(call.address.0 .0),
                communication_commitment: format!("{:?}", call.communication_commitment),
                claimed: claimed_of(call),
            });
        }
    }
    calls
}

fn claimed_of(call: &ContractCall<ProofMarker, DefaultDB>) -> Vec<ClaimedCall> {
    let mut out = Vec::new();
    for transcript in [&call.guaranteed_transcript, &call.fallible_transcript] {
        let Some(transcript) = transcript else {
            continue;
        };
        for claimed in transcript.effects.claimed_contract_calls.iter() {
            let (_position, address, entry_point, commitment) = claimed.into_inner();
            out.push(ClaimedCall {
                address: hex::encode(address.0 .0),
                entry_point: hex::encode(entry_point.0),
                commitment: format!("{commitment:?}"),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOTIFY_TX: &[u8] = include_bytes!("../fixtures/notify-tx.mn");
    const GOLDEN: &str = include_str!("../fixtures/golden-block-1366.json");

    /// The golden was minted by an independently written decoder, so reproducing it for
    /// the same captured transaction bytes is evidence this decode is right rather than
    /// merely self-consistent.
    #[test]
    fn native_transaction_decode_matches_the_committed_golden() {
        // The fixture is the node's own envelope: {"tx":{"Midnight":"<hex>"}}.
        let wrapper: serde_json::Value = serde_json::from_slice(NOTIFY_TX).unwrap();
        let blob = hex::decode(wrapper["tx"]["Midnight"].as_str().unwrap()).unwrap();

        let decoded = decode_transactions(&[blob]);
        assert!(decoded.skipped.is_empty(), "skipped: {:?}", decoded.skipped);

        let expected: DecodedTransactions = serde_json::from_str(GOLDEN).unwrap();
        assert_eq!(
            decoded, expected,
            "native decode must match the committed golden"
        );
    }
}
