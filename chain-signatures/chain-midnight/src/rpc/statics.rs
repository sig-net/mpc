//! Static subxt types for the midnight pallet: the chain's extrinsic, the
//! applied-status events every reader decodes, and their status gate.

use anyhow::Context as _;
use subxt::ext::scale_decode::DecodeAsType;
use subxt::SubstrateConfig;

use crate::emissions::{emissions_in, DecodedTransaction};
use crate::types::LedgerTxHash;

#[derive(DecodeAsType)]
#[decode_as_type(crate_path = "subxt::ext::scale_decode")]
pub(super) struct SendMnTransaction {
    pub(super) midnight_tx: Vec<u8>,
}

impl subxt::blocks::StaticExtrinsic for SendMnTransaction {
    const PALLET: &'static str = "Midnight";
    const CALL: &'static str = "send_mn_transaction";
}

/// The substrate timestamp inherent (`Timestamp::set`), present in the
/// captured Midnight runtime metadata (node 2.0.0-rc.4 fixture).
#[derive(DecodeAsType)]
#[decode_as_type(crate_path = "subxt::ext::scale_decode")]
pub(super) struct TimestampSet {
    pub(super) now: u64,
}

impl subxt::blocks::StaticExtrinsic for TimestampSet {
    const PALLET: &'static str = "Timestamp";
    const CALL: &'static str = "set";
}

#[derive(DecodeAsType)]
#[decode_as_type(crate_path = "subxt::ext::scale_decode")]
pub(super) struct TxAppliedDetails {
    pub(super) tx_hash: [u8; 32],
}

#[derive(DecodeAsType)]
#[decode_as_type(crate_path = "subxt::ext::scale_decode")]
pub(super) struct TxApplied(pub(super) TxAppliedDetails);

impl subxt::events::StaticEvent for TxApplied {
    const PALLET: &'static str = "Midnight";
    const EVENT: &'static str = "TxApplied";
}

#[derive(DecodeAsType)]
#[decode_as_type(crate_path = "subxt::ext::scale_decode")]
pub(super) struct TxPartialSuccess(pub(super) TxAppliedDetails);

impl subxt::events::StaticEvent for TxPartialSuccess {
    const PALLET: &'static str = "Midnight";
    const EVENT: &'static str = "TxPartialSuccess";
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AppliedStatus {
    Applied,
    PartialSuccess,
}

/// Accept only one unambiguous applied status from this extrinsic, with its ledger hash.
/// These are RPC-reported events; this check does not verify their inclusion.
pub(super) fn applied_status(
    events: &subxt::blocks::ExtrinsicEvents<SubstrateConfig>,
) -> anyhow::Result<Option<(LedgerTxHash, AppliedStatus)>> {
    let mut applied = None;
    let mut partial = None;
    for event in events.iter() {
        let event = event.context("Midnight status events did not match metadata")?;
        if let Some(TxApplied(details)) = event.as_event::<TxApplied>()? {
            anyhow::ensure!(
                applied
                    .replace(LedgerTxHash::from_bytes(details.tx_hash))
                    .is_none(),
                "duplicate TxApplied status"
            );
        }
        if let Some(TxPartialSuccess(details)) = event.as_event::<TxPartialSuccess>()? {
            anyhow::ensure!(
                partial
                    .replace(LedgerTxHash::from_bytes(details.tx_hash))
                    .is_none(),
                "duplicate TxPartialSuccess status"
            );
        }
    }
    anyhow::ensure!(
        applied.is_none() || partial.is_none(),
        "conflicting Midnight statuses"
    );
    Ok(applied
        .map(|hash| (hash, AppliedStatus::Applied))
        .or(partial.map(|hash| (hash, AppliedStatus::PartialSuccess))))
}

pub(super) fn decode_applied_transaction(
    bytes: &[u8],
    expected_hash: LedgerTxHash,
) -> anyhow::Result<DecodedTransaction> {
    let tx: DecodedTransaction = midnight_serialize::tagged_deserialize(&mut &bytes[..])
        .context("candidate ledger transaction did not decode")?;
    anyhow::ensure!(
        tx.transaction_hash().0 .0 == *expected_hash.as_bytes(),
        "status hash does not match the candidate ledger transaction"
    );
    Ok(tx)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::support::*;

    #[test]
    fn status_gate_uses_the_captured_extrinsic_status() {
        let raw = include_bytes!("../../fixtures/fallible-block-432-events.scale").to_vec();
        let events = captured_status_events(raw.clone(), 4);
        let (hash, status) = applied_status(&events)
            .expect("valid status")
            .expect("TxApplied");
        assert_eq!(status, AppliedStatus::Applied);
        let tx = decode_applied_transaction(
            include_bytes!("../../fixtures/fallible-deposit-tx-432.mn"),
            hash,
        )
        .expect("captured transaction matches status");
        let singleton = crate::test_utils::hex_32(
            "4daa9701226222a9db302dfb6f347f48c947278a4dc93812a79494f4086a0172",
        );
        let calls = emissions_in(&tx, &singleton).expect("successful fallible transcript decodes");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].phase, crate::emissions::TranscriptPhase::Fallible);
        assert_eq!(calls[0].physical_segment, 49592);
        assert_eq!(calls[0].emissions.len(), 1);
        assert_eq!(
            applied_status(&captured_status_events(raw, 0)).unwrap(),
            None
        );
        let mut wrong_hash = *hash.as_bytes();
        wrong_hash[0] ^= 1;
        assert!(decode_applied_transaction(
            include_bytes!("../../fixtures/fallible-deposit-tx-432.mn"),
            LedgerTxHash::from_bytes(wrong_hash),
        )
        .unwrap_err()
        .to_string()
        .contains("hash does not match"));
    }

    #[test]
    fn status_gate_reads_partial_success_and_rejects_ambiguous_statuses() {
        let events = captured_status_events(
            include_bytes!("../../fixtures/fallible-block-432-events.scale").to_vec(),
            4,
        );
        let applied = events
            .iter()
            .map(Result::unwrap)
            .find(|event| event.as_event::<TxApplied>().unwrap().is_some())
            .expect("capture has TxApplied");
        let mut partial = applied.bytes().to_vec();
        // Synthetic status cases retain the captured producer's SCALE layout:
        // ApplyExtrinsic(u32), Midnight pallet, then its event discriminant.
        assert_eq!(&partial[..7], &[0, 4, 0, 0, 0, 5, 2]);
        partial[6] = 7; // TxPartialSuccess in the captured metadata.
        assert!(
            captured_status_events(encode_status_records(&[partial.clone()]), 4)
                .find_first::<TxPartialSuccess>()
                .unwrap()
                .is_some()
        );
        let mut applied_hash = [0u8; 32];
        applied_hash.copy_from_slice(&applied.bytes()[7..39]);
        let applied_hash = LedgerTxHash::from_bytes(applied_hash);
        assert_eq!(
            applied_status(&captured_status_events(
                encode_status_records(&[partial.clone()]),
                4,
            ))
            .unwrap(),
            Some((applied_hash, AppliedStatus::PartialSuccess))
        );
        assert_eq!(
            applied_status(&captured_status_events(encode_status_records(&[]), 4,)).unwrap(),
            None
        );
        for records in [
            vec![applied.bytes().to_vec(), partial.clone()],
            vec![applied.bytes().to_vec(), applied.bytes().to_vec()],
            vec![partial.clone(), partial],
        ] {
            assert!(
                applied_status(&captured_status_events(encode_status_records(&records), 4,))
                    .is_err(),
                "ambiguous outcome must hold"
            );
        }
        assert!(
            applied_status(&captured_status_events(
                encode_status_records(&[applied.bytes()[..12].to_vec()]),
                4,
            ))
            .is_err(),
            "truncated outcome must hold"
        );
    }
}
