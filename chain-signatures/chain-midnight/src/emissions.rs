//! Singleton contract emissions recovered by executing transaction transcripts with the ledger VM.

use anyhow::Context as _;
use midnight_base_crypto::fab::{AlignmentAtom, AlignmentSegment};
use midnight_ledger_v9::structure::{ContractCall, ProofKind, ProofMarker, Signature, Transaction};
use midnight_onchain_runtime::context::QueryContext;
use midnight_onchain_runtime::cost_model::INITIAL_COST_MODEL;
use midnight_onchain_runtime::ops::{LogEventType, VersionedLogItem};
use midnight_onchain_runtime::result_mode::ResultModeVerify;
use midnight_onchain_runtime::state::{ChargedState, StateValue};
use midnight_storage::storage::Array;
use midnight_storage::DefaultDB;

pub const MISC_NAME_LEN: usize = 32;
pub const MISC_PAYLOAD_LEN: usize = 256;
const MISC_DATA_LEN: usize = MISC_NAME_LEN + MISC_PAYLOAD_LEN;
const LOG_ITEM_VERSION: u32 = 1;

const SIGN_BIDIRECTIONAL_EVENT: [u8; MISC_NAME_LEN] = padded_name(b"SignBidirectionalEvent");
const SIGNATURE_RESPONDED_EVENT: [u8; MISC_NAME_LEN] = padded_name(b"SignatureRespondedEvent");
const RESPOND_BIDIRECTIONAL_EVENT: [u8; MISC_NAME_LEN] = padded_name(b"RespondBidirectionalEvent");

const fn padded_name(text: &[u8]) -> [u8; MISC_NAME_LEN] {
    let mut padded = [0u8; MISC_NAME_LEN];
    let mut index = 0;
    while index < text.len() {
        padded[index] = text[index];
        index += 1;
    }
    padded
}

/// A decoded transaction in the proven form carried by finalized blocks.
pub type DecodedTransaction =
    Transaction<Signature, ProofMarker, <ProofMarker as ProofKind<DefaultDB>>::Pedersen, DefaultDB>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EmissionKind {
    SignBidirectional,
    SignatureResponded,
    RespondBidirectional,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Emission {
    pub kind: EmissionKind,
    pub payload: [u8; MISC_PAYLOAD_LEN],
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SingletonCallEmissions {
    /// Position in [`DecodedTransaction::calls`] before filtering by the singleton address.
    pub call_index: u32,
    pub emissions: Vec<Emission>,
}

#[derive(Debug)]
pub(crate) struct UnsupportedFallibleCall {
    pub call_index: u32,
}

impl std::fmt::Display for UnsupportedFallibleCall {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "singleton call {} contains a fallible transcript",
            self.call_index
        )
    }
}

impl std::error::Error for UnsupportedFallibleCall {}

fn log_items<P: ProofKind<DefaultDB>>(
    call: &ContractCall<P, DefaultDB>,
) -> anyhow::Result<Vec<VersionedLogItem<DefaultDB>>> {
    let context = QueryContext::new(
        ChargedState::new(StateValue::Array(Array::new())),
        call.address,
    );
    // TODO: Consider decoding fallible transcripts when indexing supports them.
    match call.guaranteed_transcript.as_deref() {
        Some(transcript) => {
            let result = context
                .query::<ResultModeVerify>(
                    &Vec::from(&transcript.program),
                    None,
                    &INITIAL_COST_MODEL,
                )
                .context("singleton guaranteed transcript rejected by the ledger VM")?;
            Ok(result.events)
        }
        None => Ok(Vec::new()),
    }
}

pub fn emission_from_log_item(item: &VersionedLogItem<DefaultDB>) -> anyhow::Result<Emission> {
    anyhow::ensure!(
        item.version == LOG_ITEM_VERSION,
        "emission-schema: log item version {} is not {LOG_ITEM_VERSION}",
        item.version
    );
    anyhow::ensure!(
        item.event_type == LogEventType::Misc,
        "emission-schema: log item type {:?} is not Misc",
        item.event_type
    );

    let StateValue::Cell(cell) = &item.data else {
        anyhow::bail!("emission-schema: Misc data is not a cell");
    };
    anyhow::ensure!(
        cell.alignment.0.as_slice()
            == [AlignmentSegment::Atom(AlignmentAtom::Bytes {
                length: MISC_DATA_LEN as u32,
            })],
        "emission-schema: Misc data is not one Bytes<{MISC_DATA_LEN}> atom"
    );
    anyhow::ensure!(
        cell.value.0.len() == 1,
        "emission-schema: Misc data contains {} atoms, expected one",
        cell.value.0.len()
    );

    let stored = &cell.value.0[0].0;
    anyhow::ensure!(
        stored.len() <= MISC_DATA_LEN,
        "emission-schema: Misc data stores {} bytes under Bytes<{MISC_DATA_LEN}>",
        stored.len()
    );
    let mut bytes = [0u8; MISC_DATA_LEN];
    bytes[..stored.len()].copy_from_slice(stored);

    let mut name = [0u8; MISC_NAME_LEN];
    name.copy_from_slice(&bytes[..MISC_NAME_LEN]);
    let kind = match name {
        SIGN_BIDIRECTIONAL_EVENT => EmissionKind::SignBidirectional,
        SIGNATURE_RESPONDED_EVENT => EmissionKind::SignatureResponded,
        RESPOND_BIDIRECTIONAL_EVENT => EmissionKind::RespondBidirectional,
        _ => anyhow::bail!(
            "emission-schema: unknown singleton event name {}",
            String::from_utf8_lossy(&name)
        ),
    };

    let mut payload = [0u8; MISC_PAYLOAD_LEN];
    payload.copy_from_slice(&bytes[MISC_NAME_LEN..]);
    Ok(Emission { kind, payload })
}

pub fn emissions_of_call<P: ProofKind<DefaultDB>>(
    call: &ContractCall<P, DefaultDB>,
) -> anyhow::Result<Vec<Emission>> {
    anyhow::ensure!(
        call.fallible_transcript.is_none(),
        "singleton call contains a fallible transcript"
    );
    log_items(call)?
        .iter()
        .map(emission_from_log_item)
        .collect()
}

pub fn emissions_in(
    tx: &DecodedTransaction,
    singleton: &[u8; 32],
) -> anyhow::Result<Vec<SingletonCallEmissions>> {
    tx.calls()
        .enumerate()
        .filter(|(_, (_, call))| call.address.0 .0 == *singleton)
        .map(|(call_index, (_, call))| {
            let call_index = u32::try_from(call_index)
                .context("transaction contains more calls than a u32 locator can represent")?;
            if call.fallible_transcript.is_some() {
                return Err(anyhow::Error::new(UnsupportedFallibleCall { call_index }));
            }
            Ok(SingletonCallEmissions {
                call_index,
                emissions: emissions_of_call(&call)?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_utils::{array_of, cell_from_atoms, trim};
    use midnight_base_crypto::cost_model::RunningCost;
    use midnight_base_crypto::time::Timestamp;
    use midnight_ledger_v9::structure::{
        ContractAction, ContractCall, Intent, ProofMarker, ProofVersioned, StandardTransaction,
    };
    use midnight_onchain_runtime::context::Effects;
    use midnight_onchain_runtime::ops::{LogEventType, Op, VersionedLogItem};
    use midnight_onchain_runtime::result_mode::ResultModeVerify;
    use midnight_onchain_runtime::state::{EntryPointBuf, StateValue};
    use midnight_onchain_runtime::transcript::Transcript;
    use midnight_storage::arena::Sp;
    use midnight_storage::storage::{Array, HashMap};
    use midnight_storage::DefaultDB;
    use midnight_transient_crypto::commitment::PureGeneratorPedersen;
    use midnight_transient_crypto::curve::{EmbeddedFr, Fr};
    use midnight_transient_crypto::proofs::Proof;

    type TestOp = Op<ResultModeVerify, DefaultDB>;

    const SINGLETON: [u8; 32] = [0x12; 32];
    const OTHER_CONTRACT: [u8; 32] = [0x34; 32];
    const GUARANTEED: [u8; MISC_PAYLOAD_LEN] = [0xa1; MISC_PAYLOAD_LEN];
    const FALLIBLE: [u8; MISC_PAYLOAD_LEN] = [0xf2; MISC_PAYLOAD_LEN];
    const CAPTURE_SINGLETON: &str =
        "b116cd0482b84922e761278a25d1ee2305fd6d630f0d48954d2af6537f8e214e";
    const CAPTURE_REQUEST_ID: &str =
        "1cd10eb1f4fa5c665084d24a7982b09aa321886dce77d85b5f6feee0687a414b";
    const NOTIFY_TX_156: &[u8] = include_bytes!("../fixtures/notify-tx-156.mn");
    const RESPOND_TX_161: &[u8] = include_bytes!("../fixtures/respond-tx-161.mn");
    const RESPOND_BIDIRECTIONAL_TX_181: &[u8] =
        include_bytes!("../fixtures/respond-bidirectional-tx-181.mn");

    fn hex_32(value: &str) -> [u8; 32] {
        let mut decoded = [0u8; 32];
        hex::decode_to_slice(value, &mut decoded).expect("fixture constant is 32-byte hex");
        decoded
    }

    const fn padded_name(text: &[u8]) -> [u8; MISC_NAME_LEN] {
        let mut padded = [0u8; MISC_NAME_LEN];
        let mut index = 0;
        while index < text.len() {
            padded[index] = text[index];
            index += 1;
        }
        padded
    }

    fn data_cell(name: &[u8; MISC_NAME_LEN], payload: &[u8], width: u32) -> StateValue<DefaultDB> {
        let mut bytes = name.to_vec();
        bytes.extend_from_slice(payload);
        cell_from_atoms(&[trim(&bytes)], &[width])
    }

    fn raw_log_item(
        version: u32,
        event_type: u8,
        data: StateValue<DefaultDB>,
    ) -> StateValue<DefaultDB> {
        array_of(vec![
            cell_from_atoms(&[trim(&version.to_le_bytes())], &[4]),
            cell_from_atoms(&[trim(&[event_type])], &[1]),
            data,
        ])
    }

    fn logging(value: StateValue<DefaultDB>) -> Vec<TestOp> {
        vec![
            Op::Push {
                storage: false,
                value,
            },
            Op::Log,
        ]
    }

    fn emit_ops(name: [u8; MISC_NAME_LEN], payload: [u8; MISC_PAYLOAD_LEN]) -> Vec<TestOp> {
        logging(raw_log_item(
            1,
            LogEventType::Misc as u8,
            data_cell(&name, &payload, (MISC_NAME_LEN + MISC_PAYLOAD_LEN) as u32),
        ))
    }

    fn transcript(ops: Vec<TestOp>) -> Transcript<DefaultDB> {
        Transcript {
            gas: RunningCost::default(),
            effects: Effects::default(),
            program: Array::new_from_slice(&ops),
            version: None,
        }
    }

    fn call(
        address: [u8; 32],
        guaranteed: Option<Vec<TestOp>>,
        fallible: Option<Vec<TestOp>>,
    ) -> ContractCall<ProofMarker, DefaultDB> {
        let mut call = ContractCall {
            address: Default::default(),
            entry_point: EntryPointBuf(b"test".to_vec()),
            guaranteed_transcript: guaranteed.map(|ops| Sp::new(transcript(ops))),
            fallible_transcript: fallible.map(|ops| Sp::new(transcript(ops))),
            communication_commitment: Fr::default(),
            proof: ProofVersioned::V2(Proof(Vec::new())),
        };
        call.address.0 .0 = address;
        call
    }

    fn transaction(calls: Vec<ContractCall<ProofMarker, DefaultDB>>) -> DecodedTransaction {
        let actions: Vec<ContractAction<ProofMarker, DefaultDB>> =
            calls.into_iter().map(ContractAction::from).collect();
        let intent = Intent {
            guaranteed_unshielded_offer: None,
            fallible_unshielded_offer: None,
            actions: Array::new_from_slice(&actions),
            dust_actions: None,
            ttl: Timestamp::from_secs(0),
            binding_commitment: PureGeneratorPedersen::largest_representable(),
        };
        midnight_ledger_v9::structure::Transaction::Standard(StandardTransaction {
            network_id: "undeployed".to_string(),
            intents: HashMap::new().insert(1u16, intent),
            guaranteed_coins: None,
            fallible_coins: HashMap::new(),
            binding_randomness: EmbeddedFr::default(),
        })
    }

    fn one_item(
        version: u32,
        event_type: LogEventType,
        data: StateValue<DefaultDB>,
    ) -> VersionedLogItem<DefaultDB> {
        VersionedLogItem {
            version,
            event_type,
            data,
        }
    }

    #[test]
    fn decodes_each_singleton_event_kind() {
        for (name, expected) in [
            (
                padded_name(b"SignBidirectionalEvent"),
                EmissionKind::SignBidirectional,
            ),
            (
                padded_name(b"SignatureRespondedEvent"),
                EmissionKind::SignatureResponded,
            ),
            (
                padded_name(b"RespondBidirectionalEvent"),
                EmissionKind::RespondBidirectional,
            ),
        ] {
            let item = one_item(1, LogEventType::Misc, data_cell(&name, &GUARANTEED, 288));
            assert_eq!(
                emission_from_log_item(&item).unwrap(),
                Emission {
                    kind: expected,
                    payload: GUARANTEED,
                }
            );
        }
    }

    #[test]
    fn captured_transactions_decode_the_three_singleton_emissions() {
        let singleton = hex_32(CAPTURE_SINGLETON);
        let request_id = hex_32(CAPTURE_REQUEST_ID);

        for (name, bytes, expected_kind, expected_call_index, rid_offset) in [
            (
                "notify-tx-156",
                NOTIFY_TX_156,
                EmissionKind::SignBidirectional,
                1,
                1,
            ),
            (
                "respond-tx-161",
                RESPOND_TX_161,
                EmissionKind::SignatureResponded,
                0,
                0,
            ),
            (
                "respond-bidirectional-tx-181",
                RESPOND_BIDIRECTIONAL_TX_181,
                EmissionKind::RespondBidirectional,
                0,
                0,
            ),
        ] {
            let tx: DecodedTransaction = midnight_serialize::tagged_deserialize(&mut &bytes[..])
                .unwrap_or_else(|err| panic!("{name}: captured transaction must decode: {err}"));
            let calls = emissions_in(&tx, &singleton)
                .unwrap_or_else(|err| panic!("{name}: singleton emissions must decode: {err:#}"));
            let [call] = calls.as_slice() else {
                panic!("{name}: expected exactly one singleton call, got {calls:?}");
            };
            assert_eq!(call.call_index, expected_call_index, "{name}: call index");
            let [emission] = call.emissions.as_slice() else {
                panic!(
                    "{name}: expected exactly one singleton emission, got {:?}",
                    call.emissions
                );
            };
            assert_eq!(emission.kind, expected_kind, "{name}: event kind");
            assert_eq!(
                emission.payload[rid_offset..rid_offset + request_id.len()],
                request_id,
                "{name}: request id at the event-specific payload offset"
            );
        }
    }

    #[test]
    fn rejects_fallible_singleton_calls() {
        let tx = transaction(vec![call(
            SINGLETON,
            Some(emit_ops(padded_name(b"SignBidirectionalEvent"), GUARANTEED)),
            Some(emit_ops(padded_name(b"SignatureRespondedEvent"), FALLIBLE)),
        )]);

        let err = emissions_in(&tx, &SINGLETON)
            .expect_err("a fallible singleton call is outside the supported integration contract");
        let unsupported = err
            .downcast_ref::<UnsupportedFallibleCall>()
            .unwrap_or_else(|| panic!("unexpected rejection: {err:#}"));
        assert_eq!(unsupported.call_index, 0);
    }

    #[test]
    fn rejects_singleton_event_schema_drift() {
        let known_name = padded_name(b"SignBidirectionalEvent");
        let foreign_name = padded_name(b"ForeignEvent");
        for (case, logged_value) in [
            (
                "foreign name",
                raw_log_item(
                    1,
                    LogEventType::Misc as u8,
                    data_cell(&foreign_name, &GUARANTEED, 288),
                ),
            ),
            (
                "version two",
                raw_log_item(
                    2,
                    LogEventType::Misc as u8,
                    data_cell(&known_name, &GUARANTEED, 288),
                ),
            ),
            (
                "event type nine",
                raw_log_item(
                    1,
                    LogEventType::Unpaused as u8,
                    data_cell(&known_name, &GUARANTEED, 288),
                ),
            ),
            (
                "Bytes<256>",
                raw_log_item(
                    1,
                    LogEventType::Misc as u8,
                    data_cell(&known_name, &GUARANTEED[..224], 256),
                ),
            ),
            (
                "version-zero VM fallback",
                data_cell(&known_name, &GUARANTEED, 288),
            ),
        ] {
            let tx = transaction(vec![call(SINGLETON, Some(logging(logged_value)), None)]);
            let error = emissions_in(&tx, &SINGLETON).unwrap_err();
            assert!(
                error.to_string().contains("emission-schema"),
                "{case}: {error:#}"
            );
        }
    }

    #[test]
    fn the_vm_rejects_log_without_a_pushed_value() {
        let tx = transaction(vec![call(SINGLETON, Some(vec![Op::Log]), None)]);

        assert!(emissions_in(&tx, &SINGLETON).is_err());
    }

    #[test]
    fn ignores_foreign_calls_but_preserves_transaction_call_indices() {
        let tx = transaction(vec![
            call(
                OTHER_CONTRACT,
                Some(emit_ops(padded_name(b"SignBidirectionalEvent"), GUARANTEED)),
                None,
            ),
            call(
                SINGLETON,
                Some(emit_ops(
                    padded_name(b"RespondBidirectionalEvent"),
                    FALLIBLE,
                )),
                None,
            ),
        ]);

        assert_eq!(
            emissions_in(&tx, &SINGLETON).unwrap(),
            vec![SingletonCallEmissions {
                call_index: 1,
                emissions: vec![Emission {
                    kind: EmissionKind::RespondBidirectional,
                    payload: FALLIBLE,
                }],
            }]
        );
    }

    #[test]
    fn retains_a_silent_singleton_call() {
        let tx = transaction(vec![call(SINGLETON, None, None)]);

        assert_eq!(
            emissions_in(&tx, &SINGLETON).unwrap(),
            vec![SingletonCallEmissions {
                call_index: 0,
                emissions: Vec::new(),
            }]
        );
    }
}
