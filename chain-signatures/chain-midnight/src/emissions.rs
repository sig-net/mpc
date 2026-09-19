//! Singleton contract emissions recovered by executing transaction transcripts with the ledger VM.

use anyhow::Context as _;
use midnight_base_crypto::fab::{AlignmentAtom, AlignmentSegment};
use midnight_ledger_v9::structure::{ContractCall, ProofKind, ProofMarker, Signature, Transaction};
use midnight_onchain_runtime::context::{Effects, QueryContext};
use midnight_onchain_runtime::cost_model::INITIAL_COST_MODEL;
use midnight_onchain_runtime::ops::{LogEventType, Op, VersionedLogItem};
use midnight_onchain_runtime::result_mode::ResultModeVerify;
use midnight_onchain_runtime::state::{ChargedState, StateValue};
use midnight_onchain_runtime::transcript::Transcript;
use midnight_storage::storage::Array;
use midnight_storage::DefaultDB;

const MISC_NAME_LEN: usize = 32;
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TranscriptPhase {
    Guaranteed,
    Fallible,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SingletonCallEmissions {
    /// Position in [`DecodedTransaction::calls`] before filtering or execution-order sorting.
    pub call_index: u32,
    pub physical_segment: u16,
    pub phase: TranscriptPhase,
    pub emissions: Vec<Emission>,
}

fn log_items<P: ProofKind<DefaultDB>>(
    call: &ContractCall<P, DefaultDB>,
    transcript: &Transcript<DefaultDB>,
) -> anyhow::Result<Vec<VersionedLogItem<DefaultDB>>> {
    let program = Vec::from(&transcript.program);
    // Live ingestion establishes TxApplied first; transaction normalization is
    // the ledger's responsibility. Only constrain what we can replay correctly.
    // Noops and checkpoints only consume gas during VM execution; they cannot
    // observe or change the stack, state, effects or logs. Ignore them for shape
    // validation, but replay the original program, preserving its gas charges.
    let log_program = program
        .iter()
        .filter(|op| !matches!(op, Op::Noop { .. } | Op::Ckpt))
        .collect::<Vec<_>>();
    let (pairs, remainder) = log_program.as_chunks::<2>();
    anyhow::ensure!(
        remainder.is_empty()
            && pairs
                .iter()
                .all(|pair| matches!(pair, [Op::Push { storage: false, .. }, Op::Log])),
        "unsupported-singleton-transcript: expected literal non-storage Push/Log pairs with Noops and checkpoints"
    );
    anyhow::ensure!(
        transcript.effects == Effects::default(),
        "unsupported-singleton-transcript: expected empty declared effects"
    );
    // The ledger starts each phase with a fresh query context. The accepted subset
    // cannot observe its omitted contract state, balance or block context.
    let context = QueryContext::new(
        ChargedState::new(StateValue::Array(Array::new())),
        call.address,
    );
    let result = context
        .query::<ResultModeVerify>(&program, None, &INITIAL_COST_MODEL)
        .context("singleton transcript rejected by the ledger VM")?;
    anyhow::ensure!(
        result.context.effects == transcript.effects,
        "unsupported-singleton-transcript: replayed effects differ from declared effects"
    );
    Ok(result.events)
}

fn emission_from_log_item(item: &VersionedLogItem<DefaultDB>) -> anyhow::Result<Emission> {
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

fn emissions_of_transcript<P: ProofKind<DefaultDB>>(
    call: &ContractCall<P, DefaultDB>,
    transcript: &Transcript<DefaultDB>,
) -> anyhow::Result<Vec<Emission>> {
    log_items(call, transcript)?
        .iter()
        .map(emission_from_log_item)
        .collect()
}

/// Decode a call's guaranteed then fallible emissions without establishing its outcome.
/// Live ingestion must establish full transaction success before using these values.
pub fn emissions_of_call<P: ProofKind<DefaultDB>>(
    call: &ContractCall<P, DefaultDB>,
) -> anyhow::Result<Vec<Emission>> {
    let mut emissions = Vec::new();
    for transcript in [
        call.guaranteed_transcript.as_deref(),
        call.fallible_transcript.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        emissions.extend(emissions_of_transcript(call, transcript)?);
    }
    Ok(emissions)
}

/// Extract only after the caller establishes that the whole transaction applied.
/// A partial-success transaction cannot use this path: its failed phases must not emit.
pub fn emissions_in(
    tx: &DecodedTransaction,
    singleton: &[u8; 32],
) -> anyhow::Result<Vec<SingletonCallEmissions>> {
    let mut calls = tx
        .calls()
        .enumerate()
        .filter(|(_, (_, call))| call.address.0 .0 == *singleton)
        .map(|(call_index, (physical_segment, call))| {
            Ok((
                physical_segment,
                u32::try_from(call_index)
                    .context("transaction contains more calls than a u32 locator can represent")?,
                call,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    // Ledger application runs all guaranteed phases before any fallible phase,
    // sorting physical segments numerically and retaining action order within each.
    calls.sort_by_key(|(segment, call_index, _)| (*segment, *call_index));
    let mut decoded = Vec::new();
    for phase in [TranscriptPhase::Guaranteed, TranscriptPhase::Fallible] {
        for (physical_segment, call_index, call) in &calls {
            let transcript = match phase {
                TranscriptPhase::Guaranteed => call.guaranteed_transcript.as_deref(),
                TranscriptPhase::Fallible => call.fallible_transcript.as_deref(),
            };
            let emissions = if let Some(transcript) = transcript {
                emissions_of_transcript(call, transcript).with_context(|| {
                    format!("singleton call {call_index}, segment {physical_segment}, {phase:?}")
                })?
            } else if phase == TranscriptPhase::Guaranteed && call.fallible_transcript.is_none() {
                Vec::new()
            } else {
                continue;
            };
            decoded.push(SingletonCallEmissions {
                call_index: *call_index,
                physical_segment: *physical_segment,
                phase,
                emissions,
            });
        }
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_utils::{array_of, cell_from_atoms, hex_32, trim};
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
        let fallible = fallible.map(|mut ops| {
            if guaranteed.is_some() {
                ops.insert(0, Op::Ckpt);
            }
            ops
        });
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
    fn captured_applied_fallible_notifications_decode() {
        for (bytes, request) in [
            (
                include_bytes!("../fixtures/fallible-deposit-tx-432.mn").as_slice(),
                "ee3385dda706877d30e802a0df57c228310016889104b8fb361c830a58d1e500",
            ),
            (
                include_bytes!("../fixtures/fallible-withdraw-tx-458.mn").as_slice(),
                "2b39323a4680ccb0b379e61e4887375190e2d5e14f8f2c0ac81d7df4ca6ba400",
            ),
            (
                include_bytes!("../fixtures/fallible-supply-tx-368.mn").as_slice(),
                "32aeb17a73a84173bce929c0225a50b2c6ffcc55a97d2c6787204fcc7cba9600",
            ),
        ] {
            let tx: DecodedTransaction =
                midnight_serialize::tagged_deserialize(&mut &bytes[..]).unwrap();
            let (_, singleton_call) = tx.calls().nth(1).unwrap();
            assert!(singleton_call.guaranteed_transcript.is_none());
            assert!(singleton_call.fallible_transcript.is_some());
            let calls = emissions_in(&tx, &singleton_call.address.0 .0).unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].call_index, 1);
            assert_eq!(calls[0].phase, TranscriptPhase::Fallible);
            assert_eq!(calls[0].emissions.len(), 1);
            assert_eq!(calls[0].emissions[0].kind, EmissionKind::SignBidirectional);
            assert_eq!(calls[0].emissions[0].payload[1..33], hex_32(request));
        }
    }

    #[test]
    fn decodes_all_event_kinds_in_either_phase() {
        for (name, kind) in [
            (SIGN_BIDIRECTIONAL_EVENT, EmissionKind::SignBidirectional),
            (SIGNATURE_RESPONDED_EVENT, EmissionKind::SignatureResponded),
            (
                RESPOND_BIDIRECTIONAL_EVENT,
                EmissionKind::RespondBidirectional,
            ),
        ] {
            for phase in [TranscriptPhase::Guaranteed, TranscriptPhase::Fallible] {
                let ops = emit_ops(name, GUARANTEED);
                let (guaranteed, fallible) = match phase {
                    TranscriptPhase::Guaranteed => (Some(ops), None),
                    TranscriptPhase::Fallible => (None, Some(ops)),
                };
                let decoded = emissions_in(
                    &transaction(vec![call(SINGLETON, guaranteed, fallible)]),
                    &SINGLETON,
                )
                .unwrap();
                assert_eq!(decoded.len(), 1);
                assert_eq!(decoded[0].phase, phase);
                assert_eq!(decoded[0].physical_segment, 1);
                assert_eq!(
                    decoded[0].emissions,
                    vec![Emission {
                        kind,
                        payload: GUARANTEED
                    }]
                );
            }
        }
    }

    #[test]
    fn decodes_both_phases_with_required_fallible_checkpoint() {
        let call = call(
            SINGLETON,
            Some(emit_ops(SIGN_BIDIRECTIONAL_EVENT, GUARANTEED)),
            Some(emit_ops(RESPOND_BIDIRECTIONAL_EVENT, FALLIBLE)),
        );
        assert_eq!(
            call.fallible_transcript.as_ref().unwrap().program.get(0),
            Some(&Op::Ckpt)
        );
        assert_eq!(
            emissions_of_call(&call).unwrap(),
            vec![
                Emission {
                    kind: EmissionKind::SignBidirectional,
                    payload: GUARANTEED
                },
                Emission {
                    kind: EmissionKind::RespondBidirectional,
                    payload: FALLIBLE
                },
            ]
        );
    }

    #[test]
    fn orders_phases_then_segments_and_actions_preserving_native_call_indices() {
        let make = |marker| {
            call(
                SINGLETON,
                Some(emit_ops(
                    SIGN_BIDIRECTIONAL_EVENT,
                    [marker; MISC_PAYLOAD_LEN],
                )),
                Some(emit_ops(
                    RESPOND_BIDIRECTIONAL_EVENT,
                    [marker + 1; MISC_PAYLOAD_LEN],
                )),
            )
        };
        let DecodedTransaction::Standard(mut tx) = transaction(vec![make(20), make(30)]) else {
            unreachable!()
        };
        let later = (*tx.intents.get(&1).unwrap()).clone();
        let DecodedTransaction::Standard(earlier) = transaction(vec![
            call(OTHER_CONTRACT, None, Some(vec![Op::Root])),
            make(10),
        ]) else {
            unreachable!()
        };
        let first = (*earlier.intents.get(&1).unwrap()).clone();
        tx.intents = HashMap::new().insert(500u16, later).insert(2u16, first);
        let tx = DecodedTransaction::Standard(tx);
        let native = tx
            .calls()
            .enumerate()
            .filter(|(_, (_, call))| call.address.0 .0 == SINGLETON)
            .map(|(index, (segment, _))| (segment, index as u32))
            .collect::<Vec<_>>();
        let mut expected = native.clone();
        expected.sort();
        let decoded = emissions_in(&tx, &SINGLETON).unwrap();
        assert_eq!(decoded.len(), 6);
        for (phase_index, phase) in [TranscriptPhase::Guaranteed, TranscriptPhase::Fallible]
            .into_iter()
            .enumerate()
        {
            let records = &decoded[phase_index * 3..phase_index * 3 + 3];
            assert_eq!(
                records
                    .iter()
                    .map(|r| (r.physical_segment, r.call_index))
                    .collect::<Vec<_>>(),
                expected
            );
            assert!(records.iter().all(|r| r.phase == phase));
            assert_eq!(
                records
                    .iter()
                    .map(|r| r.emissions[0].payload[0])
                    .collect::<Vec<_>>(),
                vec![
                    10 + phase_index as u8,
                    20 + phase_index as u8,
                    30 + phase_index as u8
                ]
            );
        }
    }

    #[test]
    fn decodes_noops_without_revalidating_normalization_in_either_phase() {
        let [push, log]: [TestOp; 2] = emit_ops(SIGN_BIDIRECTIONAL_EVENT, GUARANTEED)
            .try_into()
            .unwrap();
        for checkpoint in [false, true] {
            let mut program = vec![];
            if checkpoint {
                program.push(Op::Ckpt);
            }
            program.extend([
                Op::Noop { n: 0 },
                // Deliberately adjacent: transaction normalization belongs to the
                // ledger. This decoder fixture is not a ledger-valid transaction.
                Op::Noop { n: 2 },
                push.clone(),
                Op::Noop { n: 3 },
                log.clone(),
                Op::Noop { n: 0 },
            ]);
            for fallible in [false, true] {
                let call = if fallible {
                    call(SINGLETON, None, Some(program.clone()))
                } else {
                    call(SINGLETON, Some(program.clone()), None)
                };
                assert_eq!(
                    emissions_of_call(&call).unwrap(),
                    vec![Emission {
                        kind: EmissionKind::SignBidirectional,
                        payload: GUARANTEED,
                    }]
                );
            }
        }
    }

    #[test]
    fn decodes_checkpoints_anywhere_in_either_phase() {
        // These are decoder/VM fixtures, not proven transactions. Full transaction
        // validity and the actual phase boundary are established before extraction.
        let first = emit_ops(SIGN_BIDIRECTIONAL_EVENT, GUARANTEED);
        let second = emit_ops(SIGNATURE_RESPONDED_EVENT, FALLIBLE);
        let original = [first, second].concat();
        let expected = vec![
            Emission {
                kind: EmissionKind::SignBidirectional,
                payload: GUARANTEED,
            },
            Emission {
                kind: EmissionKind::SignatureResponded,
                payload: FALLIBLE,
            },
        ];
        // Before, inside and between Push/Log pairs, and after the last Log.
        let mut programs: Vec<_> = (0..=original.len())
            .map(|position| {
                let mut program = original.clone();
                program.insert(position, Op::Ckpt);
                program
            })
            .collect();
        programs.push(vec![
            Op::Ckpt,
            Op::Ckpt,
            original[0].clone(),
            Op::Noop { n: 0 },
            Op::Ckpt,
            original[1].clone(),
            Op::Ckpt,
            original[2].clone(),
            Op::Ckpt,
            Op::Noop { n: 2 },
            original[3].clone(),
            Op::Ckpt,
        ]);
        for program in programs {
            for fallible in [false, true] {
                let call = if fallible {
                    call(SINGLETON, None, Some(program.clone()))
                } else {
                    call(SINGLETON, Some(program.clone()), None)
                };
                assert_eq!(emissions_of_call(&call).unwrap(), expected);
            }
        }
        for fallible in [false, true] {
            let program = vec![Op::Ckpt, Op::Noop { n: 0 }, Op::Ckpt];
            let call = if fallible {
                call(SINGLETON, None, Some(program))
            } else {
                call(SINGLETON, Some(program), None)
            };
            assert!(emissions_of_call(&call).unwrap().is_empty());
        }
    }

    #[test]
    fn rejects_context_dependent_programs_in_either_phase() {
        let good = emit_ops(SIGN_BIDIRECTIONAL_EVENT, GUARANTEED);
        let mut storage_push = good.clone();
        if let Op::Push { storage, .. } = &mut storage_push[0] {
            *storage = true;
        }
        for program in [
            vec![Op::Root, Op::Log],
            vec![Op::Ckpt, Op::Root, Op::Ckpt, Op::Log],
            vec![Op::Log],
            storage_push,
            {
                let mut ops = good.clone();
                ops.push(Op::Pop);
                ops
            },
        ] {
            for fallible in [false, true] {
                let call = if fallible {
                    call(SINGLETON, None, Some(program.clone()))
                } else {
                    call(SINGLETON, Some(program.clone()), None)
                };
                let error = emissions_in(&transaction(vec![call]), &SINGLETON).unwrap_err();
                assert!(format!("{error:#}").contains("unsupported-singleton-transcript"));
            }
        }
    }

    #[test]
    fn rejects_nonempty_declared_effects_in_either_phase() {
        for fallible in [false, true] {
            let mut transcript = transcript(emit_ops(SIGN_BIDIRECTIONAL_EVENT, GUARANTEED));
            transcript.effects.unshielded_mints = HashMap::new().insert(Default::default(), 1);
            let mut call = call(SINGLETON, None, None);
            if fallible {
                call.fallible_transcript = Some(Sp::new(transcript));
            } else {
                call.guaranteed_transcript = Some(Sp::new(transcript));
            }
            let error = emissions_in(&transaction(vec![call]), &SINGLETON).unwrap_err();
            assert!(format!("{error:#}").contains("expected empty declared effects"));
        }
    }

    #[test]
    fn a_malformed_fallible_log_rejects_the_whole_extraction() {
        let tx = transaction(vec![call(
            SINGLETON,
            Some(emit_ops(SIGN_BIDIRECTIONAL_EVENT, GUARANTEED)),
            Some(logging(raw_log_item(
                2,
                LogEventType::Misc as u8,
                data_cell(&SIGN_BIDIRECTIONAL_EVENT, &FALLIBLE, 288),
            ))),
        )]);
        let error = emissions_in(&tx, &SINGLETON).unwrap_err();
        assert!(format!("{error:#}").contains("emission-schema"));
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
                format!("{error:#}").contains("emission-schema"),
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
                physical_segment: 1,
                phase: TranscriptPhase::Guaranteed,
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
                physical_segment: 1,
                phase: TranscriptPhase::Guaranteed,
                emissions: Vec::new(),
            }]
        );
    }
}
