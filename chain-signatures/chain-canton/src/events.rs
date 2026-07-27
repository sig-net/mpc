//! Canton event processing, verification, and tests.

use crate::daml::{
    RespondBidirectionalEventPayload, SignBidirectionalRequestedEvent,
    SignatureRespondedEventPayload,
};
use crate::ledger_api;
use crate::signing::{parse_canton_signature, CantonSignBidirectionalRequestedEvent};
use mpc_primitives::{Chain, ChainEvent, RespondBidirectionalEvent, SignatureRespondedEvent};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

// TODO: this is a duplicate of the same function in `mpc-node`, consider moving to shared crate like `mpc-utils` or something.
pub fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

/// Process a single Canton event from a WebSocket transaction update.
///
/// `tx_events` is the full list of events in the transaction, used for
/// defense-in-depth verification (signatory checks, ExercisedEvent check).
pub async fn process_canton_event(
    event: &ledger_api::Event,
    tx_events: &[ledger_api::Event],
    events_tx: &mpsc::Sender<ChainEvent>,
    signer_contract_id: &str,
) {
    let created = match event {
        ledger_api::Event::CreatedEvent(created) => created,
        ledger_api::Event::ArchivedEvent(_) | ledger_api::Event::ExercisedEvent(_) => return,
    };

    let template_id = &created.template_id;

    if ledger_api::template_suffix_matches(
        template_id,
        ledger_api::templates::SIGN_BIDIRECTIONAL_EVENT,
    ) {
        match serde_json::from_value::<SignBidirectionalRequestedEvent>(created.payload.clone()) {
            Ok(raw) => {
                if let Err(e) = verify_sign_event(&raw, created, tx_events, signer_contract_id) {
                    tracing::warn!(%e, "canton SignBidirectionalEvent failed verification — dropping");
                    return;
                }

                let canton_event = match CantonSignBidirectionalRequestedEvent::from_created(
                    created.contract_id.clone(),
                    raw,
                ) {
                    Ok(event) => event,
                    Err(e) => {
                        tracing::warn!(%e, "failed to parse SignBidirectionalEvent");
                        return;
                    }
                };
                let request_id = canton_event.generate_request_id();
                let entropy: [u8; 32] = alloy::primitives::keccak256(request_id).into();
                match canton_event.generate_sign_request(entropy, current_unix_timestamp()) {
                    Ok(request) => {
                        if events_tx
                            .send(ChainEvent::SignRequest {
                                request,
                                block_timestamp: None,
                            })
                            .await
                            .is_err()
                        {
                            tracing::error!("canton event channel closed");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(%e, "failed to generate canton sign request");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(%e, "failed to parse SignBidirectionalEvent");
            }
        }
    } else if ledger_api::template_suffix_matches(
        template_id,
        ledger_api::templates::SIGNATURE_RESPONDED_EVENT,
    ) {
        match parse_signature_responded_event(created) {
            Ok(event) => {
                if events_tx.send(ChainEvent::Respond(event)).await.is_err() {
                    tracing::error!("canton event channel closed");
                }
            }
            Err(e) => {
                tracing::warn!(%e, "failed to parse SignatureRespondedEvent");
            }
        }
    } else if ledger_api::template_suffix_matches(
        template_id,
        ledger_api::templates::RESPOND_BIDIRECTIONAL_EVENT,
    ) {
        match serde_json::from_value::<RespondBidirectionalEventPayload>(created.payload.clone()) {
            Ok(payload) => {
                let mut request_id = [0u8; 32];
                if let Err(e) = hex::decode_to_slice(&payload.request_id, &mut request_id) {
                    tracing::warn!(%e, "invalid request_id hex");
                } else {
                    let signature = match parse_canton_signature(&payload.signature) {
                        Ok(signature) => signature,
                        Err(e) => {
                            tracing::warn!(%e, "invalid signature in canton RespondBidirectionalEvent");
                            return;
                        }
                    };
                    if events_tx
                        .send(ChainEvent::RespondBidirectional(
                            RespondBidirectionalEvent {
                                request_id,
                                signature,
                                chain: Chain::Canton,
                            },
                        ))
                        .await
                        .is_err()
                    {
                        tracing::error!("canton event channel closed");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(%e, "failed to parse RespondBidirectionalEvent");
            }
        }
    }
}

/// Verify a SignBidirectionalEvent before processing it.
///
/// These checks are defense-in-depth on top of the Daml ledger guarantees:
/// 1. Operators from the payload must be actual signatories on the CreatedEvent
/// 2. Requester must be a signatory
/// 3. An ExercisedEvent with choice "RequestSignature" on Signer:Signer must
///    exist in the same transaction — proves the event was created through the
///    correct Daml code path, not fabricated
fn verify_sign_event(
    event: &SignBidirectionalRequestedEvent,
    created: &ledger_api::CreatedEvent,
    tx_events: &[ledger_api::Event],
    signer_contract_id: &str,
) -> anyhow::Result<()> {
    let signatories: HashSet<&str> = created.signatories.iter().map(|s| s.as_str()).collect();

    // Check 1: operators must be signatories (hard error)
    for op in &event.operators {
        if !signatories.contains(op.as_str()) {
            anyhow::bail!(
                "operator {op} is in contract payload but not in CreatedEvent.signatories — possible forgery"
            );
        }
    }

    // Check 2: requester must be a signatory (hard error)
    if !signatories.contains(event.requester.as_str()) {
        anyhow::bail!(
            "requester {} is not in CreatedEvent.signatories — possible forgery",
            event.requester
        );
    }

    // Check 3: ExercisedEvent with choice "RequestSignature" on the pinned
    // Signer contract must exist in the same transaction. Exact contract ID
    // match since the operator pinned it via CLI.
    // NOTE: after a DAR upgrade/redeployment the contract ID changes — this
    // check will reject all events until the node is restarted with the new ID.
    let has_exercise = tx_events.iter().any(|e| {
        matches!(
            e,
            ledger_api::Event::ExercisedEvent(ex)
                if ex.choice == "RequestSignature"
                    && ex.contract_id == signer_contract_id
        )
    });
    if !has_exercise {
        anyhow::bail!(
            "no ExercisedEvent with choice RequestSignature on contract {signer_contract_id} found in transaction"
        );
    }

    Ok(())
}

fn parse_signature_responded_event(
    created: &ledger_api::CreatedEvent,
) -> anyhow::Result<SignatureRespondedEvent> {
    let payload: SignatureRespondedEventPayload = serde_json::from_value(created.payload.clone())?;
    let mut request_id = [0u8; 32];
    hex::decode_to_slice(&payload.request_id, &mut request_id)
        .map_err(|e| anyhow::anyhow!("invalid request_id hex: {e}"))?;

    Ok(SignatureRespondedEvent {
        request_id,
        signature: parse_canton_signature(&payload.signature)?,
        chain: Chain::Canton,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daml::{CantonSignature, EcdsaSigData, EvmType2TransactionParams, TxParams};
    use crate::signing::der_encode_signature;
    use k256::AffinePoint;
    use mpc_chain_integration_core::utils::stream::chain_event_channel;
    use mpc_primitives::Signature;
    use serde_json::json;

    fn sample_tx_params() -> TxParams {
        TxParams::EvmType2TxParams(EvmType2TransactionParams {
            chain_id: format!("{:064x}", 1u64),
            nonce: format!("{:064x}", 0u64),
            max_priority_fee_per_gas: format!("{:064x}", 1u64),
            max_fee_per_gas: format!("{:064x}", 2u64),
            gas_limit: format!("{:064x}", 21_000u64),
            to: Some(hex::encode([3u8; 20])),
            value: format!("{:064x}", 0u64),
            calldata: String::new(),
            access_list: Vec::new(),
        })
    }

    fn sample_sign_event() -> SignBidirectionalRequestedEvent {
        SignBidirectionalRequestedEvent {
            operators: vec!["operator-1".to_string()],
            sender: hex::encode([7u8; 32]),
            requester: "requester-1".to_string(),
            sig_network: "testnet".to_string(),
            tx_params: sample_tx_params(),
            caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
            key_version: 0,
            path: "m/0".to_string(),
            algo: "secp256k1".to_string(),
            dest: Chain::Ethereum.to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: "[]".to_string(),
            respond_serialization_schema: "[]".to_string(),
        }
    }

    fn sample_created_event(signatories: &[&str]) -> ledger_api::CreatedEvent {
        ledger_api::CreatedEvent {
            contract_id: "cid-1".to_string(),
            template_id: ledger_api::templates::SIGN_BIDIRECTIONAL_EVENT.to_string(),
            payload: json!({}),
            created_event_blob: None,
            signatories: signatories.iter().map(|s| (*s).to_string()).collect(),
            witness_parties: Vec::new(),
            node_id: Some(1),
            package_name: None,
        }
    }

    fn sample_exercised_event(contract_id: &str) -> ledger_api::Event {
        ledger_api::Event::ExercisedEvent(ledger_api::ExercisedEvent {
            contract_id: contract_id.to_string(),
            template_id: "pkg:Signer:Signer".to_string(),
            choice: "RequestSignature".to_string(),
            acting_parties: Vec::new(),
            consuming: false,
            node_id: Some(2),
            last_descendant_node_id: Some(2),
            package_name: None,
        })
    }

    fn sample_canton_signature() -> CantonSignature {
        let signature = Signature::new(AffinePoint::GENERATOR, k256::Scalar::from(9u64), 0);
        let der = hex::encode(der_encode_signature(&signature).expect("signature should encode"));
        CantonSignature::EcdsaSig(EcdsaSigData {
            der,
            recovery_id: 0,
        })
    }

    #[test]
    fn verify_sign_event_rejects_missing_operator_signatory() {
        let event = sample_sign_event();
        let created = sample_created_event(&["requester-1"]);
        let tx_events = vec![sample_exercised_event("signer-contract")];

        let err = verify_sign_event(&event, &created, &tx_events, "signer-contract")
            .expect_err("verification should fail");
        assert!(err.to_string().contains("operator operator-1"));
    }

    #[test]
    fn verify_sign_event_rejects_missing_requester_signatory() {
        let event = sample_sign_event();
        let created = sample_created_event(&["operator-1"]);
        let tx_events = vec![sample_exercised_event("signer-contract")];

        let err = verify_sign_event(&event, &created, &tx_events, "signer-contract")
            .expect_err("verification should fail");
        assert!(err.to_string().contains("requester requester-1"));
    }

    #[test]
    fn verify_sign_event_rejects_missing_exercised_event() {
        let event = sample_sign_event();
        let created = sample_created_event(&["operator-1", "requester-1"]);
        let tx_events = Vec::new();

        let err = verify_sign_event(&event, &created, &tx_events, "signer-contract")
            .expect_err("verification should fail");
        assert!(err.to_string().contains("no ExercisedEvent"));
    }

    #[test]
    fn parse_signature_responded_event_rejects_invalid_hex() {
        let created = ledger_api::CreatedEvent {
            contract_id: "cid-respond".to_string(),
            template_id: ledger_api::templates::SIGNATURE_RESPONDED_EVENT.to_string(),
            payload: json!({
                "requestId": "zz",
                "responder": "alice",
                "signature": {
                    "tag": "EcdsaSig",
                    "value": {
                        "der": "00",
                        "recoveryId": "0"
                    }
                }
            }),
            created_event_blob: None,
            signatories: Vec::new(),
            witness_parties: Vec::new(),
            node_id: None,
            package_name: None,
        };

        let err = parse_signature_responded_event(&created).expect_err("invalid hex should fail");
        assert!(err.to_string().contains("invalid request_id hex"));
    }

    #[test]
    fn parse_respond_bidirectional_event_parses_valid_payload() {
        let created = ledger_api::CreatedEvent {
            contract_id: "cid-respond-bidir".to_string(),
            template_id: ledger_api::templates::RESPOND_BIDIRECTIONAL_EVENT.to_string(),
            payload: json!({
                "requestId": hex::encode([5u8; 32]),
                "responder": "alice",
                "serializedOutput": hex::encode([8u8, 9u8]),
                "signature": sample_canton_signature(),
            }),
            created_event_blob: None,
            signatories: Vec::new(),
            witness_parties: Vec::new(),
            node_id: None,
            package_name: None,
        };

        let payload: RespondBidirectionalEventPayload =
            serde_json::from_value(created.payload.clone()).expect("payload should parse");
        let mut request_id = [0u8; 32];
        hex::decode_to_slice(&payload.request_id, &mut request_id).unwrap();
        assert_eq!(request_id, [5u8; 32]);
        assert_eq!(payload.responder, "alice");
        assert_eq!(
            hex::decode(&payload.serialized_output).unwrap(),
            vec![8u8, 9u8]
        );
    }

    #[tokio::test]
    async fn process_canton_event_routes_respond_without_catchup_completed() {
        let created = ledger_api::CreatedEvent {
            contract_id: "cid-respond".to_string(),
            template_id: ledger_api::templates::SIGNATURE_RESPONDED_EVENT.to_string(),
            payload: json!({
                "requestId": hex::encode([6u8; 32]),
                "responder": "alice",
                "signature": sample_canton_signature(),
            }),
            created_event_blob: None,
            signatories: Vec::new(),
            witness_parties: Vec::new(),
            node_id: None,
            package_name: None,
        };
        let (events_tx, mut events_rx) = chain_event_channel();

        process_canton_event(
            &ledger_api::Event::CreatedEvent(created),
            &[],
            &events_tx,
            "signer-contract",
        )
        .await;

        match events_rx.recv().await {
            Some(ChainEvent::Respond(event)) => {
                assert_eq!(event.chain, Chain::Canton);
                assert_eq!(event.request_id, [6u8; 32]);
            }
            other => panic!("expected Canton respond event, got {other:?}"),
        }
        assert!(
            events_rx.try_recv().is_err(),
            "unexpected extra event emitted"
        );
    }
}
