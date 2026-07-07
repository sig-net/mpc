//! Converts reassembled SGN1 groups into node `ChainEvent`s, applying the
//! MPC-side validation rules from the wire spec: recompute-and-drop request
//! ids, keyVersion in [1, LATEST], payload must be a nonzero secp256k1 scalar,
//! bidirectional caip2 must map to a known chain. deposit is fixed to 1
//! (Midnight has no deposit gating — acknowledged trust-model gap).

use crate::requests;
use crate::wire::{recompute_request_id, EventPart, RequestKind};
use k256::Scalar;
use mpc_primitives::{
    Chain, ChainEvent, IndexedSignRequest, RespondBidirectionalEvent, ScalarExt, SignArgs,
    SignBidirectionalEvent, SignId, SignatureRespondedEvent, LATEST_MPC_KEY_VERSION,
};

fn keccak(bytes: &[u8]) -> [u8; 32] {
    alloy_primitives::keccak256(bytes).0
}

fn check_key_version(key_version: u32) -> anyhow::Result<()> {
    anyhow::ensure!(
        (1..=LATEST_MPC_KEY_VERSION).contains(&key_version),
        "unsupported keyVersion {key_version} (must be 1..={LATEST_MPC_KEY_VERSION})"
    );
    Ok(())
}

fn payload_scalar(payload: [u8; 32]) -> anyhow::Result<Scalar> {
    let scalar = <Scalar as ScalarExt>::from_bytes(payload)
        .ok_or_else(|| anyhow::anyhow!("payload is not a valid secp256k1 scalar"))?;
    anyhow::ensure!(scalar != Scalar::ZERO, "payload scalar must be nonzero");
    Ok(scalar)
}

/// Recompute the request id from the tails and require equality with the id
/// every part carried (provenance rule — request kinds only; responded events
/// carry the answered request's id verbatim).
fn check_request_id(request_id: [u8; 32], parts: &[EventPart]) -> anyhow::Result<()> {
    let tails: Vec<[u8; 224]> = parts.iter().map(|p| p.tail).collect();
    anyhow::ensure!(
        recompute_request_id(&tails) == request_id,
        "request id does not rehash from the received tails — dropping"
    );
    Ok(())
}

pub(crate) fn group_to_chain_event(
    kind: RequestKind,
    request_id: [u8; 32],
    parts: &[EventPart],
    contract_address: &str,
    sender_raw32: [u8; 32],
    unix_now: u64,
) -> anyhow::Result<ChainEvent> {
    match kind {
        RequestKind::Sign => {
            check_request_id(request_id, parts)?;
            let body = requests::decode_sign(parts)?;
            check_key_version(body.key_version)?;
            let payload = payload_scalar(body.payload)?;
            let path = hex::encode(body.commitment);
            let epsilon =
                mpc_crypto::kdf::derive_epsilon_midnight(body.key_version, contract_address, &path);
            let request = IndexedSignRequest::sign(
                SignId::new(request_id),
                SignArgs {
                    entropy: keccak(&request_id),
                    epsilon,
                    payload,
                    path,
                    key_version: body.key_version,
                },
                Chain::Midnight,
                unix_now,
            );
            Ok(ChainEvent::SignRequest {
                request,
                block_timestamp: None,
            })
        }
        RequestKind::SignBidirectional => {
            check_request_id(request_id, parts)?;
            let body = requests::decode_sign_bidirectional(parts)?;
            check_key_version(body.key_version)?;
            // The caip2 id must route to a chain this node can watch.
            Chain::from_caip2_chain_id(&body.caip2_id)
                .map_err(|e| anyhow::anyhow!("unroutable caip2 id {}: {e}", body.caip2_id))?;
            let serialized_transaction = requests::build_unsigned_eip1559(&body)?;
            let payload = payload_scalar(keccak(&serialized_transaction))?;
            let path = hex::encode(body.commitment);
            let epsilon =
                mpc_crypto::kdf::derive_epsilon_midnight(body.key_version, contract_address, &path);
            let event = SignBidirectionalEvent {
                sender: sender_raw32,
                serialized_transaction,
                caip2_id: body.caip2_id.clone(),
                key_version: body.key_version,
                deposit: 1,
                path: path.clone(),
                algo: String::new(),
                dest: body.dest.clone(),
                params: body.params.clone(),
                output_deserialization_schema: body.output_schema.clone().into_bytes(),
                respond_serialization_schema: body.respond_schema.clone().into_bytes(),
                chain: Chain::Midnight,
                // The respond call needs only the contract address (config) and
                // the request id — no per-request handle like Canton's cid.
                chain_ctx: None,
            };
            let request = IndexedSignRequest::sign_bidirectional(
                SignId::new(request_id),
                SignArgs {
                    entropy: keccak(&request_id),
                    epsilon,
                    payload,
                    path,
                    key_version: body.key_version,
                },
                Chain::Midnight,
                unix_now,
                event,
            );
            Ok(ChainEvent::SignRequest {
                request,
                block_timestamp: None,
            })
        }
        RequestKind::Respond => {
            let signature = requests::decode_respond(parts)?;
            Ok(ChainEvent::Respond(SignatureRespondedEvent {
                request_id,
                signature,
                chain: Chain::Midnight,
            }))
        }
        RequestKind::RespondBidirectional => {
            let (_output, signature) = requests::decode_respond_bidirectional(parts)?;
            Ok(ChainEvent::RespondBidirectional(
                RespondBidirectionalEvent {
                    request_id,
                    signature,
                    chain: Chain::Midnight,
                },
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_goldens::{golden, hex32, payload_bytes};
    use mpc_primitives::SignKind;

    fn parts_of(case: &serde_json::Value) -> Vec<EventPart> {
        case["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|ev| {
                let name = hex::decode(ev["name"].as_str().unwrap()).unwrap();
                EventPart::parse(&name, &payload_bytes(ev)).unwrap()
            })
            .collect()
    }

    fn fixture_contract(g: &serde_json::Value) -> (String, [u8; 32]) {
        let addr = g["fixtures"]["contractAddress"]
            .as_str()
            .unwrap()
            .to_string();
        let raw = hex32(&addr);
        (addr, raw)
    }

    fn scalar_hex(s: &Scalar) -> String {
        hex::encode(s.to_bytes())
    }

    #[test]
    fn sign_group_matches_golden_indexed_block() {
        let g = golden("sign.json");
        let case = &g["cases"][0];
        let (addr, raw) = fixture_contract(&g);
        let rid = hex32(case["requestId"].as_str().unwrap());

        let ev =
            group_to_chain_event(RequestKind::Sign, rid, &parts_of(case), &addr, raw, 7).unwrap();
        let ChainEvent::SignRequest { request, .. } = ev else {
            panic!("expected SignRequest");
        };
        let indexed = &case["indexed"];
        assert_eq!(request.chain, Chain::Midnight);
        assert_eq!(request.id.request_id, rid);
        assert_eq!(request.kind, SignKind::Sign);
        assert_eq!(
            hex::encode(request.args.entropy),
            indexed["entropy"].as_str().unwrap()
        );
        assert_eq!(request.args.path, indexed["path"].as_str().unwrap());
        assert_eq!(request.args.key_version, 1);
        assert_eq!(
            scalar_hex(&request.args.epsilon),
            indexed["epsilon"].as_str().unwrap()
        );
        assert_eq!(
            scalar_hex(&request.args.payload),
            indexed["payloadScalar"].as_str().unwrap()
        );
    }

    #[test]
    fn sign_group_with_tampered_payload_is_dropped() {
        let g = golden("sign.json");
        let case = &g["cases"][0];
        let (addr, raw) = fixture_contract(&g);
        let rid = hex32(case["requestId"].as_str().unwrap());
        let mut parts = parts_of(case);
        parts[0].tail[40] ^= 0xff; // flip a payload byte → rid no longer rehashes
        let err = group_to_chain_event(RequestKind::Sign, rid, &parts, &addr, raw, 7).unwrap_err();
        assert!(err.to_string().contains("does not rehash"));
    }

    #[test]
    fn sign_bidirectional_golden_is_dropped_for_unroutable_caip2() {
        // The golden targets eip155:11155111, which no Chain variant claims —
        // conversion must refuse it (routing safety), parse-layer goldens in
        // requests.rs cover the byte-level truth.
        let g = golden("sign_bidirectional.json");
        let case = &g["cases"][0];
        let (addr, raw) = fixture_contract(&g);
        let rid = hex32(case["requestId"].as_str().unwrap());
        let err = group_to_chain_event(
            RequestKind::SignBidirectional,
            rid,
            &parts_of(case),
            &addr,
            raw,
            7,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unroutable caip2"));
    }

    #[test]
    fn sign_bidirectional_with_mainnet_caip2_produces_full_event() {
        let g = golden("sign_bidirectional.json");
        let case = &g["cases"][0];
        let (addr, raw) = fixture_contract(&g);
        let mut parts = parts_of(case);
        // Patch part 1's caip2 field (offset 44..76) to "eip155:1" and recompute
        // the rid — legal because rid = SHA-256 of the tails.
        let mut caip2 = [0u8; 32];
        caip2[..8].copy_from_slice(b"eip155:1");
        parts[0].tail[44..76].copy_from_slice(&caip2);
        let tails: Vec<[u8; 224]> = parts.iter().map(|p| p.tail).collect();
        let rid = crate::wire::recompute_request_id(&tails);
        for p in &mut parts {
            p.request_id = rid;
        }

        let ev = group_to_chain_event(RequestKind::SignBidirectional, rid, &parts, &addr, raw, 7)
            .unwrap();
        let ChainEvent::SignRequest { request, .. } = ev else {
            panic!("expected SignRequest");
        };
        let SignKind::SignBidirectional(event) = &request.kind else {
            panic!("expected SignBidirectional kind");
        };
        assert_eq!(event.caip2_id, "eip155:1");
        assert_eq!(event.chain, Chain::Midnight);
        assert_eq!(event.sender, raw);
        assert_eq!(event.deposit, 1);
        assert_eq!(event.dest, "ethereum");
        assert_eq!(event.output_deserialization_schema, br#"["bool"]"#.to_vec());
        assert_eq!(event.respond_serialization_schema, br#"["bool"]"#.to_vec());
        assert!(event.chain_ctx.is_none());
        // payload = keccak(serialized tx), and the tx still round-trips.
        let expected_payload = <Scalar as ScalarExt>::from_bytes(
            alloy_primitives::keccak256(&event.serialized_transaction).0,
        )
        .unwrap();
        assert_eq!(request.args.payload, expected_payload);
    }

    #[test]
    fn respond_groups_become_settlement_events() {
        let g = golden("respond.json");
        let case = &g["cases"][0];
        let rid = hex32(case["inputs"]["requestId"].as_str().unwrap());
        let ev = group_to_chain_event(
            RequestKind::Respond,
            rid,
            &parts_of(case),
            "00",
            [0u8; 32],
            7,
        )
        .unwrap();
        let ChainEvent::Respond(resp) = ev else {
            panic!("expected Respond");
        };
        assert_eq!(resp.request_id, rid);
        assert_eq!(resp.chain, Chain::Midnight);
        assert_eq!(resp.signature.big_r, k256::AffinePoint::GENERATOR);

        let gbi = golden("respond_bidirectional.json");
        let case = &gbi["cases"][0];
        let rid = hex32(case["inputs"]["requestId"].as_str().unwrap());
        let ev = group_to_chain_event(
            RequestKind::RespondBidirectional,
            rid,
            &parts_of(case),
            "00",
            [0u8; 32],
            7,
        )
        .unwrap();
        assert!(matches!(ev, ChainEvent::RespondBidirectional(e) if e.request_id == rid));
    }

    #[test]
    fn key_version_zero_is_dropped() {
        let g = golden("sign.json");
        let case = &g["cases"][0];
        let (addr, raw) = fixture_contract(&g);
        let mut parts = parts_of(case);
        parts[0].tail[72..76].copy_from_slice(&0u32.to_le_bytes());
        let tails: Vec<[u8; 224]> = parts.iter().map(|p| p.tail).collect();
        let rid = crate::wire::recompute_request_id(&tails);
        parts[0].request_id = rid;
        let err = group_to_chain_event(RequestKind::Sign, rid, &parts, &addr, raw, 7).unwrap_err();
        assert!(err.to_string().contains("unsupported keyVersion"));
    }
}
