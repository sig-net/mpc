use std::str::FromStr;
use std::sync::Arc;

use alloy::sol_types::SolValue;
use anchor_client::anchor_lang::AnchorDeserialize;
use anchor_lang::Discriminator;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, Scalar};
use mpc_chain_integration_core::utils::hashing::{compute_request_id, hash_payload};
use mpc_crypto::kdf::derive_epsilon_sol;
use mpc_crypto::ScalarExt as _;
use mpc_primitives::{
    Chain, ChainEvent, IndexedSignRequest, SignArgs, SignId, SignKind, LATEST_MPC_KEY_VERSION,
    MAX_SECP256K1_SCALAR,
};
use mpc_utils::time::current_unix_timestamp;
use sha3::Digest as _;
use signet_program::{
    RespondBidirectionalEvent, SignBidirectionalEvent, SignatureRequestedEvent,
    SignatureRespondedEvent,
};
use solana_sdk::signature::Signature;
use solana_transaction_status::option_serializer::OptionSerializer;
use solana_transaction_status::{
    EncodedTransaction, EncodedTransactionWithStatusMeta, UiInstruction, UiParsedInstruction,
};
use tokio::sync::mpsc;

pub enum SolanaSignEvent {
    SignatureRequested(SignatureRequestedEvent),
    SignBidirectional(SignBidirectionalEvent),
}

impl SolanaSignEvent {
    fn is_valid(&self, sign_id: SignId) -> bool {
        let (deposit, key_version) = match self {
            SolanaSignEvent::SignatureRequested(ev) => (ev.deposit, ev.key_version),
            SolanaSignEvent::SignBidirectional(ev) => (ev.deposit, ev.key_version),
        };

        if deposit == 0 {
            tracing::warn!(?sign_id, "deposit is 0, skipping sign request");
            return false;
        }

        if key_version > LATEST_MPC_KEY_VERSION {
            tracing::warn!(?sign_id, "unsupported key version: {}", key_version);
            return false;
        }

        true
    }

    pub fn generate_request_id(&self) -> [u8; 32] {
        match self {
            SolanaSignEvent::SignatureRequested(ev) => compute_request_id(
                &ev.sender.to_string(),
                &ev.payload,
                &ev.path,
                ev.key_version,
                &ev.chain_id,
                &ev.algo,
                &ev.dest,
                &ev.params,
            ),
            SolanaSignEvent::SignBidirectional(ev) => {
                let encoded = (
                    ev.sender.to_string(),
                    ev.serialized_transaction.clone(),
                    ev.caip2_id.clone(),
                    ev.key_version,
                    ev.path.clone(),
                    ev.algo.clone(),
                    ev.dest.clone(),
                    ev.params.clone(),
                )
                    .abi_encode_packed();

                sha3::Keccak256::digest(&encoded).into()
            }
        }
    }

    pub fn generate_sign_request(&self, entropy: [u8; 32]) -> Option<IndexedSignRequest> {
        let sign_id = SignId::new(self.generate_request_id());
        if !self.is_valid(sign_id) {
            return None;
        }

        match self {
            SolanaSignEvent::SignatureRequested(ev) => {
                let payload = Scalar::from_bytes(ev.payload).or_else(|| {
                    tracing::warn!(
                        ?sign_id,
                        "solana `sign` did not produce payload hash correctly: {:?}",
                        ev.payload,
                    );
                    None
                })?;

                if payload > *MAX_SECP256K1_SCALAR {
                    tracing::warn!(?sign_id, ?payload, "payload exceeds secp256k1 curve order");
                    return None;
                }

                let epsilon = derive_epsilon_sol(ev.key_version, &ev.sender.to_string(), &ev.path);
                Some(IndexedSignRequest::sign(
                    sign_id,
                    SignArgs {
                        entropy,
                        epsilon,
                        payload,
                        path: ev.path.clone(),
                        key_version: ev.key_version,
                    },
                    Chain::Solana,
                    current_unix_timestamp(),
                ))
            }
            SolanaSignEvent::SignBidirectional(ev) => {
                let epsilon = derive_epsilon_sol(ev.key_version, &ev.sender.to_string(), &ev.path);
                let unsigned_tx_hash = hash_payload(&ev.serialized_transaction);
                let payload = Scalar::from_bytes(unsigned_tx_hash)?;

                if payload > *MAX_SECP256K1_SCALAR {
                    tracing::warn!(?payload, "payload exceeds secp256k1 curve order");
                    return None;
                }

                Some(IndexedSignRequest::sign_bidirectional(
                    sign_id,
                    SignArgs {
                        entropy,
                        epsilon,
                        payload,
                        path: ev.path.clone(),
                        key_version: ev.key_version,
                    },
                    Chain::Solana,
                    current_unix_timestamp(),
                    mpc_primitives::SignBidirectionalEvent {
                        sender: ev.sender.to_bytes(),
                        serialized_transaction: ev.serialized_transaction.clone(),
                        caip2_id: ev.caip2_id.clone(),
                        key_version: ev.key_version,
                        deposit: ev.deposit,
                        path: ev.path.clone(),
                        algo: ev.algo.clone(),
                        dest: ev.dest.clone(),
                        params: ev.params.clone(),
                        output_deserialization_schema: ev.output_deserialization_schema.clone(),
                        respond_serialization_schema: ev.respond_serialization_schema.clone(),
                        chain: Chain::Solana,
                        chain_ctx: None,
                    },
                ))
            }
        }
    }

    fn build_sign_request(self, tx_sig: &[u8]) -> Option<IndexedSignRequest> {
        let mut entropy = [0u8; 32];
        entropy.copy_from_slice(&tx_sig[..32]);
        self.generate_sign_request(entropy)
    }
}

/// Split an Anchor `emit_cpi!` event instruction payload into its 8-byte event
/// discriminator and the trailing borsh-encoded event bytes.
///
/// Returns `None` when the data should not be parsed as an event: either it
/// lacks the 8-byte Anchor event tag, or it is too short to also contain the
/// discriminator. The length guard is what prevents an out-of-bounds panic on
/// malformed (e.g. attacker-crafted) instruction data — `starts_with` only
/// guarantees the first 8 bytes, but the split needs at least 16.
fn split_cpi_event(ix_data: &[u8]) -> Option<(&[u8], &[u8])> {
    if !ix_data.starts_with(anchor_lang::event::EVENT_IX_TAG_LE) {
        return None;
    }
    if ix_data.len() < 16 {
        tracing::warn!(
            len = ix_data.len(),
            "CPI event instruction data too short; skipping"
        );
        return None;
    }
    Some((&ix_data[8..16], &ix_data[16..]))
}

enum CpiEvent {
    Sign(SolanaSignEvent),
    RespondBidirectional(RespondBidirectionalEvent),
    Responded(SignatureRespondedEvent),
}

/// Decodes the program's `emit_cpi!` events from the tx's inner instructions, in order.
fn parse_cpi_events(tx: &EncodedTransactionWithStatusMeta, program_id: &str) -> Vec<CpiEvent> {
    let Some(OptionSerializer::Some(inner_ixs)) = tx.meta.as_ref().map(|m| &m.inner_instructions)
    else {
        return Vec::new();
    };
    inner_ixs
        .iter()
        .flat_map(|set| &set.instructions)
        .filter_map(|ix| match ix {
            UiInstruction::Parsed(UiParsedInstruction::PartiallyDecoded(ui))
                if ui.program_id == program_id =>
            {
                parse_cpi_event(&ui.data)
            }
            _ => None,
        })
        .collect()
}

fn parse_cpi_event(data: &str) -> Option<CpiEvent> {
    let Ok(ix_data) = solana_sdk::bs58::decode(data).into_vec() else {
        tracing::warn!("Failed to decode instruction data for target program");
        return None;
    };
    let (discriminator, event_data) = split_cpi_event(&ix_data)?;
    match discriminator {
        SignatureRequestedEvent::DISCRIMINATOR => {
            decode(event_data).map(|ev| CpiEvent::Sign(SolanaSignEvent::SignatureRequested(ev)))
        }
        SignBidirectionalEvent::DISCRIMINATOR => {
            let ev: SignBidirectionalEvent = decode(event_data)?;
            // An invalid target chain can't be handled downstream.
            if let Err(e) = Chain::from_caip2_chain_id(&ev.caip2_id) {
                tracing::warn!("invalid caip2 chain id in sign bidirectional event: {e:?}");
                return None;
            }
            Some(CpiEvent::Sign(SolanaSignEvent::SignBidirectional(ev)))
        }
        RespondBidirectionalEvent::DISCRIMINATOR => {
            decode(event_data).map(CpiEvent::RespondBidirectional)
        }
        SignatureRespondedEvent::DISCRIMINATOR => decode(event_data).map(CpiEvent::Responded),
        _ => None,
    }
}

fn decode<T: AnchorDeserialize>(mut data: &[u8]) -> Option<T> {
    T::deserialize(&mut data)
        .inspect_err(|e| {
            tracing::warn!("Failed to deserialize {}: {e}", std::any::type_name::<T>())
        })
        .ok()
}

pub async fn emit_events(
    events_tx: &mpsc::Sender<ChainEvent>,
    program_id: &str,
    tx: &EncodedTransactionWithStatusMeta,
) -> anyhow::Result<()> {
    let events = parse_cpi_events(tx, program_id);
    if events.is_empty() {
        return Ok(());
    }
    let signature = extract_tx_signature(&tx.transaction)?;
    for event in events {
        let event = match event {
            CpiEvent::Sign(ev) => {
                let Some(request) = ev.build_sign_request(signature.as_ref()) else {
                    continue;
                };
                // `signature` is the Solana transaction signature, i.e. the tx hash
                // shown in explorers and used as the getTransaction lookup key. Log it
                // next to the sign_id so a given tx can be matched to its request.
                tracing::info!(
                    tx_hash = %signature,
                    sign_id = ?request.id,
                    bidirectional = matches!(request.kind, SignKind::SignBidirectional(_)),
                    "solana sign request parsed",
                );
                ChainEvent::SignRequest {
                    request: Arc::new(request),
                    block_timestamp: None,
                }
            }
            CpiEvent::RespondBidirectional(ev) => {
                let Ok(signature) = to_mpc_signature(&ev.signature).inspect_err(|err| {
                    tracing::warn!(
                        ?err,
                        ?ev.request_id,
                        "ignoring malformed signature in RespondBidirectional event"
                    )
                }) else {
                    continue;
                };
                ChainEvent::RespondBidirectional(mpc_primitives::RespondBidirectionalEvent {
                    attestation: None,
                    request_id: ev.request_id,
                    signature,
                    chain: Chain::Solana,
                })
            }
            CpiEvent::Responded(ev) => {
                let Ok(signature) = to_mpc_signature(&ev.signature).inspect_err(|err| {
                    tracing::warn!(
                        ?err,
                        ?ev.request_id,
                        "ignoring malformed signature in SignatureResponded event"
                    )
                }) else {
                    continue;
                };
                ChainEvent::Respond(mpc_primitives::SignatureRespondedEvent {
                    request_id: ev.request_id,
                    signature,
                    chain: Chain::Solana,
                })
            }
        };
        events_tx.send(event).await?;
    }
    Ok(())
}

pub fn extract_tx_signature(tx: &EncodedTransaction) -> anyhow::Result<Signature> {
    match tx {
        EncodedTransaction::Json(ui_tx) => {
            let signature = ui_tx
                .signatures
                .first()
                .ok_or_else(|| anyhow::anyhow!("missing signature in block transaction"))?;
            Signature::from_str(signature)
                .map_err(|err| anyhow::anyhow!(err).context("failed to parse block signature"))
        }
        other => {
            anyhow::bail!("unsupported encoded transaction variant in block catchup: {other:?}")
        }
    }
}

pub fn to_mpc_signature(
    sig: &signet_program::Signature,
) -> anyhow::Result<mpc_primitives::Signature> {
    // Create a 65-byte uncompressed point representation (0x04 || x || y)
    let mut big_r = [0u8; 65];
    big_r[0] = 0x04;
    big_r[1..33].copy_from_slice(&sig.big_r.x);
    big_r[33..65].copy_from_slice(&sig.big_r.y);

    let big_r = k256::EncodedPoint::from_bytes(big_r)
        .map_err(|err| anyhow::anyhow!("unable to parse big_r for encoded point: {err}"))?;
    let big_r_ct_opt = AffinePoint::from_encoded_point(&big_r);
    let big_r = big_r_ct_opt
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("failed to create AffinePoint from encoded point"))?;

    let s = Scalar::from_bytes(sig.s)
        .ok_or_else(|| anyhow::anyhow!("failed to create Scalar from s bytes"))?;

    Ok(mpc_primitives::Signature {
        big_r,
        s,
        recovery_id: sig.recovery_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use signet_program::SignatureRequestedEvent;
    use solana_sdk::pubkey::Pubkey;

    #[test]
    fn split_cpi_event_handles_short_and_valid_data() {
        let tag = anchor_lang::event::EVENT_IX_TAG_LE;

        // No event tag -> not an event instruction.
        assert!(split_cpi_event(b"not-an-event").is_none());

        // Tag present but too short for the 8-byte discriminator. This is the
        // regression case: previously `&ix_data[8..16]` panicked here.
        for extra in 0..8usize {
            let mut data = tag.to_vec();
            data.extend(std::iter::repeat_n(0u8, extra));
            assert!(
                split_cpi_event(&data).is_none(),
                "tag + {extra} bytes ({} total) should be skipped, not panic",
                data.len()
            );
        }

        // Tag + 8-byte discriminator + payload -> split correctly.
        let mut data = tag.to_vec();
        data.extend_from_slice(&[9u8; 8]); // discriminator
        data.extend_from_slice(&[1, 2, 3]); // event payload
        let (disc, payload) = split_cpi_event(&data).expect("well-formed event should split");
        assert_eq!(disc, [9u8; 8]);
        assert_eq!(payload, [1, 2, 3]);
    }

    #[test]
    fn request_id_matches_ethabi() {
        let event = SignatureRequestedEvent {
            sender: Pubkey::new_from_array([0x11; 32]),
            payload: [0x22; 32],
            key_version: 7,
            deposit: 12345,
            chain_id: "solana-test-chain".to_string(),
            path: "m/44'/501'/0'/0'".to_string(),
            algo: "secp256k1".to_string(),
            dest: "destination-address".to_string(),
            params: "params-json".to_string(),
            fee_payer: None,
        };

        assert_eq!(
            hex::encode(SolanaSignEvent::SignatureRequested(event).generate_request_id()),
            "7f7aee49c2a994cc17f85058f7e0b19a44603d619a7e738522f9aa329e457879"
        );
    }

    fn sign_bidirectional_ix_data(caip2_id: &str) -> String {
        let event = SignBidirectionalEvent {
            sender: Pubkey::new_from_array([0x11; 32]),
            serialized_transaction: vec![1, 2, 3],
            caip2_id: caip2_id.to_string(),
            key_version: 0,
            deposit: 0,
            path: "path".to_string(),
            algo: "secp256k1".to_string(),
            dest: "dest".to_string(),
            params: String::new(),
            program_id: Pubkey::new_from_array([0x22; 32]),
            output_deserialization_schema: vec![],
            respond_serialization_schema: vec![],
        };
        let mut data = anchor_lang::event::EVENT_IX_TAG_LE.to_vec();
        data.extend(anchor_lang::Event::data(&event));
        solana_sdk::bs58::encode(data).into_string()
    }

    #[test]
    fn emits_sign_bidirectional_cpi_event() {
        let data = sign_bidirectional_ix_data("eip155:1");
        assert!(matches!(
            parse_cpi_event(&data),
            Some(CpiEvent::Sign(SolanaSignEvent::SignBidirectional(ev))) if ev.caip2_id == "eip155:1"
        ));
    }

    #[test]
    fn skips_sign_bidirectional_event_with_invalid_caip2() {
        let data = sign_bidirectional_ix_data("not-a-chain");
        assert!(parse_cpi_event(&data).is_none());
    }

    #[test]
    fn to_mpc_signature_rejects_invalid_curve_point() {
        let sig = signet_program::Signature {
            big_r: signet_program::AffinePoint {
                x: [0x11; 32],
                y: [0x22; 32],
            },
            s: [0x33; 32],
            recovery_id: 0,
        };
        assert!(to_mpc_signature(&sig).is_err());
    }
}
