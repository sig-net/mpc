use std::str::FromStr;
use std::sync::Arc;

use alloy::sol_types::SolValue;
use anchor_client::anchor_lang::AnchorDeserialize;
use anchor_lang::solana_program::keccak;
use anchor_lang::Discriminator;
use anyhow::Context;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, Scalar};
use mpc_chain_integration_core::utils::hashing::{compute_request_id, hash_payload};
use mpc_crypto::kdf::derive_epsilon_sol;
use mpc_crypto::ScalarExt as _;
use mpc_primitives::{
    Chain, ChainEvent, IndexedSignRequest, SignArgs, SignId, LATEST_MPC_KEY_VERSION,
    MAX_SECP256K1_SCALAR,
};
use mpc_utils::time::current_unix_timestamp;
use signet_program::{
    RespondBidirectionalEvent, SignBidirectionalEvent, SignatureRequestedEvent,
    SignatureRespondedEvent,
};
use solana_sdk::{pubkey::Pubkey, signature::Signature};
use solana_transaction_status::option_serializer::OptionSerializer;
use solana_transaction_status::{
    EncodedTransaction, EncodedTransactionWithStatusMeta, UiInstruction, UiParsedInstruction,
};
use tokio::sync::mpsc;

const CPI_EVENT_HINTS: &[&str] = &[
    "Program log: Instruction: Sign",
    "Program log: Instruction: SignBidirectional",
];

const CPI_RESPOND_EVENT_HINTS: &[&str] = &[
    "Program log: Instruction: Respond",
    "Program log: Instruction: RespondBidirectional",
];

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

                keccak::hash(&encoded).to_bytes()
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

                tracing::info!(?sign_id, "solana signature requested");
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
                tracing::info!(?sign_id, "solana bidirectional signature requested");
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

fn parse_cpi_events(
    tx: &EncodedTransactionWithStatusMeta,
    target_program_id: &Pubkey,
) -> anyhow::Result<Vec<SolanaSignEvent>> {
    let Some(meta) = &tx.meta else {
        return Ok(Vec::new());
    };

    let target_program_str = target_program_id.to_string();
    let mut out = Vec::<SolanaSignEvent>::new();

    // Small helper closure to try decoding both event types from raw data
    let try_parse_events = |data: &str| -> anyhow::Result<Vec<SolanaSignEvent>> {
        let Ok(ix_data) = solana_sdk::bs58::decode(data).into_vec() else {
            tracing::warn!("Failed to decode instruction data for target program");
            return Ok(Vec::new());
        };

        // Split into the 8-byte event discriminator and trailing event bytes,
        // skipping anything that isn't a well-formed Anchor event instruction.
        let Some((event_discriminator, event_data)) = split_cpi_event(&ix_data) else {
            return Ok(Vec::new());
        };

        let mut acc = Vec::new();

        // handle both event types
        if event_discriminator == SignatureRequestedEvent::DISCRIMINATOR {
            match SignatureRequestedEvent::deserialize(&mut &event_data[..]) {
                Ok(ev) => acc.push(SolanaSignEvent::SignatureRequested(ev)),
                Err(e) => tracing::warn!("Failed to deserialize SignatureRequestedEvent: {e}"),
            }
        } else if event_discriminator == SignBidirectionalEvent::DISCRIMINATOR {
            match <SignBidirectionalEvent as AnchorDeserialize>::deserialize(&mut &event_data[..]) {
                Ok(ev) => {
                    // caip2_id represents the mainnet CAIP-2 chain ID of the target chain
                    // we won't process the event if the caip2_id is invalid, since it won't be able to be handled correctly downstream anyway
                    if let Err(e) = Chain::from_caip2_chain_id(&ev.caip2_id) {
                        tracing::warn!("invalid caip2 chain id in sign bidirectional event: {e:?}")
                    } else {
                        acc.push(SolanaSignEvent::SignBidirectional(ev))
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to deserialize SignBidirectionalEvent: {e}")
                }
            }
        }

        Ok(acc)
    };

    // Look into inner instructions for CPI calls
    let inner_ixs = match &meta.inner_instructions {
        OptionSerializer::Some(ixs) => ixs,
        _ => return Ok(Vec::new()),
    };

    for (set_idx, inner_ix_set) in inner_ixs.iter().enumerate() {
        for (ix_idx, instruction) in inner_ix_set.instructions.iter().enumerate() {
            if let UiInstruction::Parsed(UiParsedInstruction::PartiallyDecoded(ui)) = instruction {
                if ui.program_id == target_program_str {
                    match try_parse_events(&ui.data) {
                        Ok(mut v) => {
                            if !v.is_empty() {
                                tracing::info!(
                                    "parsed {} event(s) from {}.{}",
                                    v.len(),
                                    set_idx,
                                    ix_idx
                                );
                            }
                            out.append(&mut v);
                        }
                        Err(e) => tracing::warn!(
                            "Error processing inner instruction {}.{}: {}",
                            set_idx,
                            ix_idx,
                            e
                        ),
                    }
                }
            }
        }
    }

    Ok(out)
}

fn looks_like_cpi_sign_event(logs: &[String]) -> bool {
    logs.iter()
        .any(|l| CPI_EVENT_HINTS.iter().any(|h| l.contains(h)))
}

fn looks_like_respond_event(logs: &[String]) -> bool {
    logs.iter()
        .any(|l| CPI_RESPOND_EVENT_HINTS.iter().any(|h| l.contains(h)))
}

fn parse_cpi_respond_events(
    tx: &EncodedTransactionWithStatusMeta,
    target_program_id: &Pubkey,
) -> anyhow::Result<(Vec<RespondBidirectionalEvent>, Vec<SignatureRespondedEvent>)> {
    use solana_transaction_status::{UiInstruction, UiParsedInstruction};

    let Some(meta) = &tx.meta else {
        return Ok((Vec::new(), Vec::new()));
    };

    let target_program_str = target_program_id.to_string();
    let mut respond_bidirectional_events = Vec::<RespondBidirectionalEvent>::new();
    let mut signature_responded_events = Vec::<SignatureRespondedEvent>::new();

    // Helper closure to try decoding RespondBidirectionalEvent and SignatureRespondedEvent from raw data
    let try_parse_respond_event = |data: &str| -> anyhow::Result<(
        Vec<RespondBidirectionalEvent>,
        Vec<SignatureRespondedEvent>,
    )> {
        let Ok(ix_data) = solana_sdk::bs58::decode(data).into_vec() else {
            tracing::warn!("Failed to decode instruction data for target program");
            return Ok((Vec::new(), Vec::new()));
        };

        // Split into the 8-byte event discriminator and trailing event bytes,
        // skipping anything that isn't a well-formed Anchor event instruction.
        let Some((event_discriminator, event_data)) = split_cpi_event(&ix_data) else {
            return Ok((Vec::new(), Vec::new()));
        };

        let mut respond_bdx = Vec::new();
        let mut sig_resp = Vec::new();

        // Handle RespondBidirectionalEvent
        if event_discriminator == RespondBidirectionalEvent::DISCRIMINATOR {
            match RespondBidirectionalEvent::deserialize(&mut &event_data[..]) {
                Ok(ev) => respond_bdx.push(ev),
                Err(e) => {
                    tracing::warn!("Failed to deserialize RespondBidirectionalEvent: {e}")
                }
            }
        }

        // Handle SignatureRespondedEvent
        if event_discriminator == SignatureRespondedEvent::DISCRIMINATOR {
            match SignatureRespondedEvent::deserialize(&mut &event_data[..]) {
                Ok(ev) => sig_resp.push(ev),
                Err(e) => {
                    tracing::warn!("Failed to deserialize SignatureRespondedEvent: {e}")
                }
            }
        }

        Ok((respond_bdx, sig_resp))
    };

    // Look into inner instructions for CPI calls
    let inner_ixs = match &meta.inner_instructions {
        OptionSerializer::Some(ixs) => ixs,
        _ => return Ok((Vec::new(), Vec::new())),
    };

    for (set_idx, inner_ix_set) in inner_ixs.iter().enumerate() {
        for (ix_idx, instruction) in inner_ix_set.instructions.iter().enumerate() {
            if let UiInstruction::Parsed(UiParsedInstruction::PartiallyDecoded(ui)) = instruction {
                if ui.program_id == target_program_str {
                    match try_parse_respond_event(&ui.data) {
                        Ok((mut r_bdx, mut s_resp)) => {
                            if !r_bdx.is_empty() {
                                tracing::info!(
                                    "parsed {} RespondBidirectionalEvent(s) from {}.{}",
                                    r_bdx.len(),
                                    set_idx,
                                    ix_idx
                                );
                            }
                            if !s_resp.is_empty() {
                                tracing::info!(
                                    "parsed {} SignatureRespondedEvent(s) from {}.{}",
                                    s_resp.len(),
                                    set_idx,
                                    ix_idx
                                );
                            }
                            respond_bidirectional_events.append(&mut r_bdx);
                            signature_responded_events.append(&mut s_resp);
                        }
                        Err(e) => tracing::warn!(
                            "Error processing inner instruction {}.{}: {}",
                            set_idx,
                            ix_idx,
                            e
                        ),
                    }
                }
            }
        }
    }

    Ok((respond_bidirectional_events, signature_responded_events))
}

enum SolanaEvents {
    Sign(Vec<SolanaSignEvent>),
    Respond {
        bidirectional: Vec<RespondBidirectionalEvent>,
        responded: Vec<SignatureRespondedEvent>,
    },
    None,
}

impl SolanaEvents {
    fn parse(
        tx: &EncodedTransactionWithStatusMeta,
        target_program_id: &Pubkey,
        logs: &[String],
    ) -> anyhow::Result<Self> {
        if looks_like_cpi_sign_event(logs) {
            Ok(SolanaEvents::Sign(parse_cpi_events(tx, target_program_id)?))
        } else if looks_like_respond_event(logs) {
            let (bidirectional, responded) = parse_cpi_respond_events(tx, target_program_id)?;
            Ok(SolanaEvents::Respond {
                bidirectional,
                responded,
            })
        } else {
            Ok(SolanaEvents::None)
        }
    }
}

pub async fn emit_events(
    events_tx: &mpsc::Sender<ChainEvent>,
    program_id: &Pubkey,
    signature: Signature,
    tx: &EncodedTransactionWithStatusMeta,
    logs: &[String],
) -> anyhow::Result<()> {
    match SolanaEvents::parse(tx, program_id, logs)? {
        SolanaEvents::Sign(events) => {
            let sig_bytes = signature.as_ref().to_vec();
            for ev in events {
                if let Some(request) = ev.build_sign_request(&sig_bytes) {
                    // `signature` is the Solana transaction signature, i.e. the tx hash
                    // shown in explorers and used as the getTransaction lookup key. Log it
                    // next to the sign_id so a given tx can be matched to its request.
                    tracing::info!(
                        tx_hash = %signature,
                        sign_id = ?request.id,
                        "solana sign request parsed",
                    );
                    events_tx
                        .send(ChainEvent::SignRequest {
                            request: Arc::new(request),
                            block_timestamp: None,
                        })
                        .await?;
                }
            }
        }
        SolanaEvents::Respond {
            bidirectional,
            responded,
        } => {
            for ev in bidirectional {
                let signature =
                    to_mpc_signature(&ev.signature).context("failed to parse Solana signature")?;
                let _ = events_tx
                    .send(ChainEvent::RespondBidirectional(
                        mpc_primitives::RespondBidirectionalEvent {
                            request_id: ev.request_id,
                            signature,
                            chain: Chain::Solana,
                        },
                    ))
                    .await;
            }

            for ev in responded {
                let signature =
                    to_mpc_signature(&ev.signature).context("failed to parse Solana signature")?;
                let _ = events_tx
                    .send(ChainEvent::Respond(
                        mpc_primitives::SignatureRespondedEvent {
                            request_id: ev.request_id,
                            signature,
                            chain: Chain::Solana,
                        },
                    ))
                    .await;
            }
        }
        SolanaEvents::None => {}
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
}
