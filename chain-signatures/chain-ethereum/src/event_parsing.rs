//! Decoding of `ChainSignatures` contract events and helper predicates used by
//! the Ethereum indexer.

use crate::abi::{ChainSignatures, SignatureRequestedEncoding};
use alloy::primitives::hex::ToHexExt;
use alloy::primitives::{Address, Bytes, U256};
use alloy::rpc::types::Log;
use alloy::sol_types::SolEvent;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint as K256AffinePoint, EncodedPoint, FieldBytes, Scalar};
use mpc_crypto::{kdf::derive_epsilon_eth, ScalarExt as _};
use mpc_primitives::{
    Chain, ChainEvent, IndexedSignRequest, SignArgs, SignId, Signature as MpcSignature,
    SignatureRespondedEvent, LATEST_MPC_KEY_VERSION, MAX_SECP256K1_SCALAR,
};
use mpc_utils::time::current_unix_timestamp;
use tokio::sync::mpsc;

/// Whether a transaction's calldata represents a contract call.
pub fn is_contract_call(input: &Bytes) -> bool {
    input.len() > 2 && input != &Bytes::from("0x")
}

pub fn parse_filtered_logs(logs: Vec<Log>) -> Vec<IndexedSignRequest> {
    let mut indexed_requests = Vec::new();
    for log in logs {
        tracing::debug!("Parsing Ethereum log: {:?}", log);
        match sign_request_from_filtered_log(log.clone()) {
            Some(request) => indexed_requests.push(request),
            None => tracing::warn!("Failed to parse Ethereum log: {:?}", log),
        }
    }
    if indexed_requests.is_empty() {
        tracing::warn!("No valid Ethereum sign requests found in logs");
    }
    indexed_requests
}

pub async fn emit_respond_events(logs: &[Log], events_tx: mpsc::Sender<ChainEvent>) {
    for log in logs {
        let Some(sign_id) = sign_id_from_signature_responded_log(log) else {
            continue;
        };

        let event = match ChainSignatures::SignatureResponded::decode_log_data(log.data()) {
            Ok(event) => event,
            Err(err) => {
                tracing::warn!(
                    ?sign_id,
                    ?err,
                    "failed to decode SignatureResponded event data"
                );
                continue;
            }
        };
        let signature = event.signature;

        let x_bytes: [u8; 32] = signature.bigR.x.to_be_bytes();
        let y_bytes: [u8; 32] = signature.bigR.y.to_be_bytes();
        let encoded_r = EncodedPoint::from_affine_coordinates(
            FieldBytes::from_slice(&x_bytes),
            FieldBytes::from_slice(&y_bytes),
            false,
        );
        let Some(big_r) = K256AffinePoint::from_encoded_point(&encoded_r).into_option() else {
            tracing::warn!(?sign_id, "ethereum respond event, invalid big_r point");
            continue;
        };

        let Some(s) = Scalar::from_bytes(signature.s.to_be_bytes()) else {
            tracing::warn!(?sign_id, "ethereum respond event, invalid s scalar");
            continue;
        };

        let signature = MpcSignature::new(big_r, s, signature.recoveryId);

        let respond_event = SignatureRespondedEvent {
            request_id: sign_id.request_id,
            signature,
            chain: Chain::Ethereum,
        };
        tracing::info!(?sign_id, "emitting SignatureResponded event");
        if let Err(err) = events_tx.send(ChainEvent::Respond(respond_event)).await {
            tracing::error!(?err, "failed to emit Respond event");
        }
    }
}

fn sign_id_from_signature_responded_log(log: &Log) -> Option<SignId> {
    if log
        .topic0()
        .is_none_or(|topic| *topic != ChainSignatures::SignatureResponded::SIGNATURE_HASH)
    {
        return None;
    }

    let request_topic = log.topics().get(1)?;
    let request_id: [u8; 32] = (*request_topic).into();
    Some(SignId { request_id })
}

fn sign_request_from_filtered_log(log: Log) -> Option<IndexedSignRequest> {
    let event = parse_event(&log)?;
    tracing::debug!("found eth event: {:?}", event);
    if event.deposit == U256::ZERO {
        tracing::warn!("deposit is 0, skipping sign request");
        return None;
    }

    if event.key_version > LATEST_MPC_KEY_VERSION {
        tracing::warn!("unsupported key version: {}", event.key_version);
        return None;
    }

    // Create sign request from event
    let Some(payload) = Scalar::from_bytes(event.payload_hash) else {
        tracing::warn!(
            "eth `sign` did not produce payload hash correctly: {:?}",
            event.payload_hash,
        );
        return None;
    };

    if payload > *MAX_SECP256K1_SCALAR {
        tracing::warn!("payload exceeds secp256k1 curve order: {payload:?}");
        return None;
    }

    let epsilon = derive_epsilon_eth(
        event.key_version,
        format!("0x{}", event.requester.encode_hex()).as_str(),
        &event.path,
    );

    // Use transaction hash as entropy
    let tx_hash = log.transaction_hash.unwrap_or_default();
    let entropy = tx_hash;

    let sign_id = SignId::new(event.generate_request_id());
    tracing::info!(%tx_hash, ?sign_id, "eth signature requested");

    Some(IndexedSignRequest::sign(
        sign_id,
        SignArgs {
            entropy: entropy.into(),
            epsilon,
            payload,
            path: event.path,
            key_version: event.key_version,
        },
        Chain::Ethereum,
        current_unix_timestamp(),
    ))
}

fn parse_event(log: &Log) -> Option<SignatureRequestedEvent> {
    let event = match ChainSignatures::SignatureRequested::decode_log_data(log.data()) {
        Ok(event) => event,
        Err(err) => {
            tracing::warn!(?err, "failed to decode SignatureRequested event data");
            return None;
        }
    };

    tracing::info!(
        "Parsed event: requester={}, payload_hash={}, path={}, deposit={}, chain_id={}, algo={}, dest={}, params={}",
        event.sender,
        event.payload,
        event.path,
        event.deposit,
        event.chainId,
        event.algo,
        event.dest,
        event.params
    );

    Some(SignatureRequestedEvent {
        requester: event.sender,
        payload_hash: event.payload.into(),
        path: event.path,
        key_version: event.keyVersion,
        deposit: event.deposit,
        chain_id: event.chainId,
        algo: event.algo,
        dest: event.dest,
        params: event.params,
    })
}

#[derive(Debug)]
struct SignatureRequestedEvent {
    requester: Address,
    payload_hash: [u8; 32],
    path: String,
    key_version: u32,
    deposit: U256,
    chain_id: U256,
    algo: String,
    dest: String,
    params: String,
}

impl SignatureRequestedEvent {
    fn encode_abi(&self) -> Vec<u8> {
        let signature_requested_event_encoding = SignatureRequestedEncoding {
            sender: self.requester,
            payload: self.payload_hash.into(),
            path: self.path.clone(),
            keyVersion: self.key_version,
            chainId: self.chain_id,
            algo: self.algo.clone(),
            dest: self.dest.clone(),
            params: self.params.clone(),
        };
        signature_requested_event_encoding.encode_data()
    }

    pub fn generate_request_id(&self) -> [u8; 32] {
        let abi_encoded = self.encode_abi();
        alloy::primitives::keccak256(abi_encoded).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::ChainSignatures;
    use alloy::primitives::{Address, FixedBytes, Log as PrimitiveLog, U256};
    use alloy::sol_types::SolEvent;

    fn sample_requested_event() -> ChainSignatures::SignatureRequested {
        ChainSignatures::SignatureRequested {
            sender: Address::from([0x11; 20]),
            payload: FixedBytes::from([0x22; 32]),
            keyVersion: 1,
            deposit: U256::from(1000u64),
            chainId: U256::from(31337u64),
            path: "m/44'/60'/0'/0/0".to_string(),
            algo: "ecdsa".to_string(),
            dest: String::new(),
            params: "{}".to_string(),
        }
    }

    fn requested_log(data: Vec<u8>) -> Log {
        Log {
            inner: PrimitiveLog::new_unchecked(
                Address::ZERO,
                vec![ChainSignatures::SignatureRequested::SIGNATURE_HASH],
                data.into(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn is_contract_call_detects_calldata() {
        assert!(!is_contract_call(&Bytes::new()));
        assert!(!is_contract_call(&Bytes::from(vec![0u8; 2])));
        assert!(is_contract_call(&Bytes::from(vec![
            0xa9, 0x05, 0x9c, 0xbb, 0x00
        ])));
    }

    #[test]
    fn parse_event_decodes_valid_log() {
        let event = sample_requested_event();
        let log = requested_log(event.encode_data());

        let parsed = parse_event(&log).expect("valid log should parse");
        assert_eq!(parsed.requester, event.sender);
        assert_eq!(parsed.payload_hash, event.payload.0);
        assert_eq!(parsed.key_version, event.keyVersion);
        assert_eq!(parsed.deposit, event.deposit);
        assert_eq!(parsed.chain_id, event.chainId);
        assert_eq!(parsed.path, event.path);
        assert_eq!(parsed.algo, event.algo);
        assert_eq!(parsed.dest, event.dest);
        assert_eq!(parsed.params, event.params);
    }

    #[test]
    fn parse_event_generates_expected_request_id() {
        let event = sample_requested_event();
        let log = requested_log(event.encode_data());

        let parsed = parse_event(&log).expect("valid log should parse");
        let encoding = SignatureRequestedEncoding {
            sender: event.sender,
            payload: Bytes::from(event.payload.to_vec()),
            path: event.path.clone(),
            keyVersion: event.keyVersion,
            chainId: event.chainId,
            algo: event.algo.clone(),
            dest: event.dest.clone(),
            params: event.params.clone(),
        };
        let expected: [u8; 32] = alloy::primitives::keccak256(encoding.encode_data()).into();
        assert_eq!(parsed.generate_request_id(), expected);
    }

    fn responded_log(request_id: [u8; 32], data: Vec<u8>) -> Log {
        Log {
            inner: PrimitiveLog::new_unchecked(
                Address::ZERO,
                vec![
                    ChainSignatures::SignatureResponded::SIGNATURE_HASH,
                    request_id.into(),
                ],
                data.into(),
            ),
            ..Default::default()
        }
    }

    fn sample_responded_event(
        request_id: [u8; 32],
    ) -> (ChainSignatures::SignatureResponded, K256AffinePoint) {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let big_r = K256AffinePoint::GENERATOR;
        let encoded = big_r.to_encoded_point(false);
        let event = ChainSignatures::SignatureResponded {
            requestId: request_id.into(),
            responder: Address::from([0x33; 20]),
            signature: ChainSignatures::Signature {
                bigR: ChainSignatures::AffinePoint {
                    x: U256::from_be_slice(encoded.x().unwrap()),
                    y: U256::from_be_slice(encoded.y().unwrap()),
                },
                s: U256::from(12345u64),
                recoveryId: 1,
            },
        };
        (event, big_r)
    }

    #[tokio::test]
    async fn emit_respond_events_emits_valid_signature() {
        let request_id = [0x42u8; 32];
        let (event, big_r) = sample_responded_event(request_id);
        let log = responded_log(request_id, event.encode_data());

        let (tx, mut rx) = mpsc::channel(1);
        emit_respond_events(&[log], tx).await;

        let Some(ChainEvent::Respond(respond)) = rx.recv().await else {
            panic!("expected a Respond event");
        };
        assert_eq!(respond.request_id, request_id);
        assert_eq!(respond.chain, Chain::Ethereum);
        assert_eq!(respond.signature.big_r, big_r);
        assert_eq!(
            respond.signature.s,
            Scalar::from_bytes(U256::from(12345u64).to_be_bytes()).unwrap()
        );
        assert_eq!(respond.signature.recovery_id, 1);
    }

    #[tokio::test]
    async fn emit_respond_events_skips_malformed_data() {
        let logs = vec![
            responded_log([1u8; 32], vec![]),
            responded_log([2u8; 32], vec![0u8; 100]),
            responded_log([3u8; 32], vec![0u8; 159]),
        ];
        let (tx, mut rx) = mpsc::channel(1);
        emit_respond_events(&logs, tx).await;
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn emit_respond_events_skips_invalid_signature_values() {
        // decodes fine, but bigR = (0, 0) is not on the curve
        let (mut event, _) = sample_responded_event([4u8; 32]);
        event.signature.bigR.x = U256::ZERO;
        event.signature.bigR.y = U256::ZERO;
        let log = responded_log([4u8; 32], event.encode_data());

        let (tx, mut rx) = mpsc::channel(1);
        emit_respond_events(&[log], tx).await;
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn sign_id_from_responded_log_extracts_request_id() {
        let request_id = [0xabu8; 32];
        let log = responded_log(request_id, vec![]);
        let sign_id = sign_id_from_signature_responded_log(&log).expect("well-formed log");
        assert_eq!(sign_id.request_id, request_id);
    }

    #[test]
    fn sign_id_from_responded_log_rejects_wrong_topic0() {
        let mut log = responded_log([0xabu8; 32], vec![]);
        log.topics_mut()[0] = ChainSignatures::SignatureRequested::SIGNATURE_HASH;
        assert!(sign_id_from_signature_responded_log(&log).is_none());
    }

    #[test]
    fn sign_id_from_responded_log_rejects_missing_topics() {
        let no_topics = Log {
            inner: PrimitiveLog::new_unchecked(Address::ZERO, vec![], vec![].into()),
            ..Default::default()
        };
        assert!(sign_id_from_signature_responded_log(&no_topics).is_none());

        let only_topic0 = Log {
            inner: PrimitiveLog::new_unchecked(
                Address::ZERO,
                vec![ChainSignatures::SignatureResponded::SIGNATURE_HASH],
                vec![].into(),
            ),
            ..Default::default()
        };
        assert!(sign_id_from_signature_responded_log(&only_topic0).is_none());
    }

    #[test]
    fn parse_event_rejects_malformed_data() {
        // empty data
        assert!(parse_event(&requested_log(vec![])).is_none());
        // truncated below the 160-byte head
        assert!(parse_event(&requested_log(vec![0u8; 100])).is_none());
        // truncated mid-string-tail
        let valid = sample_requested_event().encode_data();
        assert!(parse_event(&requested_log(valid[..200].to_vec())).is_none());
        // out-of-bounds offset for the `path` string head word (bytes 160..192)
        let mut corrupt = sample_requested_event().encode_data();
        corrupt[160..192].fill(0xff);
        assert!(parse_event(&requested_log(corrupt)).is_none());
    }
}
