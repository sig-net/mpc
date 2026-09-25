use crate::sign_bidirectional::BidirectionalTxExt;
use alloy::primitives::Bytes;
use k256::Scalar;
use mpc_crypto::ScalarExt;
use mpc_primitives::{
    AttestationMetadata, AttestationOutcomeKind, BidirectionalTx, Chain, ChainConfig as _,
    IndexedSignRequest, RespondBidirectionalSerializedOutput, RespondBidirectionalTx,
    SerDeserFormat, SignArgs, SignId, SignKind,
};
use mpc_utils::time::current_unix_timestamp;
use std::sync::Arc;

const MAGIC_ERROR_PREFIX: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

pub(crate) fn is_failed_execution_response(response: &RespondBidirectionalTx) -> bool {
    match response.attestation {
        Some(metadata) => metadata.outcome != AttestationOutcomeKind::Executed,
        None => response.output.starts_with(&MAGIC_ERROR_PREFIX),
    }
}
const SOLANA_RESPOND_BIDIRECTIONAL_PATH: &str = "solana response key";
const HYDRATION_RESPOND_BIDIRECTIONAL_PATH: &str = "hydration response key";
pub const CANTON_RESPOND_BIDIRECTIONAL_PATH: &str = "canton response key";
pub const MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH: &str = "midnight response key";

fn respond_bidirectional_path(chain: Chain) -> Option<&'static str> {
    match chain {
        Chain::Solana => Some(SOLANA_RESPOND_BIDIRECTIONAL_PATH),
        Chain::Hydration => Some(HYDRATION_RESPOND_BIDIRECTIONAL_PATH),
        Chain::Canton => Some(CANTON_RESPOND_BIDIRECTIONAL_PATH),
        Chain::Midnight => Some(MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH),
        _ => None,
    }
}

/// Whether `request` asks for its chain's attestation key without being the leg-2
/// attestation the respond path builds. False on chains `respond_bidirectional_path` omits.
pub(crate) fn claims_attestation_key(request: &IndexedSignRequest) -> bool {
    !matches!(request.kind, SignKind::RespondBidirectional(_))
        && respond_bidirectional_path(request.chain) == Some(request.args.path.as_str())
}

pub struct CompletedTx {
    tx: Arc<BidirectionalTx>,
    chain_ctx: Option<Vec<u8>>,
    origin_indexed_at: Option<u64>,
    block_height: u64,
}

impl CompletedTx {
    pub fn new(
        tx: Arc<BidirectionalTx>,
        chain_ctx: Option<Vec<u8>>,
        origin_indexed_at: Option<u64>,
        block_height: u64,
    ) -> Self {
        Self {
            tx,
            chain_ctx,
            origin_indexed_at,
            block_height,
        }
    }

    pub(crate) async fn create_failed_sign_request(&self) -> anyhow::Result<IndexedSignRequest> {
        self.process_failed_tx().await
    }

    pub(crate) fn create_unviable_sign_request(&self) -> anyhow::Result<IndexedSignRequest> {
        anyhow::ensure!(
            self.tx.source_chain == Chain::Midnight,
            "unviable attestations are only supported for Midnight"
        );
        self.create_respond_bidirectional_sign_request(Vec::new(), AttestationOutcomeKind::Unviable)
    }

    pub(crate) fn create_sign_request_from_serialized_output(
        &self,
        serialized_output: RespondBidirectionalSerializedOutput,
    ) -> anyhow::Result<IndexedSignRequest> {
        self.create_respond_bidirectional_sign_request(
            serialized_output,
            AttestationOutcomeKind::Executed,
        )
    }

    async fn process_failed_tx(&self) -> anyhow::Result<IndexedSignRequest> {
        tracing::info!("Tx failed: {:?}", self.tx.id);

        let source_chain = self.tx.source_chain;
        if source_chain == Chain::Midnight {
            return self.create_respond_bidirectional_sign_request(
                Vec::new(),
                AttestationOutcomeKind::Failed,
            );
        }
        let respond_serialization_format = source_chain.respond_serialization_format();
        let mut output = Vec::new();
        output.extend_from_slice(&MAGIC_ERROR_PREFIX);
        let serialized_output: Vec<u8> = match respond_serialization_format {
            SerDeserFormat::Borsh => {
                let borsh_data = [1u8]; // Simple serialization: 1 = true
                output.extend_from_slice(&borsh_data);
                Bytes::from(output).into()
            }
            SerDeserFormat::Fab => {
                output.push(1);
                Bytes::from(output).into()
            }
            SerDeserFormat::Abi => {
                // Encode boolean as ABI: true = 0x0000000000000000000000000000000000000000000000000000000000000001
                let abi_encoded = [0u8; 32];
                let mut encoded = abi_encoded;
                encoded[31] = 1; // Set last byte to 1 for true
                output.extend_from_slice(&encoded);
                Bytes::from(output).into()
            }
        };
        let sign_request = self.create_respond_bidirectional_sign_request(
            serialized_output,
            AttestationOutcomeKind::Failed,
        )?;
        Ok(sign_request)
    }

    fn create_respond_bidirectional_sign_request(
        &self,
        serialized_output: RespondBidirectionalSerializedOutput,
        outcome: AttestationOutcomeKind,
    ) -> anyhow::Result<IndexedSignRequest> {
        let source_chain = self.tx.source_chain;
        let request_id_bytes = self.tx.request_id;
        tracing::info!(
            "Respond bidirectional serialized output: {:?}",
            serialized_output
        );
        let attestation = (source_chain == Chain::Midnight).then_some(AttestationMetadata {
            key_version: self.tx.key_version,
            block_height: self.block_height,
            outcome,
        });
        let message = calculate_respond_bidirectional_hash_message_for_chain(
            source_chain,
            &request_id_bytes,
            &serialized_output,
            attestation.as_ref(),
        )?;
        tracing::info!(
            "Respond bidirectional message hash: {:?}",
            hex::encode(message)
        );
        let Some(payload) = Scalar::from_bytes(message) else {
            anyhow::bail!("Failed to convert respond bidirectional message to scalar: {message:?}");
        };
        let path = respond_bidirectional_path(source_chain)
            .ok_or_else(|| anyhow::anyhow!("Unsupported chain: {}", source_chain))?
            .to_string();
        let epsilon = self.tx.epsilon(&path)?;
        let entropy = self.tx.id.0;
        Ok(IndexedSignRequest::respond_bidirectional(
            SignId::new(request_id_bytes),
            SignArgs {
                entropy,
                epsilon,
                payload,
                path,
                key_version: self.tx.key_version,
            },
            source_chain,
            current_unix_timestamp(),
            RespondBidirectionalTx {
                tx_id: self.tx.id,
                output: serialized_output,
                attestation,
                origin_indexed_at: self.origin_indexed_at,
                chain_ctx: self.chain_ctx.clone(),
            },
        ))
    }
}

pub fn calculate_respond_bidirectional_hash_message(
    request_id: &[u8],
    serialized_output: &[u8],
) -> [u8; 32] {
    let mut combined = Vec::with_capacity(request_id.len() + serialized_output.len());
    combined.extend_from_slice(request_id);
    combined.extend_from_slice(serialized_output);

    // Compute keccak256 hash
    alloy::primitives::keccak256(&combined).into()
}

fn calculate_respond_bidirectional_hash_message_for_chain(
    source_chain: Chain,
    request_id: &[u8; 32],
    serialized_output: &[u8],
    attestation: Option<&AttestationMetadata>,
) -> anyhow::Result<[u8; 32]> {
    match source_chain {
        Chain::Midnight => {
            let attestation = attestation
                .ok_or_else(|| anyhow::anyhow!("Midnight attestation metadata is required"))?;
            Ok(mpc_compact_hashing::compute_attestation_hash(
                request_id,
                attestation,
                serialized_output,
            )?)
        }
        Chain::NEAR
        | Chain::Ethereum
        | Chain::Solana
        | Chain::Bitcoin
        | Chain::Hydration
        | Chain::Canton => Ok(calculate_respond_bidirectional_hash_message(
            request_id,
            serialized_output,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, B256};
    use mpc_primitives::{BidirectionalTxId, SignKind};

    const UINT256_SCHEMA: &[u8] = br#"[{"name":"amount","type":"uint256"}]"#;

    fn sample_bidirectional_tx(source_chain: Chain, request_id: [u8; 32]) -> Arc<BidirectionalTx> {
        Arc::new(BidirectionalTx {
            id: BidirectionalTxId(B256::repeat_byte(0xab).0),
            sender: [0x11; 32],
            serialized_transaction: Vec::new(),
            source_chain,
            target_chain: Chain::Ethereum,
            caip2_id: "eip155:1".to_string(),
            key_version: 0,
            deposit: 0,
            path: "test".to_string(),
            algo: String::new(),
            dest: String::new(),
            params: String::new(),
            output_deserialization_schema: UINT256_SCHEMA.to_vec(),
            respond_serialization_schema: UINT256_SCHEMA.to_vec(),
            request_id,
            from_address: **Address::ZERO,
            nonce: 0,
        })
    }

    #[tokio::test]
    async fn create_failed_sign_request_emits_error_prefix() {
        // Solana (Borsh).
        let borsh = CompletedTx::new(
            sample_bidirectional_tx(Chain::Solana, [0x22; 32]),
            None,
            Some(100),
            456,
        )
        .create_failed_sign_request()
        .await
        .unwrap();
        let SignKind::RespondBidirectional(respond) = borsh.kind else {
            panic!("expected RespondBidirectional kind");
        };
        assert_eq!(respond.output, [&MAGIC_ERROR_PREFIX[..], &[1u8]].concat());

        // Canton (ABI).
        let abi = CompletedTx::new(
            sample_bidirectional_tx(Chain::Canton, [0x22; 32]),
            None,
            Some(100),
            456,
        )
        .create_failed_sign_request()
        .await
        .unwrap();
        let SignKind::RespondBidirectional(respond) = abi.kind else {
            panic!("expected RespondBidirectional kind");
        };
        let mut expected = MAGIC_ERROR_PREFIX.to_vec();
        expected.extend_from_slice(&[0u8; 32]);
        *expected.last_mut().unwrap() = 1;
        assert_eq!(respond.output, expected);

        // Midnight (FAB).
        let fab = CompletedTx::new(
            sample_bidirectional_tx(Chain::Midnight, [0x22; 32]),
            None,
            Some(100),
            456,
        )
        .create_failed_sign_request()
        .await
        .unwrap();
        let SignKind::RespondBidirectional(respond) = fab.kind else {
            panic!("expected RespondBidirectional kind");
        };
        assert!(respond.output.is_empty());
        assert_eq!(
            respond.attestation.unwrap(),
            AttestationMetadata {
                key_version: 0,
                block_height: 456,
                outcome: AttestationOutcomeKind::Failed
            }
        );
    }

    #[test]
    fn create_sign_request_carries_output_and_context() {
        let tx = sample_bidirectional_tx(Chain::Solana, [0x22; 32]);
        let output = vec![1, 2, 3, 4];
        let chain_ctx = Some(vec![9, 9]);
        let completed = CompletedTx::new(tx.clone(), chain_ctx.clone(), Some(100), 456);

        let req = completed
            .create_sign_request_from_serialized_output(output.clone())
            .unwrap();

        assert_eq!(req.chain, Chain::Solana);
        let SignKind::RespondBidirectional(respond) = req.kind else {
            panic!("expected RespondBidirectional kind");
        };
        assert_eq!(respond.tx_id, tx.id);
        assert_eq!(respond.output, output);
        assert_eq!(respond.origin_indexed_at, Some(100));
        assert_eq!(respond.chain_ctx, chain_ctx);
    }

    /// The metric status for a round trip is derived from this marker, so the
    /// failed and successful paths must stay distinguishable.
    #[tokio::test]
    async fn failed_execution_output_is_detectable() {
        let failed = CompletedTx::new(
            sample_bidirectional_tx(Chain::Solana, [0x31; 32]),
            None,
            Some(100),
            456,
        )
        .create_failed_sign_request()
        .await
        .unwrap();
        let SignKind::RespondBidirectional(failed) = failed.kind else {
            panic!("expected RespondBidirectional");
        };
        assert!(is_failed_execution_response(&failed));

        let succeeded = CompletedTx::new(
            sample_bidirectional_tx(Chain::Solana, [0x32; 32]),
            None,
            Some(100),
            456,
        )
        .create_sign_request_from_serialized_output(vec![1, 2, 3, 4, 5])
        .unwrap();
        let SignKind::RespondBidirectional(succeeded) = succeeded.kind else {
            panic!("expected RespondBidirectional");
        };
        assert!(!is_failed_execution_response(&succeeded));
    }

    #[test]
    fn respond_bidirectional_tx_defaults_missing_origin() {
        let response = RespondBidirectionalTx {
            tx_id: mpc_primitives::BidirectionalTxId([1; 32]),
            output: vec![],
            attestation: None,
            origin_indexed_at: Some(100),
            chain_ctx: None,
        };
        let mut encoded = serde_json::to_value(response).unwrap();
        encoded.as_object_mut().unwrap().remove("origin_indexed_at");

        let decoded: RespondBidirectionalTx = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.origin_indexed_at, None);
        assert_eq!(decoded.attestation, None);
    }

    #[test]
    fn midnight_success_with_legacy_error_bytes_remains_success() {
        let request = CompletedTx::new(
            sample_bidirectional_tx(Chain::Midnight, [3; 32]),
            None,
            None,
            456,
        )
        .create_sign_request_from_serialized_output(MAGIC_ERROR_PREFIX.to_vec())
        .unwrap();
        let SignKind::RespondBidirectional(response) = request.kind else {
            panic!("expected response")
        };
        assert!(!is_failed_execution_response(&response));
        let roundtrip: RespondBidirectionalTx =
            serde_json::from_value(serde_json::to_value(&response).unwrap()).unwrap();
        assert_eq!(roundtrip.attestation, response.attestation);
        assert_eq!(roundtrip.output, MAGIC_ERROR_PREFIX);
    }

    #[tokio::test]
    async fn midnight_failure_payload_differs_from_zero_padded_success() {
        let completed = CompletedTx::new(
            sample_bidirectional_tx(Chain::Midnight, [0x2f; 32]),
            None,
            Some(100),
            456,
        );
        let failure = completed.create_failed_sign_request().await.unwrap();
        let SignKind::RespondBidirectional(response) = &failure.kind else {
            panic!("expected RespondBidirectional kind");
        };

        for length in [8, 9] {
            let mut output = response.output.clone();
            output.resize(length, 0);
            let success = completed
                .create_sign_request_from_serialized_output(output)
                .unwrap();
            assert_ne!(failure.args.payload, success.args.payload);
        }
    }

    #[test]
    fn response_hash_policy_preserves_legacy_keccak_for_non_midnight_chains() {
        let request_id = [0x2f; 32];
        let serialized_output = (1..=32).collect::<Vec<_>>();
        let expected = "c19dbe87b89aa45fdd7be361ae98513371d19c015b591ba1194ee6d356f0e8dc";
        assert_eq!(
            hex::encode(calculate_respond_bidirectional_hash_message(
                &request_id,
                &serialized_output
            )),
            expected
        );
        for source_chain in [Chain::Solana, Chain::Hydration, Chain::Canton] {
            let request = CompletedTx::new(
                sample_bidirectional_tx(source_chain, request_id),
                None,
                None,
                456,
            )
            .create_sign_request_from_serialized_output(serialized_output.clone())
            .unwrap();
            assert_eq!(
                hex::encode(request.args.payload.to_bytes()),
                expected,
                "{source_chain}"
            );
            let SignKind::RespondBidirectional(response) = request.kind else {
                unreachable!()
            };
            assert!(response.attestation.is_none());
        }
    }

    #[test]
    fn response_hash_policy_requires_midnight_metadata() {
        let rid = [0x2f; 32];
        assert!(calculate_respond_bidirectional_hash_message_for_chain(
            Chain::Midnight,
            &rid,
            &[],
            None
        )
        .is_err());
        let metadata = AttestationMetadata {
            key_version: 1,
            block_height: 456,
            outcome: AttestationOutcomeKind::Executed,
        };
        let hash = calculate_respond_bidirectional_hash_message_for_chain(
            Chain::Midnight,
            &rid,
            &[],
            Some(&metadata),
        )
        .unwrap();
        let failed = AttestationMetadata {
            outcome: AttestationOutcomeKind::Failed,
            ..metadata
        };
        assert_ne!(
            hash,
            calculate_respond_bidirectional_hash_message_for_chain(
                Chain::Midnight,
                &rid,
                &[],
                Some(&failed)
            )
            .unwrap()
        );
    }

    #[test]
    fn completed_tx_uses_source_chain_for_midnight_response() {
        let request_id = [0x2f; 32];
        let serialized_output = (1..=32).collect::<Vec<_>>();
        let tx = sample_bidirectional_tx(Chain::Midnight, request_id);
        assert_eq!(tx.target_chain, Chain::Ethereum);

        let request = CompletedTx::new(tx, None, Some(100), 456)
            .create_sign_request_from_serialized_output(serialized_output)
            .unwrap();
        let expected_payload = Scalar::from_bytes(
            mpc_compact_hashing::compute_attestation_hash(
                &request_id,
                &AttestationMetadata {
                    key_version: 0,
                    block_height: 456,
                    outcome: AttestationOutcomeKind::Executed,
                },
                &(1..=32).collect::<Vec<_>>(),
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(request.chain, Chain::Midnight);
        assert_eq!(request.args.payload, expected_payload);
        assert_eq!(request.args.path, MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH);
    }

    #[tokio::test]
    async fn midnight_unviable_binds_replacement_height_and_empty_output() {
        let request_id = [0x2f; 32];
        let tx = sample_bidirectional_tx(Chain::Midnight, request_id);
        let completed = CompletedTx::new(tx, None, Some(100), 456);
        let request = completed.create_unviable_sign_request().unwrap();
        let SignKind::RespondBidirectional(response) = &request.kind else {
            panic!("expected a response");
        };
        let metadata = AttestationMetadata {
            key_version: request.args.key_version,
            block_height: 456,
            outcome: AttestationOutcomeKind::Unviable,
        };
        assert_eq!(response.attestation, Some(metadata));
        assert!(response.output.is_empty());
        assert_eq!(response.origin_indexed_at, Some(100));
        assert_eq!(request.args.path, MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH);
        assert_eq!(
            request.args.payload,
            Scalar::from_bytes(
                mpc_compact_hashing::compute_attestation_hash(&request_id, &metadata, &[]).unwrap()
            )
            .unwrap()
        );
        assert_ne!(
            request.args.payload,
            completed
                .create_failed_sign_request()
                .await
                .unwrap()
                .args
                .payload
        );
        assert_ne!(
            request.args.payload,
            completed
                .create_sign_request_from_serialized_output(vec![])
                .unwrap()
                .args
                .payload
        );
        assert!(is_failed_execution_response(response));

        for chain in [Chain::Solana, Chain::Canton, Chain::Hydration] {
            assert!(
                CompletedTx::new(sample_bidirectional_tx(chain, request_id), None, None, 456)
                    .create_unviable_sign_request()
                    .is_err(),
                "{chain}"
            );
        }
    }

    /// The network's own leg-2 attestation and the attack name the same path, so the
    /// request kind is all that separates them.
    #[test]
    fn claims_attestation_key_separates_the_attack_from_leg_two() {
        let tx = sample_bidirectional_tx(Chain::Solana, [0x30; 32]);
        let leg_two = CompletedTx::new(tx, None, None, 456)
            .create_sign_request_from_serialized_output(vec![1; 32])
            .unwrap();
        assert!(!claims_attestation_key(&leg_two));

        let mut attack = leg_two.clone();
        attack.kind = SignKind::Sign;
        assert!(claims_attestation_key(&attack));

        // Canton has no plain `sign`, so a first leg is its only way to ask.
        let mut leg_one =
            (*crate::backlog::mock::mock_bidi_request(SignId::new([0x31; 32]), Chain::Solana))
                .clone();
        leg_one.args.path = SOLANA_RESPOND_BIDIRECTIONAL_PATH.to_string();
        assert!(claims_attestation_key(&leg_one));

        attack.chain = Chain::Ethereum;
        assert!(
            !claims_attestation_key(&attack),
            "only the request's own chain's path is reserved"
        );
    }
}
