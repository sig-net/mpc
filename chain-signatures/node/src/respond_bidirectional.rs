use crate::sign_bidirectional::BidirectionalTxExt;
use alloy::primitives::Bytes;
use k256::Scalar;
use mpc_crypto::ScalarExt;
use mpc_primitives::{
    BidirectionalTx, Chain, ChainConfig as _, IndexedSignRequest,
    RespondBidirectionalSerializedOutput, RespondBidirectionalTx, SerDeserFormat, SignArgs, SignId,
};
use mpc_utils::time::current_unix_timestamp;
use std::sync::Arc;

const MAGIC_ERROR_PREFIX: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
const SOLANA_RESPOND_BIDIRECTIONAL_PATH: &str = "solana response key";
const HYDRATION_RESPOND_BIDIRECTIONAL_PATH: &str = "hydration response key";
pub const CANTON_RESPOND_BIDIRECTIONAL_PATH: &str = "canton response key";
pub const MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH: &str = "midnight response key";

fn respond_bidirectional_path(chain: Chain) -> anyhow::Result<String> {
    match chain {
        Chain::Solana => Ok(SOLANA_RESPOND_BIDIRECTIONAL_PATH.to_string()),
        Chain::Hydration => Ok(HYDRATION_RESPOND_BIDIRECTIONAL_PATH.to_string()),
        Chain::Canton => Ok(CANTON_RESPOND_BIDIRECTIONAL_PATH.to_string()),
        Chain::Midnight => Ok(MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH.to_string()),
        _ => anyhow::bail!("Unsupported chain: {}", chain),
    }
}

pub struct CompletedTx {
    tx: Arc<BidirectionalTx>,
}

impl CompletedTx {
    pub fn new(tx: Arc<BidirectionalTx>) -> Self {
        Self { tx }
    }

    pub(crate) async fn create_failed_sign_request(
        &self,
        chain_ctx: Option<Vec<u8>>,
    ) -> anyhow::Result<IndexedSignRequest> {
        self.process_failed_tx(chain_ctx).await
    }

    pub(crate) fn create_sign_request_from_serialized_output(
        &self,
        serialized_output: RespondBidirectionalSerializedOutput,
        chain_ctx: Option<Vec<u8>>,
    ) -> anyhow::Result<IndexedSignRequest> {
        self.create_respond_bidirectional_sign_request(serialized_output, chain_ctx)
    }

    async fn process_failed_tx(
        &self,
        chain_ctx: Option<Vec<u8>>,
    ) -> anyhow::Result<IndexedSignRequest> {
        tracing::info!("Tx failed: {:?}", self.tx.id);

        let source_chain = self.tx.source_chain;
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
        let sign_request =
            self.create_respond_bidirectional_sign_request(serialized_output, chain_ctx)?;
        Ok(sign_request)
    }

    fn create_respond_bidirectional_sign_request(
        &self,
        serialized_output: RespondBidirectionalSerializedOutput,
        chain_ctx: Option<Vec<u8>>,
    ) -> anyhow::Result<IndexedSignRequest> {
        let source_chain = self.tx.source_chain;
        let request_id_bytes = self.tx.request_id;
        tracing::info!(
            "Respond bidirectional serialized output: {:?}",
            serialized_output
        );
        let message = calculate_respond_bidirectional_hash_message_for_chain(
            source_chain,
            &request_id_bytes,
            &serialized_output,
        );
        tracing::info!(
            "Respond bidirectional message hash: {:?}",
            hex::encode(message)
        );
        let Some(payload) = Scalar::from_bytes(message) else {
            anyhow::bail!("Failed to convert respond bidirectional message to scalar: {message:?}");
        };
        let path = respond_bidirectional_path(source_chain)?;
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
                chain_ctx,
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
) -> [u8; 32] {
    match source_chain {
        Chain::Midnight => {
            mpc_compact_hashing::compute_response_hash(request_id, serialized_output)
        }
        Chain::NEAR
        | Chain::Ethereum
        | Chain::Solana
        | Chain::Bitcoin
        | Chain::Hydration
        | Chain::Canton => {
            calculate_respond_bidirectional_hash_message(request_id, serialized_output)
        }
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
        let borsh = CompletedTx::new(sample_bidirectional_tx(Chain::Solana, [0x22; 32]))
            .create_failed_sign_request(None)
            .await
            .unwrap();
        let SignKind::RespondBidirectional(respond) = borsh.kind else {
            panic!("expected RespondBidirectional kind");
        };
        assert_eq!(respond.output, [&MAGIC_ERROR_PREFIX[..], &[1u8]].concat());

        // Canton (ABI).
        let abi = CompletedTx::new(sample_bidirectional_tx(Chain::Canton, [0x22; 32]))
            .create_failed_sign_request(None)
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
        let fab = CompletedTx::new(sample_bidirectional_tx(Chain::Midnight, [0x22; 32]))
            .create_failed_sign_request(None)
            .await
            .unwrap();
        let SignKind::RespondBidirectional(respond) = fab.kind else {
            panic!("expected RespondBidirectional kind");
        };
        assert_eq!(respond.output, hex::decode("deadbeef01").unwrap());
    }

    #[test]
    fn create_sign_request_carries_output_and_context() {
        let tx = sample_bidirectional_tx(Chain::Solana, [0x22; 32]);
        let completed = CompletedTx::new(tx.clone());
        let output = vec![1, 2, 3, 4];
        let chain_ctx = Some(vec![9, 9]);

        let req = completed
            .create_sign_request_from_serialized_output(output.clone(), chain_ctx.clone())
            .unwrap();

        assert_eq!(req.chain, Chain::Solana);
        let SignKind::RespondBidirectional(respond) = req.kind else {
            panic!("expected RespondBidirectional kind");
        };
        assert_eq!(respond.tx_id, tx.id);
        assert_eq!(respond.output, output);
        assert_eq!(respond.chain_ctx, chain_ctx);
    }

    #[test]
    fn response_hash_policy_preserves_legacy_keccak_for_non_midnight_chains() {
        let request_id = [0x2f; 32];
        let serialized_output = (1..=32).collect::<Vec<_>>();
        let expected = "c19dbe87b89aa45fdd7be361ae98513371d19c015b591ba1194ee6d356f0e8dc";

        for source_chain in [
            Chain::NEAR,
            Chain::Ethereum,
            Chain::Solana,
            Chain::Bitcoin,
            Chain::Hydration,
            Chain::Canton,
        ] {
            assert_eq!(
                hex::encode(calculate_respond_bidirectional_hash_message_for_chain(
                    source_chain,
                    &request_id,
                    &serialized_output,
                )),
                expected,
                "unexpected response hash for {source_chain}"
            );
        }
    }

    #[test]
    fn response_hash_policy_uses_midnight_compact_hash() {
        let request_id = [0x2f; 32];
        let serialized_output = (1..=32).collect::<Vec<_>>();
        let keccak = alloy::primitives::keccak256(
            [request_id.as_slice(), serialized_output.as_slice()].concat(),
        );
        let midnight_hash = calculate_respond_bidirectional_hash_message_for_chain(
            Chain::Midnight,
            &request_id,
            &serialized_output,
        );

        assert_eq!(
            hex::encode(midnight_hash),
            "61c48f724b114d830caafcb9722b07c5428e2b906b5a61afa26c063735722700"
        );
        assert_ne!(midnight_hash, <B256 as Into<[u8; 32]>>::into(keccak));
    }

    #[test]
    fn completed_tx_uses_source_chain_for_midnight_response() {
        let request_id = [0x2f; 32];
        let serialized_output = (1..=32).collect::<Vec<_>>();
        let tx = sample_bidirectional_tx(Chain::Midnight, request_id);
        assert_eq!(tx.target_chain, Chain::Ethereum);

        let request = CompletedTx::new(tx)
            .create_sign_request_from_serialized_output(serialized_output, None)
            .unwrap();
        let expected_payload = Scalar::from_bytes(
            hex::decode("61c48f724b114d830caafcb9722b07c5428e2b906b5a61afa26c063735722700")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();

        assert_eq!(request.chain, Chain::Midnight);
        assert_eq!(request.args.payload, expected_payload);
        assert_eq!(request.args.path, MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH);
    }
}
