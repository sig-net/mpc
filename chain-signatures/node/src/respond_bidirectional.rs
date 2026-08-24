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
        chain: Chain,
        chain_ctx: Option<Vec<u8>>,
    ) -> anyhow::Result<IndexedSignRequest> {
        self.process_failed_tx(chain, chain_ctx).await
    }

    pub(crate) fn create_sign_request_from_serialized_output(
        &self,
        chain: Chain,
        serialized_output: RespondBidirectionalSerializedOutput,
        chain_ctx: Option<Vec<u8>>,
    ) -> anyhow::Result<IndexedSignRequest> {
        self.create_respond_bidirectional_sign_request(chain, serialized_output, chain_ctx)
    }

    async fn process_failed_tx(
        &self,
        chain: Chain,
        chain_ctx: Option<Vec<u8>>,
    ) -> anyhow::Result<IndexedSignRequest> {
        tracing::info!("Tx failed: {:?}", self.tx.id);

        let respond_serialization_format = chain.respond_serialization_format();
        let mut output = Vec::new();
        output.extend_from_slice(&MAGIC_ERROR_PREFIX);
        let serialized_output: Vec<u8> = match respond_serialization_format {
            SerDeserFormat::Borsh => {
                let borsh_data = [1u8]; // Simple serialization: 1 = true
                output.extend_from_slice(&borsh_data);
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
            self.create_respond_bidirectional_sign_request(chain, serialized_output, chain_ctx)?;
        Ok(sign_request)
    }

    fn create_respond_bidirectional_sign_request(
        &self,
        chain: Chain,
        serialized_output: RespondBidirectionalSerializedOutput,
        chain_ctx: Option<Vec<u8>>,
    ) -> anyhow::Result<IndexedSignRequest> {
        let request_id_bytes = self.tx.request_id;
        tracing::info!(
            "Respond bidirectional serialized output: {:?}",
            serialized_output
        );
        let message =
            calculate_respond_bidirectional_hash_message(&request_id_bytes, &serialized_output);
        tracing::info!(
            "Respond bidirectional message hash: {:?}",
            hex::encode(message)
        );
        let Some(payload) = Scalar::from_bytes(message) else {
            anyhow::bail!("Failed to convert respond bidirectional message to scalar: {message:?}");
        };
        let path = respond_bidirectional_path(chain)?;
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
            chain,
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, B256};
    use mpc_primitives::{BidirectionalTxId, SignKind};

    const UINT256_SCHEMA: &[u8] = br#"[{"name":"amount","type":"uint256"}]"#;

    /// Sample tx with a Solana source chain, required by `epsilon`/path derivation.
    fn sample_bidirectional_tx() -> Arc<BidirectionalTx> {
        Arc::new(BidirectionalTx {
            id: BidirectionalTxId(B256::repeat_byte(0xab).0),
            sender: [0x11; 32],
            serialized_transaction: Vec::new(),
            source_chain: Chain::Solana,
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
            request_id: [0x22; 32],
            from_address: **Address::ZERO,
            nonce: 0,
        })
    }

    #[tokio::test]
    async fn create_failed_sign_request_emits_error_prefix() {
        let completed = CompletedTx::new(sample_bidirectional_tx());

        // Solana (Borsh).
        let borsh = completed
            .create_failed_sign_request(Chain::Solana, None)
            .await
            .unwrap();
        let SignKind::RespondBidirectional(respond) = borsh.kind else {
            panic!("expected RespondBidirectional kind");
        };
        assert_eq!(respond.output, [&MAGIC_ERROR_PREFIX[..], &[1u8]].concat());

        // Canton (ABI).
        let abi = completed
            .create_failed_sign_request(Chain::Canton, None)
            .await
            .unwrap();
        let SignKind::RespondBidirectional(respond) = abi.kind else {
            panic!("expected RespondBidirectional kind");
        };
        let mut expected = MAGIC_ERROR_PREFIX.to_vec();
        expected.extend_from_slice(&[0u8; 32]);
        *expected.last_mut().unwrap() = 1;
        assert_eq!(respond.output, expected);
    }

    #[test]
    fn create_sign_request_carries_output_and_context() {
        let tx = sample_bidirectional_tx();
        let completed = CompletedTx::new(tx.clone());
        let output = vec![1, 2, 3, 4];
        let chain_ctx = Some(vec![9, 9]);

        let req = completed
            .create_sign_request_from_serialized_output(
                Chain::Solana,
                output.clone(),
                chain_ctx.clone(),
            )
            .unwrap();

        assert_eq!(req.chain, Chain::Solana);
        let SignKind::RespondBidirectional(respond) = req.kind else {
            panic!("expected RespondBidirectional kind");
        };
        assert_eq!(respond.tx_id, tx.id);
        assert_eq!(respond.output, output);
        assert_eq!(respond.chain_ctx, chain_ctx);
    }
}
