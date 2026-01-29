use crate::indexer_eth::EthereumClient;
use crate::protocol::{Chain, IndexedSignRequest};
use crate::sign_bidirectional::BidirectionalTx;
use crate::sign_bidirectional::BidirectionalTxId;
use crate::sign_bidirectional::TransactionOutput;
use alloy::consensus::Transaction;
use alloy::primitives::Bytes;
use k256::Scalar;
use mpc_crypto::ScalarExt;
use mpc_primitives::{SignArgs, SignId};
use std::sync::Arc;
use tokio::time::Duration;

const MAGIC_ERROR_PREFIX: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
const SOLANA_RESPOND_BIDIRECTIONAL_PATH: &str = "solana response key";
const HYDRATION_RESPOND_BIDIRECTIONAL_PATH: &str = "hydration response key";
// Use Borsh as this is what we are using for solana
pub(crate) const RESPOND_SERIALIZATION_FORMAT: SerDeserFormat = SerDeserFormat::Borsh;
// Use Abi as this is what we are using for ethereum
pub(crate) const OUTPUT_DESERIALIZATION_FORMAT: SerDeserFormat = SerDeserFormat::Abi;

#[derive(PartialEq)]
pub enum SerDeserFormat {
    Borsh,
    Abi,
}

pub struct CompletedTx {
    tx: BidirectionalTx,
    block_number: u64,
}

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub struct RespondBidirectionalTx {
    pub tx_id: BidirectionalTxId,
    pub output: RespondBidirectionalSerializedOutput,
}

pub type RespondBidirectionalSerializedOutput = Vec<u8>;

impl CompletedTx {
    pub fn new(tx: BidirectionalTx, block_number: u64) -> Self {
        Self { tx, block_number }
    }

    pub(crate) async fn create_failed_sign_request(
        &self,
        chain: Chain,
        signature_generation_total_timeout: Duration,
    ) -> anyhow::Result<IndexedSignRequest> {
        self.process_failed_tx(chain, signature_generation_total_timeout)
            .await
    }

    pub(crate) fn create_sign_request_from_serialized_output(
        &self,
        chain: Chain,
        serialized_output: RespondBidirectionalSerializedOutput,
        signature_generation_total_timeout: Duration,
    ) -> anyhow::Result<IndexedSignRequest> {
        self.create_respond_bidirectional_sign_request(
            chain,
            serialized_output,
            signature_generation_total_timeout,
        )
    }

    async fn process_failed_tx(
        &self,
        chain: Chain,
        total_timeout: Duration,
    ) -> anyhow::Result<IndexedSignRequest> {
        tracing::info!("Tx failed: {:?}", self.tx.id);

        let respond_serialization_format = RESPOND_SERIALIZATION_FORMAT;
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
        let sign_request = self.create_respond_bidirectional_sign_request(
            chain,
            serialized_output,
            total_timeout,
        )?;
        Ok(sign_request)
    }

    fn create_respond_bidirectional_sign_request(
        &self,
        chain: Chain,
        serialized_output: RespondBidirectionalSerializedOutput,
        signature_generation_total_timeout: Duration,
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
        let path = match chain {
            Chain::Solana => SOLANA_RESPOND_BIDIRECTIONAL_PATH.to_string(),
            Chain::Hydration => HYDRATION_RESPOND_BIDIRECTIONAL_PATH.to_string(),
            _ => anyhow::bail!("Unsupported chain: {}", chain),
        };
        let epsilon = self.tx.epsilon(&path)?;
        let entropy = self.tx.id.0;
        Ok(IndexedSignRequest {
            id: SignId::new(request_id_bytes),
            chain,
            args: SignArgs {
                entropy: entropy.into(),
                epsilon,
                payload,
                path,
                key_version: self.tx.key_version,
            },
            unix_timestamp_indexed: crate::util::current_unix_timestamp(),
            timestamp_created: std::time::Instant::now(),
            total_timeout: signature_generation_total_timeout,
            sign_request_type: crate::protocol::SignRequestType::RespondBidirectional(
                RespondBidirectionalTx {
                    tx_id: self.tx.id,
                    output: serialized_output,
                },
            ),
        })
    }

    pub async fn extract_success_tx_output(
        &self,
        client: &Arc<EthereumClient>,
    ) -> anyhow::Result<RespondBidirectionalSerializedOutput> {
        let tx = &self.tx;
        let tx_id = self.tx.id.0;
        let block_number = self.block_number;
        let Some(tx_info) = client.as_ref().get_transaction_by_hash(tx_id).await? else {
            anyhow::bail!("Failed to fetch transaction {tx_id:?}");
        };

        let data = tx_info.inner.input().clone();
        let is_contract_call = data.len() > 2 && data != Bytes::from("0x");
        let output_deserialization_format = OUTPUT_DESERIALIZATION_FORMAT;
        let output_deserialization_schema = &tx.output_deserialization_schema;

        let transaction_output = match output_deserialization_format {
            SerDeserFormat::Abi if is_contract_call => {
                let to_address = tx_info.inner.to().ok_or_else(|| {
                    anyhow::anyhow!("Transaction {:?} missing destination", tx.id)
                })?;
                let call_block = block_number.saturating_sub(1);
                let call_result = client
                    .call(tx.from_address, to_address, data.clone(), call_block)
                    .await?;
                TransactionOutput::from_call_result(output_deserialization_schema, &call_result)?
            }
            _ => TransactionOutput::non_function_call_output(),
        };

        let respond_serialization_format = RESPOND_SERIALIZATION_FORMAT;
        let respond_serialization_schema = &tx.respond_serialization_schema;
        let serialized_output = transaction_output
            .output
            .serialize(respond_serialization_format, respond_serialization_schema)?;
        Ok(serialized_output)
    }
}

fn calculate_respond_bidirectional_hash_message(
    request_id: &[u8],
    serialized_output: &[u8],
) -> [u8; 32] {
    let mut combined = Vec::with_capacity(request_id.len() + serialized_output.len());
    combined.extend_from_slice(request_id);
    combined.extend_from_slice(serialized_output);

    // Compute keccak256 hash
    alloy::primitives::keccak256(&combined).into()
}
