use crate::protocol::{Chain, IndexedSignRequest};
use crate::sign_bidirectional::BidirectionalTx;
use crate::sign_bidirectional::BidirectionalTxId;
#[cfg(feature = "light_client")]
use crate::sign_bidirectional::BidirectionalTxStatus;
#[cfg(feature = "light_client")]
use crate::sign_bidirectional::TransactionOutput;
#[cfg(feature = "light_client")]
use alloy::consensus::Transaction;
#[cfg(feature = "light_client")]
use alloy::eips::{BlockId, BlockNumberOrTag};
#[cfg(feature = "light_client")]
use alloy::primitives::Address;
use alloy::primitives::Bytes;
#[cfg(feature = "light_client")]
use alloy::rpc::types::TransactionRequest;
#[cfg(feature = "light_client")]
use helios::ethereum::EthereumClient;
use k256::Scalar;
use mpc_crypto::ScalarExt;
use mpc_primitives::{SignArgs, SignId};
use tokio::time::Duration;

const MAGIC_ERROR_PREFIX: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
const SOLANA_RESPOND_BIDIRECTIONAL_PATH: &str = "solana response key";
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
    #[cfg(feature = "light_client")]
    block_number: u64,
}

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub struct RespondBidirectionalTx {
    pub tx_id: BidirectionalTxId,
    pub output: RespondBidirectionalSerializedOutput,
}

pub type RespondBidirectionalSerializedOutput = Vec<u8>;

impl CompletedTx {
    #[cfg_attr(not(feature = "light_client"), allow(unused_variables))]
    pub fn new(tx: BidirectionalTx, block_number: u64) -> Self {
        Self {
            tx,
            #[cfg(feature = "light_client")]
            block_number,
        }
    }

    #[cfg(not(feature = "light_client"))]
    pub(crate) async fn create_failed_sign_request_without_light_client(
        &self,
        chain: Chain,
        signature_generation_total_timeout: Duration,
    ) -> anyhow::Result<IndexedSignRequest> {
        self.process_failed_tx(chain, signature_generation_total_timeout)
            .await
    }

    #[cfg(not(feature = "light_client"))]
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

    #[cfg(feature = "light_client")]
    pub async fn create_sign_request_from_completed_tx(
        &self,
        helios_client: &Arc<EthereumClient>,
        chain: Chain,
        max_attempts: u8,
        signature_generation_total_timeout: Duration,
    ) -> Option<IndexedSignRequest> {
        match self
            .process_completed_tx(
                helios_client,
                chain,
                max_attempts,
                signature_generation_total_timeout,
            )
            .await
        {
            Ok(sign_request) => {
                tracing::info!(
                    ?sign_request,
                    "Successfully created sign request from completed tx"
                );
                Some(sign_request)
            }
            Err(err) => {
                tracing::error!(
                    "Failed to process completed tx: {err:?}, tx id: {:?}",
                    self.tx.id
                );
                None
            }
        }
    }

    #[cfg(feature = "light_client")]
    async fn process_completed_tx(
        &self,
        helios_client: &Arc<EthereumClient>,
        chain: Chain,
        max_attempts: u8,
        signature_generation_total_timeout: Duration,
    ) -> anyhow::Result<IndexedSignRequest> {
        if self.tx.status == PendingRequestStatus::Success {
            self.process_success_tx(
                helios_client,
                chain,
                max_attempts,
                signature_generation_total_timeout,
            )
            .await
        } else {
            self.process_failed_tx(chain, signature_generation_total_timeout)
                .await
        }
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

    #[cfg(feature = "light_client")]
    async fn process_success_tx(
        &self,
        helios_client: &Arc<EthereumClient>,
        chain: Chain,
        max_attempts: u8,
        signature_generation_total_timeout: Duration,
    ) -> anyhow::Result<IndexedSignRequest> {
        let tx_output = self
            .extract_success_tx_output(helios_client, max_attempts)
            .await?;
        tracing::info!("Tx succeeded: {tx_output:?}");
        let respond_serialization_format = RESPOND_SERIALIZATION_FORMAT;
        let respond_serialization_schema = &self.tx.respond_serialization_schema;
        let serialized_output = tx_output
            .output
            .serialize(respond_serialization_format, respond_serialization_schema)?;
        self.create_respond_bidirectional_sign_request(
            chain,
            serialized_output,
            signature_generation_total_timeout,
        )
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
        let path = SOLANA_RESPOND_BIDIRECTIONAL_PATH.to_string();
        tracing::info!(
            "requester to derive epsilon: {:?}",
            self.tx.sender.to_string()
        );
        let epsilon = mpc_crypto::kdf::derive_epsilon_sol(
            self.tx.key_version,
            &self.tx.sender.to_string(),
            &path,
        );
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
            timestamp_sign_queue: std::time::Instant::now(),
            total_timeout: signature_generation_total_timeout,
            sign_request_type: crate::protocol::SignRequestType::RespondBidirectional(
                RespondBidirectionalTx {
                    tx_id: self.tx.id,
                    output: serialized_output,
                },
            ),
        })
    }

    #[cfg(feature = "light_client")]
    async fn extract_success_tx_output(
        &self,
        helios_client: &Arc<EthereumClient>,
        max_attempts: u8,
    ) -> anyhow::Result<TransactionOutput> {
        let tx = fetch_tx_from_helios(helios_client, self.tx.id, max_attempts).await;
        let Some(tx) = tx else {
            anyhow::bail!("Failed to fetch tx from helios, tx id: {:?}", self.tx.id);
        };
        let output_deserialization_format = OUTPUT_DESERIALIZATION_FORMAT;
        let output_deserialization_schema = &self.tx.output_deserialization_schema;
        let from_address = self.tx.from_address;

        let data = tx.inner.input();
        let is_contract_call = data.len() > 2 && *data != Bytes::from("0x");
        match output_deserialization_format {
            SerDeserFormat::Abi if is_contract_call => {
                let to_address = tx.inner.to().unwrap();
                let call_result = fetch_call_result(
                    helios_client,
                    from_address,
                    to_address,
                    data.clone(),
                    self.block_number - 1,
                    5,
                )
                .await?;
                TransactionOutput::from_call_result(output_deserialization_schema, &call_result)
            }
            _ => Ok(TransactionOutput::non_function_call_output()),
        }
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

#[cfg(feature = "light_client")]
async fn fetch_call_result(
    helios_client: &Arc<EthereumClient>,
    from_address: Address,
    to_address: Address,
    data: Bytes,
    block_number: u64,
    max_attempts: u8,
) -> anyhow::Result<Bytes> {
    let mut attempts = 0;
    loop {
        match helios_client
            .call(
                &TransactionRequest::default()
                    .from(from_address)
                    .to(to_address)
                    .input(alloy::rpc::types::TransactionInput::both(data.clone())),
                BlockId::Number(BlockNumberOrTag::Number(block_number)),
            )
            .await
        {
            Ok(call_result) => return Ok(call_result),
            Err(err) => {
                if attempts >= max_attempts {
                    anyhow::bail!(
                        "Failed to fecth call result from helios: {err:?}, exceeded maximum retry"
                    );
                }
                tracing::warn!("Failed to fecth call result from helios: {err:?}, retrying...");
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

#[cfg(feature = "light_client")]
async fn fetch_tx_from_helios(
    helios_client: &Arc<EthereumClient>,
    tx_id: BidirectionalTxId,
    max_attempts: u8,
) -> Option<alloy::rpc::types::Transaction> {
    let mut attempts = 0;
    loop {
        match helios_client.get_transaction(tx_id.0).await {
            Ok(Some(tx)) => return Some(tx),
            Ok(None) => {
                tracing::error!("Failed to fecth tx from helios: result is None");
                return None;
            }
            Err(err) => {
                if attempts >= max_attempts {
                    tracing::error!(
                        "Failed to fecth tx from helios: {err:?}, exceeded maximum retry"
                    );
                    return None;
                }
                tracing::warn!("Failed to fecth tx from helios: {err:?}, retrying...");
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
