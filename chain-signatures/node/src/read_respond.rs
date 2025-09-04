use crate::protocol::{Chain, IndexedSignRequest};
use crate::sign_respond_tx::SignRespondTx;
use crate::sign_respond_tx::SignRespondTxId;
use crate::sign_respond_tx::SignRespondTxStatus;
use crate::sign_respond_tx::TransactionOutput;
use alloy::consensus::Transaction;
use alloy::eips::{BlockId, BlockNumberOrTag};
use alloy::primitives::{Address, Bytes};
use alloy::rpc::types::TransactionRequest;
use helios::ethereum::EthereumClient;
use k256::Scalar;
use mpc_crypto::ScalarExt;
use mpc_primitives::SignArgs;
use mpc_primitives::SignId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio::time::Duration;

const MAGIC_ERROR_PREFIX: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
const SOLANA_READ_RESPOND_PATH: &str = "solana response key";

pub struct CompletedTx {
    tx: SignRespondTx,
    block_number: u64,
}

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub struct ReadRespondedTx {
    pub tx_id: SignRespondTxId,
    pub output: ReadRespondSerializedOutput,
}

pub type ReadRespondSerializedOutput = Vec<u8>;

impl CompletedTx {
    pub fn new(tx: SignRespondTx, block_number: u64) -> Self {
        Self { tx, block_number }
    }

    pub async fn create_sign_request_from_completed_tx(
        &self,
        helios_client: &Arc<EthereumClient>,
        max_attempts: u8,
        signature_generation_total_timeout: Duration,
    ) -> Option<IndexedSignRequest> {
        match self
            .process_completed_tx(
                helios_client,
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

    async fn process_completed_tx(
        &self,
        helios_client: &Arc<EthereumClient>,
        max_attempts: u8,
        signature_generation_total_timeout: Duration,
    ) -> anyhow::Result<IndexedSignRequest> {
        if self.tx.status == SignRespondTxStatus::Success {
            self.process_success_tx(
                helios_client,
                max_attempts,
                signature_generation_total_timeout,
            )
            .await
        } else {
            self.process_failed_tx(signature_generation_total_timeout)
                .await
        }
    }

    async fn process_failed_tx(
        &self,
        total_timeout: Duration,
    ) -> anyhow::Result<IndexedSignRequest> {
        tracing::info!("Tx failed: {:?}", self.tx.id);
        let callback_serialization_format = self.tx.callback_serialization_format;

        let mut output = Vec::new();
        output.extend_from_slice(&MAGIC_ERROR_PREFIX);
        let serialized_output: Vec<u8> = if callback_serialization_format == 0 {
            let borsh_data = [1u8]; // Simple serialization: 1 = true
            output.extend_from_slice(&borsh_data);
            Bytes::from(output).into()
        } else {
            // Encode boolean as ABI: true = 0x0000000000000000000000000000000000000000000000000000000000000001
            let abi_encoded = [0u8; 32];
            let mut encoded = abi_encoded;
            encoded[31] = 1; // Set last byte to 1 for true
            output.extend_from_slice(&encoded);
            Bytes::from(output).into()
        };
        let sign_request =
            self.create_read_respond_sign_request(serialized_output, total_timeout)?;
        Ok(sign_request)
    }

    async fn process_success_tx(
        &self,
        helios_client: &Arc<EthereumClient>,
        max_attempts: u8,
        signature_generation_total_timeout: Duration,
    ) -> anyhow::Result<IndexedSignRequest> {
        let tx_output = self
            .extract_success_tx_output(helios_client, max_attempts)
            .await?;
        tracing::info!("Tx succeeded: {tx_output:?}");
        let callback_serialization_format = self.tx.callback_serialization_format;
        let callback_serialization_schema = &self.tx.callback_serialization_schema;
        let serialized_output = tx_output
            .output
            .serialize(callback_serialization_format, callback_serialization_schema)?;
        self.create_read_respond_sign_request(serialized_output, signature_generation_total_timeout)
    }

    fn create_read_respond_sign_request(
        &self,
        serialized_output: ReadRespondSerializedOutput,
        signature_generation_total_timeout: Duration,
    ) -> anyhow::Result<IndexedSignRequest> {
        let request_id_bytes = self.tx.request_id;
        tracing::info!("Read respond serialized output: {:?}", serialized_output);
        let message = calculate_read_respond_hash_message(&request_id_bytes, &serialized_output);
        tracing::info!("Read respond message hash: {:?}", hex::encode(message));
        let Some(payload) = Scalar::from_bytes(message) else {
            anyhow::bail!("Failed to convert read respond message to scalar: {message:?}");
        };
        let path = SOLANA_READ_RESPOND_PATH.to_string();
        tracing::info!(
            "requester to derive epsilon: {:?}",
            self.tx.sender.to_string()
        );
        let epsilon = mpc_crypto::kdf::derive_epsilon_sol(&self.tx.sender.to_string(), &path);
        let entropy = self.tx.id.0;
        Ok(IndexedSignRequest {
            id: SignId::new(request_id_bytes),
            chain: Chain::Solana,
            args: SignArgs {
                entropy: entropy.into(),
                epsilon,
                payload,
                path,
                key_version: self.tx.key_version,
            },
            unix_timestamp_indexed: crate::util::current_unix_timestamp(),
            timestamp_sign_queue: None,
            total_timeout: signature_generation_total_timeout,
            sign_request_type: crate::protocol::SignRequestType::ReadRespond(ReadRespondedTx {
                tx_id: self.tx.id,
                output: serialized_output,
            }),
            participants: Some(self.tx.participants.clone()),
        })
    }

    async fn extract_success_tx_output(
        &self,
        helios_client: &Arc<EthereumClient>,
        max_attempts: u8,
    ) -> anyhow::Result<TransactionOutput> {
        let tx = fetch_tx_from_helios(helios_client, self.tx.id, max_attempts).await;
        let Some(tx) = tx else {
            anyhow::bail!("Failed to fetch tx from helios, tx id: {:?}", self.tx.id);
        };
        let explorer_deserialization_format = self.tx.explorer_deserialization_format;
        let explorer_deserialization_schema = &self.tx.explorer_deserialization_schema;
        let from_address = self.tx.from_address;

        let data = tx.inner.input();
        let is_contract_call = data.len() > 2 && *data != Bytes::from("0x");
        if is_contract_call && explorer_deserialization_format == 1 {
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
            TransactionOutput::from_call_result(explorer_deserialization_schema, &call_result)
        } else {
            Ok(TransactionOutput::non_function_call_output())
        }
    }
}

fn calculate_read_respond_hash_message(request_id: &[u8], serialized_output: &[u8]) -> [u8; 32] {
    let mut combined = Vec::with_capacity(request_id.len() + serialized_output.len());
    combined.extend_from_slice(request_id);
    combined.extend_from_slice(serialized_output);

    // Compute keccak256 hash
    alloy::primitives::keccak256(&combined).into()
}

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

async fn fetch_tx_from_helios(
    helios_client: &Arc<EthereumClient>,
    tx_id: SignRespondTxId,
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

#[derive(Clone)]
pub struct ReadRespondedTxChannel {
    tx: mpsc::Sender<SignRespondTxId>,
}

impl ReadRespondedTxChannel {
    pub fn send(&self, tx_id: SignRespondTxId) {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            if let Err(err) = tx.send(tx_id).await {
                tracing::error!(%err, "failed to send read responded tx id");
            }
        });
    }
}

pub struct ReadRespondedTxProcessor {
    read_responded_tx_rx: mpsc::Receiver<SignRespondTxId>,
}

const MAX_CONCURRENT_READ_RESPONDED_TX_REQUESTS: usize = 1024;

impl ReadRespondedTxProcessor {
    pub fn new() -> (ReadRespondedTxChannel, Self) {
        let (tx, rx) = mpsc::channel(MAX_CONCURRENT_READ_RESPONDED_TX_REQUESTS);
        (
            ReadRespondedTxChannel { tx },
            Self {
                read_responded_tx_rx: rx,
            },
        )
    }

    pub async fn run(
        mut self,
        sign_respond_tx_map: Arc<RwLock<HashMap<SignRespondTxId, SignRespondTx>>>,
        max_attempts: u8,
    ) {
        while let Some(sign_respond_tx_id) = self.read_responded_tx_rx.recv().await {
            for attempt in 1..=max_attempts {
                if sign_respond_tx_map
                    .write()
                    .await
                    .remove(&sign_respond_tx_id)
                    .is_some()
                {
                    tracing::info!(sign_id = ?sign_respond_tx_id, "removed sign respond tx from map");
                    break;
                } else if attempt == max_attempts {
                    tracing::error!(sign_id = ?sign_respond_tx_id, "failed to remove sign respond tx from map after {max_attempts} attempts");
                }
            }
        }
    }
}
