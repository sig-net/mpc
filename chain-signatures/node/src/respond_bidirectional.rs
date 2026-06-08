use crate::indexer_eth::EthereumClient;
use crate::protocol::{Chain, IndexedSignRequest};
use crate::sign_bidirectional::TransactionOutput;
use crate::sign_bidirectional::{BidirectionalTx, BidirectionalTxId};
use alloy::consensus::Transaction;
use alloy::primitives::Bytes;
use k256::Scalar;
use mpc_crypto::ScalarExt;
use mpc_primitives::{SerDeserFormat, SignArgs, SignId};
use std::sync::Arc;

const MAGIC_ERROR_PREFIX: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
const SOLANA_RESPOND_BIDIRECTIONAL_PATH: &str = "solana response key";
const HYDRATION_RESPOND_BIDIRECTIONAL_PATH: &str = "hydration response key";
pub const CANTON_RESPOND_BIDIRECTIONAL_PATH: &str = "canton response key";
// Use Abi as this is what we are using for ethereum
pub(crate) const OUTPUT_DESERIALIZATION_FORMAT: SerDeserFormat = SerDeserFormat::Abi;

pub struct CompletedTx {
    tx: BidirectionalTx,
}

#[derive(Hash, PartialEq, Eq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RespondBidirectionalTx {
    pub tx_id: BidirectionalTxId,
    pub output: RespondBidirectionalSerializedOutput,
    /// Opaque per-chain context blob. The producing indexer serializes its own
    /// struct (see e.g. `indexer_canton::CantonChainCtx`) into bytes; the
    /// consuming publisher deserializes it back. Backlog and protocol layers
    /// treat this as opaque bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_ctx: Option<Vec<u8>>,
}

pub type RespondBidirectionalSerializedOutput = Vec<u8>;

impl CompletedTx {
    pub fn new(tx: BidirectionalTx) -> Self {
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
        let path = match chain {
            Chain::Solana => SOLANA_RESPOND_BIDIRECTIONAL_PATH.to_string(),
            Chain::Hydration => HYDRATION_RESPOND_BIDIRECTIONAL_PATH.to_string(),
            Chain::Canton => CANTON_RESPOND_BIDIRECTIONAL_PATH.to_string(),
            _ => anyhow::bail!("Unsupported chain: {}", chain),
        };
        let epsilon = self.tx.epsilon(&path)?;
        let entropy = self.tx.id.0;
        Ok(IndexedSignRequest::respond_bidirectional(
            SignId::new(request_id_bytes),
            SignArgs {
                entropy: entropy.into(),
                epsilon,
                payload,
                path,
                key_version: self.tx.key_version,
            },
            chain,
            crate::util::current_unix_timestamp(),
            RespondBidirectionalTx {
                tx_id: self.tx.id,
                output: serialized_output,
                chain_ctx,
            },
        ))
    }

    pub async fn extract_success_tx_output(
        &self,
        client: &Arc<EthereumClient>,
    ) -> anyhow::Result<RespondBidirectionalSerializedOutput> {
        let tx = &self.tx;
        let tx_id = self.tx.id.0;
        let Some(tx_info) = client.as_ref().get_transaction_by_hash(tx_id).await? else {
            anyhow::bail!("Failed to fetch transaction {tx_id:?}");
        };

        // A deployment transaction has no `to`. For a CREATE the trace's
        // `output` is the deployed runtime bytecode, not ABI return data, so it
        // cannot be decoded against the output schema — reject it up front.
        // TODO(#808): support contract deployments.
        if tx_info.inner.to().is_none() {
            anyhow::bail!("unsupported contract deployment (CREATE): {tx_id:?}");
        }

        let data = tx_info.inner.input().clone();
        let is_contract_call = is_contract_call(&data);

        let trace_output = if is_contract_call {
            tracing::info!(
                ?tx_id,
                "Extracting transaction output via debug_traceTransaction"
            );
            Some(client.trace_transaction_output(tx_id).await?)
        } else {
            None
        };

        build_serialized_output(
            is_contract_call,
            &tx.output_deserialization_schema,
            trace_output.as_ref(),
            tx.source_chain.respond_serialization_format(),
            &tx.respond_serialization_schema,
        )
    }
}

/// Whether a transaction's calldata represents a contract call.
fn is_contract_call(input: &Bytes) -> bool {
    input.len() > 2 && input != &Bytes::from("0x")
}

/// Decode a transaction's output and re-serialize it for the respond chain.
///
/// `trace_output` is the `debug_traceTransaction` return data, required when
/// `is_contract_call` is true.
fn build_serialized_output(
    is_contract_call: bool,
    output_deserialization_schema: &[u8],
    trace_output: Option<&Bytes>,
    respond_serialization_format: SerDeserFormat,
    respond_serialization_schema: &[u8],
) -> anyhow::Result<RespondBidirectionalSerializedOutput> {
    let transaction_output = match OUTPUT_DESERIALIZATION_FORMAT {
        SerDeserFormat::Abi if is_contract_call => {
            let trace_output = trace_output.ok_or_else(|| {
                anyhow::anyhow!("contract-call output extraction requires trace output")
            })?;
            TransactionOutput::from_call_result(output_deserialization_schema, trace_output)?
        }
        _ => TransactionOutput::non_contract_call_output(),
    };

    transaction_output
        .output
        .serialize(respond_serialization_format, respond_serialization_schema)
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
    use crate::protocol::SignKind;
    use alloy::primitives::{Address, B256};

    const UINT256_SCHEMA: &[u8] = br#"[{"name":"amount","type":"uint256"}]"#;

    /// Sample tx with a Solana source chain, required by `epsilon`/path derivation.
    fn sample_bidirectional_tx() -> BidirectionalTx {
        BidirectionalTx {
            id: BidirectionalTxId(B256::repeat_byte(0xab)),
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
            from_address: Address::ZERO,
            nonce: 0,
        }
    }

    /// ABI-encoded `uint256` (32-byte big-endian).
    fn abi_uint256(value: u64) -> Bytes {
        let mut buf = [0u8; 32];
        buf[24..].copy_from_slice(&value.to_be_bytes());
        Bytes::from(buf.to_vec())
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
    fn build_serialized_output_decodes_contract_call() {
        // A contract-call tx whose function returned `uint256` 12345; `trace`
        // is that ABI-encoded return value from debug_traceTransaction.
        let trace = abi_uint256(12_345);
        let out = build_serialized_output(
            true,
            UINT256_SCHEMA,
            Some(&trace),
            SerDeserFormat::Abi,
            UINT256_SCHEMA,
        )
        .unwrap();
        assert_eq!(out, trace.to_vec());
    }

    #[test]
    fn build_serialized_output_non_contract_call_uses_defaults() {
        // `default_output_for_non_contract_call` only supports `bool`/`string`.
        let bool_schema: &[u8] = br#"[{"name":"ok","type":"bool"}]"#;
        let out =
            build_serialized_output(false, bool_schema, None, SerDeserFormat::Abi, bool_schema)
                .unwrap();
        // A plain transfer synthesizes a default: bool -> true, ABI-encoded as
        // a 32-byte word.
        let mut expected = vec![0u8; 32];
        expected[31] = 1;
        assert_eq!(out, expected);
    }

    #[test]
    fn build_serialized_output_requires_trace_for_contract_call() {
        let err = build_serialized_output(
            true,
            UINT256_SCHEMA,
            None,
            SerDeserFormat::Abi,
            UINT256_SCHEMA,
        );
        assert!(
            err.is_err(),
            "contract call without trace output must error"
        );
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
