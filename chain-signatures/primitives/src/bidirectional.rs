use crate::{BidirectionalTxId, Chain, SignId, Signature};

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct BidirectionalTx {
    pub id: BidirectionalTxId,
    pub sender: [u8; 32],
    pub serialized_transaction: Vec<u8>,
    pub source_chain: Chain,
    pub target_chain: Chain,
    // mainnet caip2_id of the target chain where the signed transaction will be sent
    // This must be a supported chain in the Chain enum in primitives.
    pub caip2_id: String,
    pub key_version: u32,
    pub deposit: u64,
    pub path: String,
    pub algo: String,
    pub dest: String,
    pub params: String,
    pub output_deserialization_schema: Vec<u8>,
    pub respond_serialization_schema: Vec<u8>,
    pub request_id: [u8; 32],
    // TODO: Same as comment above for BidirectionalTxId: Use Address from Alloy once we can bump the minimum Rust version to 1.85+
    #[serde(with = "serde_bytes")]
    pub from_address: [u8; 20],
    pub nonce: u64,
}

impl BidirectionalTx {
    pub const fn sign_id(&self) -> SignId {
        SignId::new(self.request_id)
    }
}

#[derive(Hash, PartialEq, Eq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RespondBidirectionalTx {
    pub tx_id: BidirectionalTxId,
    pub output: crate::RespondBidirectionalSerializedOutput,
    /// Opaque per-chain context blob. The producing indexer serializes its own
    /// struct (see e.g. `indexer_canton::CantonChainCtx`) into bytes; the
    /// consuming publisher deserializes it back. Backlog and protocol layers
    /// treat this as opaque bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_ctx: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct RespondBidirectionalEvent {
    pub request_id: [u8; 32],
    pub signature: Signature,
    pub chain: Chain,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SignBidirectionalEvent {
    pub sender: [u8; 32],
    pub serialized_transaction: Vec<u8>,
    pub caip2_id: String,
    pub key_version: u32,
    pub deposit: u64,
    pub path: String,
    pub algo: String,
    pub dest: String,
    pub params: String,
    pub output_deserialization_schema: Vec<u8>,
    pub respond_serialization_schema: Vec<u8>,
    pub chain: Chain,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_ctx: Option<Vec<u8>>,
}
