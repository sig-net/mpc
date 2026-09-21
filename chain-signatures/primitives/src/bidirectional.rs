use crate::{BidirectionalTxId, Chain, RequestId, Signature};

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
    /// Persisted checkpoints predate `RequestId` here and store the bare array, hence the adapter.
    #[serde(rename = "request_id", with = "crate::request_id_as_array")]
    pub request_id: RequestId,
    // TODO: Same as comment above for BidirectionalTxId: Use Address from Alloy once we can bump the minimum Rust version to 1.85+
    #[serde(with = "serde_bytes")]
    pub from_address: [u8; 20],
    pub nonce: u64,
}

#[derive(Hash, PartialEq, Eq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RespondBidirectionalTx {
    pub tx_id: BidirectionalTxId,
    pub output: crate::RespondBidirectionalSerializedOutput,
    /// Unix timestamp at which the initial request was indexed. This remains
    /// distinct from the follow-up request's own indexing timestamp so queueing
    /// and per-leg latency metrics retain their existing semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_indexed_at: Option<u64>,
    /// Opaque per-chain context blob. The producing indexer serializes its own
    /// struct (see e.g. `indexer_canton::CantonChainCtx`) into bytes; the
    /// consuming publisher deserializes it back. Backlog and protocol layers
    /// treat this as opaque bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_ctx: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct RespondBidirectionalEvent {
    pub request_id: RequestId,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tx() -> BidirectionalTx {
        BidirectionalTx {
            id: BidirectionalTxId([0xab; 32]),
            sender: [0x11; 32],
            serialized_transaction: vec![1, 2, 3],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "eip155:1".to_string(),
            key_version: 0,
            deposit: 0,
            path: "test".to_string(),
            algo: String::new(),
            dest: String::new(),
            params: String::new(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: vec![],
            request_id: RequestId::from_u8(0x2f),
            from_address: [0u8; 20],
            nonce: 7,
        }
    }

    /// Mirror of `BidirectionalTx` as it was persisted before `request_id` became a
    /// `RequestId`: the same field name with a bare array.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct LegacyTx {
        id: BidirectionalTxId,
        sender: [u8; 32],
        serialized_transaction: Vec<u8>,
        source_chain: Chain,
        target_chain: Chain,
        caip2_id: String,
        key_version: u32,
        deposit: u64,
        path: String,
        algo: String,
        dest: String,
        params: String,
        output_deserialization_schema: Vec<u8>,
        respond_serialization_schema: Vec<u8>,
        request_id: [u8; 32],
        #[serde(with = "serde_bytes")]
        from_address: [u8; 20],
        nonce: u64,
    }

    /// Backlog checkpoints in Redis are CBOR written while this field was a bare
    /// `[u8; 32]` named `request_id`; both directions must keep that layout.
    #[test]
    fn persisted_layout_of_request_id_is_bare_array() {
        let tx = sample_tx();
        let mut legacy_bytes = Vec::new();
        ciborium::into_writer(
            &LegacyTx {
                id: tx.id,
                sender: tx.sender,
                serialized_transaction: tx.serialized_transaction.clone(),
                source_chain: tx.source_chain,
                target_chain: tx.target_chain,
                caip2_id: tx.caip2_id.clone(),
                key_version: tx.key_version,
                deposit: tx.deposit,
                path: tx.path.clone(),
                algo: tx.algo.clone(),
                dest: tx.dest.clone(),
                params: tx.params.clone(),
                output_deserialization_schema: tx.output_deserialization_schema.clone(),
                respond_serialization_schema: tx.respond_serialization_schema.clone(),
                request_id: tx.request_id.bytes,
                from_address: tx.from_address,
                nonce: tx.nonce,
            },
            &mut legacy_bytes,
        )
        .unwrap();

        let mut current_bytes = Vec::new();
        ciborium::into_writer(&tx, &mut current_bytes).unwrap();
        assert_eq!(current_bytes, legacy_bytes);

        let decoded: BidirectionalTx = ciborium::from_reader(legacy_bytes.as_slice()).unwrap();
        assert_eq!(decoded, tx);
    }
}
