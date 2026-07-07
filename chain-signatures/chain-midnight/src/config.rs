/// Configuration for the Midnight chain integration.
///
/// The indexer half needs only the GraphQL endpoints, the node RPC (for the finality
/// gate), and the watched contract address. Transaction building/proving/submission —
/// and thus the dust wallet seed, proof-server URL, and compiled-artifact paths — live
/// in the isolated `midnight-publisher` service, reached via `publisher_url`.
#[derive(Clone, Debug)]
pub struct MidnightConfig {
    /// Indexer GraphQL HTTP endpoint (v4), e.g. `http://host:8088/api/v4/graphql`.
    pub indexer_graphql_url: String,
    /// Indexer GraphQL WebSocket endpoint, e.g. `ws://host:8088/api/v4/graphql/ws`.
    pub indexer_graphql_ws_url: String,
    /// Node RPC URL, queried directly for `chain_getFinalizedHead` (finality gate).
    pub node_rpc_url: String,
    /// Isolated publisher service base URL (build/prove/submit respond txs).
    pub publisher_url: String,
    /// Deployed signer contract address (untagged lowercase hex, 64 chars, no `0x`).
    /// This exact string is the epsilon-derivation `sender`.
    pub contract_address: String,
    /// Network id (e.g. `undeployed`, `testnet`).
    pub network_id: String,
}

impl MidnightConfig {
    /// The epsilon-derivation `sender` is the contract address string verbatim.
    pub fn epsilon_sender(&self) -> &str {
        &self.contract_address
    }

    /// The contract address decoded to raw bytes — carried in
    /// `SignBidirectionalEvent.sender` and hex-encoded back by the node's
    /// `sender_string` (untagged lowercase 64-char hex, the epsilon sender).
    pub fn sender_raw32(&self) -> anyhow::Result<[u8; 32]> {
        let mut out = [0u8; 32];
        hex::decode_to_slice(&self.contract_address, &mut out)
            .map_err(|e| anyhow::anyhow!("contract_address is not 32-byte hex: {e}"))?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_is_contract_address() {
        let cfg = MidnightConfig {
            indexer_graphql_url: "http://localhost:8088/api/v4/graphql".into(),
            indexer_graphql_ws_url: "ws://localhost:8088/api/v4/graphql/ws".into(),
            node_rpc_url: "ws://localhost:9944".into(),
            publisher_url: "http://localhost:8090".into(),
            contract_address: "4c39f6fe5c9625abb55dc443eb859dd539b9ee7e7bc26b4250d331ed10e391b2"
                .into(),
            network_id: "undeployed".into(),
        };
        assert_eq!(cfg.epsilon_sender(), cfg.contract_address);
        assert_eq!(cfg.contract_address.len(), 64);
        assert!(cfg.sender_raw32().is_ok());
    }
}
