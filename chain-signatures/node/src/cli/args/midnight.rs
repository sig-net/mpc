use mpc_chain_midnight::MidnightConfig;

/// CLI arguments for the Midnight indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_midnight_options")]
pub struct MidnightArgs {
    /// Midnight indexer GraphQL HTTP endpoint (v4), e.g. http://host:8088/api/v4/graphql
    #[arg(
        long,
        env("MPC_MIDNIGHT_INDEXER_GRAPHQL_URL"),
        requires_all = [
            "midnight_indexer_graphql_ws_url",
            "midnight_node_rpc_url",
            "midnight_publisher_url",
            "midnight_contract_address",
            "midnight_network_id",
        ]
    )]
    pub midnight_indexer_graphql_url: Option<String>,
    /// Midnight indexer GraphQL WebSocket endpoint, e.g. ws://host:8088/api/v4/graphql/ws
    #[arg(
        long,
        env("MPC_MIDNIGHT_INDEXER_GRAPHQL_WS_URL"),
        requires = "midnight_indexer_graphql_url"
    )]
    pub midnight_indexer_graphql_ws_url: Option<String>,
    /// Midnight node JSON-RPC endpoint over HTTP (finality gate), e.g. http://host:9944
    #[arg(
        long,
        env("MPC_MIDNIGHT_NODE_RPC_URL"),
        requires = "midnight_indexer_graphql_url"
    )]
    pub midnight_node_rpc_url: Option<String>,
    /// Base URL of the isolated midnight-publisher service, e.g. http://host:8790
    #[arg(
        long,
        env("MPC_MIDNIGHT_PUBLISHER_URL"),
        requires = "midnight_indexer_graphql_url"
    )]
    pub midnight_publisher_url: Option<String>,
    /// Deployed signet-signer contract address (untagged lowercase hex, 64 chars).
    /// This exact string is the epsilon-derivation sender.
    #[arg(
        long,
        env("MPC_MIDNIGHT_CONTRACT_ADDRESS"),
        requires = "midnight_indexer_graphql_url"
    )]
    pub midnight_contract_address: Option<String>,
    /// Midnight network id (e.g. undeployed, testnet).
    #[arg(
        long,
        env("MPC_MIDNIGHT_NETWORK_ID"),
        requires = "midnight_indexer_graphql_url"
    )]
    pub midnight_network_id: Option<String>,
}

impl MidnightArgs {
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::with_capacity(12);
        if let Some(v) = self.midnight_indexer_graphql_url {
            args.extend(["--midnight-indexer-graphql-url".to_string(), v]);
        }
        if let Some(v) = self.midnight_indexer_graphql_ws_url {
            args.extend(["--midnight-indexer-graphql-ws-url".to_string(), v]);
        }
        if let Some(v) = self.midnight_node_rpc_url {
            args.extend(["--midnight-node-rpc-url".to_string(), v]);
        }
        if let Some(v) = self.midnight_publisher_url {
            args.extend(["--midnight-publisher-url".to_string(), v]);
        }
        if let Some(v) = self.midnight_contract_address {
            args.extend(["--midnight-contract-address".to_string(), v]);
        }
        if let Some(v) = self.midnight_network_id {
            args.extend(["--midnight-network-id".to_string(), v]);
        }
        args
    }

    pub fn into_config(self) -> Option<MidnightConfig> {
        Some(MidnightConfig {
            indexer_graphql_url: self.midnight_indexer_graphql_url?,
            indexer_graphql_ws_url: self.midnight_indexer_graphql_ws_url?,
            node_rpc_url: self.midnight_node_rpc_url?,
            publisher_url: self.midnight_publisher_url?,
            contract_address: self.midnight_contract_address?,
            network_id: self.midnight_network_id?,
        })
    }

    pub fn from_config(config: Option<MidnightConfig>) -> Self {
        match config {
            Some(c) => MidnightArgs {
                midnight_indexer_graphql_url: Some(c.indexer_graphql_url),
                midnight_indexer_graphql_ws_url: Some(c.indexer_graphql_ws_url),
                midnight_node_rpc_url: Some(c.node_rpc_url),
                midnight_publisher_url: Some(c.publisher_url),
                midnight_contract_address: Some(c.contract_address),
                midnight_network_id: Some(c.network_id),
            },
            None => MidnightArgs {
                midnight_indexer_graphql_url: None,
                midnight_indexer_graphql_ws_url: None,
                midnight_node_rpc_url: None,
                midnight_publisher_url: None,
                midnight_contract_address: None,
                midnight_network_id: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_roundtrip() {
        let config = MidnightConfig {
            indexer_graphql_url: "http://localhost:8089/api/v4/graphql".into(),
            indexer_graphql_ws_url: "ws://localhost:8089/api/v4/graphql/ws".into(),
            node_rpc_url: "http://localhost:9945".into(),
            publisher_url: "http://localhost:8790".into(),
            contract_address: "ab".repeat(32),
            network_id: "undeployed".into(),
        };
        let args = MidnightArgs::from_config(Some(config.clone()));
        let str_args = args.clone().into_str_args();
        assert_eq!(str_args.len(), 12);
        let back = args.into_config().unwrap();
        assert_eq!(back.contract_address, config.contract_address);
        assert_eq!(back.publisher_url, config.publisher_url);
        assert!(MidnightArgs::from_config(None).into_config().is_none());
    }
}
