use std::fmt;
use std::time::Duration;

/// Configuration for the Solana indexer.
#[derive(Clone, Copy, Debug)]
pub struct SolIndexerConfig {
    /// Delay between polling iterations
    pub poll_interval: Duration,
}

impl Default for SolIndexerConfig {
    fn default() -> Self {
        Self {
            // The finalized frontier advances ~every 400ms,
            // polling faster than that can never observe a new anchor
            poll_interval: Duration::from_secs(1),
        }
    }
}

#[derive(Clone)]
pub struct SolConfig {
    /// The solana account secret key used to sign solana respond txn.
    pub account_sk: String,
    /// Solana RPC http URL
    pub rpc_http_url: String,
    /// The program address to watch
    pub program_address: String,
    /// Indexer polling tunables.
    pub indexer: SolIndexerConfig,
}

impl SolConfig {
    /// Solana payer address derived from the configured account secret key.
    pub fn signer_address(&self) -> String {
        use solana_sdk::signer::Signer;
        solana_sdk::signer::keypair::Keypair::from_base58_string(&self.account_sk)
            .pubkey()
            .to_string()
    }
}

impl fmt::Debug for SolConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SolConfig")
            .field("account_sk", &"<hidden>")
            .field("rpc_http_url", &self.rpc_http_url)
            .field("program_address", &self.program_address)
            .field("indexer", &self.indexer)
            .finish()
    }
}
