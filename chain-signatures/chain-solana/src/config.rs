use secrecy::{ExposeSecret as _, SecretString};
use solana_sdk::pubkey::Pubkey;
use std::time::Duration;
use url::Url;

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

#[derive(Clone, Debug)]
pub struct SolConfig {
    /// The solana account secret key used to sign solana respond txn.
    ///
    /// Carried as a [`SecretString`] so derived `Debug` redacts it; exposed only
    /// at the point of use.
    pub account_sk: SecretString,
    /// Solana RPC http URL
    pub rpc_http_url: Url,
    /// The program address to watch
    pub program_address: Pubkey,
    /// Indexer polling tunables.
    pub indexer: SolIndexerConfig,
}

impl SolConfig {
    /// Solana payer address derived from the configured account secret key.
    pub fn signer_address(&self) -> String {
        use solana_sdk::signer::Signer;
        solana_sdk::signer::keypair::Keypair::from_base58_string(self.account_sk.expose_secret())
            .pubkey()
            .to_string()
    }
}
