use sp_core::sr25519;
use sp_core::Pair as _;
use sp_core::H256;
use sp_runtime::traits::{IdentifyAccount, Verify};
use sp_runtime::MultiSignature as SpMultiSignature;
use std::fmt;
use subxt::config::substrate::AccountId32;

#[derive(Clone)]
pub struct HydrationConfig {
    /// Hydration RPC ws URL
    pub rpc_ws_url: String,
    /// Hydration signer URI
    pub signer_uri: String,
    /// Genesis hash of the target chain
    pub genesis_hash: H256,
}

impl HydrationConfig {
    /// Substrate account address derived from the configured signer URI.
    pub fn signer_address(&self) -> Option<String> {
        let pair = sr25519::Pair::from_string(&self.signer_uri, None).ok()?;
        let account_id = <SpMultiSignature as Verify>::Signer::from(pair.public()).into_account();
        Some(AccountId32(account_id.into()).to_string())
    }
}

impl fmt::Debug for HydrationConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HydrationConfig")
            .field("rpc_ws_url", &"<hidden>") // May contain API keys
            .field("signer_uri", &"<hidden>")
            .field("genesis_hash", &self.genesis_hash)
            .finish()
    }
}
