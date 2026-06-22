use std::fmt;

#[derive(Clone)]
pub struct HydrationConfig {
    /// Hydration RPC ws URL
    pub rpc_ws_url: String,
    /// Hydration signer URI
    pub signer_uri: String,
}

impl fmt::Debug for HydrationConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HydrationConfig")
            .field("rpc_ws_url", &"<hidden>") // May contain API keys
            .field("signer_uri", &"<hidden>")
            .finish()
    }
}
