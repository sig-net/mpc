use std::fmt;

use crate::indexer_canton::CantonAuthConfig;

/// Canton JSON Ledger API configuration.
#[derive(Clone)]
pub struct CantonConfig {
    pub json_api_url: String,
    pub json_api_ws_url: String,
    pub auth: CantonAuthConfig,
    pub ledger_api_user: String,
    pub party_id: String,
    /// The Signer contract ID on the Canton ledger. Changes on every DAR
    /// redeployment — requires MPC node restart with the new value.
    pub signer_contract_id: String,
    /// Template ID of the Signer contract, in package-name form
    /// (`#signet-signer-v1:Signer:Signer`) — stable across DAR upgrades.
    pub signer_template_id: String,
}

impl fmt::Debug for CantonConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CantonConfig")
            .field("json_api_url", &self.json_api_url)
            .field("json_api_ws_url", &self.json_api_ws_url)
            .field("auth", &self.auth.kind())
            .field("ledger_api_user", &self.ledger_api_user)
            .field("party_id", &self.party_id)
            .field("signer_contract_id", &self.signer_contract_id)
            .field("signer_template_id", &self.signer_template_id)
            .finish()
    }
}
