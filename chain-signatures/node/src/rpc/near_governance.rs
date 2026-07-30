use crate::protocol::Governance;
pub use mpc_contract::primitives::{Read, View};
use mpc_keys::hpke;

use near_account_id::AccountId;
use near_crypto::InMemorySigner;
use near_fetch::Client as NearFetchClient;
use serde_json::json;
use url::Url;

/// Base delay in milliseconds between NEAR governance RPC retries
const NEAR_RETRY_BASE_DELAY_MS: u64 = 500;
/// Maximum number of retry attempts for NEAR governance calls (vote, join)
const NEAR_GOVERNANCE_MAX_RETRIES: usize = 5;

/// NEAR [`Governance`] client.
///
/// Owns the RPC connection and signer used to submit MPC governance transactions
/// and read MPC contract state (`read`) for the
/// node's contract-state watcher.
#[derive(Clone)]
pub struct NearGovernanceClient {
    client: NearFetchClient,
    contract_id: AccountId,
    my_addr: Url,
    signer: InMemorySigner,
    cipher_pk: hpke::PublicKey,
    sign_pk: near_crypto::PublicKey,
}

impl NearGovernanceClient {
    pub fn new(
        near_rpc: &str,
        my_addr: &Url,
        sign_sk: &near_crypto::SecretKey,
        cipher_sk: &hpke::SecretKey,
        contract_id: &AccountId,
        signer: InMemorySigner,
    ) -> Self {
        Self {
            client: NearFetchClient::new(near_rpc),
            contract_id: contract_id.clone(),
            my_addr: my_addr.clone(),
            signer,
            cipher_pk: cipher_sk.public_key(),
            sign_pk: sign_sk.public_key(),
        }
    }

    /// Read views from the MPC contract.
    pub async fn read(&self, reads: Vec<Read>) -> anyhow::Result<Vec<View>> {
        let views: Vec<View> = self
            .client
            .view(&self.contract_id, "read")
            .args_json(json!({ "reads": reads }))
            .await?
            .json()?;
        Ok(views)
    }
}

impl Governance for NearGovernanceClient {
    fn propose_join(&self) -> impl std::future::Future<Output = anyhow::Result<()>> + Send {
        tracing::info!(signer_id = %self.signer.account_id, "joining the protocol");
        async move {
            self.client
                .call(&self.signer, &self.contract_id, "join")
                .args_json(json!({
                    "url": self.my_addr,
                    "cipher_pk": self.cipher_pk.to_bytes(),
                    "sign_pk": self.sign_pk,
                }))
                .max_gas()
                .retry_exponential(NEAR_RETRY_BASE_DELAY_MS, NEAR_GOVERNANCE_MAX_RETRIES)
                .transact()
                .await?
                .into_result()?;

            Ok(())
        }
    }

    fn vote_reshared(
        &self,
        epoch: u64,
    ) -> impl std::future::Future<Output = anyhow::Result<bool>> + Send {
        tracing::info!(%epoch, signer_id = %self.signer.account_id, "voting for reshared");
        async move {
            let result = self
                .client
                .call(&self.signer, &self.contract_id, "vote_reshared")
                .args_json(json!({
                    "epoch": epoch
                }))
                .max_gas()
                .retry_exponential(NEAR_RETRY_BASE_DELAY_MS, NEAR_GOVERNANCE_MAX_RETRIES)
                .transact()
                .await
                .inspect_err(|err| {
                    tracing::warn!(%err, "failed to vote for reshared");
                })?
                .json()?;

            Ok(result)
        }
    }

    fn vote_public_key(
        &self,
        public_key: &near_crypto::PublicKey,
    ) -> impl std::future::Future<Output = anyhow::Result<bool>> + Send {
        tracing::info!(%public_key, signer_id = %self.signer.account_id, "voting for public key");
        let public_key = public_key.clone();
        async move {
            let result = self
                .client
                .call(&self.signer, &self.contract_id, "vote_pk")
                .args_json(json!({
                    "public_key": public_key
                }))
                .max_gas()
                .retry_exponential(NEAR_RETRY_BASE_DELAY_MS, NEAR_GOVERNANCE_MAX_RETRIES)
                .transact()
                .await
                .inspect_err(|err| {
                    tracing::warn!(%err, "failed to vote for public key");
                })?
                .json()?;

            Ok(result)
        }
    }

    fn vote_new_threshold(
        &self,
        new_threshold: usize,
    ) -> impl std::future::Future<Output = anyhow::Result<bool>> + Send {
        tracing::info!(
            new_threshold,
            signer_id = %self.signer.account_id,
            "voting for new threshold"
        );
        async move {
            let result = self
                .client
                .call(&self.signer, &self.contract_id, "vote_new_threshold")
                .args_json(json!({
                    "new_threshold": new_threshold
                }))
                .max_gas()
                .retry_exponential(NEAR_RETRY_BASE_DELAY_MS, NEAR_GOVERNANCE_MAX_RETRIES)
                .transact()
                .await
                .inspect_err(|err| {
                    tracing::warn!(%err, "failed to vote for new threshold");
                })?
                .json()?;

            Ok(result)
        }
    }
}
