use super::{ChainPublisher, PublishAction};
use crate::config::NetworkConfig;
use crate::protocol::Governance;
use crate::util::AffinePointExt as _;
pub use mpc_contract::primitives::{Read, View};

use mpc_keys::hpke;
use mpc_primitives::{ConsensusCheckpointDigest, SignId, SignKind, Signature};

use near_account_id::AccountId;
use near_crypto::InMemorySigner;
use near_fetch::result::ExecutionFinalResult;
use serde_json::json;
use url::Url;

/// Base delay in milliseconds between NEAR RPC retries
const NEAR_RETRY_BASE_DELAY_MS: u64 = 500;
/// Maximum number of retry attempts for NEAR RPC calls
const NEAR_RESPOND_MAX_RETRIES: usize = 3;
/// Maximum number of retry attempts for NEAR governance calls (vote, join)
const NEAR_GOVERNANCE_MAX_RETRIES: usize = 5;

#[derive(Clone)]
pub struct NearClient {
    client: near_fetch::Client,
    contract_id: AccountId,
    my_addr: Url,
    signer: InMemorySigner,
    cipher_pk: hpke::PublicKey,
    sign_pk: near_crypto::PublicKey,
}

impl Governance for NearClient {
    async fn propose_join(&self) -> anyhow::Result<()> {
        self.propose_join().await
    }

    async fn vote_reshared(&self, epoch: u64) -> anyhow::Result<bool> {
        self.vote_reshared(epoch).await
    }

    async fn vote_public_key(&self, public_key: &near_crypto::PublicKey) -> anyhow::Result<bool> {
        self.vote_public_key(public_key).await
    }
}

impl NearClient {
    pub fn new(
        near_rpc: &str,
        my_addr: &Url,
        network: &NetworkConfig,
        contract_id: &AccountId,
        signer: InMemorySigner,
    ) -> Self {
        Self {
            client: near_fetch::Client::new(near_rpc),
            contract_id: contract_id.clone(),
            my_addr: my_addr.clone(),
            signer,
            cipher_pk: network.cipher_sk.public_key(),
            sign_pk: network.sign_sk.public_key(),
        }
    }

    pub fn rpc_addr(&self) -> String {
        self.client.rpc_addr()
    }

    async fn vote_public_key(&self, public_key: &near_crypto::PublicKey) -> anyhow::Result<bool> {
        tracing::info!(%public_key, signer_id = %self.signer.account_id, "voting for public key");
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

    async fn vote_reshared(&self, epoch: u64) -> anyhow::Result<bool> {
        tracing::info!(%epoch, signer_id = %self.signer.account_id, "voting for reshared");
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

    async fn propose_join(&self) -> anyhow::Result<()> {
        tracing::info!(signer_id = %self.signer.account_id, "joining the protocol");
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

    async fn call_respond(
        &self,
        id: &SignId,
        response: &Signature,
    ) -> Result<ExecutionFinalResult, near_fetch::Error> {
        self.client
            .call(&self.signer, &self.contract_id, "respond")
            .args_json(json!({
                "sign_id": id,
                "signature": response,
            }))
            .max_gas()
            .retry_exponential(NEAR_RETRY_BASE_DELAY_MS, NEAR_RESPOND_MAX_RETRIES)
            .transact()
            .await
    }

    pub async fn read(&self, reads: Vec<Read>) -> anyhow::Result<Vec<View>> {
        let views: Vec<View> = self
            .client
            .view(&self.contract_id, "read")
            .args_json(json!({ "reads": reads }))
            .await?
            .json()?;
        Ok(views)
    }

    async fn call_respond_checkpoint(
        &self,
        checkpoint: &ConsensusCheckpointDigest,
        signature: &Signature,
    ) -> Result<ExecutionFinalResult, near_fetch::Error> {
        self.client
            .call(&self.signer, &self.contract_id, "respond_checkpoint")
            .args_json(json!({
                "checkpoint": checkpoint,
                "signature": signature,
            }))
            .max_gas()
            .retry_exponential(NEAR_RETRY_BASE_DELAY_MS, NEAR_RESPOND_MAX_RETRIES)
            .transact()
            .await
    }
}

#[async_trait::async_trait]
impl ChainPublisher for NearClient {
    async fn publish_signature(&self, action: &PublishAction) -> anyhow::Result<()> {
        let timestamp = action.timestamp;
        let signature = &action.signature;
        let outcome = match &action.indexed.kind {
            SignKind::Checkpoint(checkpoint) => {
                self.call_respond_checkpoint(checkpoint, signature).await
            }
            _ => self.call_respond(&action.indexed.id, signature).await,
        }
        .map_err(|e| anyhow::anyhow!("near rpc error: {e}"))
        .inspect_err(|err| {
            tracing::error!(
                sign_id = ?action.indexed.id,
                ?err,
                "failed to publish signature",
            );
        })?;

        outcome
            .json::<()>()
            .map_err(|e| anyhow::anyhow!("contract rejected response: {e}"))
            .inspect_err(|err| {
                tracing::error!(
                    sign_id = ?action.indexed.id,
                    big_r = signature.big_r.to_base58(),
                    s = ?signature.s,
                    ?err,
                    "smart contract threw error",
                );
            })?;

        tracing::info!(
            sign_id = ?action.indexed.id,
            big_r = signature.big_r.to_base58(),
            s = ?signature.s,
            elapsed = ?timestamp.elapsed(),
            "published signature sucessfully",
        );

        super::record_publish_metrics(action);

        Ok(())
    }
}
