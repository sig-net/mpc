use super::PublishAction;
use crate::config::{ContractConfig, NetworkConfig};
use crate::protocol::{Governance, ProtocolState};
use crate::util::AffinePointExt as _;
pub use mpc_contract::primitives::{Read, View};

use mpc_keys::hpke;
use mpc_primitives::{ConsensusCheckpointDigest, SignId, SignKind, Signature};

use near_account_id::AccountId;
use near_crypto::InMemorySigner;
use near_fetch::result::ExecutionFinalResult;
use serde_json::json;
use std::time::Instant;
use url::Url;

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

    pub async fn fetch_state(&self) -> anyhow::Result<ProtocolState> {
        let contract_state: mpc_contract::ProtocolContractState =
            self.client.view(&self.contract_id, "state").await?.json()?;

        let protocol_state: ProtocolState = contract_state.try_into().map_err(|_| {
            anyhow::anyhow!("failed to parse protocol state, has it been initialized?")
        })?;

        tracing::debug!(?protocol_state, "protocol state");
        Ok(protocol_state)
    }

    pub async fn fetch_config(&self) -> Option<ContractConfig> {
        self.client
            .view(&self.contract_id, "config")
            .await
            .inspect_err(|err| {
                tracing::warn!(%err, "failed to fetch contract config");
            })
            .ok()?
            .json()
            .inspect(|configs| {
                tracing::debug!(?configs, "contract config");
            })
            .inspect_err(|err| {
                tracing::warn!(%err, "unable to parse config");
            })
            .ok()
    }

    pub async fn vote_public_key(
        &self,
        public_key: &near_crypto::PublicKey,
    ) -> anyhow::Result<bool> {
        tracing::info!(%public_key, signer_id = %self.signer.account_id, "voting for public key");
        let result = self
            .client
            .call(&self.signer, &self.contract_id, "vote_pk")
            .args_json(json!({
                "public_key": public_key
            }))
            .max_gas()
            .retry_exponential(10, 5)
            .transact()
            .await
            .inspect_err(|err| {
                tracing::warn!(%err, "failed to vote for public key");
            })?
            .json()?;

        Ok(result)
    }

    pub async fn vote_reshared(&self, epoch: u64) -> anyhow::Result<bool> {
        tracing::info!(%epoch, signer_id = %self.signer.account_id, "voting for reshared");
        let result = self
            .client
            .call(&self.signer, &self.contract_id, "vote_reshared")
            .args_json(json!({
                "epoch": epoch
            }))
            .max_gas()
            .retry_exponential(10, 5)
            .transact()
            .await
            .inspect_err(|err| {
                tracing::warn!(%err, "failed to vote for reshared");
            })?
            .json()?;

        Ok(result)
    }

    pub async fn propose_join(&self) -> anyhow::Result<()> {
        tracing::info!(signer_id = %self.signer.account_id, "joining the protocol");
        self.client
            .call(&self.signer, &self.contract_id, "join")
            .args_json(json!({
                "url": self.my_addr,
                "cipher_pk": self.cipher_pk.to_bytes(),
                "sign_pk": self.sign_pk,
            }))
            .max_gas()
            .retry_exponential(10, 3)
            .transact()
            .await?
            .into_result()?;

        Ok(())
    }

    pub async fn call_respond(
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

    pub async fn call_respond_checkpoint(
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
            .transact()
            .await
    }
}

// TODO: make client method
pub async fn try_publish_near(
    near: &NearClient,
    action: &PublishAction,
    timestamp: &Instant,
    signature: &Signature,
) -> Result<(), near_fetch::Error> {
    let outcome = match &action.indexed.kind {
        SignKind::Checkpoint(checkpoint) => {
            near.call_respond_checkpoint(checkpoint, signature).await
        }
        _ => near.call_respond(&action.indexed.id, signature).await,
    }
    .inspect_err(|err| {
        tracing::error!(
            sign_id = ?action.indexed.id,
            ?err,
            "failed to publish signature",
        );
    })?;

    let _: () = outcome.json().inspect_err(|err| {
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
    Ok(())
}
