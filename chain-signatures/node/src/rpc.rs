use crate::config::{Config, ContractConfig, NetworkConfig};
use crate::protocol::ProtocolState;

use crypto_shared::SignatureResponse;
use mpc_contract::primitives::SignatureRequest;
use mpc_keys::hpke;

use near_account_id::AccountId;
use near_crypto::InMemorySigner;
use near_fetch::result::ExecutionFinalResult;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use url::Url;

pub struct RpcExecutor {
    client: RpcClient,
}

impl RpcExecutor {
    pub fn new(client: &RpcClient) -> Self {
        Self {
            client: client.clone(),
        }
    }

    pub async fn run(
        self,
        contract_state: Arc<RwLock<Option<ProtocolState>>>,
        config: Arc<RwLock<Config>>,
    ) -> anyhow::Result<()> {
        let mut interval = tokio::time::interval(Duration::from_millis(3000));
        loop {
            interval.tick().await;
            match self.client.fetch_state().await {
                Err(error) => {
                    tracing::error!(?error, "could not fetch contract's state");
                }
                Ok(state) => {
                    let mut contract_state_guard = contract_state.write().await;
                    *contract_state_guard = Some(state);
                }
            }

            let mut config = config.write().await;
            if let Err(error) = config.fetch_inplace(&self.client).await {
                tracing::error!("could not fetch contract's config: {error:?}");
            }
        }
    }
}

#[derive(Clone)]
pub struct RpcClient {
    client: near_fetch::Client,
    contract_id: AccountId,
    my_addr: Url,
    signer: InMemorySigner,
    cipher_pk: hpke::PublicKey,
    sign_pk: near_crypto::PublicKey,
}

impl RpcClient {
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
            cipher_pk: network.cipher_pk.clone(),
            sign_pk: network.sign_sk.public_key(),
        }
    }

    pub fn rpc_addr(&self) -> String {
        self.client.rpc_addr()
    }

    pub async fn fetch_state(&self) -> anyhow::Result<ProtocolState> {
        let contract_state: mpc_contract::ProtocolContractState = self
            .client
            .view(&self.contract_id, "state")
            .await
            .inspect_err(|err| {
                tracing::warn!(%err, "failed to fetch protocol state");
            })?
            .json()?;

        let protocol_state: ProtocolState = contract_state.try_into().map_err(|_| {
            let msg = "failed to parse protocol state, has it been initialized?".to_string();
            tracing::error!(msg);
            anyhow::anyhow!(msg)
        })?;

        tracing::debug!(?protocol_state, "protocol state");
        Ok(protocol_state)
    }

    pub async fn fetch_config(&self, original: &Config) -> anyhow::Result<Config> {
        let contract_config: ContractConfig = self
            .client
            .view(&self.contract_id, "config")
            .await
            .inspect_err(|err| {
                tracing::warn!(%err, "failed to fetch contract config");
            })?
            .json()?;
        tracing::debug!(?contract_config, "contract config");
        Config::try_from_contract(contract_config, original).ok_or_else(|| {
            let msg = "failed to parse contract config";
            tracing::error!(msg);
            anyhow::anyhow!(msg)
        })
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
        request: &SignatureRequest,
        response: &SignatureResponse,
    ) -> Result<ExecutionFinalResult, near_fetch::Error> {
        let response = self
            .client
            .call(&self.signer, &self.contract_id, "respond")
            .args_json(json!({
                "request": request,
                "response": response,
            }))
            .max_gas()
            .retry_exponential(10, 5)
            .transact()
            .await?;

        Ok(response)
    }
}
