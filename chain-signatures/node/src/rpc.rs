use crate::config::{Config, ContractConfig, NetworkConfig};
use crate::protocol::signature::ToPublish;
use crate::protocol::{Chain, ProtocolState};
use crate::util::AffinePointExt as _;

use crypto_shared::SignatureResponse;
use mpc_contract::primitives::SignatureRequest;
use mpc_keys::hpke;

use near_account_id::AccountId;
use near_crypto::InMemorySigner;
use near_fetch::result::ExecutionFinalResult;
use near_primitives::hash::CryptoHash;
use serde_json::json;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use url::Url;

pub const PUBLISH_MAX_RETRY: u8 = 6;

enum RpcAction {
    Publish(crypto_shared::PublicKey, ToPublish),
}

#[derive(Clone)]
pub struct RpcChannel {
    tx: mpsc::Sender<RpcAction>,
}

impl RpcChannel {
    pub async fn publish(&self, public_key: crypto_shared::PublicKey, to_publish: ToPublish) {
        if let Err(err) = self
            .tx
            .send(RpcAction::Publish(public_key, to_publish))
            .await
        {
            tracing::error!(%err, "failed to send publish action");
        }
    }
}

pub struct RpcExecutor {
    client: RpcClient,
    action_rx: mpsc::Receiver<RpcAction>,
    tasks: VecDeque<tokio::task::JoinHandle<()>>,
}

impl RpcExecutor {
    pub fn new(client: &RpcClient) -> (RpcChannel, Self) {
        let (tx, rx) = mpsc::channel(1024);
        (
            RpcChannel { tx },
            Self {
                client: client.clone(),
                action_rx: rx,
                tasks: VecDeque::new(),
            },
        )
    }

    pub async fn run(
        mut self,
        contract_state: Arc<RwLock<Option<ProtocolState>>>,
        config: Arc<RwLock<Config>>,
    ) {
        let mut update_interval = tokio::time::interval(Duration::from_millis(3000));
        let mut action_interval = tokio::time::interval(Duration::from_millis(25));
        loop {
            tokio::select! {
                action = self.action_rx.recv() => {
                    if let Some(action) = action {
                        let task = match action {
                            RpcAction::Publish(public_key, to_publish) => {
                                execute_publish(self.client.clone(), public_key, to_publish)
                            }
                        };
                        self.tasks.push_back(tokio::spawn(task));
                    } else {
                        tracing::error!("rpc channel closed unexpectedly");
                        return;
                    }
                }
                _ = action_interval.tick() => {
                    // Remove finished tasks
                    self.tasks.retain(|task| !task.is_finished());
                }
                _ = update_interval.tick() => {
                    self.update_contract(&contract_state).await;
                    self.update_config(&config).await;
                }
            }
        }
    }

    async fn update_contract(&mut self, contract_state: &Arc<RwLock<Option<ProtocolState>>>) {
        match self.client.fetch_state().await {
            Err(error) => {
                tracing::error!(?error, "could not fetch contract's state");
            }
            Ok(state) => {
                let mut contract_state_guard = contract_state.write().await;
                *contract_state_guard = Some(state);
            }
        }
    }

    async fn update_config(&mut self, config: &Arc<RwLock<Config>>) {
        let mut config = config.write().await;
        if let Err(error) = config.fetch_inplace(&self.client).await {
            tracing::error!("could not fetch contract's config: {error:?}");
        }
    }
}

#[derive(Clone)]
pub struct RpcClient {
    client: near_fetch::Client,
    contract_id: AccountId,
    my_addr: Url,
    my_account_id: AccountId,
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
            my_account_id: signer.account_id.clone(),
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
            .transact()
            .await?;

        Ok(response)
    }
}

/// Publish the signature and retry if it fails
async fn execute_publish(
    client: RpcClient,
    public_key: crypto_shared::PublicKey,
    mut to_publish: ToPublish,
) {
    loop {
        if try_publish(&client, &public_key, &mut to_publish)
            .await
            .is_ok()
        {
            break;
        }

        tokio::time::sleep(Duration::from_secs(300)).await;
        if to_publish.retry_count >= PUBLISH_MAX_RETRY {
            tracing::info!(
                request_id = ?CryptoHash(to_publish.request_id),
                "exceeded max retries, trashing publish request",
            );
            break;
        } else {
            tracing::info!(
                request_id = ?CryptoHash(to_publish.request_id),
                retry_count = to_publish.retry_count,
                "failed to publish, retrying"
            );
        }
    }
}

async fn try_publish(
    client: &RpcClient,
    public_key: &crypto_shared::PublicKey,
    to_publish: &mut ToPublish,
) -> Result<(), near_fetch::Error> {
    let ToPublish {
        request_id,
        request,
        signature,
        chain,
        ..
    } = &to_publish;
    let expected_public_key = crypto_shared::derive_key(*public_key, request.epsilon.scalar);
    // We do this here, rather than on the client side, so we can use the ecrecover system function on NEAR to validate our signature
    let Ok(signature) = crate::kdf::into_eth_sig(
        &expected_public_key,
        &signature.big_r,
        &signature.s,
        request.payload_hash.scalar,
    ) else {
        tracing::error!(
            request_id = ?CryptoHash(*request_id),
            "failed to generate a recovery id -- trashing publish request",
        );
        return Ok(());
    };

    match *chain {
        Chain::NEAR => try_publish_near(client, to_publish, signature).await?,
        Chain::Ethereum => {}
    }
    Ok(())
}

async fn try_publish_near(
    client: &RpcClient,
    to_publish: &mut ToPublish,
    signature: SignatureResponse,
) -> Result<(), near_fetch::Error> {
    let ToPublish {
        request_id,
        request,
        retry_count,
        time_added,
        ..
    } = to_publish;

    let outcome = client
        .call_respond(&request, &signature)
        .await
        .inspect_err(|err| {
            tracing::error!(
                request_id = ?CryptoHash(*request_id),
                ?request,
                ?err,
                "failed to publish the signature",
            );
            crate::metrics::SIGNATURE_PUBLISH_FAILURES
                .with_label_values(&[client.my_account_id.as_str()])
                .inc();
            *retry_count += 1;
        })?;

    let _: () = outcome.json().inspect_err(|err| {
        tracing::error!(
            request_id = ?CryptoHash(*request_id),
            ?request,
            big_r = signature.big_r.affine_point.to_base58(),
            s = ?signature.s,
            ?err,
            "smart contract threw error",
        );
        crate::metrics::SIGNATURE_PUBLISH_RESPONSE_ERRORS
            .with_label_values(&[client.my_account_id.as_str()])
            .inc();
    })?;
    tracing::info!(
        request_id = ?CryptoHash(*request_id),
        ?request,
        big_r = signature.big_r.affine_point.to_base58(),
        s = ?signature.s,
        "published signature sucessfully",
    );

    crate::metrics::NUM_SIGN_SUCCESS
        .with_label_values(&[client.my_account_id.as_str()])
        .inc();
    crate::metrics::SIGN_LATENCY
        .with_label_values(&[client.my_account_id.as_str()])
        .observe(time_added.elapsed().as_secs_f64());
    if time_added.elapsed().as_secs() <= 30 {
        crate::metrics::NUM_SIGN_SUCCESS_30S
            .with_label_values(&[client.my_account_id.as_str()])
            .inc();
    }

    Ok(())
}
