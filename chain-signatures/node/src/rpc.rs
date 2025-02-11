use crate::config::{Config, ContractConfig, NetworkConfig};
use crate::indexer_eth::EthConfig;
use crate::protocol::signature::SignRequest;
use crate::protocol::{Chain, ProtocolState};
use crate::util::AffinePointExt as _;

use cait_sith::FullSignature;
use k256::Secp256k1;
use mpc_contract::primitives::SignatureRequest;
use mpc_crypto::SignatureResponse;
use mpc_keys::hpke;

use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use near_account_id::AccountId;
use near_crypto::InMemorySigner;
use near_fetch::result::ExecutionFinalResult;
use serde_json::json;
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use url::Url;
use web3::contract::tokens::Tokenizable as _;
use web3::ethabi::Token;
use web3::types::U256;

/// The maximum amount of times to retry publishing a signature.
const MAX_PUBLISH_RETRY: usize = 6;
/// The maximum number of concurrent RPC requests the system can make
const MAX_CONCURRENT_RPC_REQUESTS: usize = 1024;
/// The update interval to fetch and update the contract state and config
const UPDATE_INTERVAL: Duration = Duration::from_secs(3);

struct PublishAction {
    public_key: mpc_crypto::PublicKey,
    request: SignRequest,
    output: FullSignature<Secp256k1>,
    timestamp: Instant,
    retry_count: usize,
}

enum RpcAction {
    Publish(PublishAction),
}

#[derive(Clone)]
pub struct RpcChannel {
    tx: mpsc::Sender<RpcAction>,
}

impl RpcChannel {
    pub fn publish(
        &self,
        public_key: mpc_crypto::PublicKey,
        request: SignRequest,
        output: FullSignature<Secp256k1>,
    ) {
        let rpc = self.clone();
        tokio::spawn(async move {
            if let Err(err) = rpc
                .tx
                .send(RpcAction::Publish(PublishAction {
                    public_key,
                    request,
                    output,
                    timestamp: Instant::now(),
                    retry_count: 0,
                }))
                .await
            {
                tracing::error!(%err, "failed to send publish action");
            }
        });
    }
}

pub struct RpcExecutor {
    near: NearClient,
    eth: Option<EthClient>,
    action_rx: mpsc::Receiver<RpcAction>,
}

impl RpcExecutor {
    pub fn new(near: &NearClient, eth: &Option<EthConfig>) -> (RpcChannel, Self) {
        let eth = eth.as_ref().map(EthClient::new);
        let (tx, rx) = mpsc::channel(MAX_CONCURRENT_RPC_REQUESTS);
        (
            RpcChannel { tx },
            Self {
                near: near.clone(),
                eth,
                action_rx: rx,
            },
        )
    }

    pub async fn run(
        mut self,
        contract_state: Arc<RwLock<Option<ProtocolState>>>,
        config: Arc<RwLock<Config>>,
    ) {
        // spin up update task for updating contract state and config
        let near = self.near.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(UPDATE_INTERVAL);
            loop {
                interval.tick().await;
                tokio::spawn(update_contract(near.clone(), contract_state.clone()));
                tokio::spawn(update_config(near.clone(), config.clone()));
            }
        });

        // process incoming actions related to RPC
        loop {
            let Some(action) = self.action_rx.recv().await else {
                tracing::error!("rpc channel closed unexpectedly");
                return;
            };
            let task = match action {
                RpcAction::Publish(action) => {
                    execute_publish(self.client(&action.request.indexed.chain), action)
                }
            };
            tokio::spawn(task);
        }
    }

    /// Get the client for the given chain
    fn client(&self, chain: &Chain) -> ChainClient {
        match chain {
            Chain::NEAR => ChainClient::Near(self.near.clone()),
            Chain::Ethereum => {
                if let Some(eth) = &self.eth {
                    ChainClient::Ethereum(eth.clone())
                } else {
                    ChainClient::Err("no eth client available for node")
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct NearClient {
    client: near_fetch::Client,
    contract_id: AccountId,
    my_addr: Url,
    my_account_id: AccountId,
    signer: InMemorySigner,
    cipher_pk: hpke::PublicKey,
    sign_pk: near_crypto::PublicKey,
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
        self.client
            .call(&self.signer, &self.contract_id, "respond")
            .args_json(json!({
                "request": request,
                "response": response,
            }))
            .max_gas()
            .transact()
            .await
    }
}

#[derive(Clone)]
pub struct EthClient {
    client: web3::Web3<web3::transports::Http>,
    contract: web3::contract::Contract<web3::transports::Http>,
    account_sk: web3::signing::SecretKey,
}

impl EthClient {
    pub fn new(eth: &EthConfig) -> Self {
        let transport = web3::transports::Http::new(&eth.rpc_http_url).unwrap();
        let client = web3::Web3::new(transport);
        let address = web3::types::H160::from_str(&eth.contract_address).unwrap();

        let contract_json: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../contract-eth/artifacts/contracts/ChainSignatures.sol/ChainSignatures.json"
        ))
        .unwrap();
        let contract = web3::contract::Contract::from_json(
            client.eth(),
            address,
            contract_json["abi"].to_string().as_bytes(),
        )
        .unwrap();
        Self {
            client,
            contract,
            account_sk: web3::signing::SecretKey::from_str(&eth.account_sk)
                .expect("failed to parse eth account sk, should not begin with 0x"),
        }
    }
}

/// Client related to a specific chain
pub enum ChainClient {
    Err(&'static str),
    Near(NearClient),
    Ethereum(EthClient),
}

async fn update_contract(near: NearClient, contract_state: Arc<RwLock<Option<ProtocolState>>>) {
    match near.fetch_state().await {
        Ok(state) => {
            *contract_state.write().await = Some(state);
        }
        Err(error) => {
            tracing::error!(?error, "could not fetch contract state");
        }
    }
}

async fn update_config(near: NearClient, config: Arc<RwLock<Config>>) {
    let mut config = config.write().await;
    if let Err(error) = config.fetch_inplace(&near).await {
        tracing::error!(?error, "could not fetch contract config");
    }
}

/// Publish the signature and retry if it fails
async fn execute_publish(client: ChainClient, mut action: PublishAction) {
    tracing::info!(
        sign_id = ?action.request.indexed.id,
        chain = ?action.request.indexed.chain,
        started_at = ?action.timestamp.elapsed(),
        "trying to publish signature",
    );
    let expected_public_key =
        mpc_crypto::derive_key(action.public_key, action.request.indexed.id.epsilon);

    // We do this here, rather than on the client side, so we can use the ecrecover system function on NEAR to validate our signature
    let Ok(signature) = crate::kdf::into_eth_sig(
        &expected_public_key,
        &action.output.big_r,
        &action.output.s,
        action.request.indexed.id.payload,
    ) else {
        tracing::error!(
            sign_id = ?action.request.indexed.id,
            "failed to generate a recovery id; trashing publish request",
        );
        return;
    };

    loop {
        let publish = match &client {
            ChainClient::Near(near) => {
                try_publish_near(near, &action, &action.timestamp, &signature)
                    .await
                    .map_err(|_| ())
            }
            ChainClient::Ethereum(eth) => {
                try_publish_eth(eth, &action, &action.timestamp, &signature).await
            }
            ChainClient::Err(msg) => {
                tracing::warn!(msg, "no client for chain");
                Ok(())
            }
        };
        if publish.is_ok() {
            break;
        }

        action.retry_count += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
        if action.retry_count >= MAX_PUBLISH_RETRY {
            tracing::info!(
                sign_id = ?action.request.indexed.id,
                elapsed = ?action.timestamp.elapsed(),
                "exceeded max retries, trashing publish request",
            );
            break;
        } else {
            tracing::info!(
                sign_id = ?action.request.indexed.id,
                retry_count = action.retry_count,
                elapsed = ?action.timestamp.elapsed(),
                "failed to publish, retrying"
            );
        }
    }
}

async fn try_publish_near(
    near: &NearClient,
    action: &PublishAction,
    timestamp: &Instant,
    signature: &SignatureResponse,
) -> Result<(), near_fetch::Error> {
    let request = SignatureRequest {
        epsilon: action.request.indexed.id.epsilon,
        payload: action.request.indexed.id.payload,
    };

    let outcome = near
        .call_respond(&request, signature)
        .await
        .inspect_err(|err| {
            tracing::error!(
                sign_id = ?action.request.indexed.id,
                ?request,
                ?err,
                "failed to publish signature",
            );
            crate::metrics::SIGNATURE_PUBLISH_FAILURES
                .with_label_values(&[near.my_account_id.as_str()])
                .inc();
        })?;

    let _: () = outcome.json().inspect_err(|err| {
        tracing::error!(
            sign_id = ?action.request.indexed.id,
            ?request,
            big_r = signature.big_r.affine_point.to_base58(),
            s = ?signature.s,
            ?err,
            "smart contract threw error",
        );
        crate::metrics::SIGNATURE_PUBLISH_RESPONSE_ERRORS
            .with_label_values(&[near.my_account_id.as_str()])
            .inc();
    })?;
    tracing::info!(
        sign_id = ?action.request.indexed.id,
        ?request,
        big_r = signature.big_r.affine_point.to_base58(),
        s = ?signature.s,
        elapsed = ?timestamp.elapsed(),
        "published signature sucessfully",
    );

    crate::metrics::NUM_SIGN_SUCCESS
        .with_label_values(&[near.my_account_id.as_str()])
        .inc();
    crate::metrics::SIGN_TOTAL_LATENCY
        .with_label_values(&[near.my_account_id.as_str()])
        .observe(action.request.indexed.timestamp.elapsed().as_secs_f64());
    crate::metrics::SIGN_RESPOND_LATENCY
        .with_label_values(&[near.my_account_id.as_str()])
        .observe(timestamp.elapsed().as_secs_f64());
    if action.request.indexed.timestamp.elapsed().as_secs() <= 30 {
        crate::metrics::NUM_SIGN_SUCCESS_30S
            .with_label_values(&[near.my_account_id.as_str()])
            .inc();
    }

    Ok(())
}

async fn try_publish_eth(
    eth: &EthClient,
    action: &PublishAction,
    timestamp: &Instant,
    signature: &SignatureResponse,
) -> Result<(), ()> {
    let params = [
        Token::FixedBytes(action.request.indexed.id.request_id.to_vec()),
        Token::Tuple(vec![
            Token::Tuple(vec![
                Token::Uint(U256::from_big_endian(&signature.big_r.affine_point.x())),
                Token::Uint(U256::from_big_endian(
                    signature
                        .big_r
                        .affine_point
                        .to_encoded_point(false)
                        .y()
                        .unwrap(),
                )),
            ]),
            Token::Uint(U256::from_big_endian(&signature.s.to_bytes())),
            signature.recovery_id.into_token(),
        ]),
    ];

    let data = eth
        .contract
        .abi()
        .function("respond")
        .unwrap()
        .encode_input(&params)
        .unwrap();

    let txn = web3::types::TransactionParameters {
        to: Some(eth.contract.address()),
        data: web3::types::Bytes(data),
        gas: web3::types::U256::from(100_000),
        ..Default::default()
    };

    // should never panic because up to this point, txn is valid and key is valid
    let signed = eth
        .client
        .accounts()
        .sign_transaction(txn, &eth.account_sk)
        .await
        .unwrap();

    let result = eth
        .client
        .eth()
        .send_raw_transaction(signed.raw_transaction)
        .await;
    match result {
        Ok(tx_hash) => {
            tracing::info!(
                sign_id = ?action.request.indexed.id,
                tx_hash = ?tx_hash,
                elapsed = ?timestamp.elapsed(),
                "published ethereum signature successfully"
            );
            Ok(())
        }
        Err(err) => {
            tracing::error!(
                sign_id = ?action.request.indexed.id,
                error = ?err,
                "failed to publish ethereum signature"
            );
            Err(())
        }
    }
    // TODO: add metrics for Ethereum
}
