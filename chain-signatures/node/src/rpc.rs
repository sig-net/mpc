use crate::config::{Config, ContractConfig, NetworkConfig};
use crate::indexer_eth::EthConfig;
use crate::indexer_sol::SolConfig;
use crate::protocol::contract::primitives::{ParticipantMap, Participants};
use crate::protocol::contract::RunningContractState;
use crate::protocol::signature::SignRequest;
use crate::protocol::{Chain, ProtocolState};
use crate::util::AffinePointExt as _;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::keypair::Keypair;

use alloy::primitives::Address;
use alloy::providers::fillers::{FillProvider, JoinFill, WalletFiller};
use alloy::providers::{Provider, RootProvider, WalletProvider};
use alloy::rpc::types::{Transaction, TransactionReceipt};
use cait_sith::protocol::Participant;
use cait_sith::FullSignature;
use k256::{AffinePoint, Secp256k1};
use mpc_keys::hpke;
use mpc_primitives::SignId;
use mpc_primitives::Signature;

use alloy::contract::{ContractInstance, Interface};
use alloy::dyn_abi::DynSolValue;
use alloy::network::EthereumWallet;
use alloy::primitives::U256;
use alloy::providers::ProviderBuilder;
use alloy_signer_local::PrivateKeySigner;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use near_account_id::AccountId;
use near_crypto::InMemorySigner;
use near_fetch::result::ExecutionFinalResult;
use serde_json::json;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use url::Url;

/// The maximum amount of times to retry publishing a signature.
const MAX_PUBLISH_RETRY: usize = 6;
/// The maximum number of concurrent RPC requests the system can make
const MAX_CONCURRENT_RPC_REQUESTS: usize = 1024;
/// The update interval to fetch and update the contract state and config
const UPDATE_INTERVAL: Duration = Duration::from_secs(10);
/// The interval to batch send Ethereum responses
const ETH_RESPOND_BATCH_INTERVAL: Duration = Duration::from_millis(2000);
/// The batch size for Ethereum responses
const ETH_RESPOND_BATCH_SIZE: usize = 10;
/// The maximum number of attempts to fetch eth tx and its receipt
const ETH_TX_RECEIPT_MAX_ATTEMPTS: usize = 6;

type EthContractFillProvider = FillProvider<
    JoinFill<
        JoinFill<
            alloy::providers::Identity,
            JoinFill<
                alloy::providers::fillers::GasFiller,
                JoinFill<
                    alloy::providers::fillers::BlobGasFiller,
                    JoinFill<
                        alloy::providers::fillers::NonceFiller,
                        alloy::providers::fillers::ChainIdFiller,
                    >,
                >,
            >,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

type EthContractInstance = ContractInstance<EthContractFillProvider>;

#[derive(Clone)]
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

#[derive(Clone)]
pub struct ContractStateWatcher {
    account_id: AccountId,
    contract_state: watch::Receiver<Option<ProtocolState>>,
}

impl ContractStateWatcher {
    pub fn new(id: &AccountId) -> (Self, watch::Sender<Option<ProtocolState>>) {
        let (tx, rx) = watch::channel(None);
        (
            Self {
                account_id: id.clone(),
                contract_state: rx,
            },
            tx,
        )
    }

    pub fn with(
        id: &AccountId,
        state: ProtocolState,
    ) -> (Self, watch::Sender<Option<ProtocolState>>) {
        let (tx, rx) = watch::channel(Some(state));
        (
            Self {
                account_id: id.clone(),
                contract_state: rx,
            },
            tx,
        )
    }

    pub fn with_running(
        node_id: &AccountId,
        public_key: AffinePoint,
        threshold: usize,
        participants: Participants,
    ) -> (Self, watch::Sender<Option<ProtocolState>>) {
        Self::with(
            node_id,
            ProtocolState::Running(RunningContractState {
                epoch: 0,
                public_key,
                participants,
                candidates: Default::default(),
                join_votes: Default::default(),
                leave_votes: Default::default(),
                threshold,
            }),
        )
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn borrow_state(&self) -> watch::Ref<'_, Option<ProtocolState>> {
        self.contract_state.borrow()
    }

    pub fn state(&self) -> Option<ProtocolState> {
        self.borrow_state().clone()
    }

    pub async fn next_state(&mut self) -> Option<ProtocolState> {
        let _ = self.contract_state.changed().await;
        self.contract_state.borrow_and_update().clone()
    }

    pub fn mark_changed(&mut self) {
        self.contract_state.mark_changed();
    }

    pub fn participants(&self) -> Option<Participants> {
        match self.borrow_state().as_ref()? {
            ProtocolState::Initializing(state) => Some(state.candidates.clone().into()),
            ProtocolState::Running(state) => Some(state.participants.clone()),
            ProtocolState::Resharing(state) => Some(state.new_participants.clone()),
        }
    }

    pub async fn me(&self) -> Option<Participant> {
        match self.borrow_state().as_ref()? {
            ProtocolState::Initializing(_) => None,
            ProtocolState::Running(state) => state
                .participants
                .find_participant(&self.account_id)
                .copied(),
            ProtocolState::Resharing(state) => state
                .new_participants
                .find_participant(&self.account_id)
                .copied(),
        }
    }

    pub async fn threshold(&self) -> Option<usize> {
        match self.state().clone()? {
            ProtocolState::Initializing(_) => None,
            ProtocolState::Running(state) => Some(state.threshold),
            ProtocolState::Resharing(state) => Some(state.threshold),
        }
    }

    pub async fn info(&self) -> Option<(usize, Participant)> {
        match self.state().clone()? {
            ProtocolState::Initializing(_) => None,
            ProtocolState::Running(state) => Some((
                state.threshold,
                *state.participants.find_participant(&self.account_id)?,
            )),
            ProtocolState::Resharing(state) => Some((
                state.threshold,
                *state.new_participants.find_participant(&self.account_id)?,
            )),
        }
    }

    pub async fn participant_map(&self) -> ParticipantMap {
        let Some(state) = self.state().clone() else {
            return ParticipantMap::Zero;
        };

        match state {
            ProtocolState::Initializing(state) => {
                ParticipantMap::One(state.candidates.clone().into())
            }
            ProtocolState::Running(state) => ParticipantMap::One(state.participants.clone()),
            ProtocolState::Resharing(state) => ParticipantMap::Two(
                state.new_participants.clone(),
                state.old_participants.clone(),
            ),
        }
    }
}

pub struct RpcExecutor {
    near: NearClient,
    eth: Option<EthClient>,
    solana: Option<SolanaClient>,
    action_rx: mpsc::Receiver<RpcAction>,
}

impl RpcExecutor {
    pub fn new(
        near: &NearClient,
        eth: &Option<EthConfig>,
        solana: &Option<SolConfig>,
    ) -> (RpcChannel, Self) {
        let eth = eth.as_ref().map(EthClient::new);
        let solana = solana.as_ref().map(SolanaClient::new);
        let (tx, rx) = mpsc::channel(MAX_CONCURRENT_RPC_REQUESTS);
        (
            RpcChannel { tx },
            Self {
                near: near.clone(),
                eth,
                solana,
                action_rx: rx,
            },
        )
    }

    pub async fn run(
        mut self,
        contract: watch::Sender<Option<ProtocolState>>,
        config: watch::Sender<Config>,
    ) {
        // spin up update task for updating contract state and config
        let near = self.near.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(UPDATE_INTERVAL);
            loop {
                interval.tick().await;
                tokio::spawn(update_contract(near.clone(), contract.clone()));
                tokio::spawn(update_config(near.clone(), config.clone()));
            }
        });

        let eth_client = self.client(&Chain::Ethereum);
        let near_account_id_clone = self.near.my_account_id.clone();
        let (eth_rpc_tx, eth_rpc_rx) = mpsc::channel(MAX_CONCURRENT_RPC_REQUESTS);
        // spin up update task for batch sending eth responses
        tokio::spawn({
            run_batch_respond(
                eth_client,
                eth_rpc_rx,
                ETH_RESPOND_BATCH_INTERVAL,
                ETH_RESPOND_BATCH_SIZE,
                near_account_id_clone.clone(),
            )
        });

        // process incoming actions related to RPC
        loop {
            let Some(RpcAction::Publish(action)) = self.action_rx.recv().await else {
                tracing::error!("rpc channel closed unexpectedly");
                return;
            };

            let chain = action.request.indexed.chain;
            let client = self.client(&chain);
            let near_account_id = self.near.my_account_id.clone();
            let eth_rpc_tx = eth_rpc_tx.clone(); // clone for task use

            tokio::spawn(async move {
                match chain {
                    Chain::NEAR | Chain::Solana => {
                        execute_publish(client, action, near_account_id).await;
                    }
                    Chain::Ethereum => {
                        if let Err(err) = eth_rpc_tx.send(action).await {
                            tracing::error!(%err, "eth: failed to send publish action");
                        }
                    }
                }
            });
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
            Chain::Solana => {
                if let Some(sol) = &self.solana {
                    ChainClient::Solana(sol.clone())
                } else {
                    ChainClient::Err("no solana client available for node")
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
}

#[derive(Clone)]
pub struct EthClient {
    contract: EthContractInstance,
}

impl EthClient {
    pub fn new(eth: &EthConfig) -> Self {
        let signer: PrivateKeySigner = eth
            .account_sk
            .parse()
            .expect("cannot parse Eth account sk into PrivateKeySigner");
        let wallet = EthereumWallet::from(signer.clone());
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(eth.execution_rpc_http_url.parse().unwrap());
        // Create a contract instance.
        let json: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../contract-eth/artifacts/contracts/ChainSignatures.sol/ChainSignatures.json"
        ))
        .unwrap();

        // Get `abi` from the artifact.
        let abi_value = json.get("abi").expect("Failed to get ABI from artifact");
        let abi = serde_json::from_str(&abi_value.to_string()).unwrap();

        let contract = ContractInstance::new(
            Address::from_str(&format!("0x{}", eth.contract_address)).unwrap(),
            provider.clone(),
            Interface::new(abi),
        );
        Self { contract }
    }
}

#[derive(Clone)]
pub struct SolanaClient {
    client: Arc<anchor_client::Client<Arc<Keypair>>>,
    program_id: Pubkey,
    payer: Arc<Keypair>,
}

impl SolanaClient {
    pub fn new(sol: &SolConfig) -> Self {
        let keypair = Keypair::from_base58_string(&sol.account_sk);
        let payer = Arc::new(keypair);
        let cluster =
            anchor_client::Cluster::Custom(sol.rpc_http_url.clone(), sol.rpc_ws_url.clone());
        let client = anchor_client::Client::new_with_options(
            cluster,
            payer.clone(),
            CommitmentConfig::confirmed(),
        );
        Self {
            client: Arc::new(client),
            program_id: Pubkey::from_str(&sol.program_address)
                .expect("Invalid Solana program address provided in configuration"),
            payer,
        }
    }
}

/// Client related to a specific chain
#[allow(clippy::large_enum_variant)]
pub enum ChainClient {
    Err(&'static str),
    Near(NearClient),
    Ethereum(EthClient),
    Solana(SolanaClient),
}

async fn update_contract(near: NearClient, contract: watch::Sender<Option<ProtocolState>>) {
    let new_state = match near.fetch_state().await {
        Ok(state) => state,
        Err(error) => {
            tracing::error!(?error, "could not fetch contract state");
            return;
        }
    };

    contract.send_if_modified(|old_state| {
        if let Some(old_state) = old_state {
            if *old_state == new_state {
                return false;
            }
        }
        *old_state = Some(new_state);
        true
    });
}

async fn update_config(near: NearClient, config: watch::Sender<Config>) {
    let Some(contract_config) = near.fetch_config().await else {
        return;
    };

    config.send_if_modified(|config| config.update(contract_config));
}

/// Publish the signature and retry if it fails
async fn execute_publish(
    client: ChainClient,
    mut action: PublishAction,
    near_account_id: AccountId,
) {
    let chain = action.request.indexed.chain;
    tracing::info!(
        sign_id = ?action.request.indexed.id,
        chain = ?chain,
        started_at = ?action.timestamp.elapsed(),
        "trying to publish signature",
    );
    let expected_public_key =
        mpc_crypto::derive_key(action.public_key, action.request.indexed.args.epsilon);

    // We do this here, rather than on the client side, so we can use the ecrecover system function on NEAR to validate our signature
    let Ok(signature) = crate::kdf::into_eth_sig(
        &expected_public_key,
        &action.output.big_r,
        &action.output.s,
        action.request.indexed.args.payload,
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
                try_publish_eth(
                    eth,
                    &action,
                    &action.timestamp,
                    &signature,
                    &near_account_id,
                )
                .await
            }
            ChainClient::Solana(sol) => try_publish_sol(
                sol,
                &action,
                &action.timestamp,
                &signature,
                &near_account_id,
            )
            .await
            .map_err(|_| ()),
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

async fn run_batch_respond(
    client: ChainClient,
    mut actions_rx: mpsc::Receiver<PublishAction>,
    batch_interval: Duration,
    batch_size: usize,
    near_account_id: AccountId,
) {
    let mut start = Instant::now();
    let mut actions_batch: Vec<PublishAction> = vec![];
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    loop {
        interval.tick().await;
        if (start.elapsed() > batch_interval || actions_batch.len() >= batch_size)
            && !actions_batch.is_empty()
        {
            tracing::info!(
                num_requests = actions_batch.len(),
                "publishing batch of signatures",
            );
            execute_batch_publish(
                &client,
                &mut actions_batch,
                &near_account_id,
                Instant::now(),
            )
            .await;
            start = Instant::now();
        }
        if let Ok(action) = actions_rx.try_recv() {
            actions_batch.push(action);
        }
    }
}

async fn try_publish_near(
    near: &NearClient,
    action: &PublishAction,
    timestamp: &Instant,
    signature: &Signature,
) -> Result<(), near_fetch::Error> {
    let chain = action.request.indexed.chain;
    let outcome = near
        .call_respond(&action.request.indexed.id, signature)
        .await
        .inspect_err(|err| {
            tracing::error!(
                sign_id = ?action.request.indexed.id,
                ?err,
                "failed to publish signature",
            );
            crate::metrics::SIGNATURE_PUBLISH_FAILURES
                .with_label_values(&[chain.as_str(), near.my_account_id.as_str()])
                .inc();
        })?;

    let _: () = outcome.json().inspect_err(|err| {
        tracing::error!(
            sign_id = ?action.request.indexed.id,
            big_r = signature.big_r.to_base58(),
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
        big_r = signature.big_r.to_base58(),
        s = ?signature.s,
        elapsed = ?timestamp.elapsed(),
        "published signature sucessfully",
    );

    crate::metrics::NUM_SIGN_SUCCESS
        .with_label_values(&[chain.as_str(), near.my_account_id.as_str()])
        .inc();
    if let Some(timestamp_sign_queue) = action.request.indexed.timestamp_sign_queue {
        crate::metrics::SIGN_TOTAL_LATENCY
            .with_label_values(&[chain.as_str(), near.my_account_id.as_str()])
            .observe(timestamp_sign_queue.elapsed().as_secs_f64());
    }
    crate::metrics::SIGN_RESPOND_LATENCY
        .with_label_values(&[chain.as_str(), near.my_account_id.as_str()])
        .observe(timestamp.elapsed().as_secs_f64());
    if let Some(timestamp_sign_queue) = action.request.indexed.timestamp_sign_queue {
        if timestamp_sign_queue.elapsed().as_secs() <= 30 {
            crate::metrics::NUM_SIGN_SUCCESS_30S
                .with_label_values(&[chain.as_str(), near.my_account_id.as_str()])
                .inc();
        }
    }

    Ok(())
}

/// Retry with exponential backoff starting at the specified `initial_delay`
async fn handle_wait_for_polling_retry(
    attempt: &mut usize,
    max_attempts: usize,
    sign_ids: &[SignId],
    near_account_id: &AccountId,
    error_msg: &str,
    initial_delay: Duration,
) -> Result<(), ()> {
    *attempt += 1;
    tracing::error!(?sign_ids, attempt = *attempt, "{}", error_msg);
    if *attempt >= max_attempts {
        tracing::error!(?sign_ids, "exceeded max attempts");
        crate::metrics::SIGNATURE_PUBLISH_FAILURES
            .with_label_values(&[Chain::Ethereum.as_str(), near_account_id.as_str()])
            .inc();
        return Err(());
    }
    let backoff = initial_delay * 2u64.pow((*attempt - 1) as u32) as u32;
    tokio::time::sleep(backoff).await;
    Ok(())
}

// wait for transaction receipt with max_attempts and exponential delay backoff starting at 5s
async fn wait_for_pending_tx(
    provider: &EthContractFillProvider,
    tx_hash: alloy::primitives::B256,
    near_account_id: &AccountId,
    sign_ids: Vec<SignId>,
    max_attempts: usize,
) -> Result<Transaction, ()> {
    let mut attempt = 0;
    let initial_delay = Duration::from_secs(5);
    loop {
        match tokio::time::timeout(
            Duration::from_secs(10),
            provider.get_transaction_by_hash(tx_hash),
        )
        .await
        {
            Ok(result) => match result {
                Ok(Some(tx)) => {
                    tracing::info!(?sign_ids, "eth signature respond pending transaction found");
                    return Ok(tx);
                }
                Ok(None) => {
                    handle_wait_for_polling_retry(
                        &mut attempt,
                        max_attempts,
                        &sign_ids,
                        near_account_id,
                        "eth signature respond pending transaction not found, retrying",
                        initial_delay,
                    )
                    .await?;
                }
                Err(err) => {
                    handle_wait_for_polling_retry(
                        &mut attempt,
                        max_attempts,
                        &sign_ids,
                        near_account_id,
                        &format!("failed to get eth signature respond pending transaction, retrying: {err:?}"),
                        initial_delay,
                    ).await?;
                }
            },
            Err(_) => {
                handle_wait_for_polling_retry(
                    &mut attempt,
                    max_attempts,
                    &sign_ids,
                    near_account_id,
                    "timeout while getting eth signature respond pending transaction, retrying",
                    initial_delay,
                )
                .await?;
            }
        }
    }
}

// wait for transaction receipt with max_attempts and exponential delay backoff starting at 5s
async fn wait_for_transaction_receipt(
    provider: &EthContractFillProvider,
    tx_hash: alloy::primitives::B256,
    near_account_id: &AccountId,
    sign_ids: Vec<SignId>,
    max_attempts: usize,
) -> Result<TransactionReceipt, ()> {
    let mut attempt = 0;
    let initial_delay = Duration::from_secs(5);
    loop {
        match tokio::time::timeout(
            Duration::from_secs(10),
            provider.get_transaction_receipt(tx_hash),
        )
        .await
        {
            Ok(result) => match result {
                Ok(Some(receipt)) => {
                    tracing::info!(?sign_ids, "eth signature respond transaction receipt found");
                    return Ok(receipt);
                }
                Ok(None) => {
                    handle_wait_for_polling_retry(
                        &mut attempt,
                        max_attempts,
                        &sign_ids,
                        near_account_id,
                        "eth signature respond transaction receipt not found, retrying",
                        initial_delay,
                    )
                    .await?;
                }
                Err(err) => {
                    handle_wait_for_polling_retry(
                        &mut attempt,
                        max_attempts,
                        &sign_ids,
                        near_account_id,
                        &format!("failed to get eth signature respond transaction receipt, retrying: {err:?}"),
                        initial_delay,
                    ).await?;
                }
            },
            Err(_) => {
                handle_wait_for_polling_retry(
                    &mut attempt,
                    max_attempts,
                    &sign_ids,
                    near_account_id,
                    "timeout while getting eth signature respond transaction receipt, retrying",
                    initial_delay,
                )
                .await?;
            }
        }
    }
}

async fn send_eth_transaction(
    contract: &EthContractInstance,
    params: &[DynSolValue],
    gas: u64,
    sign_ids: &[SignId],
    near_account_id: &AccountId,
) -> Result<alloy::primitives::B256, ()> {
    let chain = Chain::Ethereum;
    // fetch nonce manually since the automatic nonce management in ContractInstance is lagging
    let nonce = match tokio::time::timeout(
        Duration::from_secs(10),
        contract
            .provider()
            .get_transaction_count(contract.provider().default_signer_address()),
    )
    .await
    {
        Ok(Ok(nonce)) => {
            tracing::info!(nonce, "will send eth tx with nonce");
            nonce
        }
        Ok(Err(err)) => {
            tracing::error!(?err, "failed to get nonce");
            return Err(());
        }
        Err(err) => {
            tracing::error!(?err, "timeout to get nonce");
            return Err(());
        }
    };

    let result = tokio::time::timeout(
        Duration::from_secs(30),
        contract
            .function("respond", params)
            .unwrap()
            .gas(gas)
            // setting nonce manually since the automatic nonce management in ContractInstance is lagging
            .nonce(nonce)
            .send(),
    )
    .await
    .map_err(|_| {
        tracing::error!(
            ?sign_ids,
            "timeout while sending ethereum signature transaction"
        );
        crate::metrics::SIGNATURE_PUBLISH_FAILURES
            .with_label_values(&[chain.as_str(), near_account_id.as_str()])
            .inc();
    })?
    .map_err(|err| {
        tracing::error!(
            ?sign_ids,
            ?err,
            "failed to send ethereum signature transaction"
        );
        crate::metrics::SIGNATURE_PUBLISH_FAILURES
            .with_label_values(&[chain.as_str(), near_account_id.as_str()])
            .inc();
    })?;

    Ok(*result.tx_hash())
}

async fn try_publish_eth(
    eth: &EthClient,
    action: &PublishAction,
    timestamp: &Instant,
    signature: &Signature,
    near_account_id: &AccountId,
) -> Result<(), ()> {
    let params = [DynSolValue::Array(vec![DynSolValue::Tuple(vec![
        DynSolValue::FixedBytes(action.request.indexed.id.request_id.into(), 32),
        DynSolValue::Tuple(vec![
            DynSolValue::Tuple(vec![
                DynSolValue::from(U256::from_be_slice(&signature.big_r.x())),
                DynSolValue::from(U256::from_be_slice(
                    signature.big_r.to_encoded_point(false).y().unwrap(),
                )),
            ]),
            DynSolValue::from(U256::from_be_slice(&signature.s.to_bytes())),
            DynSolValue::from(signature.recovery_id),
        ]),
    ])])];

    let tx_hash = send_eth_transaction(
        &eth.contract,
        &params,
        40000,
        &[action.request.indexed.id],
        near_account_id,
    )
    .await?;

    let receipt = wait_for_transaction_receipt(
        eth.contract.provider(),
        tx_hash,
        near_account_id,
        vec![action.request.indexed.id],
        ETH_TX_RECEIPT_MAX_ATTEMPTS,
    )
    .await?;

    // Check if transaction was successful
    if !receipt.status() {
        tracing::error!(
            sign_id = ?action.request.indexed.id,
            tx_hash = ?receipt.transaction_hash,
            "transaction failed"
        );
        crate::metrics::SIGNATURE_PUBLISH_FAILURES
            .with_label_values(&[
                action.request.indexed.chain.as_str(),
                near_account_id.as_str(),
            ])
            .inc();
        return Err(());
    }

    let chain = action.request.indexed.chain;
    let tx_hash = receipt.transaction_hash;
    tracing::info!(
        sign_id = ?action.request.indexed.id,
        tx_hash = ?tx_hash,
        elapsed = ?timestamp.elapsed(),
        "published ethereum signature successfully"
    );

    crate::metrics::NUM_SIGN_SUCCESS
        .with_label_values(&[chain.as_str(), near_account_id.as_str()])
        .inc();
    if let Some(timestamp_sign_queue) = action.request.indexed.timestamp_sign_queue {
        crate::metrics::SIGN_TOTAL_LATENCY
            .with_label_values(&[chain.as_str(), near_account_id.as_str()])
            .observe(timestamp_sign_queue.elapsed().as_secs_f64());
        if timestamp_sign_queue.elapsed().as_secs() <= 30 {
            crate::metrics::NUM_SIGN_SUCCESS_30S
                .with_label_values(&[chain.as_str(), near_account_id.as_str()])
                .inc();
        }
    }

    crate::metrics::SIGN_RESPOND_LATENCY
        .with_label_values(&[chain.as_str(), near_account_id.as_str()])
        .observe(timestamp.elapsed().as_secs_f64());

    Ok(())
}

async fn try_batch_publish_eth(
    eth: &EthClient,
    actions: &Vec<PublishAction>,
    signatures: &HashMap<SignId, Signature>,
    near_account_id: &AccountId,
    start: Instant,
) -> Result<(), ()> {
    let chain = Chain::Ethereum;
    let mut params_vec = vec![];
    let num_requests = actions.len();
    let sign_ids = actions
        .iter()
        .map(|action| action.request.indexed.id)
        .collect::<Vec<_>>();
    tracing::info!(?sign_ids, "will send eth batch tx");
    for action in actions {
        let signature = signatures
            .get(&action.request.indexed.id)
            .expect("signature not found in map");
        params_vec.push(DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(action.request.indexed.id.request_id.into(), 32),
            DynSolValue::Tuple(vec![
                DynSolValue::Tuple(vec![
                    DynSolValue::from(U256::from_be_slice(&signature.big_r.x())),
                    DynSolValue::from(U256::from_be_slice(
                        signature.big_r.to_encoded_point(false).y().unwrap(),
                    )),
                ]),
                DynSolValue::from(U256::from_be_slice(&signature.s.to_bytes())),
                DynSolValue::from(signature.recovery_id),
            ]),
        ]));
    }

    let params = [DynSolValue::Array(params_vec.clone())];
    let gas = std::cmp::max(40000, 20000 * num_requests as u64);

    let tx_hash =
        send_eth_transaction(&eth.contract, &params, gas, &sign_ids, near_account_id).await?;

    tracing::info!(?tx_hash, "sent eth tx");

    let tx = wait_for_pending_tx(
        eth.contract.provider(),
        tx_hash,
        near_account_id,
        sign_ids.clone(),
        ETH_TX_RECEIPT_MAX_ATTEMPTS,
    )
    .await?;

    tracing::info!(?tx, "tx found in mempool");

    let receipt = wait_for_transaction_receipt(
        eth.contract.provider(),
        tx_hash,
        near_account_id,
        sign_ids.clone(),
        ETH_TX_RECEIPT_MAX_ATTEMPTS,
    )
    .await?;

    // Check if transaction was successful
    if !receipt.status() {
        tracing::error!(
            ?sign_ids,
            tx_hash = ?receipt.transaction_hash,
            "eth batch transaction failed"
        );
        crate::metrics::SIGNATURE_PUBLISH_FAILURES
            .with_label_values(&[chain.as_str(), near_account_id.as_str()])
            .inc();
        return Err(());
    }

    let tx_hash = receipt.transaction_hash;
    tracing::info!(
        ?chain,
        ?sign_ids,
        ?tx_hash,
        num_requests,
        "eth batch published ethereum signatures successfully"
    );

    crate::metrics::NUM_SIGN_SUCCESS
        .with_label_values(&[chain.as_str(), near_account_id.as_str()])
        .inc_by(num_requests as f64);
    for action in actions {
        if let Some(timestamp_sign_queue) = action.request.indexed.timestamp_sign_queue {
            crate::metrics::SIGN_TOTAL_LATENCY
                .with_label_values(&[chain.as_str(), near_account_id.as_str()])
                .observe(timestamp_sign_queue.elapsed().as_secs_f64());
            if timestamp_sign_queue.elapsed().as_secs() <= 30 {
                crate::metrics::NUM_SIGN_SUCCESS_30S
                    .with_label_values(&[chain.as_str(), near_account_id.as_str()])
                    .inc();
            }
        }
    }
    crate::metrics::SIGN_RESPOND_LATENCY
        .with_label_values(&[chain.as_str(), near_account_id.as_str()])
        .observe(start.elapsed().as_secs_f64());

    Ok(())
}

async fn execute_batch_publish(
    client: &ChainClient,
    actions: &mut Vec<PublishAction>,
    near_account_id: &AccountId,
    start: Instant,
) {
    let mut signatures: HashMap<SignId, Signature> = HashMap::new();

    for action in actions.iter() {
        let expected_public_key =
            mpc_crypto::derive_key(action.public_key, action.request.indexed.args.epsilon);

        let Ok(signature) = crate::kdf::into_eth_sig(
            &expected_public_key,
            &action.output.big_r,
            &action.output.s,
            action.request.indexed.args.payload,
        ) else {
            tracing::error!(
                sign_id = ?action.request.indexed.id,
                "failed to generate a recovery id; trashing publish request",
            );
            return;
        };
        signatures.insert(action.request.indexed.id, signature);
    }

    let mut retry_count = 0;
    loop {
        let publish = match client {
            ChainClient::Near(_) => {
                tracing::error!("near has no batch publish");
                Ok(())
            }
            ChainClient::Solana(_) => {
                tracing::error!("Solana has no batch publish");
                Ok(())
            }
            ChainClient::Ethereum(eth) => {
                try_batch_publish_eth(eth, actions, &signatures, near_account_id, start).await
            }
            ChainClient::Err(msg) => {
                tracing::warn!(msg, "no client for chain");
                Ok(())
            }
        };
        if publish.is_ok() {
            actions.clear();
            break;
        }

        tracing::warn!("batch publish failed, {publish:?}");
        retry_count += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
        if retry_count >= MAX_PUBLISH_RETRY {
            tracing::info!("exceeded max retries, trashing publish request",);
            // clearing actions to avoid retrying
            actions.clear();
            break;
        } else {
            tracing::info!("failed to publish, retrying");
        }
    }
}

use chain_signatures_project::accounts::Respond as SolanaRespondAccount;
use chain_signatures_project::instruction::Respond as SolanaRespond;
use chain_signatures_project::AffinePoint as SolanaContractAffinePoint;
use chain_signatures_project::Signature as SolanaContractSignature;
use solana_sdk::signature::Signer as SolanaSigner;
async fn try_publish_sol(
    sol: &SolanaClient,
    action: &PublishAction,
    timestamp: &Instant,
    signature: &Signature,
    near_account_id: &AccountId,
) -> Result<(), ()> {
    let chain = action.request.indexed.chain;
    let program = sol.client.program(sol.program_id).map_err(|_| ())?;

    let request_ids = vec![action.request.indexed.id.request_id];
    let signature = SolanaContractSignature {
        big_r: SolanaContractAffinePoint {
            x: signature.big_r.to_encoded_point(false).as_bytes()[1..33]
                .try_into()
                .unwrap(),
            y: signature.big_r.to_encoded_point(false).as_bytes()[33..65]
                .try_into()
                .unwrap(),
        },
        s: signature.s.to_bytes().into(),
        recovery_id: signature.recovery_id,
    };

    let tx = program
        .request()
        .signer(sol.payer.clone())
        .accounts(SolanaRespondAccount {
            responder: sol.payer.clone().try_pubkey().unwrap(),
        })
        .args(SolanaRespond {
            request_ids,
            signatures: vec![signature],
        })
        .send()
        .await
        .map_err(|err| {
            tracing::error!(
                sign_id = ?action.request.indexed.id,
                error = ?err,
                "failed to publish solana signature"
            );
            crate::metrics::SIGNATURE_PUBLISH_FAILURES
                .with_label_values(&[chain.as_str(), near_account_id.as_str()])
                .inc();
        })?;

    tracing::info!(
        sign_id = ?action.request.indexed.id,
        tx_hash = ?tx,
        elapsed = ?timestamp.elapsed(),
        "published solana signature successfully"
    );

    crate::metrics::NUM_SIGN_SUCCESS
        .with_label_values(&[chain.as_str(), near_account_id.as_str()])
        .inc();
    let sign_latency_in_secs = crate::util::duration_between_unix(
        action.request.indexed.unix_timestamp_indexed,
        crate::util::current_unix_timestamp(),
    )
    .as_secs();
    crate::metrics::SIGN_TOTAL_LATENCY
        .with_label_values(&[chain.as_str(), near_account_id.as_str()])
        .observe(sign_latency_in_secs as f64);
    crate::metrics::SIGN_RESPOND_LATENCY
        .with_label_values(&[chain.as_str(), near_account_id.as_str()])
        .observe(timestamp.elapsed().as_secs_f64());
    if sign_latency_in_secs <= 30 {
        crate::metrics::NUM_SIGN_SUCCESS_30S
            .with_label_values(&[chain.as_str(), near_account_id.as_str()])
            .inc();
    }

    Ok(())
}
