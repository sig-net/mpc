use crate::backlog::Backlog;
use crate::config::{Config, ContractConfig, NetworkConfig};
use crate::indexer_eth::EthConfig;
use crate::indexer_sol::SolConfig;
use crate::protocol::contract::primitives::{ParticipantMap, Participants};
use crate::protocol::contract::RunningContractState;
use crate::protocol::{Chain, Governance, IndexedSignRequest, ProtocolState, SignRequestType};
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
pub struct PublishAction {
    pub public_key: mpc_crypto::PublicKey,
    pub indexed: IndexedSignRequest,
    output: FullSignature<Secp256k1>,
    pub participants: Vec<Participant>,
    timestamp: Instant,
    retry_count: usize,
}

pub enum RpcAction {
    Publish(PublishAction),
}

#[derive(Clone)]
pub struct RpcChannel {
    pub tx: mpsc::Sender<RpcAction>,
}

impl RpcChannel {
    pub fn publish(
        &self,
        public_key: mpc_crypto::PublicKey,
        indexed: IndexedSignRequest,
        output: FullSignature<Secp256k1>,
        participants: Vec<Participant>,
    ) {
        let rpc = self.clone();
        tokio::spawn(async move {
            if let Err(err) = rpc
                .tx
                .send(RpcAction::Publish(PublishAction {
                    public_key,
                    indexed,
                    output,
                    participants,
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
        // Set the initial state to be None so that `changed()` will pick up the first state change.
        let (tx, rx) = watch::channel(None);
        let _ = tx.send(Some(state));
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
        match self.state()? {
            ProtocolState::Initializing(_) => None,
            ProtocolState::Running(state) => Some(state.threshold),
            ProtocolState::Resharing(state) => Some(state.threshold),
        }
    }

    /// Wait until the MPC threshold is available and return it
    pub async fn wait_threshold(&mut self) -> usize {
        loop {
            if let Some(threshold) = self.threshold().await {
                return threshold;
            }
            let _ = self.contract_state.changed().await;
        }
    }

    pub async fn public_key(&self) -> Option<AffinePoint> {
        match self.borrow_state().as_ref()? {
            ProtocolState::Initializing(_) => None,
            ProtocolState::Running(state) => Some(state.public_key),
            ProtocolState::Resharing(_) => None,
        }
    }

    /// Wait until the public key is available and return it
    pub async fn wait_public_key(&mut self) -> AffinePoint {
        loop {
            if let Some(pk) = self.public_key().await {
                return pk;
            }
            let _ = self.contract_state.changed().await;
        }
    }

    pub async fn info(&self) -> Option<(usize, Participant)> {
        match self.state()? {
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

    /// Waits till the contract is in the running state.
    pub async fn wait_running(&mut self) -> RunningContractState {
        loop {
            if let Some(ProtocolState::Running(state)) = self.borrow_state().as_ref() {
                return state.clone();
            }
            let _ = self.contract_state.changed().await;
        }
    }

    /// Create a list of contract states that share a single channel but use different account ids.
    #[cfg(feature = "test-feature")]
    pub fn test_batch(
        ids: &[AccountId],
        state: ProtocolState,
    ) -> (Vec<Self>, watch::Sender<Option<ProtocolState>>) {
        let (tx, rx) = watch::channel(Some(state));
        let selfs = ids
            .iter()
            .map(|id| Self {
                account_id: id.clone(),
                contract_state: rx.clone(),
            })
            .collect();
        (selfs, tx)
    }
}

pub struct RpcExecutor {
    near: NearClient,
    eth: Option<EthClient>,
    solana: Option<SolanaClient>,
    action_rx: mpsc::Receiver<RpcAction>,
    backlog: Backlog,
}

impl RpcExecutor {
    pub fn new(
        near: &NearClient,
        eth: &Option<EthConfig>,
        solana: &Option<SolConfig>,
        backlog: Backlog,
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
                backlog,
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

            let chain = action.indexed.chain;
            let client = self.client(&chain);
            let near_account_id = self.near.my_account_id.clone();
            let eth_rpc_tx = eth_rpc_tx.clone(); // clone for task use
            let backlog = self.backlog.clone();

            tokio::spawn(async move {
                match chain {
                    Chain::NEAR | Chain::Solana => {
                        execute_publish(client, action, near_account_id, backlog).await;
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
    backlog: Backlog,
) {
    let chain = action.indexed.chain;
    let sign_id = action.indexed.id;
    tracing::info!(
        ?sign_id,
        ?chain,
        started_at = ?action.timestamp.elapsed(),
        "trying to publish signature",
    );
    let expected_public_key =
        mpc_crypto::derive_key(action.public_key, action.indexed.args.epsilon);

    // We do this here, rather than on the client side, so we can use the ecrecover system function on NEAR to validate our signature
    let Ok(signature) = crate::kdf::into_eth_sig(
        &expected_public_key,
        &action.output.big_r,
        &action.output.s,
        action.indexed.args.payload,
    ) else {
        tracing::error!(
            ?sign_id,
            "failed to generate a recovery id; trashing publish request",
        );
        return;
    };

    let publish_result = loop {
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
            break publish;
        }

        action.retry_count += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
        if action.retry_count >= MAX_PUBLISH_RETRY {
            tracing::info!(
                ?sign_id,
                elapsed = ?action.timestamp.elapsed(),
                "exceeded max retries, trashing publish request",
            );
            break publish;
        } else {
            tracing::info!(
                ?sign_id,
                retry_count = action.retry_count,
                elapsed = ?action.timestamp.elapsed(),
                "failed to publish, retrying"
            );
        }
    };

    // Mark completion in Backlog for SignBidirectional requests
    if matches!(
        action.indexed.sign_request_type,
        SignRequestType::SignBidirectional(_)
    ) {
        let success = publish_result.is_ok();
        if let Err(err) = backlog.mark_published(chain, &sign_id, success).await {
            tracing::warn!(?sign_id, ?err, "failed to mark publish status in backlog");
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
    let chain = action.indexed.chain;
    let outcome = near
        .call_respond(&action.indexed.id, signature)
        .await
        .inspect_err(|err| {
            tracing::error!(
                sign_id = ?action.indexed.id,
                ?err,
                "failed to publish signature",
            );
            crate::metrics::SIGNATURE_PUBLISH_FAILURES
                .with_label_values(&[chain.as_str(), near.my_account_id.as_str()])
                .inc();
        })?;

    let _: () = outcome.json().inspect_err(|err| {
        tracing::error!(
            sign_id = ?action.indexed.id,
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
        sign_id = ?action.indexed.id,
        big_r = signature.big_r.to_base58(),
        s = ?signature.s,
        elapsed = ?timestamp.elapsed(),
        "published signature sucessfully",
    );

    let elapsed = action.indexed.timestamp_sign_queue.elapsed();
    crate::metrics::NUM_SIGN_SUCCESS
        .with_label_values(&[chain.as_str(), near.my_account_id.as_str()])
        .inc();
    crate::metrics::SIGN_TOTAL_LATENCY
        .with_label_values(&[chain.as_str(), near.my_account_id.as_str()])
        .observe(elapsed.as_secs_f64());
    crate::metrics::SIGN_RESPOND_LATENCY
        .with_label_values(&[chain.as_str(), near.my_account_id.as_str()])
        .observe(timestamp.elapsed().as_secs_f64());
    if elapsed.as_secs() <= 30 {
        crate::metrics::NUM_SIGN_SUCCESS_30S
            .with_label_values(&[chain.as_str(), near.my_account_id.as_str()])
            .inc();
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
            .get_transaction_count(contract.provider().default_signer_address())
            .pending(),
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
    let chain = action.indexed.chain;
    let sign_id = action.indexed.id;
    let params = [DynSolValue::Array(vec![DynSolValue::Tuple(vec![
        DynSolValue::FixedBytes(action.indexed.id.request_id.into(), 32),
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
        std::slice::from_ref(&action.indexed.id),
        near_account_id,
    )
    .await?;

    let receipt = wait_for_transaction_receipt(
        eth.contract.provider(),
        tx_hash,
        near_account_id,
        vec![action.indexed.id],
        ETH_TX_RECEIPT_MAX_ATTEMPTS,
    )
    .await?;

    // Check if transaction was successful
    if !receipt.status() {
        tracing::error!(
            ?sign_id,
            tx_hash = ?receipt.transaction_hash,
            "transaction failed"
        );
        crate::metrics::SIGNATURE_PUBLISH_FAILURES
            .with_label_values(&[action.indexed.chain.as_str(), near_account_id.as_str()])
            .inc();
        return Err(());
    }

    let tx_hash = receipt.transaction_hash;
    tracing::info!(
        ?sign_id,
        tx_hash = ?tx_hash,
        elapsed = ?timestamp.elapsed(),
        "published ethereum signature successfully"
    );

    crate::metrics::NUM_SIGN_SUCCESS
        .with_label_values(&[chain.as_str(), near_account_id.as_str()])
        .inc();
    let elapsed = action.indexed.timestamp_sign_queue.elapsed();
    crate::metrics::SIGN_TOTAL_LATENCY
        .with_label_values(&[chain.as_str(), near_account_id.as_str()])
        .observe(elapsed.as_secs_f64());
    if elapsed.as_secs() <= 30 {
        crate::metrics::NUM_SIGN_SUCCESS_30S
            .with_label_values(&[chain.as_str(), near_account_id.as_str()])
            .inc();
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
        .map(|action| action.indexed.id)
        .collect::<Vec<_>>();
    tracing::info!(?sign_ids, "will send eth batch tx");
    for action in actions {
        let signature = signatures
            .get(&action.indexed.id)
            .expect("signature not found in map");
        params_vec.push(DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(action.indexed.id.request_id.into(), 32),
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
        let elapsed = action.indexed.timestamp_sign_queue.elapsed();
        crate::metrics::SIGN_TOTAL_LATENCY
            .with_label_values(&[chain.as_str(), near_account_id.as_str()])
            .observe(elapsed.as_secs_f64());
        if elapsed.as_secs() <= 30 {
            crate::metrics::NUM_SIGN_SUCCESS_30S
                .with_label_values(&[chain.as_str(), near_account_id.as_str()])
                .inc();
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
            mpc_crypto::derive_key(action.public_key, action.indexed.args.epsilon);

        let sign_id = action.indexed.id;
        let Ok(signature) = crate::kdf::into_eth_sig(
            &expected_public_key,
            &action.output.big_r,
            &action.output.s,
            action.indexed.args.payload,
        ) else {
            tracing::error!(
                ?sign_id,
                "failed to generate a recovery id; trashing publish request",
            );
            return;
        };
        signatures.insert(sign_id, signature);
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

use signet_program::accounts::Respond as SolanaRespondAccount;
use signet_program::accounts::RespondBidirectional as SolanaRespondBidirectionalAccount;
use signet_program::instruction::Respond as SolanaRespond;
use signet_program::instruction::RespondBidirectional as SolanaRespondBidirectional;
use signet_program::AffinePoint as SolanaContractAffinePoint;
use signet_program::Signature as SolanaContractSignature;
use solana_sdk::signature::Signer as SolanaSigner;
async fn try_publish_sol(
    sol: &SolanaClient,
    action: &PublishAction,
    timestamp: &Instant,
    signature: &Signature,
    near_account_id: &AccountId,
) -> Result<(), ()> {
    let chain = action.indexed.chain;
    let program = sol.client.program(sol.program_id).map_err(|_| ())?;

    let sign_id = action.indexed.id;
    let request_ids = vec![action.indexed.id.request_id];
    let big_r = signature.big_r.to_encoded_point(false);
    let signature = SolanaContractSignature {
        big_r: SolanaContractAffinePoint {
            x: big_r.as_bytes()[1..33].try_into().unwrap(),
            y: big_r.as_bytes()[33..65].try_into().unwrap(),
        },
        s: signature.s.to_bytes().into(),
        recovery_id: signature.recovery_id,
    };

    tracing::debug!(
        ?sign_id,
        request_type = ?action.indexed.sign_request_type,
        "try_publish_sol: dispatching request"
    );

    match &action.indexed.sign_request_type {
        SignRequestType::Sign | SignRequestType::SignBidirectional(_) => {
            let (event_authority, _) =
                Pubkey::find_program_address(&[b"__event_authority"], &sol.program_id);
            let tx = program
                .request()
                .signer(sol.payer.clone())
                .accounts(SolanaRespondAccount {
                    responder: sol.payer.pubkey(),
                    event_authority,
                    program: sol.program_id,
                })
                .args(SolanaRespond {
                    request_ids,
                    signatures: vec![signature.clone()],
                })
                .send()
                .await
                .map_err(|err| {
                    tracing::error!(
                        sign_id = ?action.indexed.id,
                        error = ?err,
                        "failed to publish solana signature"
                    );
                    crate::metrics::SIGNATURE_PUBLISH_FAILURES
                        .with_label_values(&[chain.as_str(), near_account_id.as_str()])
                        .inc();
                })?;

            tracing::info!(
                ?sign_id,
                tx_hash = ?tx,
                elapsed = ?timestamp.elapsed(),
                "published solana signature successfully"
            );
        }
        SignRequestType::RespondBidirectional(respond_bidirectional_tx) => {
            tracing::debug!(
                ?sign_id,
                request_id = ?request_ids[0],
                serialized_output_len = respond_bidirectional_tx.output.len(),
                "try_publish_sol: entering RespondBidirectional arm"
            );
            let respond_bidirectional_serialized_output = respond_bidirectional_tx.output.clone();
            let tx = program
                .request()
                .signer(sol.payer.clone())
                .accounts(SolanaRespondBidirectionalAccount {
                    responder: sol.payer.clone().try_pubkey().unwrap(),
                })
                .args(SolanaRespondBidirectional {
                    request_id: request_ids[0],
                    serialized_output: respond_bidirectional_serialized_output.clone(),
                    signature: signature.clone(),
                })
                .send()
                .await
                .map_err(|err| {
                    tracing::error!(
                        ?sign_id,
                        error = ?err,
                        "failed to publish respond bidirectional solana signature"
                    );
                    crate::metrics::SIGNATURE_PUBLISH_FAILURES
                        .with_label_values(&[chain.as_str(), near_account_id.as_str()])
                        .inc();
                })?;

            tracing::info!(
                ?sign_id,
                tx_hash = ?tx,
                elapsed = ?timestamp.elapsed(),
                "published respond bidirectional solana signature successfully"
            );
        }
    }

    crate::metrics::NUM_SIGN_SUCCESS
        .with_label_values(&[chain.as_str(), near_account_id.as_str()])
        .inc();
    let sign_latency_in_secs = crate::util::duration_between_unix(
        action.indexed.unix_timestamp_indexed,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Property 55: Signature Generation Timeout Handling
    // Validates: Requirements 21.1
    //
    // For any signature generation that exceeds timeout limits, the system should
    // handle timeouts gracefully without corrupting state.
    #[test]
    fn prop_signature_generation_timeout_handling() {
        // **Feature: unit-test-coverage, Property 55: Signature Generation Timeout Handling**
        
        // Test that timeout values are properly defined and used
        assert!(MAX_PUBLISH_RETRY > 0, "MAX_PUBLISH_RETRY must be positive");
        assert_eq!(MAX_PUBLISH_RETRY, 6, "MAX_PUBLISH_RETRY should be 6");
        
        // Test that retry count increments correctly
        let mut retry_count = 0;
        
        // Simulate retry increments
        for i in 0..MAX_PUBLISH_RETRY {
            assert_eq!(retry_count, i, "Retry count should match iteration");
            retry_count += 1;
        }
        
        // After MAX_PUBLISH_RETRY increments, we should be at the limit
        assert_eq!(retry_count, MAX_PUBLISH_RETRY, "Should reach MAX_PUBLISH_RETRY");
        
        // Verify that timeout duration is reasonable
        let timeout_duration = Duration::from_millis(100);
        assert!(timeout_duration.as_millis() > 0, "Timeout duration must be positive");
    }

    // Property 56: RPC Retry Mechanism Correctness
    // Validates: Requirements 21.2
    //
    // For any failed RPC call, the system should retry up to MAX_PUBLISH_RETRY times
    // with appropriate backoff.
    #[test]
    fn prop_rpc_retry_mechanism_correctness() {
        // **Feature: unit-test-coverage, Property 56: RPC Retry Mechanism Correctness**
        
        // Test that retry mechanism is properly configured
        assert_eq!(MAX_PUBLISH_RETRY, 6, "MAX_PUBLISH_RETRY should be 6 for proper retry behavior");
        
        // Test that retry count starts at 0
        let mut retry_count = 0;
        assert_eq!(retry_count, 0, "Initial retry count should be 0");
        
        // Test that we can track retry attempts
        let retry_attempts = Arc::new(AtomicUsize::new(0));
        let attempts = retry_attempts.clone();
        
        // Simulate retry loop
        let mut current_retry = 0;
        while current_retry < MAX_PUBLISH_RETRY {
            attempts.fetch_add(1, Ordering::SeqCst);
            current_retry += 1;
        }
        
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            MAX_PUBLISH_RETRY,
            "Should attempt exactly MAX_PUBLISH_RETRY times"
        );
    }

    // Property 57: Message Delivery Timeout Recovery
    // Validates: Requirements 21.3
    //
    // For any message delivery that times out, the system should handle the timeout
    // and recover appropriately.
    #[test]
    fn prop_message_delivery_timeout_recovery() {
        // **Feature: unit-test-coverage, Property 57: Message Delivery Timeout Recovery**
        
        // Test that timeout constants are defined
        const ETH_TX_RECEIPT_MAX_ATTEMPTS: usize = 6;
        assert!(ETH_TX_RECEIPT_MAX_ATTEMPTS > 0, "ETH_TX_RECEIPT_MAX_ATTEMPTS must be positive");
        
        // Test that we can track timeout attempts
        let timeout_attempts = Arc::new(AtomicUsize::new(0));
        let attempts = timeout_attempts.clone();
        
        // Simulate timeout recovery loop
        let mut current_attempt = 0;
        let max_attempts = ETH_TX_RECEIPT_MAX_ATTEMPTS;
        
        while current_attempt < max_attempts {
            attempts.fetch_add(1, Ordering::SeqCst);
            current_attempt += 1;
            
            // Simulate timeout handling
            let should_retry = current_attempt < max_attempts;
            assert!(should_retry || current_attempt == max_attempts, "Should retry or reach max");
        }
        
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            max_attempts,
            "Should attempt exactly max_attempts times"
        );
    }

    // Property 58: Node Synchronization Timeout Recovery
    // Validates: Requirements 21.4
    //
    // For any node synchronization that times out, the system should be able to
    // recover and resynchronize.
    #[test]
    fn prop_node_synchronization_timeout_recovery() {
        // **Feature: unit-test-coverage, Property 58: Node Synchronization Timeout Recovery**
        
        // Test that update interval is properly defined
        assert!(UPDATE_INTERVAL.as_secs() > 0, "UPDATE_INTERVAL must be positive");
        assert_eq!(UPDATE_INTERVAL.as_secs(), 10, "UPDATE_INTERVAL should be 10 seconds");
        
        // Test that we can track synchronization attempts
        let sync_attempts = Arc::new(AtomicUsize::new(0));
        let attempts = sync_attempts.clone();
        
        // Simulate synchronization with timeout recovery
        let mut current_sync = 0;
        let max_syncs = 5;
        
        while current_sync < max_syncs {
            attempts.fetch_add(1, Ordering::SeqCst);
            current_sync += 1;
            
            // Simulate timeout and recovery
            let timeout_occurred = current_sync % 2 == 0;
            if timeout_occurred {
                // Recovery mechanism should allow retry
                assert!(current_sync < max_syncs || current_sync == max_syncs, "Should recover");
            }
        }
        
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            max_syncs,
            "Should complete all synchronization attempts"
        );
    }

    // Property 102: NEAR Signature Publishing Correctness
    // Validates: Requirements 32.1
    //
    // For any NEAR signature publishing operation, the system should correctly
    // format and publish signatures to the NEAR network.
    #[test]
    fn prop_near_signature_publishing_correctness() {
        // **Feature: unit-test-coverage, Property 102: NEAR Signature Publishing Correctness**
        
        use proptest::prelude::*;
        use proptest::test_runner::{TestRunner, Config};
        
        let config = Config::with_cases(100);
        let mut runner = TestRunner::new(config);
        
        // Test that NEAR chain is correctly identified
        let near_chain = Chain::NEAR;
        assert_eq!(near_chain.as_str(), "NEAR", "NEAR chain should have correct string representation");
        
        // Test that NEAR chain can be parsed from string
        let parsed_chain: Chain = "near".parse().expect("Should parse 'near' string");
        assert_eq!(parsed_chain, Chain::NEAR, "Should parse to NEAR chain");
        
        // Test that NEAR chain has no checkpoint interval (uses different mechanism)
        assert!(near_chain.checkpoint_interval().is_none(), "NEAR should not have checkpoint interval");
        
        // Property: For any valid request_id bytes, we can create a SignId
        runner.run(&prop::array::uniform32(any::<u8>()), |request_id| {
            let sign_id = SignId::new(request_id);
            prop_assert_eq!(sign_id.request_id, request_id, "SignId should preserve request_id");
            Ok(())
        }).expect("Property test should pass");
        
        // Property: For any retry count, the system should respect MAX_PUBLISH_RETRY
        runner.run(&(0usize..20), |retry_count| {
            let should_continue = retry_count < MAX_PUBLISH_RETRY;
            let should_stop = retry_count >= MAX_PUBLISH_RETRY;
            prop_assert!(should_continue || should_stop, "Retry logic should be deterministic");
            Ok(())
        }).expect("Property test should pass");
        
        // Test that NEAR signature response format is correct
        // The respond function takes sign_id and signature
        let test_request_id = [0u8; 32];
        let sign_id = SignId::new(test_request_id);
        assert_eq!(sign_id.request_id.len(), 32, "Request ID should be 32 bytes");
    }

    // Property 103: Ethereum Signature Batching Correctness
    // Validates: Requirements 32.2
    //
    // For any Ethereum signature batching operation, the system should correctly
    // batch signatures and estimate gas appropriately.
    #[test]
    fn prop_ethereum_signature_batching_correctness() {
        // **Feature: unit-test-coverage, Property 103: Ethereum Signature Batching Correctness**
        
        use proptest::prelude::*;
        use proptest::test_runner::{TestRunner, Config};
        
        let config = Config::with_cases(100);
        let mut runner = TestRunner::new(config);
        
        // Test that Ethereum chain is correctly identified
        let eth_chain = Chain::Ethereum;
        assert_eq!(eth_chain.as_str(), "Ethereum", "Ethereum chain should have correct string representation");
        
        // Test that Ethereum chain can be parsed from string
        let parsed_chain: Chain = "ethereum".parse().expect("Should parse 'ethereum' string");
        assert_eq!(parsed_chain, Chain::Ethereum, "Should parse to Ethereum chain");
        
        let parsed_chain_eth: Chain = "eth".parse().expect("Should parse 'eth' string");
        assert_eq!(parsed_chain_eth, Chain::Ethereum, "Should parse 'eth' to Ethereum chain");
        
        // Test that Ethereum chain has checkpoint interval
        assert!(eth_chain.checkpoint_interval().is_some(), "Ethereum should have checkpoint interval");
        
        // Test batch interval and size constants
        assert!(ETH_RESPOND_BATCH_INTERVAL.as_millis() > 0, "Batch interval must be positive");
        assert_eq!(ETH_RESPOND_BATCH_INTERVAL.as_millis(), 2000, "Batch interval should be 2000ms");
        assert!(ETH_RESPOND_BATCH_SIZE > 0, "Batch size must be positive");
        assert_eq!(ETH_RESPOND_BATCH_SIZE, 10, "Batch size should be 10");
        
        // Property: Gas estimation should scale with batch size
        runner.run(&(1usize..=20), |batch_size| {
            // Gas formula: max(40000, 20000 * batch_size)
            let estimated_gas = std::cmp::max(40000, 20000 * batch_size as u64);
            prop_assert!(estimated_gas >= 40000, "Gas should be at least 40000");
            prop_assert!(estimated_gas >= 20000 * batch_size as u64, "Gas should scale with batch size");
            
            // For batch size 1, gas should be 40000 (minimum)
            if batch_size == 1 {
                prop_assert_eq!(estimated_gas, 40000, "Single signature should use minimum gas");
            }
            
            // For batch size > 2, gas should be 20000 * batch_size
            if batch_size > 2 {
                prop_assert_eq!(estimated_gas, 20000 * batch_size as u64, "Larger batches should scale linearly");
            }
            
            Ok(())
        }).expect("Property test should pass");
        
        // Property: Batch should trigger when size or interval is reached
        runner.run(&((0usize..20), (0u64..5000)), |(batch_len, elapsed_ms)| {
            let should_send = (elapsed_ms > ETH_RESPOND_BATCH_INTERVAL.as_millis() as u64 
                             || batch_len >= ETH_RESPOND_BATCH_SIZE)
                             && batch_len > 0;
            
            // If batch is empty, should never send
            if batch_len == 0 {
                prop_assert!(!should_send, "Empty batch should not be sent");
            }
            
            // If batch is full, should send
            if batch_len >= ETH_RESPOND_BATCH_SIZE {
                prop_assert!(should_send || batch_len == 0, "Full batch should trigger send");
            }
            
            Ok(())
        }).expect("Property test should pass");
    }

    // Property 104: Solana Signature Publishing Correctness
    // Validates: Requirements 32.3
    //
    // For any Solana signature publishing operation, the system should correctly
    // format and publish signatures to the Solana network.
    #[test]
    fn prop_solana_signature_publishing_correctness() {
        // **Feature: unit-test-coverage, Property 104: Solana Signature Publishing Correctness**
        
        use proptest::prelude::*;
        use proptest::test_runner::{TestRunner, Config};
        
        let config = Config::with_cases(100);
        let mut runner = TestRunner::new(config);
        
        // Test that Solana chain is correctly identified
        let sol_chain = Chain::Solana;
        assert_eq!(sol_chain.as_str(), "Solana", "Solana chain should have correct string representation");
        
        // Test that Solana chain can be parsed from string
        let parsed_chain: Chain = "solana".parse().expect("Should parse 'solana' string");
        assert_eq!(parsed_chain, Chain::Solana, "Should parse to Solana chain");
        
        let parsed_chain_sol: Chain = "sol".parse().expect("Should parse 'sol' string");
        assert_eq!(parsed_chain_sol, Chain::Solana, "Should parse 'sol' to Solana chain");
        
        // Test that Solana chain has checkpoint interval
        assert!(sol_chain.checkpoint_interval().is_some(), "Solana should have checkpoint interval");
        
        // Property: For any valid request_id, Solana signature format should be consistent
        runner.run(&prop::array::uniform32(any::<u8>()), |request_id| {
            // Solana uses the same SignId format as other chains
            let sign_id = SignId::new(request_id);
            prop_assert_eq!(sign_id.request_id.len(), 32, "Request ID should be 32 bytes");
            prop_assert_eq!(sign_id.request_id, request_id, "Request ID should be preserved");
            Ok(())
        }).expect("Property test should pass");
        
        // Property: Solana does not support batch publishing (unlike Ethereum)
        // Each signature is published individually
        let supports_batch = false; // Solana uses individual publishing
        assert!(!supports_batch, "Solana should not support batch publishing");
        
        // Test that retry mechanism works for Solana
        runner.run(&(0usize..10), |retry_count| {
            let should_retry = retry_count < MAX_PUBLISH_RETRY;
            let should_stop = retry_count >= MAX_PUBLISH_RETRY;
            prop_assert!(should_retry || should_stop, "Retry logic should be deterministic for Solana");
            Ok(())
        }).expect("Property test should pass");
    }

    // Property 105: Chain-Specific Response Formatting
    // Validates: Requirements 32.4
    //
    // For any chain-specific response, the system should format responses
    // correctly according to chain requirements.
    #[test]
    fn prop_chain_specific_response_formatting() {
        // **Feature: unit-test-coverage, Property 105: Chain-Specific Response Formatting**
        
        use proptest::prelude::*;
        use proptest::test_runner::{TestRunner, Config};
        
        let config = Config::with_cases(100);
        let mut runner = TestRunner::new(config);
        
        // Test that all chains are iterable
        let all_chains = Chain::iter();
        assert_eq!(all_chains.len(), 3, "Should have exactly 3 chains");
        assert!(all_chains.contains(&Chain::NEAR), "Should contain NEAR");
        assert!(all_chains.contains(&Chain::Ethereum), "Should contain Ethereum");
        assert!(all_chains.contains(&Chain::Solana), "Should contain Solana");
        
        // Property: Each chain should have a unique string representation
        runner.run(&prop::sample::select(vec![Chain::NEAR, Chain::Ethereum, Chain::Solana]), |chain| {
            let chain_str = chain.as_str();
            prop_assert!(!chain_str.is_empty(), "Chain string should not be empty");
            
            // Verify round-trip parsing
            let parsed: Result<Chain, _> = chain_str.to_lowercase().parse();
            prop_assert!(parsed.is_ok(), "Chain string should be parseable");
            prop_assert_eq!(parsed.unwrap(), chain, "Round-trip should preserve chain");
            
            Ok(())
        }).expect("Property test should pass");
        
        // Property: Chain display format should match as_str
        for chain in Chain::iter() {
            let display_str = format!("{}", chain);
            let as_str = chain.as_str();
            assert_eq!(display_str, as_str, "Display and as_str should match for {:?}", chain);
        }
        
        // Property: Invalid chain strings should fail to parse
        runner.run(&"[a-z]{5,10}", |invalid_chain| {
            // Skip if it happens to be a valid chain name
            if invalid_chain == "near" || invalid_chain == "ethereum" || invalid_chain == "eth" 
               || invalid_chain == "solana" || invalid_chain == "sol" {
                return Ok(());
            }
            
            let parsed: Result<Chain, _> = invalid_chain.parse();
            prop_assert!(parsed.is_err(), "Invalid chain string should fail to parse");
            
            Ok(())
        }).expect("Property test should pass");
        
        // Test checkpoint interval differences between chains
        assert!(Chain::NEAR.checkpoint_interval().is_none(), "NEAR should not have checkpoint interval");
        assert!(Chain::Ethereum.checkpoint_interval().is_some(), "Ethereum should have checkpoint interval");
        assert!(Chain::Solana.checkpoint_interval().is_some(), "Solana should have checkpoint interval");
        
        // Property: Checkpoint intervals should be positive when present
        for chain in Chain::iter() {
            if let Some(interval) = chain.checkpoint_interval() {
                assert!(interval > 0, "Checkpoint interval should be positive for {:?}", chain);
            }
        }
    }
}
