use crate::config::{Config, ContractConfig, NetworkConfig};
use crate::indexer_eth::EthConfig;
use crate::indexer_sol::SolConfig;
use crate::metrics::requests::{record_request_latency_since, SignRequestStep};
use crate::protocol::contract::primitives::{ParticipantMap, Participants};
use crate::protocol::contract::RunningContractState;
use crate::protocol::{Chain, Governance, IndexedSignRequest, ProtocolState, SignKind};
use crate::util::AffinePointExt as _;
use std::collections::BTreeSet;

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

use crate::util::retry::{retry_async, Backoff, RetryConfig, RetryError, RetryReason};
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
use sp_core::{sr25519, Pair as _};
use sp_runtime::{
    traits::{IdentifyAccount, Verify},
    MultiSignature as SpMultiSignature,
};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use url::Url;

use crate::indexer_canton::ledger_api::{
    ActiveContractEntry, CumulativeFilter, EventFormat, GetActiveContractsRequest,
    IdentifierFilter, JsCommands, LedgerEndResponse, PartyFilter,
    SubmitAndWaitForTransactionRequest, SubmitAndWaitForTransactionResponse, TemplateFilterValue,
};
use crate::indexer_canton::{CantonAuthProvider, CantonConfig};
use crate::indexer_hydration::HydrationConfig;
use parity_scale_codec::{Decode, Encode};
use subxt::config::substrate::{
    AccountId32, BlakeTwo256, MultiSignature, SubstrateConfig, SubstrateExtrinsicParams,
    SubstrateHeader,
};
use subxt::tx::Payload;
use subxt::Config as SubxtConfig;
use subxt::OnlineClient;

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
    pub signature: Signature,
    pub participants: Vec<Participant>,
    pub timestamp: Instant,
}

impl PublishAction {
    pub fn new(
        public_key: mpc_crypto::PublicKey,
        indexed: IndexedSignRequest,
        output: FullSignature<Secp256k1>,
        participants: Vec<Participant>,
    ) -> Option<Self> {
        let expected_public_key = mpc_crypto::derive_key(public_key, indexed.args.epsilon);
        let signature = crate::kdf::into_signature(
            &expected_public_key,
            &output.big_r,
            &output.s,
            indexed.args.payload,
        )
        .ok()?;
        Some(Self {
            public_key,
            indexed,
            signature,
            participants,
            timestamp: Instant::now(),
        })
    }
}

pub enum RpcAction {
    Publish(PublishAction),
}

#[derive(Debug, Clone)]
pub struct GovernanceInfo {
    pub me: Participant,
    pub threshold: usize,
    pub epoch: u64,
    pub public_key: mpc_crypto::PublicKey,
    pub participants: BTreeSet<Participant>,
    pub is_running: bool,
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
        let sign_id = indexed.id;
        let Some(action) = PublishAction::new(public_key, indexed, output, participants) else {
            tracing::error!(
                ?sign_id,
                "failed to validate signature; trashing publish request",
            );
            return;
        };
        let rpc = self.clone();
        tokio::spawn(async move {
            if let Err(err) = rpc.tx.send(RpcAction::Publish(action)).await {
                tracing::error!(%err, "failed to send publish action");
            }
        });
    }

    pub fn publish_signature(
        &self,
        public_key: mpc_crypto::PublicKey,
        indexed: IndexedSignRequest,
        signature: Signature,
        participants: Vec<Participant>,
    ) {
        let rpc = self.clone();
        tokio::spawn(async move {
            if let Err(err) = rpc
                .tx
                .send(RpcAction::Publish(PublishAction {
                    public_key,
                    indexed,
                    signature,
                    participants,
                    timestamp: Instant::now(),
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

    pub fn governance(&self) -> Option<GovernanceInfo> {
        self.state()?.governance(&self.account_id)
    }

    pub async fn wait_governance(&mut self) -> GovernanceInfo {
        loop {
            if let Some(governance) = self.governance() {
                return governance;
            }
            let _ = self.contract_state.changed().await;
        }
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
    hydration: Option<HydrationClient>,
    canton: Option<CantonClient>,
    action_rx: mpsc::Receiver<RpcAction>,
}

impl RpcExecutor {
    pub async fn new(
        near: &NearClient,
        eth: &Option<EthConfig>,
        solana: &Option<SolConfig>,
        hydration: &Option<HydrationConfig>,
        canton: &Option<CantonConfig>,
    ) -> (RpcChannel, Self) {
        let eth = eth.as_ref().map(EthClient::new);
        let solana = solana.as_ref().map(SolanaClient::new);
        let hydration = match hydration {
            Some(h) => match HydrationClient::new(h).await {
                Ok(client) => Some(client),
                Err(e) => {
                    tracing::error!(%e, "failed to create hydration client");
                    None
                }
            },
            None => None,
        };
        let canton = match canton {
            Some(c) => match CantonClient::new(c).await {
                Ok(client) => Some(client),
                Err(e) => {
                    tracing::error!(%e, "failed to create canton client");
                    None
                }
            },
            None => None,
        };
        let (tx, rx) = mpsc::channel(MAX_CONCURRENT_RPC_REQUESTS);
        (
            RpcChannel { tx },
            Self {
                near: near.clone(),
                eth,
                solana,
                hydration,
                canton,
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
        let (eth_rpc_tx, eth_rpc_rx) = mpsc::channel(MAX_CONCURRENT_RPC_REQUESTS);
        // spin up update task for batch sending eth responses
        tokio::spawn({
            run_batch_respond(
                eth_client,
                eth_rpc_rx,
                ETH_RESPOND_BATCH_INTERVAL,
                ETH_RESPOND_BATCH_SIZE,
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
            let eth_rpc_tx = eth_rpc_tx.clone(); // clone for task use

            tokio::spawn(async move {
                match chain {
                    Chain::NEAR | Chain::Solana | Chain::Hydration | Chain::Canton => {
                        execute_publish(client, action).await;
                    }
                    Chain::Ethereum => {
                        if let Err(err) = eth_rpc_tx.send(action).await {
                            tracing::error!(%err, "eth: failed to send publish action");
                        }
                    }
                    Chain::Bitcoin => {
                        tracing::warn!(
                            ?chain,
                            "publish not supported for Bitcoin yet, dropping action"
                        );
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
            Chain::Hydration => {
                if let Some(hydration) = &self.hydration {
                    ChainClient::Hydration(hydration.clone())
                } else {
                    ChainClient::Err("no hydration client available for node")
                }
            }
            Chain::Canton => {
                if let Some(canton) = &self.canton {
                    ChainClient::Canton(canton.clone())
                } else {
                    ChainClient::Err("no canton client available for node")
                }
            }
            Chain::Bitcoin => ChainClient::Err("no bitcoin client available for node"),
        }
    }
}

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

enum HydradxConfig {}

impl SubxtConfig for HydradxConfig {
    type AccountId = <SubstrateConfig as SubxtConfig>::AccountId;
    type Address = <SubstrateConfig as SubxtConfig>::AccountId;
    type Signature = <SubstrateConfig as SubxtConfig>::Signature;
    type Hasher = BlakeTwo256;
    type Header = SubstrateHeader<u32, BlakeTwo256>;
    type ExtrinsicParams = SubstrateExtrinsicParams<Self>;
    type AssetId = <SubstrateConfig as SubxtConfig>::AssetId;
}

#[derive(Clone)]
struct HydrationSigner {
    account_id: AccountId32,
    signer: sr25519::Pair,
}

impl HydrationSigner {
    fn from_uri(uri: &str) -> anyhow::Result<Self> {
        let signer = sr25519::Pair::from_string(uri, None)?;
        let account_id = <SpMultiSignature as Verify>::Signer::from(signer.public()).into_account();

        Ok(Self {
            account_id: AccountId32(account_id.into()),
            signer,
        })
    }
}

impl subxt::tx::Signer<HydradxConfig> for HydrationSigner {
    fn account_id(&self) -> <HydradxConfig as SubxtConfig>::AccountId {
        self.account_id.clone()
    }

    fn sign(&self, signer_payload: &[u8]) -> <HydradxConfig as SubxtConfig>::Signature {
        MultiSignature::Sr25519(self.signer.sign(signer_payload).0)
    }
}

#[derive(Clone)]
pub struct HydrationClient {
    api: OnlineClient<HydradxConfig>,
    signer: HydrationSigner,
}

const PALLET_SIGNET: &str = "Signet";

/// This type mirrors the on-chain representation of an affine point
#[derive(Clone, Debug, Encode, Decode)]
struct HydrationAffinePoint {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// This type mirrors the on-chain signature format
#[derive(Clone, Debug, Encode, Decode)]
struct HydrationSignature {
    pub big_r: HydrationAffinePoint,
    pub s: [u8; 32],
    pub recovery_id: u8,
}

/// A thin wrapper used to mirror the on-chain `BoundedVec` type for SCALE
/// encoding/decoding. This type does **not** enforce any length bounds; it
/// is effectively just a `Vec<T>` on the client side.
///
/// Callers are responsible for ensuring that the inner `Vec` length respects
/// the maximum length enforced by the on-chain pallet, otherwise the
/// resulting transaction may be rejected on-chain.
#[derive(Clone, Debug, Encode, Decode)]
struct BoundedVec<T>(pub Vec<T>);

/// this type is used to construct tx to call respond() on pallet
struct HydrationRespondTx {
    pub request_ids: BoundedVec<[u8; 32]>,
    pub signatures: BoundedVec<HydrationSignature>,
}

impl Payload for HydrationRespondTx {
    fn encode_call_data_to(
        &self,
        metadata: &subxt::Metadata,
        out: &mut Vec<u8>,
    ) -> std::result::Result<(), subxt::ext::subxt_core::Error> {
        let pallet = metadata.pallet_by_name(PALLET_SIGNET).ok_or_else(|| {
            subxt::ext::subxt_core::Error::Metadata(
                subxt::error::MetadataError::PalletNameNotFound(PALLET_SIGNET.to_string()),
            )
        })?;

        let respond_call_index = pallet
            .call_variant_by_name("respond")
            .ok_or_else(|| {
                subxt::ext::subxt_core::Error::Metadata(
                    subxt::error::MetadataError::CallNameNotFound("respond".to_string()),
                )
            })?
            .index;

        let pallet_index: u8 = pallet.index();

        out.push(pallet_index);
        out.push(respond_call_index);

        (&self.request_ids, &self.signatures).encode_to(out);
        Ok(())
    }
}

/// this type is used to construct tx to call respond_bidirectional() on pallet
struct HydrationRespondBidirectionalTx {
    pub request_id: [u8; 32],
    pub serialized_output: BoundedVec<u8>,
    pub signature: HydrationSignature,
}

impl Payload for HydrationRespondBidirectionalTx {
    fn encode_call_data_to(
        &self,
        metadata: &subxt::Metadata,
        out: &mut Vec<u8>,
    ) -> std::result::Result<(), subxt::ext::subxt_core::Error> {
        let pallet = metadata.pallet_by_name(PALLET_SIGNET).ok_or_else(|| {
            subxt::ext::subxt_core::Error::Metadata(
                subxt::error::MetadataError::PalletNameNotFound(PALLET_SIGNET.to_string()),
            )
        })?;

        let pallet_index: u8 = pallet.index();

        let respond_bidirectional_call_index = pallet
            .call_variant_by_name("respond_bidirectional")
            .ok_or_else(|| {
                subxt::ext::subxt_core::Error::Metadata(
                    subxt::error::MetadataError::CallNameNotFound(
                        "respond_bidirectional".to_string(),
                    ),
                )
            })?
            .index;

        out.push(pallet_index);
        out.push(respond_bidirectional_call_index);

        // respond_bidirectional(origin, request_id, serialized_output, signature)
        (&self.request_id, &self.serialized_output, &self.signature).encode_to(out);
        Ok(())
    }
}

impl HydrationClient {
    pub async fn new(config: &HydrationConfig) -> anyhow::Result<Self> {
        let api = OnlineClient::<HydradxConfig>::from_url(&config.rpc_ws_url).await?;
        let signer = HydrationSigner::from_uri(&config.signer_uri)?;
        Ok(Self { api, signer })
    }

    fn to_hydration_signature(sig: &Signature) -> anyhow::Result<HydrationSignature> {
        let enc = sig.big_r.to_encoded_point(false);

        let x: [u8; 32] = enc
            .x()
            .ok_or_else(|| anyhow::anyhow!("missing x"))?
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("x must be 32 bytes"))?;

        let y: [u8; 32] = enc
            .y()
            .ok_or_else(|| anyhow::anyhow!("missing y"))?
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("y must be 32 bytes"))?;

        let s: [u8; 32] = sig.s.to_bytes().into();

        Ok(HydrationSignature {
            big_r: HydrationAffinePoint { x, y },
            s,
            recovery_id: sig.recovery_id,
        })
    }

    async fn call_respond(&self, id: &SignId, response: &Signature) -> anyhow::Result<()> {
        let tx = HydrationRespondTx {
            request_ids: BoundedVec(vec![id.request_id]),
            signatures: BoundedVec(vec![Self::to_hydration_signature(response)?]),
        };

        let progress = self
            .api
            .tx()
            .sign_and_submit_then_watch_default(&tx, &self.signer)
            .await?;

        progress.wait_for_finalized_success().await?;
        Ok(())
    }

    async fn call_respond_bidirectional(
        &self,
        id: &SignId,
        serialized_output: Vec<u8>,
        response: &Signature,
    ) -> anyhow::Result<subxt::config::HashFor<HydradxConfig>> {
        let tx = HydrationRespondBidirectionalTx {
            request_id: id.request_id,
            serialized_output: BoundedVec(serialized_output),
            signature: Self::to_hydration_signature(response)?,
        };

        let progress = self
            .api
            .tx()
            .sign_and_submit_then_watch_default(&tx, &self.signer)
            .await?;

        let events = progress.wait_for_finalized_success().await?;
        Ok(events.extrinsic_hash())
    }
}

#[derive(Clone)]
pub struct CantonClient {
    pub(crate) config: CantonConfig,
    http_client: reqwest::Client,
    auth_provider: CantonAuthProvider,
}

impl std::fmt::Debug for CantonClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CantonClient")
            .field("config", &self.config)
            .field("auth_provider", &"<hidden>")
            .finish()
    }
}

impl CantonClient {
    pub async fn new(config: &CantonConfig) -> anyhow::Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let auth_provider = CantonAuthProvider::new(config.auth.clone())?;

        if !config.signer_contract_id.is_empty() || !config.signer_template_id.is_empty() {
            tracing::info!(
                signer_cid = %config.signer_contract_id,
                signer_template_id = %config.signer_template_id,
                "canton Signer contract configured"
            );
        }

        Ok(Self {
            config: config.clone(),
            http_client,
            auth_provider,
        })
    }

    pub fn ledger_api_user(&self) -> &str {
        &self.config.ledger_api_user
    }

    pub async fn bearer_token(&self) -> anyhow::Result<String> {
        self.auth_provider.bearer_token().await
    }

    fn json_api_endpoint(&self, path: &str) -> String {
        format!("{}{}", self.config.json_api_url, path)
    }

    pub async fn auth_post(&self, path: &str) -> anyhow::Result<reqwest::RequestBuilder> {
        let token = self.bearer_token().await?;
        Ok(self
            .http_client
            .post(self.json_api_endpoint(path))
            .bearer_auth(token))
    }

    pub async fn auth_get(&self, path: &str) -> anyhow::Result<reqwest::RequestBuilder> {
        let token = self.bearer_token().await?;
        Ok(self
            .http_client
            .get(self.json_api_endpoint(path))
            .bearer_auth(token))
    }

    pub async fn fetch_ledger_end(&self) -> anyhow::Result<u64> {
        let resp = self.auth_get("/v2/state/ledger-end").await?.send().await?;
        let resp = check_response(resp, "ledger-end").await?;
        let body: LedgerEndResponse = resp.json().await?;
        Ok(body.offset)
    }

    pub async fn fetch_active_contracts(
        &self,
        parties: &[&str],
        template_id: Option<&str>,
        include_blob: bool,
    ) -> anyhow::Result<Vec<ActiveContractEntry>> {
        let offset = self.fetch_ledger_end().await?;

        let mut filters = serde_json::Map::new();
        for party in parties {
            let value = match template_id {
                Some(tid) => serde_json::to_value(PartyFilter {
                    cumulative: vec![CumulativeFilter {
                        identifier_filter: IdentifierFilter::TemplateFilter {
                            value: TemplateFilterValue {
                                template_id: tid.to_string(),
                                include_created_event_blob: include_blob,
                            },
                        },
                    }],
                })?,
                None => serde_json::json!({}),
            };
            filters.insert(party.to_string(), value);
        }

        let req = GetActiveContractsRequest {
            active_at_offset: offset,
            event_format: EventFormat {
                filters_by_party: filters,
                verbose: true,
            },
        };

        let resp = self
            .auth_post("/v2/state/active-contracts")
            .await?
            .json(&req)
            .send()
            .await?;

        let resp = check_response(resp, "active-contracts query").await?;
        Ok(resp.json().await?)
    }

    pub async fn submit_and_wait(
        &self,
        commands: JsCommands,
        context: &str,
    ) -> anyhow::Result<SubmitAndWaitForTransactionResponse> {
        let resp = self
            .auth_post("/v2/commands/submit-and-wait-for-transaction")
            .await?
            .json(&SubmitAndWaitForTransactionRequest { commands })
            .send()
            .await?;
        let resp = check_response(resp, context).await?;
        Ok(resp.json().await?)
    }

    pub async fn exercise_choice(
        &self,
        command_id: &str,
        choice: &str,
        choice_argument: serde_json::Value,
    ) -> anyhow::Result<()> {
        use crate::indexer_canton::ledger_api::{Command, JsCommands};
        let commands = JsCommands {
            command_id: command_id.to_string(),
            user_id: self.config.ledger_api_user.clone(),
            act_as: vec![self.config.party_id.clone()],
            read_as: vec![self.config.party_id.clone()],
            commands: vec![Command::ExerciseCommand {
                template_id: self.config.signer_template_id.clone(),
                contract_id: self.config.signer_contract_id.clone(),
                choice: choice.to_string(),
                choice_argument,
            }],
            disclosed_contracts: vec![],
        };
        self.submit_and_wait(commands, &format!("canton {choice}"))
            .await?;
        Ok(())
    }
}

async fn check_response(
    resp: reqwest::Response,
    context: &str,
) -> anyhow::Result<reqwest::Response> {
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("{context} failed: {status} {text}");
    }
    Ok(resp)
}

/// Client related to a specific chain
#[allow(clippy::large_enum_variant)]
pub enum ChainClient {
    Err(&'static str),
    Near(NearClient),
    Ethereum(EthClient),
    Solana(SolanaClient),
    Hydration(HydrationClient),
    Canton(CantonClient),
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
async fn execute_publish(client: ChainClient, action: PublishAction) {
    let chain = action.indexed.chain;
    let sign_id = action.indexed.id;

    tracing::info!(
        ?sign_id,
        ?chain,
        started_at = ?action.timestamp.elapsed(),
        "trying to publish signature",
    );

    let retry_cfg = RetryConfig {
        max_attempts: MAX_PUBLISH_RETRY,
        per_attempt_timeout: Duration::from_secs(120),
        backoff: Backoff::Fixed(Duration::from_secs(5)),
    };

    let publish_res: Result<(), RetryError<()>> = retry_async(
        retry_cfg,
        |_attempt| async {
            match &client {
                ChainClient::Near(near) => {
                    try_publish_near(near, &action, &action.timestamp, &action.signature)
                        .await
                        .map_err(|_| ())
                }
                ChainClient::Ethereum(eth) => {
                    try_publish_eth(eth, &action, &action.timestamp, &action.signature).await
                }
                ChainClient::Solana(sol) => {
                    try_publish_sol(sol, &action, &action.timestamp, &action.signature)
                        .await
                        .map_err(|_| ())
                }
                ChainClient::Hydration(hyd) => {
                    try_publish_hydration(hyd, &action, &action.timestamp, &action.signature)
                        .await
                        .map_err(|_| ())
                }
                ChainClient::Canton(canton) => {
                    try_publish_canton(canton, &action, &action.timestamp, &action.signature)
                        .await
                        .map_err(|_| ())
                }
                ChainClient::Err(msg) => {
                    tracing::error!(msg, "no client for chain");
                    Ok(())
                }
            }
        },
        |_attempt, _reason| true,
        |attempt, reason, sleep| match reason {
            RetryReason::Error(_) => {
                tracing::warn!(
                    ?sign_id,
                    retry_count = attempt.saturating_sub(1),
                    elapsed = ?action.timestamp.elapsed(),
                    chain = ?action.indexed.chain,
                    "failed to publish, retrying in {sleep:?}"
                );
            }
            RetryReason::Timeout(t) => {
                tracing::warn!(
                    ?sign_id,
                    retry_count = attempt.saturating_sub(1),
                    elapsed = ?action.timestamp.elapsed(),
                    chain = ?action.indexed.chain,
                    "publish timed out after {t:?}, retrying in {sleep:?}"
                );
            }
        },
    )
    .await;

    let publish_ok = publish_res.is_ok();

    if publish_ok {
        let elapsed_secs =
            crate::util::unix_elapsed(action.indexed.unix_timestamp_indexed).as_secs();
        if elapsed_secs <= chain.expected_response_time_secs() {
            record_request_latency_since(
                chain,
                SignRequestStep::Total,
                "in_time",
                action.indexed.unix_timestamp_indexed,
            );
        } else {
            record_request_latency_since(
                chain,
                SignRequestStep::Total,
                "expired",
                action.indexed.unix_timestamp_indexed,
            );
        }
        record_request_latency_since(chain, SignRequestStep::Responding, "ok", action.timestamp);
    } else {
        tracing::info!(
            ?sign_id,
            elapsed = ?action.timestamp.elapsed(),
            "exceeded max retries, trashing publish request"
        );
    }
}

async fn run_batch_respond(
    client: ChainClient,
    mut actions_rx: mpsc::Receiver<PublishAction>,
    batch_interval: Duration,
    batch_size: usize,
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
            execute_batch_publish(&client, &mut actions_batch).await;
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
    let outcome = near
        .call_respond(&action.indexed.id, signature)
        .await
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

#[derive(Debug)]
enum PollErr {
    NotReady,
    Rpc(anyhow::Error),
}

// wait for transaction receipt with max_attempts and exponential delay backoff starting at 5s
async fn wait_for_pending_tx(
    provider: &EthContractFillProvider,
    tx_hash: alloy::primitives::B256,
    sign_ids: Vec<SignId>,
    max_attempts: usize,
) -> Result<Transaction, ()> {
    let sign_ids_ref = &sign_ids;

    let cfg = RetryConfig {
        max_attempts,
        per_attempt_timeout: Duration::from_secs(5),
        backoff: Backoff::ExponentialJitter {
            base: Duration::from_secs(1),
            cap: Duration::from_secs(10),
            jitter_max_ms: 0,
        },
    };

    let res: Result<Transaction, RetryError<PollErr>> = retry_async(
        cfg,
        |_attempt| async {
            match provider.get_transaction_by_hash(tx_hash).await {
                Ok(Some(tx)) => {
                    tracing::info!(?sign_ids_ref, "eth signature respond pending transaction found");
                    Ok(tx)
                }
                Ok(None) => Err(PollErr::NotReady),
                Err(e) => Err(PollErr::Rpc(anyhow::anyhow!(e))),
            }
        },
        |_attempt, _reason| true,
        |attempt, reason, sleep| match reason {
            RetryReason::Error(PollErr::NotReady) => {
                tracing::error!(
                    ?sign_ids_ref,
                    attempt,
                    "eth signature respond pending transaction not found, retrying in {sleep:?}"
                );
            }
            RetryReason::Error(PollErr::Rpc(e)) => {
                tracing::error!(
                    ?sign_ids_ref,
                    attempt,
                    "failed to get eth signature respond pending transaction, retrying in {sleep:?}: {e:?}"
                );
            }
            RetryReason::Timeout(_t) => {
                tracing::error!(
                    ?sign_ids_ref,
                    attempt,
                    "timeout while getting eth signature respond pending transaction, retrying in {sleep:?}"
                );
            }
        },
    )
    .await;

    match res {
        Ok(tx) => Ok(tx),
        Err(_) => Err(()),
    }
}

// wait for transaction receipt with max_attempts and exponential delay backoff starting at 5s
async fn wait_for_transaction_receipt(
    provider: &EthContractFillProvider,
    tx_hash: alloy::primitives::B256,
    sign_ids: Vec<SignId>,
    max_attempts: usize,
) -> Result<TransactionReceipt, ()> {
    let sign_ids_ref = &sign_ids;

    let retry_config = RetryConfig {
        max_attempts,
        per_attempt_timeout: Duration::from_secs(2),
        backoff: Backoff::ExponentialJitter {
            base: Duration::from_secs(1),
            cap: Duration::from_secs(20),
            jitter_max_ms: 0,
        },
    };

    let res: Result<TransactionReceipt, RetryError<PollErr>> = retry_async(
        retry_config,
        |_attempt| async {
            match provider.get_transaction_receipt(tx_hash).await {
                Ok(Some(receipt)) => {
                    tracing::info!(?sign_ids_ref, "eth signature respond transaction receipt found");
                    Ok(receipt)
                }
                Ok(None) => Err(PollErr::NotReady),
                Err(e) => Err(PollErr::Rpc(anyhow::anyhow!(e))),
            }
        },
        |_attempt, _reason| true,
        |attempt, reason, sleep| match reason {
            RetryReason::Error(PollErr::NotReady) => {
                tracing::error!(
                    ?sign_ids_ref,
                    attempt,
                    "eth signature respond transaction receipt not found, retrying in {sleep:?}"
                );
            }
            RetryReason::Error(PollErr::Rpc(e)) => {
                tracing::error!(
                    ?sign_ids_ref,
                    attempt,
                    "failed to get eth signature respond transaction receipt, retrying in {sleep:?}: {e:?}"
                );
            }
            RetryReason::Timeout(_t) => {
                tracing::error!(
                    ?sign_ids_ref,
                    attempt,
                    "timeout while getting eth signature respond transaction receipt, retrying in {sleep:?}"
                );
            }
        },
    )
    .await;

    match res {
        Ok(r) => Ok(r),
        Err(_) => Err(()),
    }
}

fn log_retry_err(ctx: &str, sign_ids: &[SignId], err: RetryError<anyhow::Error>) {
    match err {
        RetryError::Exhausted {
            attempts,
            last_error,
        } => {
            tracing::error!(
                ?sign_ids,
                attempts,
                ?last_error,
                "{ctx}: retry attempts exhausted"
            );
        }
        RetryError::TimeoutExhausted {
            attempts,
            last_timeout,
        } => {
            tracing::error!(
                ?sign_ids,
                attempts,
                ?last_timeout,
                "{ctx}: timeout exhausted"
            );
        }
    }
}

async fn send_eth_transaction(
    contract: &EthContractInstance,
    params: &[DynSolValue],
    gas: u64,
    sign_ids: &[SignId],
) -> Result<alloy::primitives::B256, ()> {
    let cfg_nonce = RetryConfig {
        max_attempts: 3,
        per_attempt_timeout: Duration::from_secs(2),
        backoff: Backoff::ExponentialJitter {
            base: Duration::from_millis(500),
            cap: Duration::from_secs(5),
            jitter_max_ms: 200,
        },
    };

    let nonce_res: Result<u64, RetryError<anyhow::Error>> = retry_async(
        cfg_nonce,
        |_attempt| async {
            contract
                .provider()
                .get_transaction_count(contract.provider().default_signer_address())
                .pending()
                .await
                .map_err(|e| anyhow::anyhow!(e))
        },
        |_attempt, _reason| true,
        |attempt, reason, sleep| match reason {
            RetryReason::Error(e) => {
                tracing::warn!(
                    ?sign_ids,
                    attempt,
                    ?e,
                    "get_nonce failed, retrying in {sleep:?}"
                );
            }
            RetryReason::Timeout(t) => {
                tracing::warn!(
                    ?sign_ids,
                    attempt,
                    "get_nonce timed out after {t:?}, retrying in {sleep:?}"
                );
            }
        },
    )
    .await;

    let nonce = match nonce_res {
        Ok(nonce) => {
            tracing::info!(nonce, "will send eth tx with nonce");
            nonce
        }
        Err(err) => {
            log_retry_err("failed to get nonce", sign_ids, err);
            return Err(());
        }
    };

    let cfg_send = RetryConfig {
        max_attempts: 3,
        per_attempt_timeout: Duration::from_secs(5),
        backoff: Backoff::ExponentialJitter {
            base: Duration::from_millis(500),
            cap: Duration::from_secs(10),
            jitter_max_ms: 200,
        },
    };

    let send_res: Result<alloy::primitives::B256, RetryError<anyhow::Error>> = retry_async(
        cfg_send,
        |_attempt| async {
            let pending = contract
                .function("respond", params)
                .unwrap()
                .gas(gas)
                .nonce(nonce)
                .send()
                .await
                .map_err(|e| anyhow::anyhow!(e))?;

            Ok(*pending.tx_hash())
        },
        |_attempt, _reason| true,
        |attempt, reason, sleep| match reason {
            RetryReason::Error(e) => {
                tracing::warn!(
                    ?sign_ids,
                    attempt,
                    ?e,
                    "send eth tx failed, retrying in {sleep:?}"
                );
            }
            RetryReason::Timeout(t) => {
                tracing::warn!(
                    ?sign_ids,
                    attempt,
                    "send eth tx timed out after {t:?}, retrying in {sleep:?}"
                );
            }
        },
    )
    .await;

    match send_res {
        Ok(tx_hash) => Ok(tx_hash),
        Err(err) => {
            log_retry_err(
                "failed to send ethereum signature transaction",
                sign_ids,
                err,
            );
            Err(())
        }
    }
}

async fn try_publish_eth(
    eth: &EthClient,
    action: &PublishAction,
    timestamp: &Instant,
    signature: &Signature,
) -> Result<(), ()> {
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
    )
    .await?;

    let receipt = wait_for_transaction_receipt(
        eth.contract.provider(),
        tx_hash,
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
        return Err(());
    }

    let tx_hash = receipt.transaction_hash;
    tracing::info!(
        ?sign_id,
        tx_hash = ?tx_hash,
        elapsed = ?timestamp.elapsed(),
        "published ethereum signature successfully"
    );
    Ok(())
}

async fn try_batch_publish_eth(
    eth: &EthClient,
    actions: &Vec<PublishAction>,
    signatures: &HashMap<SignId, Signature>,
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

    let tx_hash = send_eth_transaction(&eth.contract, &params, gas, &sign_ids).await?;

    tracing::info!(?tx_hash, "sent eth tx");

    let tx = wait_for_pending_tx(
        eth.contract.provider(),
        tx_hash,
        sign_ids.clone(),
        ETH_TX_RECEIPT_MAX_ATTEMPTS,
    )
    .await?;

    tracing::info!(?tx, "tx found in mempool");

    let receipt = wait_for_transaction_receipt(
        eth.contract.provider(),
        tx_hash,
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
    Ok(())
}

async fn execute_batch_publish(client: &ChainClient, actions: &mut Vec<PublishAction>) {
    let signatures: HashMap<SignId, Signature> = actions
        .iter()
        .map(|action| (action.indexed.id, action.signature))
        .collect();

    let cfg = RetryConfig {
        max_attempts: MAX_PUBLISH_RETRY,
        per_attempt_timeout: Duration::from_secs(120),
        backoff: Backoff::ExponentialJitter {
            base: Duration::from_secs(1),
            cap: Duration::from_secs(10),
            jitter_max_ms: 0,
        },
    };

    let res: Result<(), RetryError<()>> = retry_async(
        cfg,
        |_attempt| async {
            match client {
                ChainClient::Near(_) => {
                    tracing::error!("near has no batch publish");
                    Ok(())
                }
                ChainClient::Solana(_) => {
                    tracing::error!("Solana has no batch publish");
                    Ok(())
                }
                ChainClient::Ethereum(eth) => {
                    try_batch_publish_eth(eth, actions, &signatures).await
                }
                ChainClient::Hydration(_) => {
                    tracing::error!("Hydration has no batch publish");
                    Ok(())
                }
                ChainClient::Canton(_) => {
                    tracing::error!("Canton does not support batch publish");
                    Ok(())
                }
                ChainClient::Err(msg) => {
                    tracing::error!(msg, "no client for chain");
                    Ok(())
                }
            }
        },
        |_attempt, _reason| true,
        |attempt, reason, sleep| match reason {
            RetryReason::Error(_e) => {
                tracing::warn!("batch publish failed (attempt {attempt}), retrying in {sleep:?}");
            }
            RetryReason::Timeout(t) => {
                tracing::warn!(
                    "batch publish timed out after {t:?} (attempt {attempt}), retrying in {sleep:?}"
                );
            }
        },
    )
    .await;

    if res.is_ok() {
        for action in actions.iter() {
            let chain = action.indexed.chain;
            let elapsed = crate::util::unix_elapsed(action.indexed.unix_timestamp_indexed);
            if elapsed.as_secs() <= chain.expected_response_time_secs() {
                record_request_latency_since(
                    chain,
                    SignRequestStep::Total,
                    "in_time",
                    action.indexed.unix_timestamp_indexed,
                );
            } else {
                record_request_latency_since(
                    chain,
                    SignRequestStep::Total,
                    "expired",
                    action.indexed.unix_timestamp_indexed,
                );
            }
            record_request_latency_since(
                chain,
                SignRequestStep::Responding,
                "ok",
                action.timestamp,
            );
        }
        actions.clear();
        return;
    }

    tracing::info!("exceeded max retries, trashing publish request");
    actions.clear();
}

use signet_program::accounts::Respond as SolanaRespondAccount;
use signet_program::accounts::RespondBidirectional as SolanaRespondBidirectionalAccount;
use signet_program::instruction::Respond as SolanaRespond;
use signet_program::instruction::RespondBidirectional as SolanaRespondBidirectional;
use solana_sdk::signature::Signer as SolanaSigner;
async fn try_publish_sol(
    sol: &SolanaClient,
    action: &PublishAction,
    timestamp: &Instant,
    signature: &Signature,
) -> Result<(), ()> {
    let program = sol.client.program(sol.program_id).map_err(|_| ())?;

    let sign_id = action.indexed.id;
    let request_ids = vec![action.indexed.id.request_id];
    let big_r = signature.big_r.to_encoded_point(false);
    let signature = crate::util::mpc_to_sol_signature(signature, big_r);

    tracing::debug!(
        ?sign_id,
        request_type = ?action.indexed.kind,
        "try_publish_sol: dispatching request"
    );

    match &action.indexed.kind {
        SignKind::Sign | SignKind::SignBidirectional(_) => {
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
                })?;

            tracing::info!(
                ?sign_id,
                tx_hash = ?tx,
                elapsed = ?timestamp.elapsed(),
                "published solana signature successfully"
            );
        }
        SignKind::RespondBidirectional(respond_bidirectional_tx) => {
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
                })?;

            tracing::info!(
                ?sign_id,
                tx_hash = ?tx,
                elapsed = ?timestamp.elapsed(),
                "published respond bidirectional solana signature successfully"
            );
        }
    }

    Ok(())
}

async fn try_publish_hydration(
    hyd: &HydrationClient,
    action: &PublishAction,
    timestamp: &Instant,
    signature: &Signature,
) -> Result<(), ()> {
    let chain = action.indexed.chain;
    let sign_id = action.indexed.id;
    let request_ids = [action.indexed.id.request_id];

    tracing::info!(
        ?sign_id,
        ?chain,
        elapsed = ?timestamp.elapsed(),
        request_id = ?request_ids[0],
        "Hydration: publishing signature"
    );

    match &action.indexed.kind {
        SignKind::Sign | SignKind::SignBidirectional(_) => {
            hyd.call_respond(&action.indexed.id, signature)
                .await
                .map_err(|e| {
                    tracing::error!(?sign_id, ?e, "Hydration: failed to publish signature");
                })?;
            tracing::info!(
                ?sign_id,
                elapsed = ?timestamp.elapsed(),
                "published hydration signature successfully"
            );
        }
        SignKind::RespondBidirectional(respond_bidirectional_tx) => {
            let serialized_output = respond_bidirectional_tx.output.clone();
            tracing::debug!(
                ?sign_id,
                request_id = ?request_ids[0],
                serialized_output_len = serialized_output.len(),
                "try_publish_hydration: entering RespondBidirectional arm"
            );
            let tx_hash = hyd
                .call_respond_bidirectional(&action.indexed.id, serialized_output, signature)
                .await
                .map_err(|e| {
                    tracing::error!(
                        ?sign_id,
                        ?e,
                        "Hydration: failed to publish respond bidirectional signature"
                    );
                })?;
            tracing::info!(
                ?sign_id,
                tx_hash = ?tx_hash,
                elapsed = ?timestamp.elapsed(),
                "published respond bidirectional hydration signature successfully"
            );
        }
    }

    Ok(())
}

async fn try_publish_canton(
    canton: &CantonClient,
    action: &PublishAction,
    timestamp: &std::time::Instant,
    signature: &mpc_primitives::Signature,
) -> anyhow::Result<()> {
    let sign_id = action.indexed.id;
    let request_id_hex = hex::encode(action.indexed.id.request_id);

    tracing::info!(
        ?sign_id,
        chain = ?action.indexed.chain,
        elapsed = ?timestamp.elapsed(),
        request_id = %request_id_hex,
        "canton: publishing signature"
    );

    use crate::indexer_canton::contracts::{CantonSignature, EcdsaSigData};
    let der_sig = hex::encode(crate::indexer_canton::der_encode_signature(signature)?);
    let canton_signature = serde_json::to_value(CantonSignature::EcdsaSig(EcdsaSigData {
        der: der_sig,
        recovery_id: signature.recovery_id,
    }))?;

    let (choice, command_id, choice_argument) = match &action.indexed.kind {
        SignKind::SignBidirectional(crate::stream::ops::SignBidirectionalEvent::Canton(event)) => (
            "Respond",
            format!("mpc-respond-{request_id_hex}"),
            serde_json::json!({
                "signEventCid": &event.sign_event_contract_id,
                "requestId": request_id_hex,
                "signature": canton_signature,
            }),
        ),
        SignKind::RespondBidirectional(respond_tx) => {
            let chain_ctx_bytes = respond_tx
                .chain_ctx
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("missing chain_ctx on Canton response"))?;
            let ctx: crate::indexer_canton::CantonChainCtx = borsh::from_slice(chain_ctx_bytes)
                .map_err(|e| anyhow::anyhow!("failed to deserialize CantonChainCtx: {e}"))?;
            (
                "RespondBidirectional",
                format!("mpc-respond-bidir-{request_id_hex}"),
                serde_json::json!({
                    "signEventCid": ctx.sign_event_contract_id,
                    "requestId": request_id_hex,
                    "serializedOutput": hex::encode(&respond_tx.output),
                    "signature": canton_signature,
                }),
            )
        }
        _ => anyhow::bail!("Canton supports only Canton SignBidirectional or RespondBidirectional"),
    };

    canton
        .exercise_choice(&command_id, choice, choice_argument)
        .await
        .inspect_err(|err| {
            tracing::error!(
                ?sign_id,
                choice,
                request_id = %request_id_hex,
                error = %err,
                "canton: failed to publish signature"
            );
        })?;

    tracing::info!(
        ?sign_id,
        choice,
        elapsed = ?timestamp.elapsed(),
        "published canton {choice} successfully"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::contract::primitives::{ParticipantInfo, Participants};
    use crate::protocol::contract::{ResharingContractState, RunningContractState};
    use crate::protocol::ProtocolState;
    use cait_sith::protocol::Participant;
    use k256::elliptic_curve::ops::Reduce;
    use k256::elliptic_curve::point::DecompressPoint;
    use mpc_crypto::kdf::derive_secret_key;

    fn scalar(bytes: &[u8; 32]) -> k256::Scalar {
        <k256::Scalar as Reduce<<Secp256k1 as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(
            bytes.into(),
        )
    }

    fn make_signature(
        sk: &k256::SecretKey,
        epsilon: k256::Scalar,
        payload: k256::Scalar,
    ) -> FullSignature<Secp256k1> {
        let signing_key = k256::ecdsa::SigningKey::from(&derive_secret_key(sk, epsilon));
        let (ecdsa_sig, _): (k256::ecdsa::Signature, _) =
            <k256::ecdsa::SigningKey as k256::ecdsa::signature::hazmat::PrehashSigner<_>>::sign_prehash(
                &signing_key,
                &payload.to_bytes(),
            )
            .expect("signing should succeed");
        let (r_bytes, _) = ecdsa_sig.split_bytes();
        let big_r =
            AffinePoint::decompress(&r_bytes, k256::elliptic_curve::subtle::Choice::from(0))
                .unwrap();
        FullSignature {
            big_r,
            s: *ecdsa_sig.s().as_ref(),
        }
    }

    fn make_indexed(epsilon: k256::Scalar, payload: k256::Scalar) -> IndexedSignRequest {
        IndexedSignRequest {
            id: SignId::new([0u8; 32]),
            args: mpc_primitives::SignArgs {
                entropy: [0u8; 32],
                epsilon,
                payload,
                path: "test".into(),
                key_version: 0,
            },
            chain: Chain::NEAR,
            unix_timestamp_indexed: 0,
            kind: SignKind::Sign,
        }
    }

    fn test_participants() -> Participants {
        let mut participants = Participants::default();
        participants.insert(&Participant::from(0), ParticipantInfo::new(0));
        participants.insert(&Participant::from(1), ParticipantInfo::new(1));
        participants.insert(&Participant::from(2), ParticipantInfo::new(2));
        participants
    }

    #[tokio::test]
    async fn wait_governance_tracks_resharing_state() {
        let account_id: AccountId = "p-0".parse().unwrap();
        let participants = test_participants();
        let (mut watcher, tx) = ContractStateWatcher::new(&account_id);

        let initial = RunningContractState {
            epoch: 0,
            public_key: AffinePoint::default(),
            participants: participants.clone(),
            candidates: Default::default(),
            join_votes: Default::default(),
            leave_votes: Default::default(),
            threshold: 2,
        };
        tx.send(Some(ProtocolState::Running(initial))).unwrap();

        let governance = watcher.governance().expect("running governance");
        assert_eq!(governance.epoch, 0);
        assert_eq!(governance.threshold, 2);
        assert_eq!(governance.me, Participant::from(0));

        let resharing = ResharingContractState {
            old_epoch: 0,
            old_participants: participants.clone(),
            new_participants: participants.clone(),
            threshold: 2,
            public_key: AffinePoint::default(),
            finished_votes: Default::default(),
            cancel_votes: Default::default(),
        };
        tx.send(Some(ProtocolState::Resharing(resharing))).unwrap();

        let paused = watcher.governance().expect("resharing governance");
        assert_eq!(paused.epoch, 1);
        assert_eq!(paused.threshold, 2);
        assert_eq!(paused.me, Participant::from(0));

        let running = RunningContractState {
            epoch: 1,
            public_key: AffinePoint::default(),
            participants,
            candidates: Default::default(),
            join_votes: Default::default(),
            leave_votes: Default::default(),
            threshold: 2,
        };
        tx.send(Some(ProtocolState::Running(running))).unwrap();

        let resumed = watcher.wait_governance().await;
        assert_eq!(resumed.epoch, 1);
        assert_eq!(resumed.threshold, 2);
        assert_eq!(resumed.me, Participant::from(0));
    }

    #[test]
    fn publish_action_accepts_valid_signature() {
        let sk = k256::SecretKey::random(&mut rand::thread_rng());
        let pk: AffinePoint = sk.public_key().into();
        let epsilon = scalar(&[1u8; 32]);
        let payload = scalar(&[42u8; 32]);

        let output = make_signature(&sk, epsilon, payload);
        let indexed = make_indexed(epsilon, payload);

        assert!(PublishAction::new(pk, indexed, output, vec![]).is_some());
    }

    #[test]
    fn publish_action_rejects_invalid_signature() {
        let sk = k256::SecretKey::random(&mut rand::thread_rng());
        let pk: AffinePoint = sk.public_key().into();
        let epsilon = scalar(&[1u8; 32]);
        let payload = scalar(&[42u8; 32]);

        let mut output = make_signature(&sk, epsilon, payload);
        output.s += k256::Scalar::ONE;
        let indexed = make_indexed(epsilon, payload);

        assert!(PublishAction::new(pk, indexed, output, vec![]).is_none());
    }
}
